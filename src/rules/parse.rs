// simplewall-rs — rule-string parser.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// String → `Vec<RuleClause>`. Form detection is character-class
// based:
//
//     starts with '['   → bracketed IPv6 (with optional `:port`)
//     contains '.'      → IPv4 form (single, range, or CIDR; with
//                         optional `:port`)
//     contains ':'      → bare IPv6 (single or CIDR; cannot have
//                         a port — bracket form is required for
//                         port disambiguation, since IPv6 itself
//                         uses colons)
//     otherwise         → port form (single or range)
//
// The parser is conservative — anything that looks malformed by
// these rules surfaces as `ParseError::*` rather than being
// silently coerced.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{AddrSpec, PortSpec, RuleClause};

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// An entire rule string was empty after splitting / trimming.
    Empty,
    /// A specific clause was empty (e.g. `";;80"`).
    EmptyClause,
    /// An IPv4 / IPv6 address didn't parse.
    BadAddress(String),
    /// A port number didn't parse, or was out of range.
    BadPort(String),
    /// A CIDR prefix was missing or > max for the address family.
    BadCidr(String),
    /// A range had `end < start` or was otherwise malformed.
    BadRange(String),
    /// Generic structural problem (mismatched bracket, etc.).
    Malformed(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "rule string is empty"),
            Self::EmptyClause => write!(f, "empty clause between `;` separators"),
            Self::BadAddress(s) => write!(f, "invalid IP address: `{s}`"),
            Self::BadPort(s) => write!(f, "invalid port: `{s}`"),
            Self::BadCidr(s) => write!(f, "invalid CIDR: `{s}`"),
            Self::BadRange(s) => write!(f, "invalid range: `{s}`"),
            Self::Malformed(s) => write!(f, "malformed clause: {s}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a full rule string into a list of clauses.
///
/// Empty inputs and inputs that contain only whitespace and
/// separators yield `Err(ParseError::Empty)`. Trailing semicolons
/// (`"80; 443;"`) are tolerated to match upstream's permissive
/// handling.
pub fn parse_str(s: &str) -> Result<Vec<RuleClause>, ParseError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut out = Vec::new();
    for raw in trimmed.split(';') {
        let clause = raw.trim();
        if clause.is_empty() {
            // Trailing or interleaved `;` — tolerate.
            continue;
        }
        out.push(parse_clause(clause)?);
    }
    if out.is_empty() {
        return Err(ParseError::Empty);
    }
    Ok(out)
}

/// Parse a single clause. The input must be already trimmed and
/// non-empty.
pub fn parse_clause(s: &str) -> Result<RuleClause, ParseError> {
    if s.is_empty() {
        return Err(ParseError::EmptyClause);
    }

    if let Some(rest) = s.strip_prefix('[') {
        return parse_bracketed_ipv6(rest);
    }
    if s.contains('.') {
        return parse_ipv4_form(s);
    }
    if s.contains(':') {
        // Bare IPv6 — colons are part of the IPv6 syntax, no port.
        let addr = parse_ipv6_addr_or_cidr(s)?;
        return Ok(RuleClause { addr: Some(addr), port: None });
    }
    // Port form (digits only, possibly with `-` for range).
    let port = parse_port_or_range(s)?;
    Ok(RuleClause { addr: None, port: Some(port) })
}

fn parse_bracketed_ipv6(rest: &str) -> Result<RuleClause, ParseError> {
    // `rest` is everything after the opening `[`. Find the matching
    // `]`; everything between is the IPv6 (single or CIDR), anything
    // after is `:port` or empty.
    let close = rest
        .find(']')
        .ok_or(ParseError::Malformed("missing `]` after `[`"))?;
    let inner = &rest[..close];
    let after = &rest[close + 1..];

    let port = if let Some(stripped) = after.strip_prefix(':') {
        Some(parse_port_or_range(stripped)?)
    } else if after.is_empty() {
        None
    } else {
        return Err(ParseError::Malformed("trailing characters after `]`"));
    };

    let addr = parse_ipv6_addr_or_cidr(inner)?;
    Ok(RuleClause { addr: Some(addr), port })
}

fn parse_ipv4_form(s: &str) -> Result<RuleClause, ParseError> {
    // The IPv4 form may have an optional `:port`. Because IPv4 has
    // no colons, splitting on the LAST `:` cleanly separates the
    // address part from the port part if present.
    let (addr_part, port_part) = match s.rfind(':') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };

    let addr = parse_ipv4_addr_range_or_cidr(addr_part)?;
    let port = match port_part {
        Some(p) => Some(parse_port_or_range(p)?),
        None => None,
    };
    Ok(RuleClause { addr: Some(addr), port })
}

fn parse_ipv4_addr_range_or_cidr(s: &str) -> Result<AddrSpec, ParseError> {
    if let Some(slash) = s.find('/') {
        let addr: Ipv4Addr = s[..slash]
            .parse()
            .map_err(|_| ParseError::BadAddress(s.to_string()))?;
        let prefix: u8 = s[slash + 1..]
            .parse()
            .map_err(|_| ParseError::BadCidr(s.to_string()))?;
        if prefix > 32 {
            return Err(ParseError::BadCidr(s.to_string()));
        }
        return Ok(AddrSpec::Ipv4Cidr(addr, prefix));
    }
    if let Some(dash) = s.find('-') {
        let a: Ipv4Addr = s[..dash]
            .parse()
            .map_err(|_| ParseError::BadAddress(s.to_string()))?;
        let b: Ipv4Addr = s[dash + 1..]
            .parse()
            .map_err(|_| ParseError::BadAddress(s.to_string()))?;
        if u32::from(a) > u32::from(b) {
            return Err(ParseError::BadRange(s.to_string()));
        }
        return Ok(AddrSpec::Ipv4Range(a, b));
    }
    let addr: Ipv4Addr = s
        .parse()
        .map_err(|_| ParseError::BadAddress(s.to_string()))?;
    Ok(AddrSpec::Ipv4(addr))
}

fn parse_ipv6_addr_or_cidr(s: &str) -> Result<AddrSpec, ParseError> {
    if let Some(slash) = s.find('/') {
        let addr: Ipv6Addr = s[..slash]
            .parse()
            .map_err(|_| ParseError::BadAddress(s.to_string()))?;
        let prefix: u8 = s[slash + 1..]
            .parse()
            .map_err(|_| ParseError::BadCidr(s.to_string()))?;
        if prefix > 128 {
            return Err(ParseError::BadCidr(s.to_string()));
        }
        return Ok(AddrSpec::Ipv6Cidr(addr, prefix));
    }
    let addr: Ipv6Addr = s
        .parse()
        .map_err(|_| ParseError::BadAddress(s.to_string()))?;
    Ok(AddrSpec::Ipv6(addr))
}

fn parse_port_or_range(s: &str) -> Result<PortSpec, ParseError> {
    if let Some(dash) = s.find('-') {
        let a: u16 = s[..dash]
            .parse()
            .map_err(|_| ParseError::BadPort(s.to_string()))?;
        let b: u16 = s[dash + 1..]
            .parse()
            .map_err(|_| ParseError::BadPort(s.to_string()))?;
        if a > b {
            return Err(ParseError::BadRange(s.to_string()));
        }
        return Ok(PortSpec::Range(a, b));
    }
    let p: u16 = s
        .parse()
        .map_err(|_| ParseError::BadPort(s.to_string()))?;
    Ok(PortSpec::Single(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // ---- single forms ----

    #[test]
    fn ipv4_single() {
        let c = parse_clause("192.168.0.1").unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv4(v4(192, 168, 0, 1))));
        assert_eq!(c.port, None);
    }

    #[test]
    fn ipv4_with_port() {
        let c = parse_clause("192.168.0.1:80").unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv4(v4(192, 168, 0, 1))));
        assert_eq!(c.port, Some(PortSpec::Single(80)));
    }

    #[test]
    fn ipv4_range() {
        let c = parse_clause("192.168.0.1-192.168.0.10").unwrap();
        assert_eq!(
            c.addr,
            Some(AddrSpec::Ipv4Range(v4(192, 168, 0, 1), v4(192, 168, 0, 10)))
        );
        assert_eq!(c.port, None);
    }

    #[test]
    fn ipv4_range_with_port() {
        let c = parse_clause("10.0.0.0-10.0.0.255:443").unwrap();
        assert_eq!(
            c.addr,
            Some(AddrSpec::Ipv4Range(v4(10, 0, 0, 0), v4(10, 0, 0, 255)))
        );
        assert_eq!(c.port, Some(PortSpec::Single(443)));
    }

    #[test]
    fn ipv4_cidr() {
        let c = parse_clause("192.168.0.0/16").unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv4Cidr(v4(192, 168, 0, 0), 16)));
        assert_eq!(c.port, None);
    }

    #[test]
    fn ipv4_cidr_with_port() {
        let c = parse_clause("10.0.0.0/8:1234").unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv4Cidr(v4(10, 0, 0, 0), 8)));
        assert_eq!(c.port, Some(PortSpec::Single(1234)));
    }

    #[test]
    fn ipv6_bracketed_single() {
        let c = parse_clause("[fc00::]").unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv6("fc00::".parse().unwrap())));
        assert_eq!(c.port, None);
    }

    #[test]
    fn ipv6_bracketed_with_port() {
        let c = parse_clause("[fc00::]:443").unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv6("fc00::".parse().unwrap())));
        assert_eq!(c.port, Some(PortSpec::Single(443)));
    }

    #[test]
    fn ipv6_bare_single() {
        let c = parse_clause("fe80::1").unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv6("fe80::1".parse().unwrap())));
        assert_eq!(c.port, None);
    }

    #[test]
    fn ipv6_cidr_bare() {
        let c = parse_clause("fe80::/10").unwrap();
        let addr: Ipv6Addr = "fe80::".parse().unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv6Cidr(addr, 10)));
        assert_eq!(c.port, None);
    }

    #[test]
    fn ipv6_cidr_bracketed_with_port() {
        // CIDR goes inside the brackets — the brackets enclose the
        // full address spec including any prefix length. The form
        // `[addr]/prefix:port` (CIDR outside brackets) is rejected
        // as malformed; see `cidr_outside_brackets_is_malformed`.
        let c = parse_clause("[fe80::/10]:443").unwrap();
        let addr: Ipv6Addr = "fe80::".parse().unwrap();
        assert_eq!(c.addr, Some(AddrSpec::Ipv6Cidr(addr, 10)));
        assert_eq!(c.port, Some(PortSpec::Single(443)));
    }

    #[test]
    fn cidr_outside_brackets_is_malformed() {
        let err = parse_clause("[fe80::]/10").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn port_single() {
        let c = parse_clause("443").unwrap();
        assert_eq!(c.addr, None);
        assert_eq!(c.port, Some(PortSpec::Single(443)));
    }

    #[test]
    fn port_range() {
        let c = parse_clause("49152-65534").unwrap();
        assert_eq!(c.addr, None);
        assert_eq!(c.port, Some(PortSpec::Range(49152, 65534)));
    }

    // ---- multi-clause strings ----

    #[test]
    fn multi_clause_ports_and_ips() {
        let cs = parse_str("80; 443; 192.168.0.1; [fe80::]:443").unwrap();
        assert_eq!(cs.len(), 4);
        assert_eq!(cs[0].port, Some(PortSpec::Single(80)));
        assert_eq!(cs[1].port, Some(PortSpec::Single(443)));
        assert!(matches!(cs[2].addr, Some(AddrSpec::Ipv4(_))));
        assert!(matches!(cs[3].addr, Some(AddrSpec::Ipv6(_))));
    }

    #[test]
    fn trailing_semicolon_is_tolerated() {
        let cs = parse_str("80;").unwrap();
        assert_eq!(cs.len(), 1);
    }

    #[test]
    fn upstream_readme_example_string_round_trips() {
        // Composite from the upstream README:
        //   "21; 80; 443; 192.168.0.1:443; 10.0.0.0/8;
        //    192.168.0.1-192.168.0.255; [fc00::]:443; 20-21;"
        let s = "21; 80; 443; 192.168.0.1:443; 10.0.0.0/8; \
                 192.168.0.1-192.168.0.255; [fc00::]:443; 20-21;";
        let cs = parse_str(s).unwrap();
        assert_eq!(cs.len(), 8);
    }

    // ---- error paths ----

    #[test]
    fn empty_string_errors() {
        assert_eq!(parse_str(""), Err(ParseError::Empty));
        assert_eq!(parse_str("   ").unwrap_err(), ParseError::Empty);
        assert_eq!(parse_str(";;").unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn empty_clause_inside_separators_is_skipped_not_errored() {
        // `;;80` has an empty middle which we tolerate per
        // upstream's permissive split.
        let cs = parse_str("80;;443").unwrap();
        assert_eq!(cs.len(), 2);
    }

    #[test]
    fn bad_ipv4_address() {
        let err = parse_clause("999.0.0.1").unwrap_err();
        assert!(matches!(err, ParseError::BadAddress(_)));
    }

    #[test]
    fn port_out_of_range() {
        let err = parse_clause("70000").unwrap_err();
        assert!(matches!(err, ParseError::BadPort(_)));
    }

    #[test]
    fn cidr_prefix_too_large_v4() {
        let err = parse_clause("10.0.0.0/33").unwrap_err();
        assert!(matches!(err, ParseError::BadCidr(_)));
    }

    #[test]
    fn cidr_prefix_too_large_v6() {
        let err = parse_clause("fe80::/129").unwrap_err();
        assert!(matches!(err, ParseError::BadCidr(_)));
    }

    #[test]
    fn ipv4_range_reversed_is_error() {
        let err = parse_clause("10.0.0.10-10.0.0.5").unwrap_err();
        assert!(matches!(err, ParseError::BadRange(_)));
    }

    #[test]
    fn port_range_reversed_is_error() {
        let err = parse_clause("100-50").unwrap_err();
        assert!(matches!(err, ParseError::BadRange(_)));
    }

    #[test]
    fn unmatched_open_bracket() {
        let err = parse_clause("[fe80::").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn trailing_chars_after_close_bracket() {
        let err = parse_clause("[fe80::]xyz").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }
}

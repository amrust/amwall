// amwall — rule-string parser.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
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
    // IPv6 addresses never contain `-`, so any dash is a `start-end`
    // range divider. Upstream simplewall splits rules on `-` for both
    // families (helper.c DIVIDER_RULE_RANGE); amwall previously only
    // handled the IPv4 range form, so a migrated IPv6-range rule was
    // rejected and silently skipped at install.
    if let Some(dash) = s.find('-') {
        let a: Ipv6Addr = s[..dash]
            .parse()
            .map_err(|_| ParseError::BadAddress(s.to_string()))?;
        let b: Ipv6Addr = s[dash + 1..]
            .parse()
            .map_err(|_| ParseError::BadAddress(s.to_string()))?;
        if u128::from(a) > u128::from(b) {
            return Err(ParseError::BadRange(s.to_string()));
        }
        return Ok(AddrSpec::Ipv6Range(a, b));
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
    fn ipv6_range() {
        let c = parse_clause("2001:db8::1-2001:db8::10").unwrap();
        assert_eq!(
            c.addr,
            Some(AddrSpec::Ipv6Range(
                "2001:db8::1".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ))
        );
        assert_eq!(c.port, None);
    }

    #[test]
    fn ipv6_range_bracketed_with_port() {
        // `[start-end]:port` — brackets disambiguate the range from the
        // trailing port, same as the single / CIDR bracketed forms.
        let c = parse_clause("[2001:db8::1-2001:db8::ff]:443").unwrap();
        assert_eq!(
            c.addr,
            Some(AddrSpec::Ipv6Range(
                "2001:db8::1".parse().unwrap(),
                "2001:db8::ff".parse().unwrap(),
            ))
        );
        assert_eq!(c.port, Some(PortSpec::Single(443)));
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
    fn ipv6_range_reversed_rejected() {
        // start > end must be rejected, not compiled into a filter that
        // silently matches nothing (same guard as the v4 / port ranges).
        let err = parse_clause("2001:db8::10-2001:db8::1").unwrap_err();
        assert!(matches!(err, ParseError::BadRange(_)));
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

// =================================================================
// Property tests (M3.4).
//
// Two coarse properties:
//
//   PT1  — `parse_str` must never panic on arbitrary UTF-8 input.
//          Adversarial input (random bytes, malformed clauses,
//          edge-case structural chars) goes to `Err`, never to
//          a panic / overflow / index-out-of-bounds.
//
//   PT2  — Round-trip via `Display`. For every valid `RuleClause`
//          the AST can produce, `parse_clause(c.to_string())` must
//          return an AST equal to `c`. This catches Display ↔ parse
//          drift (e.g. forgetting to bracket IPv6+port).
//
// Multi-clause variant of PT2 is covered by PT3 — generate a small
// `Vec<RuleClause>`, render via `format_clauses`, parse_str back,
// expect the same Vec.
// =================================================================

#[cfg(test)]
mod proptests {
    use super::super::{format_clauses, AddrSpec, PortSpec, RuleClause};
    use super::{parse_clause, parse_str};
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---- strategies ----

    fn ipv4() -> impl Strategy<Value = Ipv4Addr> {
        any::<u32>().prop_map(Ipv4Addr::from)
    }

    fn ipv6() -> impl Strategy<Value = Ipv6Addr> {
        any::<u128>().prop_map(Ipv6Addr::from)
    }

    fn ipv4_range() -> impl Strategy<Value = (Ipv4Addr, Ipv4Addr)> {
        // Keep `a <= b` so we don't trip BadRange.
        (any::<u32>(), any::<u32>()).prop_map(|(x, y)| {
            let (lo, hi) = if x <= y { (x, y) } else { (y, x) };
            (Ipv4Addr::from(lo), Ipv4Addr::from(hi))
        })
    }

    fn port_range() -> impl Strategy<Value = (u16, u16)> {
        (any::<u16>(), any::<u16>()).prop_map(|(x, y)| {
            if x <= y { (x, y) } else { (y, x) }
        })
    }

    fn addr_spec() -> impl Strategy<Value = AddrSpec> {
        prop_oneof![
            ipv4().prop_map(AddrSpec::Ipv4),
            ipv4_range().prop_map(|(a, b)| AddrSpec::Ipv4Range(a, b)),
            (ipv4(), 0u8..=32).prop_map(|(a, p)| AddrSpec::Ipv4Cidr(a, p)),
            ipv6().prop_map(AddrSpec::Ipv6),
            (ipv6(), 0u8..=128).prop_map(|(a, p)| AddrSpec::Ipv6Cidr(a, p)),
        ]
    }

    fn port_spec() -> impl Strategy<Value = PortSpec> {
        prop_oneof![
            any::<u16>().prop_map(PortSpec::Single),
            port_range().prop_map(|(a, b)| PortSpec::Range(a, b)),
        ]
    }

    fn rule_clause() -> impl Strategy<Value = RuleClause> {
        // Three valid shapes: addr-only, port-only, addr+port.
        // (Both-None is structurally impossible from the parser, so
        // we don't generate it.)
        prop_oneof![
            addr_spec().prop_map(|a| RuleClause { addr: Some(a), port: None }),
            port_spec().prop_map(|p| RuleClause { addr: None, port: Some(p) }),
            (addr_spec(), port_spec())
                .prop_map(|(a, p)| RuleClause { addr: Some(a), port: Some(p) }),
        ]
    }

    // ---- PT1: panic-freedom on arbitrary input ----

    proptest! {
        #[test]
        fn parse_str_doesnt_panic_on_arbitrary_utf8(s in ".*") {
            let _ = parse_str(&s);
        }

        // Targeted: strings drawn from the rule-syntax alphabet. More
        // likely to actually exercise parser branches than `.*`, which
        // mostly produces obvious-garbage that bails at the first
        // dispatch check.
        #[test]
        fn parse_str_doesnt_panic_on_rule_alphabet(
            s in r"[0-9a-fA-F.:/;\-\[\] ]{0,200}"
        ) {
            let _ = parse_str(&s);
        }

        // Targeted: a full clause-shaped grammar. Exercises happy-path
        // parsing far more often than the alphabet sampler.
        #[test]
        fn parse_clause_doesnt_panic_on_clauselike_strings(
            s in r"\[?[0-9a-fA-F.:]{1,40}\]?(/[0-9]{1,3})?(:[0-9]{1,6}(-[0-9]{1,6})?)?"
        ) {
            let _ = parse_clause(&s);
        }
    }

    // ---- PT2: AST → Display → parse_clause round-trip ----

    proptest! {
        #[test]
        fn rule_clause_display_roundtrips(clause in rule_clause()) {
            let s = clause.to_string();
            let parsed = parse_clause(&s).unwrap_or_else(|e| {
                panic!("formatted clause `{s}` failed to parse: {e}")
            });
            prop_assert_eq!(clause, parsed);
        }

        #[test]
        fn addr_spec_display_roundtrips_when_used_alone(addr in addr_spec()) {
            // An address-only clause is the simplest carrier — exercise
            // AddrSpec::Display through the full clause pipeline.
            let clause = RuleClause { addr: Some(addr.clone()), port: None };
            let s = clause.to_string();
            let parsed = parse_clause(&s).unwrap();
            prop_assert_eq!(parsed.addr, Some(addr));
            prop_assert_eq!(parsed.port, None);
        }

        #[test]
        fn port_spec_display_roundtrips_when_used_alone(port in port_spec()) {
            let clause = RuleClause { addr: None, port: Some(port) };
            let s = clause.to_string();
            let parsed = parse_clause(&s).unwrap();
            prop_assert_eq!(parsed.addr, None);
            prop_assert_eq!(parsed.port, Some(port));
        }
    }

    // ---- PT3: Vec<RuleClause> → format_clauses → parse_str ----

    proptest! {
        #[test]
        fn format_clauses_roundtrips(clauses in prop::collection::vec(rule_clause(), 1..16)) {
            let s = format_clauses(&clauses);
            let parsed = parse_str(&s).unwrap_or_else(|e| {
                panic!("formatted rule string `{s}` failed to parse: {e}")
            });
            prop_assert_eq!(clauses, parsed);
        }
    }

    // ---- PT4: whitespace + trailing-semicolon tolerance ----

    proptest! {
        #[test]
        fn whitespace_and_trailing_semicolons_dont_change_result(
            clauses in prop::collection::vec(rule_clause(), 1..8),
            extra_trailing in 0u32..3,
            extra_inner_spaces in 0u32..3,
        ) {
            // Canonical form.
            let canonical = format_clauses(&clauses);
            let canonical_parsed = parse_str(&canonical).unwrap();

            // Build a noisy variant with extra spaces around `;` and
            // up to a few trailing semicolons. Per parser docs both
            // are tolerated and shouldn't change the result.
            let mut noisy = String::new();
            for (i, c) in clauses.iter().enumerate() {
                if i > 0 {
                    noisy.push(';');
                    for _ in 0..extra_inner_spaces {
                        noisy.push(' ');
                    }
                }
                use std::fmt::Write;
                let _ = write!(noisy, "{c}");
            }
            for _ in 0..extra_trailing {
                noisy.push(';');
            }
            let noisy_parsed = parse_str(&noisy).unwrap();

            prop_assert_eq!(canonical_parsed, noisy_parsed);
        }
    }
}

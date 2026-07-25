// amwall — rule-string AST + parser.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Upstream simplewall encodes user rule conditions as a single
// semicolon-separated string (see the `rule` and `rule_local`
// attributes inside profile.xml `<item>` elements). This module
// defines the typed AST those strings parse to, and the
// `parse_str` / `parse_clause` entry points.
//
// The syntax (from upstream README — "Rule syntax format"):
//
//     192.168.0.1                    single IPv4
//     192.168.0.1:80                 IPv4 + port
//     192.168.0.1-192.168.0.255      IPv4 range
//     192.168.0.1-192.168.0.255:80   IPv4 range + port
//     192.168.0.0/16                 IPv4 CIDR
//     [fc00::]                       single IPv6 (bracketed)
//     fc00::1                        single IPv6 (bare)
//     [fc00::]:443                   IPv6 + port (bracketed only)
//     fe80::/10                      IPv6 CIDR
//     80                             single port
//     20-21                          port range
//     "192.168.0.1; 80; 443"         multiple clauses, `;`-separated
//
// Compilation of `Vec<RuleClause>` into `wfp::condition::FilterCondition`
// values lands in M3.2.

pub mod parse;

#[cfg(windows)]
pub mod compile;

use std::net::{Ipv4Addr, Ipv6Addr};

pub use parse::{parse_clause, parse_str, ParseError};

#[cfg(windows)]
pub use compile::{compile, Side};

/// One semicolon-separated clause from a rule string. Either
/// `addr` or `port` is present (or both); a clause with both
/// `None` is structurally impossible from the parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleClause {
    pub addr: Option<AddrSpec>,
    pub port: Option<PortSpec>,
}

/// Address-side match spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrSpec {
    /// Single IPv4 address.
    Ipv4(Ipv4Addr),
    /// IPv4 inclusive range, `start-end`.
    Ipv4Range(Ipv4Addr, Ipv4Addr),
    /// IPv4 CIDR — address + prefix length 0..=32.
    Ipv4Cidr(Ipv4Addr, u8),
    /// Single IPv6 address.
    Ipv6(Ipv6Addr),
    /// IPv6 inclusive range, `start-end`.
    Ipv6Range(Ipv6Addr, Ipv6Addr),
    /// IPv6 CIDR — address + prefix length 0..=128.
    Ipv6Cidr(Ipv6Addr, u8),
}

/// Port-side match spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec {
    /// One port number.
    Single(u16),
    /// Inclusive port range, `start-end`.
    Range(u16, u16),
}

impl AddrSpec {
    /// `true` if this is an IPv6-family spec (single or CIDR).
    /// Used by `Display` for `RuleClause` to decide whether the
    /// address needs `[…]` brackets when a port is present.
    pub fn is_ipv6(&self) -> bool {
        matches!(
            self,
            Self::Ipv6(_) | Self::Ipv6Cidr(_, _) | Self::Ipv6Range(_, _)
        )
    }
}

impl std::fmt::Display for AddrSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4(a) => write!(f, "{a}"),
            Self::Ipv4Range(a, b) => write!(f, "{a}-{b}"),
            Self::Ipv4Cidr(a, p) => write!(f, "{a}/{p}"),
            Self::Ipv6(a) => write!(f, "{a}"),
            Self::Ipv6Range(a, b) => write!(f, "{a}-{b}"),
            Self::Ipv6Cidr(a, p) => write!(f, "{a}/{p}"),
        }
    }
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(p) => write!(f, "{p}"),
            Self::Range(a, b) => write!(f, "{a}-{b}"),
        }
    }
}

impl std::fmt::Display for RuleClause {
    /// Render as a string the parser would round-trip back to an
    /// equal `RuleClause`. IPv6 is ALWAYS bracketed — with a port
    /// (`[fe80::/10]:443`) because IPv6 uses colons, and WITHOUT a port
    /// too, because an IPv4-mapped address (`::ffff:1.2.3.4`) renders
    /// with embedded dots that the parser's `.`-first dispatch would
    /// otherwise misroute to the IPv4 branch and reject, dropping the
    /// rule on a save->load cycle.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.addr, &self.port) {
            (Some(a), Some(p)) if a.is_ipv6() => write!(f, "[{a}]:{p}"),
            (Some(a), Some(p)) => write!(f, "{a}:{p}"),
            (Some(a), None) if a.is_ipv6() => write!(f, "[{a}]"),
            (Some(a), None) => write!(f, "{a}"),
            (None, Some(p)) => write!(f, "{p}"),
            (None, None) => Ok(()),
        }
    }
}

/// Format a list of clauses back to an upstream-style `;`-separated
/// rule string. `format_clauses(parse_str(s))` is a normalized
/// version of `s` (canonical IPv6 forms, single-space separator,
/// no trailing semicolon).
pub fn format_clauses(clauses: &[RuleClause]) -> String {
    let mut out = String::new();
    for (i, c) in clauses.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        use std::fmt::Write;
        let _ = write!(out, "{c}");
    }
    out
}

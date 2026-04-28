// simplewall-rs — rule-string AST + parser.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
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

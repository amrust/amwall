// simplewall-rs — rule-clause compiler.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// `Vec<RuleClause>` (the M3.1 AST) → `Vec<FilterCondition>` (the
// M1.5 type that `wfp::filter::add` consumes). Closes the bridge
// between the profile-on-disk format and the kernel-side filter
// installation.
//
// Range forms compile to `FWP_RANGE0`-backed `FilterCondition::*Range`
// variants (M3.3); single + CIDR + IPv6 compile to single-value
// conditions (M3.2).
//
// Windows-only because `FilterCondition` is windows-only — see
// `src/rules.rs` for the cfg-gating.

use crate::rules::{AddrSpec, PortSpec, RuleClause};
use crate::wfp::condition::FilterCondition;

/// Whether a clause matches the local or remote endpoint of a
/// connection. Determines which `FWPM_CONDITION_IP_*` field-key
/// the compiled condition uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// `<item rule_local="...">` — match against the local endpoint.
    Local,
    /// `<item rule="...">` — match against the remote endpoint.
    Remote,
}

/// Compile a list of clauses into a flat `Vec<FilterCondition>`.
///
/// Each clause may produce one or two conditions: one for the
/// address part (if present), one for the port part (if present).
/// The kernel ANDs all conditions on a filter, so the resulting
/// vector matches a packet only when every condition does — which
/// is upstream's semantic for `rule="addr1; addr2"` (each
/// semicolon-separated clause becomes a SEPARATE filter, not a
/// single filter ANDing them all). Callers that want one filter
/// per clause should call `compile` once per clause, not once with
/// the full list.
///
/// Infallible: every parser-produced AST variant maps to a
/// `FilterCondition`. There is no error path.
pub fn compile(side: Side, clauses: &[RuleClause]) -> Vec<FilterCondition> {
    let mut out = Vec::with_capacity(clauses.len() * 2);
    for clause in clauses {
        if let Some(addr) = &clause.addr {
            out.push(compile_addr(side, addr));
        }
        if let Some(port) = clause.port {
            out.push(compile_port(side, port));
        }
    }
    out
}

fn compile_addr(side: Side, addr: &AddrSpec) -> FilterCondition {
    match *addr {
        AddrSpec::Ipv4(a) => match side {
            Side::Local => FilterCondition::LocalAddrV4 { addr: a, prefix: None },
            Side::Remote => FilterCondition::RemoteAddrV4 { addr: a, prefix: None },
        },
        AddrSpec::Ipv4Cidr(a, p) => match side {
            Side::Local => FilterCondition::LocalAddrV4 { addr: a, prefix: Some(p) },
            Side::Remote => FilterCondition::RemoteAddrV4 { addr: a, prefix: Some(p) },
        },
        AddrSpec::Ipv4Range(lo, hi) => match side {
            Side::Local => FilterCondition::LocalAddrV4Range(lo, hi),
            Side::Remote => FilterCondition::RemoteAddrV4Range(lo, hi),
        },
        AddrSpec::Ipv6(a) => match side {
            Side::Local => FilterCondition::LocalAddrV6 { addr: a, prefix: None },
            Side::Remote => FilterCondition::RemoteAddrV6 { addr: a, prefix: None },
        },
        AddrSpec::Ipv6Cidr(a, p) => match side {
            Side::Local => FilterCondition::LocalAddrV6 { addr: a, prefix: Some(p) },
            Side::Remote => FilterCondition::RemoteAddrV6 { addr: a, prefix: Some(p) },
        },
    }
}

fn compile_port(side: Side, port: PortSpec) -> FilterCondition {
    match port {
        PortSpec::Single(p) => match side {
            Side::Local => FilterCondition::LocalPort(p),
            Side::Remote => FilterCondition::RemotePort(p),
        },
        PortSpec::Range(lo, hi) => match side {
            Side::Local => FilterCondition::LocalPortRange(lo, hi),
            Side::Remote => FilterCondition::RemotePortRange(lo, hi),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_clause;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn one(side: Side, s: &str) -> Vec<FilterCondition> {
        let clause = parse_clause(s).unwrap();
        compile(side, &[clause])
    }

    #[test]
    fn single_ipv4_remote() {
        let conds = one(Side::Remote, "192.168.0.1");
        assert_eq!(conds.len(), 1);
        match &conds[0] {
            FilterCondition::RemoteAddrV4 { addr, prefix } => {
                assert_eq!(*addr, Ipv4Addr::new(192, 168, 0, 1));
                assert_eq!(*prefix, None);
            }
            other => panic!("unexpected condition: {other:?}"),
        }
    }

    #[test]
    fn ipv4_cidr_local() {
        let conds = one(Side::Local, "10.0.0.0/8");
        assert_eq!(conds.len(), 1);
        match &conds[0] {
            FilterCondition::LocalAddrV4 { addr, prefix } => {
                assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 0));
                assert_eq!(*prefix, Some(8));
            }
            other => panic!("unexpected condition: {other:?}"),
        }
    }

    #[test]
    fn ipv4_with_port_emits_two_conditions() {
        let conds = one(Side::Remote, "192.168.0.1:443");
        assert_eq!(conds.len(), 2);
        assert!(matches!(
            conds[0],
            FilterCondition::RemoteAddrV4 { prefix: None, .. }
        ));
        assert!(matches!(conds[1], FilterCondition::RemotePort(443)));
    }

    #[test]
    fn ipv6_single_bracketed() {
        let conds = one(Side::Remote, "[fc00::]");
        let expected: Ipv6Addr = "fc00::".parse().unwrap();
        match &conds[0] {
            FilterCondition::RemoteAddrV6 { addr, prefix: None } => {
                assert_eq!(*addr, expected);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ipv6_cidr_with_port() {
        let conds = one(Side::Remote, "[fe80::/10]:443");
        assert_eq!(conds.len(), 2);
        match &conds[0] {
            FilterCondition::RemoteAddrV6 { addr, prefix } => {
                assert_eq!(*addr, "fe80::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(*prefix, Some(10));
            }
            other => panic!("addr: {other:?}"),
        }
        assert!(matches!(conds[1], FilterCondition::RemotePort(443)));
    }

    #[test]
    fn port_only_local() {
        let conds = one(Side::Local, "1234");
        assert_eq!(conds.len(), 1);
        assert!(matches!(conds[0], FilterCondition::LocalPort(1234)));
    }

    #[test]
    fn multi_clause_flattens_conditions() {
        let parsed = crate::rules::parse_str("80; 443; 192.168.0.0/16").unwrap();
        let conds = compile(Side::Remote, &parsed);
        // Three clauses → three conditions: two ports + one address.
        assert_eq!(conds.len(), 3);
        assert!(matches!(conds[0], FilterCondition::RemotePort(80)));
        assert!(matches!(conds[1], FilterCondition::RemotePort(443)));
        assert!(matches!(
            conds[2],
            FilterCondition::RemoteAddrV4 { prefix: Some(16), .. }
        ));
    }

    #[test]
    fn ipv4_range_compiles_to_addr_range() {
        let conds = one(Side::Remote, "10.0.0.1-10.0.0.10");
        assert_eq!(conds.len(), 1);
        match &conds[0] {
            FilterCondition::RemoteAddrV4Range(lo, hi) => {
                assert_eq!(*lo, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(*hi, Ipv4Addr::new(10, 0, 0, 10));
            }
            other => panic!("unexpected condition: {other:?}"),
        }
    }

    #[test]
    fn port_range_compiles_to_port_range() {
        let conds = one(Side::Local, "20-21");
        assert_eq!(conds.len(), 1);
        assert!(matches!(conds[0], FilterCondition::LocalPortRange(20, 21)));
    }

    #[test]
    fn ipv4_range_with_port_emits_two_range_conditions() {
        let conds = one(Side::Remote, "10.0.0.0-10.0.0.255:443");
        assert_eq!(conds.len(), 2);
        assert!(matches!(conds[0], FilterCondition::RemoteAddrV4Range(_, _)));
        assert!(matches!(conds[1], FilterCondition::RemotePort(443)));
    }
}

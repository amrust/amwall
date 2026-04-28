// simplewall-rs — profile.xml types + I/O.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// On-disk profile format used by upstream simplewall, both for the
// user's own `profile.xml` (apps + rule overrides + custom rules)
// and for the bundled `profile_internal.xml` (system rules,
// shipped-default custom rules, blocklist).
//
// Parsing surface lives in `parse`; serialization arrives in M2.2.
//
// Schema (from `simplewall-master/src/db.c::_app_db_parse`):
//
//   <root timestamp=".." type=".." version="..">
//     <apps>           — user profile only
//       <item path=".." is_enabled=".." is_silent=".." ... />
//     </apps>
//     <rules_config>   — user profile only
//       <item name=".." is_enabled=".." apps=".." />
//     </rules_config>
//     <rules_system>   — internal profile only
//       <item ... />
//     </rules_system>
//     <rules_custom>   — both flavors (means different things)
//       <item ... />
//     </rules_custom>
//     <rules_blocklist>— internal profile only
//       <item ... />
//     </rules_blocklist>
//   </root>
//
// We model both flavors with one `Profile` struct + a `kind` field
// rather than a sum type because (a) most fields are shared, (b)
// many WFP-port use cases want to read either flavor uniformly, and
// (c) round-trip serialization is simpler with a stable struct
// shape.

pub mod parse;

use std::path::PathBuf;

pub use parse::{parse_str, ParseError};

/// Top-level profile — the deserialized form of one `<root>` element.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// Unix timestamp from `<root timestamp="...">`.
    pub timestamp: i64,
    /// Profile flavor. Distinguishes `profile.xml` (user) from
    /// `profile_internal.xml` (bundled blocklist + system rules).
    pub kind: ProfileKind,
    /// On-disk format version from `<root version="...">`. Upstream's
    /// minimum required is 5 as of v3.8.7.
    pub version: u32,
    /// `<apps>` section. Empty unless this is a user profile.
    pub apps: Vec<App>,
    /// `<rules_config>` — per-rule enable/disable + app-list overrides.
    /// Empty unless this is a user profile.
    pub rule_configs: Vec<RuleConfig>,
    /// `<rules_system>`. Empty unless this is the internal profile.
    pub system_rules: Vec<Rule>,
    /// `<rules_custom>`. In a user profile these are the user's
    /// hand-authored rules; in the internal profile they're the
    /// bundled defaults.
    pub custom_rules: Vec<Rule>,
    /// `<rules_blocklist>`. Empty unless this is the internal profile.
    pub blocklist_rules: Vec<Rule>,
}

/// Whether this profile is a user profile or the bundled internal one.
/// Encoded numerically in `<root type="...">` — upstream uses 4 for
/// the user profile; the internal profile carries a different number
/// that we capture as `Internal(raw)` to preserve round-trip fidelity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    User,
    Internal,
    /// An unrecognized type number. Preserved verbatim so a future
    /// upstream change doesn't make us lose data on round-trip.
    Other(u32),
}

impl ProfileKind {
    pub fn raw(self) -> u32 {
        match self {
            Self::User => 4,
            // Type code observed in upstream profile_internal.xml is
            // also 4 in v3.8.7's bundled file (see
            // `simplewall-master/bin/profile_internal.xml`). The
            // distinction between user and internal is by FILE NAME
            // and which sections are populated, not by the type
            // number. We carry the field for round-trip but treat
            // both flavors equivalently when emitting.
            Self::Internal => 4,
            Self::Other(n) => n,
        }
    }
}

/// `<apps><item ...>` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct App {
    pub path: PathBuf,
    pub is_enabled: bool,
    pub is_silent: bool,
    pub is_undeletable: bool,
    pub timestamp: i64,
    pub timer: i64,
    pub hash: Option<String>,
    pub comment: Option<String>,
}

/// `<rules_config><item ...>` entry — overrides for a named rule
/// (typically applied to a system rule).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleConfig {
    pub name: String,
    pub is_enabled: bool,
    pub apps: Option<String>,
}

/// `<item ...>` entry inside any of the rule sections. Same shape
/// across `rules_system` / `rules_custom` / `rules_blocklist`; the
/// containing section determines semantic role.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub name: String,
    /// `rule` attribute — semicolon-separated remote-side matchers
    /// (IPs, IP ranges, CIDRs, ports, IP:port pairs).
    pub remote: Option<String>,
    /// `rule_local` attribute — same syntax as `remote`, but matched
    /// against the local endpoint.
    pub local: Option<String>,
    pub direction: Direction,
    pub action: Action,
    pub protocol: Option<u8>,
    pub address_family: Option<AddressFamily>,
    /// `apps` attribute — `|`-separated app paths or service names.
    pub apps: Option<String>,
    pub is_services: bool,
    pub is_enabled: bool,
    /// `os_version` attribute — minimum-Windows-version gate, e.g.
    /// `"6.2"` (Win 8) or `"10.0"` (Win 10).
    pub os_version: Option<String>,
    pub comment: Option<String>,
}

/// Filter direction. Numeric encoding from `<item dir="...">` matches
/// `FWP_DIRECTION` (0 = outbound, 1 = inbound) plus an `Any` (2)
/// extension upstream uses for bidirectional rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// Default when `dir` is absent or `0`.
    #[default]
    Outbound,
    Inbound,
    /// `dir="2"` — bidirectional, observed on rules like DHCP / SNMP
    /// in `profile_internal.xml` where both ends initiate traffic.
    Any,
    /// Unrecognized direction value preserved for round-trip.
    Other(i32),
}

impl Direction {
    pub fn raw(self) -> i32 {
        match self {
            Self::Outbound => 0,
            Self::Inbound => 1,
            Self::Any => 2,
            Self::Other(n) => n,
        }
    }

    fn from_raw(n: i32) -> Self {
        match n {
            0 => Self::Outbound,
            1 => Self::Inbound,
            2 => Self::Any,
            other => Self::Other(other),
        }
    }
}

/// Filter action. Encoded as `is_block="true"|"false"` rather than
/// a numeric code — upstream stores the boolean directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    #[default]
    Permit,
    Block,
}

/// `<item version="...">` — Windows address-family numeric. Stored
/// alongside the protocol / IP rule because upstream uses it to skip
/// IPv4 rules when only IPv6 traffic is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// `AF_INET` — IPv4-only.
    Ipv4,
    /// `AF_INET6` — IPv6-only.
    Ipv6,
    /// Unrecognized AF preserved for round-trip.
    Other(u32),
}

impl AddressFamily {
    pub fn raw(self) -> u32 {
        match self {
            Self::Ipv4 => 2, // AF_INET
            Self::Ipv6 => 23, // AF_INET6
            Self::Other(n) => n,
        }
    }

    fn from_raw(n: u32) -> Self {
        match n {
            2 => Self::Ipv4,
            23 => Self::Ipv6,
            other => Self::Other(other),
        }
    }
}

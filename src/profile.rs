// amwall — profile.xml types + I/O.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
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
pub mod serialize;

use std::path::PathBuf;

pub use parse::{decode_profile_bytes, parse_str, ParseError};
pub use serialize::to_string;

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

/// What kind of "app" the `path` field actually identifies. Upstream
/// simplewall's profile.xml stores three flavors in one `<apps>`
/// section, distinguished by the path's shape rather than a `type`
/// attribute (matches upstream's runtime classification in
/// `_app_addapplication`):
///
///   - `File` — a real executable path (`C:\...\app.exe`,
///     `\device\harddiskvolume3\...`, `%systemroot%\...`). Always
///     contains `\` or `/`.
///   - `Service` — an SCM service short name (`Dnscache`, `Dhcp`,
///     `wuauserv`). No path separators, not a SID.
///   - `Uwp` — a UWP package family security id (`S-1-15-2-XXX-
///     YYY-...`). Distinctive `S-1-15-2-` prefix.
///
/// Each kind is supposed to surface on its respective tab — File
/// in `Apps`, Service in `Services`, Uwp in `UWP apps`. Without
/// this split, importing a simplewall profile dumps all three
/// kinds into the Apps tab where most users only expect to see
/// .exe entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    File,
    Service,
    Uwp,
}

impl App {
    /// Classify this entry by inspecting its `path`. See
    /// [`AppKind`].
    pub fn kind(&self) -> AppKind {
        Self::kind_for(&self.path)
    }

    /// Stand-alone classifier (no `App` instance required) so
    /// callers like `gui::apps_context_menu::target_from_click`
    /// can route a service/UWP candidate without constructing a
    /// throwaway `App`.
    pub fn kind_for(path: &std::path::Path) -> AppKind {
        let s = path.to_string_lossy();
        if s.starts_with("S-1-15-2-") {
            return AppKind::Uwp;
        }
        if s.contains('\\') || s.contains('/') {
            return AppKind::File;
        }
        AppKind::Service
    }

    /// The file this entry actually refers to on this machine.
    ///
    /// simplewall profiles routinely store app paths in variable form
    /// (`%ProgramFiles%\…`, `%SystemRoot%\…`). `path` keeps the stored
    /// string verbatim so saving never rewrites the user's profile into
    /// machine-specific absolutes; everything that needs a real file —
    /// the "does not exist" highlight, `Purge unused`, hashing,
    /// signature checks, and above all the WFP app-id blob — must go
    /// through here instead. Issue #12: using `path` directly meant
    /// those entries resolved to nothing, so their permits were never
    /// installed and the apps were silently blocked.
    ///
    /// Mirrors upstream's `ITEM_APP.original_path` / `real_path` split
    /// (simplewall-master/src/helper.c:645-650).
    pub fn resolved_path(&self) -> std::borrow::Cow<'_, std::path::Path> {
        Self::resolve(&self.path)
    }

    /// Stand-alone form of [`App::resolved_path`], for callers holding
    /// a bare path (a listview row, a rule's app token) rather than an
    /// `App`. Service short names and UWP package SIDs are not
    /// filesystem paths and are returned untouched.
    pub fn resolve(path: &std::path::Path) -> std::borrow::Cow<'_, std::path::Path> {
        match Self::kind_for(path) {
            AppKind::File => crate::paths::resolve_app_path(path),
            AppKind::Service | AppKind::Uwp => std::borrow::Cow::Borrowed(path),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn app_kind_classifies_uwp_sid() {
        assert_eq!(
            App::kind_for(Path::new(
                "S-1-15-2-3110756066-2507771734-389907848-353554127-1230786711-3973453966-120447785"
            )),
            AppKind::Uwp,
        );
    }

    #[test]
    fn app_kind_classifies_service_short_name() {
        assert_eq!(App::kind_for(Path::new("CryptSvc")), AppKind::Service);
        assert_eq!(App::kind_for(Path::new("Dnscache")), AppKind::Service);
        assert_eq!(App::kind_for(Path::new("wuauserv")), AppKind::Service);
    }

    #[test]
    fn app_kind_classifies_file_paths() {
        assert_eq!(
            App::kind_for(Path::new(r"C:\Windows\system32\svchost.exe")),
            AppKind::File,
        );
        assert_eq!(
            App::kind_for(Path::new(r"%systemroot%\system32\lsass.exe")),
            AppKind::File,
        );
        // Forward-slash form (less common on Windows but valid).
        assert_eq!(
            App::kind_for(Path::new("/usr/bin/whatever")),
            AppKind::File,
        );
        // NT-form native path used by WFP app-id blobs.
        assert_eq!(
            App::kind_for(Path::new(r"\device\harddiskvolume3\foo.exe")),
            AppKind::File,
        );
    }

    #[test]
    fn app_kind_empty_path_is_service() {
        // Edge case — no separator, no SID prefix, so falls
        // through to Service. Profile.xml shouldn't ship empty
        // paths but the heuristic shouldn't panic on one.
        assert_eq!(App::kind_for(Path::new("")), AppKind::Service);
    }

    // ---- resolved_path (issue #12) ---------------------------------

    #[test]
    fn resolve_expands_a_file_paths_variables() {
        let resolved = App::resolve(Path::new(r"%SystemRoot%\System32\svchost.exe"));
        assert!(
            !resolved.to_string_lossy().contains('%'),
            "expected expansion, got {}",
            resolved.display()
        );
    }

    #[test]
    fn resolve_leaves_a_service_name_untouched() {
        // A service short name is not a path; expanding it would be
        // meaningless and could corrupt a name containing `%`.
        assert_eq!(App::resolve(Path::new("Dnscache")).as_ref(), Path::new("Dnscache"));
    }

    #[test]
    fn resolve_leaves_a_uwp_sid_untouched() {
        let sid = Path::new("S-1-15-2-1234567890-987654321");
        assert_eq!(App::resolve(sid).as_ref(), sid);
    }

    #[test]
    fn resolved_path_does_not_mutate_the_stored_path() {
        // The whole design: `path` stays exactly as loaded so saving
        // never rewrites the user's profile.
        let app = App {
            path: PathBuf::from(r"%SystemRoot%\System32\svchost.exe"),
            is_enabled: true,
            is_silent: false,
            is_undeletable: false,
            timestamp: 0,
            timer: 0,
            hash: None,
            comment: None,
        };
        let resolved = app.resolved_path().into_owned();
        assert_ne!(resolved, app.path, "resolution should have changed something");
        assert_eq!(
            app.path,
            PathBuf::from(r"%SystemRoot%\System32\svchost.exe"),
            "stored path must be untouched"
        );
    }
}

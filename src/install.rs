// amwall — high-level install / uninstall.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Bridges the parsed `Profile` (M2) and the rules engine (M3) to
// the kernel-side filter installation (M1). Used by the CLI binary
// (`-install` / `-uninstall`) and exposed publicly so embedders can
// call into the same flow.
//
// Stable provider + sublayer GUIDs let `-install` and `-uninstall`
// cooperate across process invocations: install creates persistent
// records under the well-known keys; uninstall finds them via
// `cleanup_provider(PROVIDER_KEY)` and removes everything tagged
// with that provider — filters, the sublayer, the provider itself.
//
// Windows-only because it sits on top of `wfp`.

#![cfg(windows)]

use std::path::PathBuf;

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
};
use windows::core::GUID;

use crate::profile::{Action, AddressFamily, Direction, Profile, Rule};
use crate::rules::{self, AddrSpec, RuleClause};
use crate::wfp::condition::{FilterCondition, IpProto};
use crate::wfp::filter::{self, FilterAction};
use crate::wfp::{CleanupReport, WfpEngine, WfpError, provider, sublayer};

/// Stable provider GUID — randomly generated, hardcoded so that
/// `-install` (which creates the provider) and `-uninstall` (which
/// finds it via enumeration) reach the same kernel object across
/// process invocations.
///
/// This GUID is unique to amwall and does NOT match upstream
/// simplewall's `GUID_WfpProvider` (`{ 0x4dbcf69d, ... }`); the two
/// projects can coexist on the same machine without colliding on
/// state.
pub const PROVIDER_KEY: GUID =
    GUID::from_u128(0xc6d7_462a_f26f_4f18_9f35_5ed4_42a6_d98e);

/// Stable sublayer GUID — same rationale as `PROVIDER_KEY`.
pub const SUBLAYER_KEY: GUID =
    GUID::from_u128(0xaf71_5b16_1777_40d4_a7ca_3ed3_88fa_5201);

const PROVIDER_NAME: &str = "amwall";
const PROVIDER_DESCRIPTION: &str =
    "Rust port of simplewall — Windows Filtering Platform firewall";
const SUBLAYER_NAME: &str = "amwall sublayer";
/// Sublayer weight — mid-range so we don't override system filters
/// at higher weights but rank above default ones. Matches the
/// upstream `FW_SUBLAYER_WEIGHT` default.
const SUBLAYER_WEIGHT: u16 = 0x4000;

/// Errors surfaced by `install_profile`.
#[derive(Debug)]
pub enum InstallError {
    /// A WFP-layer call (provider/sublayer/filter add) failed.
    Wfp(WfpError),
    /// A rule-string attribute (`rule` / `rule_local`) didn't parse.
    /// Rule name is preserved so the operator can identify which
    /// rule in the profile was malformed.
    RuleParse {
        rule_name: String,
        source: rules::ParseError,
    },
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wfp(e) => write!(f, "wfp: {e}"),
            Self::RuleParse { rule_name, source } => {
                write!(f, "rule `{rule_name}`: {source}")
            }
        }
    }
}

impl std::error::Error for InstallError {}

impl From<WfpError> for InstallError {
    fn from(e: WfpError) -> Self {
        Self::Wfp(e)
    }
}

/// Counts returned by `install_profile`.
#[derive(Debug, Clone, Copy)]
pub struct InstallReport {
    /// Number of filters successfully installed.
    pub filters_added: u32,
    /// Number of rules in the profile that produced zero filters
    /// (e.g. disabled, or only had `apps` / `direction` constraints
    /// the current MVP doesn't compile yet). Helpful for surfacing
    /// "your profile has 50 rules but only 30 filtered" feedback.
    pub rules_skipped: u32,
}

/// Per-category mode for the bundled blocklist (M7). Matches the
/// upstream simplewall Settings → Blocklist tri-state radio groups
/// (Spy / Update / Extra each get one). `Disable` skips loading
/// that category entirely; `Allow` installs the category as
/// permit filters (a whitelist for those endpoints); `Block`
/// installs them as block filters (a blacklist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlocklistAction {
    #[default]
    Disable,
    Allow,
    Block,
}

/// Per-category blocklist configuration. Three categories are
/// derived from the rule name's prefix in `profile_internal.xml`
/// (`spy_*`, `update_*`, `extra_*`).
#[derive(Debug, Clone, Copy, Default)]
pub struct BlocklistConfig {
    pub spy: BlocklistAction,
    pub update: BlocklistAction,
    pub extra: BlocklistAction,
}

impl BlocklistConfig {
    /// Resolve which action to apply to a single blocklist rule
    /// based on its name prefix. Returns `Disable` for unknown
    /// prefixes — better to no-op than misclassify.
    fn action_for(&self, name: &str) -> BlocklistAction {
        match name.split_once('_').map(|(p, _)| p) {
            Some("spy") => self.spy,
            Some("update") => self.update,
            Some("extra") => self.extra,
            _ => BlocklistAction::Disable,
        }
    }
}

/// Install all enabled rules in `profile` into the kernel.
///
/// Idempotent in the provider/sublayer sense: re-running this
/// against an already-installed system tolerates the persistent
/// provider + sublayer that the previous run created
/// (`FWP_E_ALREADY_EXISTS` is treated as success). Filters are
/// always created fresh — running `install_profile` twice without
/// an intervening `uninstall` will accumulate duplicate filters.
///
/// `persistent = true` writes records that survive reboots
/// (upstream's default `-install` mode); `persistent = false`
/// writes session-scoped records that the kernel removes on
/// engine close (upstream's `-install -temp` mode).
///
/// Layer selection: each rule fans out to one filter per
/// `(direction × address-family)` pair, with the kernel layer chosen
/// from `FWPM_LAYER_ALE_AUTH_{CONNECT,RECV_ACCEPT}_{V4,V6}`. A rule
/// with `direction = Any` and no address-family hint installs four
/// filters per clause (out-v4, out-v6, in-v4, in-v6). A rule whose
/// clause has a v4 address only installs at v4 layers; same for v6.
/// Mismatched-family clause-pairs (a v4 remote with a v6 local) are
/// silently skipped — they can't match anything anyway.
///
/// Requires admin.
pub fn install_profile(
    engine: &WfpEngine,
    profile: &Profile,
    persistent: bool,
) -> Result<InstallReport, InstallError> {
    install_with_internal(engine, profile, None, &BlocklistConfig::default(), persistent)
}

/// Like `install_profile`, but also installs the bundled internal
/// profile (system rules + categorized blocklist) per the user's
/// `BlocklistConfig`. The internal profile is amwall's
/// `profile_internal.xml` — embedded at build time and loaded into
/// `App.internal_profile` on startup.
///
/// System rules from the internal profile are installed
/// unconditionally (they're things like DHCP / DNS that need to
/// remain reachable for the OS to function), with the exception of
/// any whose `is_enabled = false`.
///
/// Blocklist rules from the internal profile are installed
/// per-category according to `BlocklistConfig.action_for(name)`:
///   - `Disable` → skip the rule (counted in `rules_skipped`).
///   - `Allow`   → install with `FilterAction::Permit`.
///   - `Block`   → install with `FilterAction::Block`.
///
/// `internal_profile` may be `None` to mirror the bare
/// `install_profile` behaviour (used by `-install` from the CLI,
/// which currently doesn't have access to the bundled profile —
/// future M9 work brings that in).
pub fn install_with_internal(
    engine: &WfpEngine,
    user_profile: &Profile,
    internal_profile: Option<&Profile>,
    blocklist: &BlocklistConfig,
    persistent: bool,
) -> Result<InstallReport, InstallError> {
    provider::add_with_key(
        engine,
        PROVIDER_NAME,
        PROVIDER_DESCRIPTION,
        persistent,
        &PROVIDER_KEY,
    )?;
    sublayer::add_with_key(
        engine,
        SUBLAYER_NAME,
        "",
        SUBLAYER_WEIGHT,
        Some(&PROVIDER_KEY),
        persistent,
        &SUBLAYER_KEY,
    )?;

    let mut filters_added = 0u32;
    let mut rules_skipped = 0u32;

    // 1. User custom rules — same flow as before.
    for rule in &user_profile.custom_rules {
        if !rule.is_enabled {
            rules_skipped += 1;
            continue;
        }
        let action = filter_action_from_rule(rule);
        let added = install_one_rule(engine, persistent, rule, action)?;
        if added == 0 {
            rules_skipped += 1;
        }
        filters_added += added;
    }

    // 2. System rules (DHCP, DNS, NetBIOS, etc.) — always Permit.
    //    The XML's per-rule `is_enabled` still gates application,
    //    matching upstream's behaviour where users can disable
    //    individual system rules via the rules_config overrides.
    if let Some(internal) = internal_profile {
        for rule in &internal.system_rules {
            if !rule.is_enabled {
                rules_skipped += 1;
                continue;
            }
            let added = install_one_rule(engine, persistent, rule, FilterAction::Permit)?;
            if added == 0 {
                rules_skipped += 1;
            }
            filters_added += added;
        }

        // 3. Blocklist rules — per-category mode decides the action.
        for rule in &internal.blocklist_rules {
            let action = match blocklist.action_for(&rule.name) {
                BlocklistAction::Disable => {
                    rules_skipped += 1;
                    continue;
                }
                BlocklistAction::Allow => FilterAction::Permit,
                BlocklistAction::Block => FilterAction::Block,
            };
            let added = install_one_rule(engine, persistent, rule, action)?;
            if added == 0 {
                rules_skipped += 1;
            }
            filters_added += added;
        }
    }

    // 4. Per-app permit filters. Each enabled `<app>` entry in
    //    the user profile gets a Permit filter at all four ALE
    //    layers keyed by its NT-form image path. Disabled apps
    //    get NO filter — they're caught by the default-deny step
    //    below. Service-shaped (path-less) and UWP-SID entries
    //    are skipped here; their respective tabs / install paths
    //    handle them once those features land.
    let app_filters = install_per_app_filters(engine, &user_profile.apps, persistent)?;
    filters_added += app_filters.added;
    rules_skipped += app_filters.skipped;

    // 5. Default-deny catch-all at FW_WEIGHT_LOWEST. Anything not
    //    matched by a per-app permit / system rule / blocklist
    //    Allow drops here. Without this filter, amwall's
    //    "Enable filters" silently allows everything that isn't
    //    explicitly blocked — caught during the user's M9.4
    //    testing where right-clicking Block on brave.exe had no
    //    effect since no per-app filters existed and no default-
    //    deny was installed.
    filters_added += install_default_deny(engine, persistent)?;

    Ok(InstallReport {
        filters_added,
        rules_skipped,
    })
}

/// Walk `apps` and install a Permit filter for each enabled
/// File-kind entry. Service-shaped and UWP-SID entries skip with
/// `skipped += 1`. Any underlying WFP error short-circuits the
/// whole walk so the caller's accumulated counts stay accurate.
fn install_per_app_filters(
    engine: &WfpEngine,
    apps: &[crate::profile::App],
    persistent: bool,
) -> Result<PerAppCounts, InstallError> {
    use crate::profile::AppKind;

    let mut counts = PerAppCounts::default();
    for app in apps {
        if !app.is_enabled {
            // Disabled apps rely on the default-deny — no
            // explicit block needed. Counts as skipped only if
            // we ever wanted to surface "not installed" rows.
            continue;
        }
        if app.kind() != AppKind::File {
            // Service / UWP entries don't use AppPath; they need
            // their own resolution path (service name → exe;
            // UWP SID → package family token). Skip cleanly.
            counts.skipped += 1;
            continue;
        }

        let conds = [crate::wfp::condition::FilterCondition::AppPath(
            app.path.clone(),
        )];

        // FwpmGetAppIdFromFileName0 fails for paths that don't
        // exist on disk (an old simplewall profile may reference
        // apps the user has since uninstalled). `filter::add`
        // surfaces that as a WfpError; treat it as skipped on the
        // first layer's attempt rather than aborting the whole
        // install. If the first layer succeeds, the remaining
        // three should too — they share the same AppPath
        // resolution.
        let display = app
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| app.path.display().to_string());
        let mut layer_failed_first = false;
        for (idx, layer) in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ]
        .iter()
        .enumerate()
        {
            let result = filter::add(
                engine,
                &format!("Allow {display}"),
                "amwall: per-app permit",
                layer,
                &SUBLAYER_KEY,
                Some(&PROVIDER_KEY),
                &conds,
                FilterAction::Permit,
                persistent,
                None, // kernel-assigned mid-range weight
            );
            match result {
                Ok(_) => counts.added += 1,
                Err(e) if idx == 0 => {
                    // First layer failed — typically AppPath
                    // resolution (file missing). Treat as
                    // skipped and skip remaining layers.
                    eprintln!(
                        "amwall: per-app permit skipped for {}: {e:?}",
                        app.path.display()
                    );
                    counts.skipped += 1;
                    layer_failed_first = true;
                    break;
                }
                Err(e) => {
                    // Layers 2+ failed despite layer 1 succeeding
                    // — shouldn't happen since they share the
                    // same AppPath. Bubble it; rolling back the
                    // partial install is the caller's job via
                    // cleanup_provider on the next disable.
                    return Err(e.into());
                }
            }
        }
        let _ = layer_failed_first; // silence unused: communicates intent above
    }
    Ok(counts)
}

#[derive(Default)]
struct PerAppCounts {
    added: u32,
    skipped: u32,
}

/// Install the catch-all block at the lowest weight. Anything not
/// permitted by a higher-weight per-app / system / blocklist Allow
/// drops here. Mirrors upstream's `_app_install_filters` final
/// pass at FW_WEIGHT_LOWEST.
fn install_default_deny(engine: &WfpEngine, persistent: bool) -> Result<u32, InstallError> {
    let layers = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ];
    let mut count = 0u32;
    for layer in &layers {
        filter::add(
            engine,
            "amwall default-deny",
            "amwall: catch-all block at lowest weight",
            layer,
            &SUBLAYER_KEY,
            Some(&PROVIDER_KEY),
            &[], // no conditions = match-all
            FilterAction::Block,
            persistent,
            Some(0), // FW_WEIGHT_LOWEST — every per-app permit wins
        )?;
        count += 1;
    }
    Ok(count)
}

fn filter_action_from_rule(rule: &Rule) -> FilterAction {
    match rule.action {
        Action::Permit => FilterAction::Permit,
        Action::Block => FilterAction::Block,
    }
}

/// Remove every filter, sublayer, and the provider itself
/// associated with `PROVIDER_KEY`. Idempotent — running twice
/// reports `provider_deleted = false` on the second call.
///
/// Requires admin.
pub fn uninstall(engine: &WfpEngine) -> Result<CleanupReport, WfpError> {
    engine.cleanup_provider(&PROVIDER_KEY)
}

/// Install all the filters that come out of one `Rule`.
///
/// Cross-product fan-out across four dimensions:
/// `remote-clause × local-clause × app × (direction, family)`.
/// The app dimension is `[None]` for rules without an `apps`
/// attribute (one no-AppPath-condition pseudo-app), or a `Vec` of
/// resolved file paths for rules with `apps`.
fn install_one_rule(
    engine: &WfpEngine,
    persistent: bool,
    rule: &Rule,
    action: FilterAction,
) -> Result<u32, InstallError> {
    let remotes = parse_rule_string(&rule.name, rule.remote.as_deref())?;
    let locals = parse_rule_string(&rule.name, rule.local.as_deref())?;
    let apps = match parse_apps(rule.apps.as_deref()) {
        AppSet::None => vec![None],
        AppSet::Paths(paths) => paths.into_iter().map(Some).collect(),
        AppSet::AllSkipped => {
            // Rule references only service names (no executable
            // paths). Service-name → exe-path resolution isn't yet
            // implemented; treat the whole rule as skipped so the
            // operator sees it in `rules_skipped`.
            return Ok(0);
        }
    };

    let mut count = 0u32;
    for remote in &remotes {
        for local in &locals {
            let layer_pairs = pick_layer_pairs(
                rule.direction,
                rule.address_family,
                remote.as_ref(),
                local.as_ref(),
            );
            for &(direction, family) in &layer_pairs {
                let Some(layer) = layer_guid(direction, family) else {
                    continue; // unsupported layer combination
                };

                for app in &apps {
                    let mut conds: Vec<FilterCondition> = Vec::new();
                    if let Some(p) = rule.protocol {
                        conds.push(FilterCondition::Protocol(IpProto::Other(p)));
                    }
                    if let Some(r) = remote {
                        conds.extend(rules::compile(
                            rules::Side::Remote,
                            std::slice::from_ref(r),
                        ));
                    }
                    if let Some(l) = local {
                        conds.extend(rules::compile(
                            rules::Side::Local,
                            std::slice::from_ref(l),
                        ));
                    }
                    if let Some(path) = app {
                        conds.push(FilterCondition::AppPath(path.clone()));
                    }
                    // No conditions == match-all-traffic — too
                    // dangerous to install silently. Skip; surfaces
                    // in `rules_skipped` (one count per rule, not
                    // one per would-be filter).
                    if conds.is_empty() {
                        continue;
                    }

                    filter::add(
                        engine,
                        &rule.name,
                        rule.comment.as_deref().unwrap_or(""),
                        layer,
                        &SUBLAYER_KEY,
                        Some(&PROVIDER_KEY),
                        &conds,
                        action,
                        persistent,
                        None, // kernel-assigned weight
                    )?;
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

/// Outcome of parsing a rule's `apps="..."` attribute.
enum AppSet {
    /// Attribute absent or empty/whitespace — no app constraint.
    None,
    /// One or more resolved file paths. Each becomes its own
    /// `AppPath` condition (and its own filter, in the cross-product).
    Paths(Vec<PathBuf>),
    /// Attribute had tokens but every one of them was a service
    /// name (no path separator). We don't yet resolve service
    /// names to executable paths, so the entire rule is skipped.
    AllSkipped,
}

/// Parse a `rule.apps` attribute. Tokens are `|`-separated. A token
/// is treated as a path if it contains `\`, `/`, or `:` (drive-letter,
/// directory separator, or UNC path); otherwise it's treated as a
/// service name and dropped.
///
/// Path tokens go through `expand_env` first to handle entries like
/// `%systemroot%\system32\lsass.exe` from `profile_internal.xml`.
fn parse_apps(s: Option<&str>) -> AppSet {
    let Some(s) = s else { return AppSet::None };

    let mut had_token = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for tok in s.split('|') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        had_token = true;
        if looks_like_path(tok) {
            paths.push(PathBuf::from(expand_env(tok)));
        }
        // Service-name tokens silently skipped here. Aggregated as
        // AllSkipped below if every token was a service name.
    }

    if !had_token {
        AppSet::None
    } else if paths.is_empty() {
        AppSet::AllSkipped
    } else {
        AppSet::Paths(paths)
    }
}

/// Heuristic: a token is a path iff it contains a path-separator
/// character (`\`, `/`) or a drive-letter colon (`:`). Anything
/// else is assumed to be a service name.
///
/// Edge cases:
///   - `firefox.exe` (no separator) → service-name. Loses some real
///     bare-exe-name profiles. Resolution: encourage full paths in
///     user profiles. Service-name resolution is a future M4.x
///     follow-up.
///   - `\\server\share\app.exe` (UNC) → path (contains `\`).
fn looks_like_path(s: &str) -> bool {
    s.contains('\\') || s.contains('/') || s.contains(':')
}

/// Expand `%VAR%` placeholders against `std::env`. Unknown variables
/// are emitted literally (`%FOO%`) rather than dropped, matching
/// Win32 `ExpandEnvironmentStringsW` semantics for unmatched names.
fn expand_env(s: &str) -> String {
    expand_env_with(s, |k| std::env::var(k).ok())
}

fn expand_env_with<F: Fn(&str) -> Option<String>>(s: &str, lookup: F) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // Collect chars until the closing `%`. If no closing `%`
        // appears, emit the buffered text literally (with the
        // leading `%`).
        let mut name = String::new();
        let mut closed = false;
        while let Some(&peek) = chars.peek() {
            chars.next();
            if peek == '%' {
                closed = true;
                break;
            }
            name.push(peek);
        }
        if closed {
            match lookup(&name) {
                Some(v) => out.push_str(&v),
                None => {
                    // Unknown var: emit `%NAME%` literally.
                    out.push('%');
                    out.push_str(&name);
                    out.push('%');
                }
            }
        } else {
            // Unmatched `%`: emit `%NAME` literally.
            out.push('%');
            out.push_str(&name);
        }
    }
    out
}

/// Decide which `(direction, address-family)` layer pairs a rule's
/// clause-pair should install at. Returns the empty vec when the
/// remote and local clauses disagree on address family — no kernel
/// layer can match such a filter, so we skip cleanly rather than
/// erroring.
///
/// Direction fan-out:
///   `Outbound`           → only `Outbound`
///   `Inbound`            → only `Inbound`
///   `Any`                → both `Outbound` and `Inbound`
///   `Other(_)` (unknown) → fall back to `Outbound`
///
/// Family fan-out:
///   - If any clause has a v4 address → only `Ipv4`
///   - If any clause has a v6 address → only `Ipv6`
///   - If neither side has an address (port-only or empty) →
///     use `rule.address_family` as a hint, else fall through to
///     installing at BOTH `Ipv4` and `Ipv6` so a "block remote
///     port 80" rule covers both v4 and v6 traffic.
///   - If remote and local disagree on family → return empty (skip).
fn pick_layer_pairs(
    rule_direction: Direction,
    rule_address_family: Option<AddressFamily>,
    remote: Option<&RuleClause>,
    local: Option<&RuleClause>,
) -> Vec<(Direction, AddressFamily)> {
    let directions: &[Direction] = match rule_direction {
        Direction::Outbound | Direction::Other(_) => &[Direction::Outbound],
        Direction::Inbound => &[Direction::Inbound],
        Direction::Any => &[Direction::Outbound, Direction::Inbound],
    };

    let from_remote = remote.and_then(clause_address_family);
    let from_local = local.and_then(clause_address_family);
    let families: Vec<AddressFamily> = match (from_remote, from_local) {
        (Some(a), Some(b)) if a != b => return Vec::new(), // mismatch
        (Some(a), _) | (_, Some(a)) => vec![a],
        (None, None) => match rule_address_family {
            Some(AddressFamily::Ipv4) => vec![AddressFamily::Ipv4],
            Some(AddressFamily::Ipv6) => vec![AddressFamily::Ipv6],
            // Unset or `Other(_)` → install at both v4 and v6.
            _ => vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
        },
    };

    let mut pairs = Vec::with_capacity(directions.len() * families.len());
    for &d in directions {
        for &f in &families {
            pairs.push((d, f));
        }
    }
    pairs
}

/// Map a `(direction, family)` pair to the corresponding ALE layer
/// GUID. `None` for combinations we don't model (currently only
/// `AddressFamily::Other`).
fn layer_guid(direction: Direction, family: AddressFamily) -> Option<&'static GUID> {
    match (direction, family) {
        (Direction::Outbound, AddressFamily::Ipv4) => Some(&FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        (Direction::Outbound, AddressFamily::Ipv6) => Some(&FWPM_LAYER_ALE_AUTH_CONNECT_V6),
        (Direction::Inbound, AddressFamily::Ipv4) => Some(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4),
        (Direction::Inbound, AddressFamily::Ipv6) => Some(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
        // pick_layer_pairs already collapses `Any` to {Outbound,
        // Inbound} and `Other(_)` to `Outbound`; family `Other(_)`
        // just falls through to None and the caller skips the layer.
        _ => None,
    }
}

/// Address family from a clause's address spec, or `None` if the
/// clause has no address (port-only).
fn clause_address_family(c: &RuleClause) -> Option<AddressFamily> {
    match c.addr.as_ref()? {
        AddrSpec::Ipv4(_) | AddrSpec::Ipv4Range(..) | AddrSpec::Ipv4Cidr(..) => {
            Some(AddressFamily::Ipv4)
        }
        AddrSpec::Ipv6(_) | AddrSpec::Ipv6Cidr(..) => Some(AddressFamily::Ipv6),
    }
}

/// Parse a `rule` / `rule_local` string into a list of clauses,
/// each wrapped in `Some` so the cross-product loop can iterate
/// uniformly. An absent attribute yields a single `None` so the
/// other side still produces filters.
fn parse_rule_string(
    rule_name: &str,
    s: Option<&str>,
) -> Result<Vec<Option<rules::RuleClause>>, InstallError> {
    match s {
        None => Ok(vec![None]),
        Some(s) => {
            let clauses = rules::parse_str(s).map_err(|source| InstallError::RuleParse {
                rule_name: rule_name.to_string(),
                source,
            })?;
            Ok(clauses.into_iter().map(Some).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::rules::{AddrSpec, PortSpec};

    fn port_only_clause(port: u16) -> RuleClause {
        RuleClause {
            addr: None,
            port: Some(PortSpec::Single(port)),
        }
    }

    fn v4_clause(a: u8, b: u8, c: u8, d: u8) -> RuleClause {
        RuleClause {
            addr: Some(AddrSpec::Ipv4(Ipv4Addr::new(a, b, c, d))),
            port: None,
        }
    }

    fn v6_clause(s: &str) -> RuleClause {
        RuleClause {
            addr: Some(AddrSpec::Ipv6(s.parse().unwrap())),
            port: None,
        }
    }

    #[test]
    fn pick_layers_outbound_port_only_fans_out_to_v4_and_v6() {
        let pairs = pick_layer_pairs(
            Direction::Outbound,
            None,
            Some(&port_only_clause(80)),
            None,
        );
        assert_eq!(
            pairs,
            vec![
                (Direction::Outbound, AddressFamily::Ipv4),
                (Direction::Outbound, AddressFamily::Ipv6),
            ]
        );
    }

    #[test]
    fn pick_layers_inbound_v4_clause_yields_only_v4() {
        let pairs = pick_layer_pairs(
            Direction::Inbound,
            None,
            Some(&v4_clause(192, 168, 0, 1)),
            None,
        );
        assert_eq!(pairs, vec![(Direction::Inbound, AddressFamily::Ipv4)]);
    }

    #[test]
    fn pick_layers_any_with_v6_clause_yields_outbound_and_inbound_v6() {
        let pairs = pick_layer_pairs(
            Direction::Any,
            None,
            Some(&v6_clause("fc00::")),
            None,
        );
        assert_eq!(
            pairs,
            vec![
                (Direction::Outbound, AddressFamily::Ipv6),
                (Direction::Inbound, AddressFamily::Ipv6),
            ]
        );
    }

    #[test]
    fn pick_layers_mismatched_remote_local_families_returns_empty() {
        let pairs = pick_layer_pairs(
            Direction::Outbound,
            None,
            Some(&v4_clause(10, 0, 0, 1)),
            Some(&v6_clause("fc00::")),
        );
        assert!(pairs.is_empty());
    }

    #[test]
    fn pick_layers_rule_address_family_overrides_when_clauses_have_no_addr() {
        let pairs = pick_layer_pairs(
            Direction::Outbound,
            Some(AddressFamily::Ipv4),
            Some(&port_only_clause(80)),
            None,
        );
        assert_eq!(pairs, vec![(Direction::Outbound, AddressFamily::Ipv4)]);
    }

    // ---- parse_apps / expand_env / looks_like_path ----

    fn paths(set: AppSet) -> Vec<PathBuf> {
        match set {
            AppSet::Paths(v) => v,
            AppSet::None => panic!("expected Paths, got None"),
            AppSet::AllSkipped => panic!("expected Paths, got AllSkipped"),
        }
    }

    #[test]
    fn parse_apps_none_for_missing_attribute() {
        assert!(matches!(parse_apps(None), AppSet::None));
    }

    #[test]
    fn parse_apps_none_for_whitespace_only() {
        assert!(matches!(parse_apps(Some("   ")), AppSet::None));
        assert!(matches!(parse_apps(Some("|||")), AppSet::None));
    }

    #[test]
    fn parse_apps_single_path() {
        let p = paths(parse_apps(Some(r"C:\Windows\System32\cmd.exe")));
        assert_eq!(p, vec![PathBuf::from(r"C:\Windows\System32\cmd.exe")]);
    }

    #[test]
    fn parse_apps_multiple_paths() {
        let p = paths(parse_apps(Some(r"C:\a.exe|D:\b.exe")));
        assert_eq!(
            p,
            vec![PathBuf::from(r"C:\a.exe"), PathBuf::from(r"D:\b.exe")]
        );
    }

    #[test]
    fn parse_apps_service_name_only_yields_all_skipped() {
        assert!(matches!(parse_apps(Some("Dnscache")), AppSet::AllSkipped));
        assert!(matches!(
            parse_apps(Some("Dnscache|Dhcp|Spooler")),
            AppSet::AllSkipped
        ));
    }

    #[test]
    fn parse_apps_mixed_drops_services_keeps_paths() {
        let p = paths(parse_apps(Some(r"C:\a.exe|Dnscache|D:\b.exe")));
        assert_eq!(
            p,
            vec![PathBuf::from(r"C:\a.exe"), PathBuf::from(r"D:\b.exe")]
        );
    }

    #[test]
    fn parse_apps_unc_path_recognized() {
        let p = paths(parse_apps(Some(r"\\server\share\app.exe")));
        assert_eq!(p, vec![PathBuf::from(r"\\server\share\app.exe")]);
    }

    #[test]
    fn expand_env_with_known_var() {
        let out = expand_env_with(r"%FOO%\bar", |k| {
            if k == "FOO" {
                Some(r"C:\baz".to_string())
            } else {
                None
            }
        });
        assert_eq!(out, r"C:\baz\bar");
    }

    #[test]
    fn expand_env_with_unknown_var_keeps_literal() {
        let out = expand_env_with("%missing%/end", |_| None);
        assert_eq!(out, "%missing%/end");
    }

    #[test]
    fn expand_env_with_unmatched_percent_keeps_literal() {
        let out = expand_env_with("prefix %unmatched", |_| Some("X".into()));
        assert_eq!(out, "prefix %unmatched");
    }

    #[test]
    fn expand_env_with_no_percent_passes_through() {
        let out = expand_env_with(r"C:\Windows\System32", |_| None);
        assert_eq!(out, r"C:\Windows\System32");
    }

    #[test]
    fn blocklist_action_for_routes_by_name_prefix() {
        let cfg = BlocklistConfig {
            spy: BlocklistAction::Block,
            update: BlocklistAction::Allow,
            extra: BlocklistAction::Disable,
        };
        assert_eq!(cfg.action_for("spy_8.8.8.8"), BlocklistAction::Block);
        assert_eq!(cfg.action_for("update_207.46.114.58"), BlocklistAction::Allow);
        assert_eq!(cfg.action_for("extra_13.64.186.225"), BlocklistAction::Disable);
        // Unknown prefix or no underscore: defaults to Disable so an
        // unexpectedly-named entry doesn't get silently misclassified.
        assert_eq!(cfg.action_for("unknown_1.2.3.4"), BlocklistAction::Disable);
        assert_eq!(cfg.action_for("noprefix"), BlocklistAction::Disable);
    }

    #[test]
    fn looks_like_path_known_cases() {
        assert!(looks_like_path(r"C:\foo.exe"));
        assert!(looks_like_path(r"D:\some\path"));
        assert!(looks_like_path(r"\\unc\share"));
        assert!(looks_like_path("/usr/bin/foo")); // forward-slash form
        assert!(!looks_like_path("Dnscache"));
        assert!(!looks_like_path("firefox.exe")); // bare exe is ambiguous; treated as service
        assert!(!looks_like_path(""));
    }

    // ---- pick_layer_pairs (continued) ----

    #[test]
    fn pick_layers_other_direction_falls_back_to_outbound() {
        let pairs = pick_layer_pairs(
            Direction::Other(99),
            None,
            Some(&v4_clause(10, 0, 0, 1)),
            None,
        );
        assert_eq!(pairs, vec![(Direction::Outbound, AddressFamily::Ipv4)]);
    }

    /// Live admin-only smoke test for the install module's public
    /// API. Installs a tiny profile (one rule, two port-only
    /// clauses) and asserts the post-M4.4 layer fan-out: each
    /// port-only clause produces filters at both v4 and v6 layers,
    /// so 2 clauses × 2 families = 4 filters. Volatile
    /// (`persistent = false`) to avoid leaking persistent kernel
    /// state on test failure.
    #[test]
    #[ignore = "requires elevated shell"]
    fn install_profile_then_uninstall_admin_smoke() {
        let xml = r#"<?xml version="1.0" ?>
<root timestamp="0" type="4" version="5">
  <rules_custom>
    <item name="install-test" rule="65530;65531" protocol="6" is_enabled="true" />
  </rules_custom>
</root>"#;
        let profile = crate::profile::parse_str(xml).expect("profile parse failed");
        let engine = WfpEngine::open().expect("engine open failed");

        let report = install_profile(&engine, &profile, false).expect("install failed");
        // 2 clauses × 2 address families (v4 + v6, since neither
        // clause specifies an address and rule.address_family is
        // unset) × 1 direction (Outbound, the default) = 4 filters.
        assert_eq!(report.filters_added, 4);
        assert_eq!(report.rules_skipped, 0);

        let cleanup = uninstall(&engine).expect("uninstall failed");
        assert_eq!(cleanup.filters_deleted, 4);
        assert_eq!(cleanup.sublayers_deleted, 1);
        assert!(cleanup.provider_deleted);
    }
}

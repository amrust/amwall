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


use std::path::PathBuf;

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK, FWP_CONDITION_FLAG_IS_IPSEC_SECURED,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP,
    FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD,
    FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4,
    FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
};
use windows::core::GUID;

use crate::internal_rules_state::{InternalRulesState, RuleKind};
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

/// Build the self-relative security descriptor that upstream
/// simplewall installs on per-service filters. The SD has a
/// single ACE granting `FWP_ACTRL_MATCH_FILTER` (= 1) to the
/// service-specific SID derived from the service name.
///
/// Service-SID derivation goes through `LookupAccountNameW` with
/// the `"NT SERVICE\\<name>"` form — the public Win32 spelling
/// of `RtlCreateServiceSid`'s output. The resulting SID is what
/// the kernel sees as the principal of svchost.exe processes
/// running that service, so a `FWPM_CONDITION_ALE_USER_ID` filter
/// keyed on this SD distinguishes (e.g.) Dnscache from BITS even
/// though both share `svchost.exe`.
///
/// Returns `None` if the service name doesn't resolve to a SID
/// (typo / missing service / Win32 error). Errors are not bubbled
/// because per-service install failures should be local to the
/// row, not aborting the whole `-install`.
///
/// Mirrors upstream `simplewall-master/src/packages.c:610-657`
/// (the `_app_package_getserviceslist` SD-build sequence).
fn service_security_descriptor(service_name: &str) -> Option<Vec<u8>> {
    use std::mem::MaybeUninit;

    use windows::Win32::Foundation::{HLOCAL, LocalFree, PSID};
    use windows::Win32::Security::Authorization::{
        BuildSecurityDescriptorW, EXPLICIT_ACCESS_W, GRANT_ACCESS, TRUSTEE_IS_SID,
        TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        LookupAccountNameW, NO_INHERITANCE, PSECURITY_DESCRIPTOR, SID_NAME_USE,
    };
    use windows::core::{PCWSTR, PWSTR};

    // Account name format the LSA accepts for service SIDs.
    // Anything that doesn't resolve via this path won't be a real
    // service.
    let account_name = format!("NT SERVICE\\{service_name}");
    let wname: Vec<u16> =
        account_name.encode_utf16().chain(std::iter::once(0)).collect();

    // Probe call: gets sizes for the SID + referenced-domain
    // buffers without writing anything.
    let mut sid_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut name_use = SID_NAME_USE::default();
    let probe = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wname.as_ptr()),
            PSID::default(),
            &mut sid_len,
            PWSTR::null(),
            &mut domain_len,
            &mut name_use,
        )
    };
    // Probe always fails (insufficient buffer); we just need the
    // sizes. If the function reports a real failure (account
    // doesn't exist), sid_len stays 0 and we bail.
    let _ = probe;
    if sid_len == 0 {
        return None;
    }

    let mut sid_buf = vec![0u8; sid_len as usize];
    let mut domain_buf: Vec<u16> = vec![0u16; domain_len.max(1) as usize];
    if unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wname.as_ptr()),
            PSID(sid_buf.as_mut_ptr() as *mut _),
            &mut sid_len,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_len,
            &mut name_use,
        )
    }
    .is_err()
    {
        return None;
    }

    // EXPLICIT_ACCESS_W granting FWP_ACTRL_MATCH_FILTER to the
    // service SID. TRUSTEE_W carries the SID by raw pointer; the
    // sid_buf must outlive the BuildSecurityDescriptorW call.
    let trustee = TRUSTEE_W {
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(sid_buf.as_mut_ptr() as *mut u16),
        ..TRUSTEE_W::default()
    };

    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions:
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTRL_MATCH_FILTER,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: trustee,
    };

    let mut sd_size: u32 = 0;
    let mut sd: PSECURITY_DESCRIPTOR =
        unsafe { MaybeUninit::zeroed().assume_init() };
    let result = unsafe {
        BuildSecurityDescriptorW(
            None,
            None,
            Some(std::slice::from_ref(&access)),
            None,
            PSECURITY_DESCRIPTOR(std::ptr::null_mut()),
            &mut sd_size,
            &mut sd,
        )
    };
    // BuildSecurityDescriptorW returns a WIN32_ERROR; 0 == ERROR_SUCCESS.
    if result.0 != 0 || sd.0.is_null() || sd_size == 0 {
        return None;
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(sd.0 as *const u8, sd_size as usize) }
            .to_vec();
    unsafe {
        let _ = LocalFree(HLOCAL(sd.0));
    }
    Some(bytes)
}

/// Convert a textual SID like `"S-1-15-2-…"` into the raw byte
/// sequence WFP wants for `FWP_SID`. Wraps `ConvertStringSidToSidW`
/// (advapi32) and copies the kernel-allocated SID into our own
/// `Vec<u8>` so the caller gets stable ownership and we can free
/// the Win32 buffer immediately.
///
/// Returns `None` for malformed inputs — the underlying Win32
/// call validates the structure (correct prefix, well-formed
/// subAuthority list).
fn parse_sid_string(s: &str) -> Option<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree, PSID};
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::GetLengthSid;
    use windows::core::PCWSTR;

    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid = PSID::default();
    if unsafe { ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid) }.is_err() {
        return None;
    }
    if psid.0.is_null() {
        return None;
    }
    let len = unsafe { GetLengthSid(psid) } as usize;
    let bytes = unsafe { std::slice::from_raw_parts(psid.0 as *const u8, len) }.to_vec();
    // ConvertStringSidToSidW allocates with LocalAlloc; release
    // via LocalFree per the MSDN contract. windows-rs 0.54 spells
    // this as `LocalFree(HLOCAL(ptr))` and returns the freed
    // handle (always 0 on success).
    unsafe {
        let _ = LocalFree(HLOCAL(psid.0));
    }
    Some(bytes)
}

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
#[derive(Debug, Clone, Default)]
pub struct InstallReport {
    /// Number of filters successfully installed.
    pub filters_added: u32,
    /// Number of rules in the profile that produced zero filters
    /// (e.g. disabled, or only had `apps` / `direction` constraints
    /// the current MVP doesn't compile yet). Helpful for surfacing
    /// "your profile has 50 rules but only 30 filtered" feedback.
    pub rules_skipped: u32,
    /// Runtime filter ids grouped by category. Consumed by the
    /// GUI's drain_events to gate the connect-prompt dialog
    /// against the user's `exclude_*` flags — drops sourced from
    /// blocklist filters can be silenced when `exclude_blocklist`
    /// is on, etc.
    pub filter_ids: CategorizedFilterIds,
}

/// Sets of runtime filter ids, partitioned by which install
/// path created them. Empty `Default::default()` so non-GUI
/// callers (CLI -install) and pre-install state are usable as-is.
#[derive(Debug, Clone, Default)]
pub struct CategorizedFilterIds {
    /// Filters from `internal_profile.blocklist_rules`.
    pub blocklist: Vec<u64>,
    /// Filters from `user_profile.custom_rules`.
    pub user_rules: Vec<u64>,
    /// Filters from `internal_profile.system_rules`.
    pub system_rules: Vec<u64>,
    /// Per-app permits (one Permit at each of the four ALE
    /// layers per enabled `App`).
    pub per_app: Vec<u64>,
    /// The four catch-all default-deny block filters at
    /// FW_WEIGHT_LOWEST.
    pub default_deny: Vec<u64>,
    /// Settings → Rules global filters (block_outbound,
    /// allow_loopback, allow_windows_update, etc.).
    pub global_rules: Vec<u64>,
    /// Stealth-mode ICMP-error blocks.
    pub stealth: Vec<u64>,
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

/// Global rules from Settings → Rules tab. Each toggle adds a
/// matching filter to the install set when on. Implemented as a
/// `Default::default()` (all-false) struct so non-GUI callers
/// (CLI -install) can opt out of the whole bag at once.
#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalRulesConfig {
    /// Block every outbound connection at the ALE layer. Per-app
    /// permits installed after this still win (they get a higher
    /// weight); the toggle is "block-by-default for everything
    /// else even without the default-deny."
    pub block_outbound: bool,
    /// Block every inbound connection at the ALE accept layer.
    pub block_inbound: bool,
    /// Permit traffic to/from 127.0.0.0/8 (v4) and ::1/128 (v6).
    /// Above per-app permits in weight so loopback always works
    /// even when the app's outbound rule is Block.
    pub allow_loopback: bool,
    /// Permit IPv6-in-IPv4 (protocol 41) tunneling. Currently a
    /// no-op — needs IP_PACKET layer support which we don't have
    /// yet. Toggle persists; install path documents the gap.
    pub allow_6to4: bool,
    /// Permit `%systemroot%\System32\svchost.exe` traffic — the
    /// service host that wuauserv (Windows Update) runs in.
    /// Coarse but effective: lets Windows Update's network
    /// activity through without the user authoring a per-app
    /// rule. Same approach upstream takes.
    pub allow_windows_update: bool,
    /// "Prevent port scanning (stealth mode)". Blocks outbound
    /// ICMP destination-unreachable (type 3) so UDP port scanners
    /// can't tell open ports from closed ones. Loopback exempt.
    /// The TCP-RST silent-drop part of upstream's stealth mode
    /// needs a kernel callout driver we don't ship — only the
    /// filter-engine-only ICMP block lands here.
    pub use_stealth_mode: bool,
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
    install_with_internal(
        engine,
        profile,
        None,
        None,
        &BlocklistConfig::default(),
        &GlobalRulesConfig::default(),
        persistent,
    )
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
    // Per-user override state for the bundled internal-profile rules
    // (System Rules + preset User Rules). The CLI passes `None` and
    // gets bundled defaults; the GUI passes `Some` so checkbox
    // toggles from the rules tab actually affect what gets installed.
    // Has no effect when `internal_profile` is `None` (there are no
    // internal rules to override).
    internal_rules_state: Option<&InternalRulesState>,
    blocklist: &BlocklistConfig,
    global_rules: &GlobalRulesConfig,
    persistent: bool,
) -> Result<InstallReport, InstallError> {
    // Wrap the entire install in one WFP transaction. Each
    // FwpmFilterAdd0 / FwpmSubLayerAdd0 / FwpmProviderAdd0 is
    // synchronous-kernel-commit when called outside a transaction —
    // amwall's bundled profile holds ~1500 rules, each fanning out
    // to multiple filters via the cross-product walk in
    // install_one_rule, so the non-transactional path is many
    // seconds of frozen UI. Inside a transaction the kernel buffers
    // every modification and applies them all at commit time, which
    // is the difference between "feels frozen" and "<1 s click".
    // Mirrors upstream simplewall's `wfp.c:631-660`.
    //
    // The transaction is opened FIRST so even the
    // provider+sublayer Add calls below benefit. Any `?`-style
    // early return drops the guard, which aborts; only the
    // explicit `commit()` at the end persists.
    let tx = engine.transaction_begin()?;

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

    let mut report = InstallReport::default();

    // 1. User custom rules.
    for rule in &user_profile.custom_rules {
        if !rule.is_enabled {
            report.rules_skipped += 1;
            continue;
        }
        let action = filter_action_from_rule(rule);
        let added = install_one_rule(
            engine,
            persistent,
            rule,
            action,
            &mut report.filter_ids.user_rules,
        )?;
        if added == 0 {
            report.rules_skipped += 1;
        }
        report.filters_added += added;
    }

    // 2. System rules (DHCP, DNS, NetBIOS, etc.) — always Permit.
    // The user can flip each rule's effective enabled state through
    // the System Rules tab checkbox; that state lives in
    // `internal_rules_state` and overlays the bundled `is_enabled`.
    if let Some(internal) = internal_profile {
        for rule in &internal.system_rules {
            let enabled = internal_rules_state
                .map(|s| s.effective_is_enabled(RuleKind::System, &rule.name, rule.is_enabled))
                .unwrap_or(rule.is_enabled);
            if !enabled {
                report.rules_skipped += 1;
                continue;
            }
            let added = install_one_rule(
                engine,
                persistent,
                rule,
                FilterAction::Permit,
                &mut report.filter_ids.system_rules,
            )?;
            if added == 0 {
                report.rules_skipped += 1;
            }
            report.filters_added += added;
        }

        // 2b. Preset user rules (the 9 simplewall-style protocol
        // presets in `<rules_custom>` of profile_internal.xml — DNS
        // protocol, FTP, HTTP, ICMPv4/6, IMAP/POP3/SMTP, QUIC, SSH,
        // Telnet). All ship disabled-by-default and are exposed in
        // the User Rules tab alongside the user-added rules. Same
        // override path as system rules.
        for rule in &internal.custom_rules {
            let enabled = internal_rules_state
                .map(|s| s.effective_is_enabled(RuleKind::Custom, &rule.name, rule.is_enabled))
                .unwrap_or(rule.is_enabled);
            if !enabled {
                report.rules_skipped += 1;
                continue;
            }
            let action = filter_action_from_rule(rule);
            let added = install_one_rule(
                engine,
                persistent,
                rule,
                action,
                &mut report.filter_ids.user_rules,
            )?;
            if added == 0 {
                report.rules_skipped += 1;
            }
            report.filters_added += added;
        }

        // 3. Blocklist rules — per-category mode decides the action.
        // (Per-rule override is intentionally not threaded here:
        // blocklist toggling is already coarser-grained via the
        // Settings → Blocklist Spy/Update/Extra tri-state.)
        for rule in &internal.blocklist_rules {
            let action = match blocklist.action_for(&rule.name) {
                BlocklistAction::Disable => {
                    report.rules_skipped += 1;
                    continue;
                }
                BlocklistAction::Allow => FilterAction::Permit,
                BlocklistAction::Block => FilterAction::Block,
            };
            let added = install_one_rule(
                engine,
                persistent,
                rule,
                action,
                &mut report.filter_ids.blocklist,
            )?;
            if added == 0 {
                report.rules_skipped += 1;
            }
            report.filters_added += added;
        }
    }

    // 4. Per-app permit filters.
    let app_filters = install_per_app_filters(
        engine,
        &user_profile.apps,
        persistent,
        &mut report.filter_ids.per_app,
    )?;
    report.filters_added += app_filters.added;
    report.rules_skipped += app_filters.skipped;

    // 5. Default-deny catch-all at FW_WEIGHT_LOWEST.
    report.filters_added +=
        install_default_deny(engine, persistent, &mut report.filter_ids.default_deny)?;

    // 6. Settings → Rules global toggles.
    report.filters_added += install_global_rules(
        engine,
        persistent,
        global_rules,
        &mut report.filter_ids.global_rules,
    )?;

    // 7. Stealth-mode filters (split out so they categorize
    //    separately for `exclude_stealth`).
    report.filters_added += install_stealth_filters(
        engine,
        persistent,
        global_rules,
        &mut report.filter_ids.stealth,
    )?;

    // Atomically apply everything queued in this transaction. If
    // any of the steps above bailed via `?`, the Drop impl on `tx`
    // already aborted and the kernel state is untouched — partial
    // installs are impossible.
    tx.commit()?;

    Ok(report)
}

/// Install the optional Settings → Rules filters per the
/// per-toggle config. Each enabled flag emits 2-4 filters at
/// higher weight than per-app permits. See `GlobalRulesConfig`
/// for the per-flag semantics. Stealth lives in its own helper
/// because it needs distinct categorization for the
/// `exclude_stealth` flag.
fn install_global_rules(
    engine: &WfpEngine,
    persistent: bool,
    cfg: &GlobalRulesConfig,
    ids: &mut Vec<u64>,
) -> Result<u32, InstallError> {
    use crate::wfp::condition::FilterCondition;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut count = 0u32;

    // Block all outbound — empty-condition Block at the connect
    // ALE layers. Weight 14 lands above per-app permits (which
    // use the default mid-weight) but below allow_loopback (15)
    // so loopback still works when both flags are on.
    if cfg.block_outbound {
        for layer in &[FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
            let f = filter::add(
                engine,
                "amwall block-all-outbound",
                "amwall: Settings -> Rules -> Block outbound for all",
                layer,
                &SUBLAYER_KEY,
                Some(&PROVIDER_KEY),
                &[],
                FilterAction::Block,
                persistent,
                Some(14),
            )?;
            ids.push(f.runtime_id());
            count += 1;
        }
    }

    // Block all inbound — same shape, accept-side ALE layers.
    if cfg.block_inbound {
        for layer in &[
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ] {
            let f = filter::add(
                engine,
                "amwall block-all-inbound",
                "amwall: Settings -> Rules -> Block inbound for all",
                layer,
                &SUBLAYER_KEY,
                Some(&PROVIDER_KEY),
                &[],
                FilterAction::Block,
                persistent,
                Some(14),
            )?;
            ids.push(f.runtime_id());
            count += 1;
        }
    }

    // Allow loopback — Permit at all four ALE layers, gated by
    // RemoteAddr in the loopback range. Weight 15 (above the
    // block-all toggles).
    if cfg.allow_loopback {
        let v4_loopback = FilterCondition::RemoteAddrV4 {
            addr: Ipv4Addr::new(127, 0, 0, 0),
            prefix: Some(8),
        };
        let v6_loopback = FilterCondition::RemoteAddrV6 {
            addr: Ipv6Addr::LOCALHOST,
            prefix: Some(128),
        };
        for layer in &[FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4] {
            let f = filter::add(
                engine,
                "amwall allow-loopback-v4",
                "amwall: Settings -> Rules -> Allow loopback (v4)",
                layer,
                &SUBLAYER_KEY,
                Some(&PROVIDER_KEY),
                std::slice::from_ref(&v4_loopback),
                FilterAction::Permit,
                persistent,
                Some(15),
            )?;
            ids.push(f.runtime_id());
            count += 1;
        }
        for layer in &[FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6] {
            let f = filter::add(
                engine,
                "amwall allow-loopback-v6",
                "amwall: Settings -> Rules -> Allow loopback (v6)",
                layer,
                &SUBLAYER_KEY,
                Some(&PROVIDER_KEY),
                std::slice::from_ref(&v6_loopback),
                FilterAction::Permit,
                persistent,
                Some(15),
            )?;
            ids.push(f.runtime_id());
            count += 1;
        }
    }

    // Allow Windows Update — Permit on the svchost.exe AppPath at
    // all four ALE layers. Coarse but matches upstream's strategy
    // (svchost hosts wuauserv + Background Intelligent Transfer).
    if cfg.allow_windows_update {
        let svchost = std::path::PathBuf::from(r"C:\Windows\System32\svchost.exe");
        if svchost.is_file() {
            let cond = FilterCondition::AppPath(svchost);
            for layer in &[
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ] {
                let f = filter::add(
                    engine,
                    "amwall allow-windows-update",
                    "amwall: Settings -> Rules -> Allow Windows Update (svchost.exe)",
                    layer,
                    &SUBLAYER_KEY,
                    Some(&PROVIDER_KEY),
                    std::slice::from_ref(&cond),
                    FilterAction::Permit,
                    persistent,
                    Some(15),
                )?;
                ids.push(f.runtime_id());
                count += 1;
            }
        }
    }

    // Allow IPv6 redirections (6to4) — five-filter bundle that
    // keeps the IPv6 stack functional under default-deny. Mirrors
    // upstream simplewall wfp.c:1965-2062 exactly. All filters at
    // weight 15 (same as the other Settings -> Rules allows).
    //
    //   1. Permit protocol 41 (IPPROTO_IPV6 — "IPv6 header") at
    //      ALE_AUTH_RECV_ACCEPT_V4. This is the actual 6to4
    //      tunnel: an IPv6 packet wrapped in an IPv4 outer header.
    //
    //   2-5. Permit ICMPv6 types 133/134/135/136 at
    //      ALE_AUTH_RECV_ACCEPT_V6 — the four neighbor- and
    //      router-discovery messages the IPv6 stack needs to
    //      function. Without these the v6 stack can't resolve
    //      link-local neighbors or learn about routers, which
    //      breaks IPv6 connectivity even when the rest of the
    //      profile would allow it.
    //
    // ICMPv6 condition uses FWPM_CONDITION_ICMP_TYPE (which is
    // an alias for FWPM_CONDITION_IP_LOCAL_PORT at the ICMP
    // layers — see wfp::condition).
    if cfg.allow_6to4 {
        // 1. IPv6-in-IPv4 encapsulation. Protocol 41 is the
        //    "IPv6 header" IANA assignment; in WinSDK this is
        //    IPPROTO_IPV6. Carried by IpProto::Other(41) since
        //    our IpProto::IcmpV6 (58) is the v6 control plane,
        //    not the encapsulating outer protocol.
        let ipv6_in_ipv4 = FilterCondition::Protocol(
            crate::wfp::condition::IpProto::Other(41),
        );
        let f = filter::add(
            engine,
            "amwall allow-6to4-ipv6-encap",
            "amwall: Settings -> Rules -> Allow IPv6 redirections (6to4 protocol 41)",
            &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            &SUBLAYER_KEY,
            Some(&PROVIDER_KEY),
            std::slice::from_ref(&ipv6_in_ipv4),
            FilterAction::Permit,
            persistent,
            Some(15),
        )?;
        ids.push(f.runtime_id());
        count += 1;

        // 2-5. ICMPv6 neighbor / router discovery permits.
        //   133 — Router Solicitation
        //   134 — Router Advertisement
        //   135 — Neighbor Solicitation
        //   136 — Neighbor Advertisement
        for (icmp_type, name) in &[
            (133u16, "router-sol"),
            (134u16, "router-adv"),
            (135u16, "neighbor-sol"),
            (136u16, "neighbor-adv"),
        ] {
            let cond = FilterCondition::IcmpType(*icmp_type);
            let display_name = format!("amwall allow-6to4-icmpv6-{name}");
            let description = format!(
                "amwall: Settings -> Rules -> Allow IPv6 redirections (ICMPv6 type {icmp_type})"
            );
            let f = filter::add(
                engine,
                &display_name,
                &description,
                &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                &SUBLAYER_KEY,
                Some(&PROVIDER_KEY),
                std::slice::from_ref(&cond),
                FilterAction::Permit,
                persistent,
                Some(15),
            )?;
            ids.push(f.runtime_id());
            count += 1;
        }
    }

    Ok(count)
}

/// Stealth-mode filters — full parity with upstream simplewall
/// `wfp.c:2064-2141`. Two parts:
///
///   1. UDP-port-scan defence: block outbound ICMP type 3
///      (Destination Unreachable). Without these the kernel's
///      "no listener" reply tells a scanner which UDP ports are
///      closed; suppressing the ICMP keeps closed ports
///      indistinguishable from filtered ports.
///
///   2. TCP-port-scan defence: route inbound TCP discards
///      through the built-in `FWPM_CALLOUT_WFP_TRANSPORT_LAYER_*_SILENT_DROP`
///      callout. The callout swallows the packet without
///      emitting a TCP RST — without this filter the kernel's
///      default "RST on no listener" tells a scanner which TCP
///      ports are closed.
///
/// Both parts exempt loopback and (Win8+) appcontainer-loopback
/// via `FWP_CONDITION_FLAG_IS_LOOPBACK | …_APPCONTAINER_LOOPBACK`.
/// The TCP-RST half also exempts IPsec-secured packets so VPN /
/// IPSec tunnels stay functional — matching upstream's
/// `FWP_CONDITION_FLAG_IS_IPSEC_SECURED` OR-in.
///
/// The callout half is built-in to Windows (no driver shipped
/// with amwall), so user-mode is enough — no kernel-mode code
/// needed.
///
/// Separate from `install_global_rules` so the resulting filter
/// ids land in `CategorizedFilterIds.stealth` for the
/// `exclude_stealth` flag to act on.
fn install_stealth_filters(
    engine: &WfpEngine,
    persistent: bool,
    cfg: &GlobalRulesConfig,
    ids: &mut Vec<u64>,
) -> Result<u32, InstallError> {
    use crate::wfp::condition::FilterCondition;
    if !cfg.use_stealth_mode {
        return Ok(0);
    }
    let loopback_mask =
        FWP_CONDITION_FLAG_IS_LOOPBACK | FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK;
    let icmp_stealth_conds = [
        FilterCondition::FlagsNoneSet(loopback_mask),
        FilterCondition::IcmpType(3),
    ];
    let mut count = 0u32;
    for layer in &[
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4,
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
    ] {
        let f = filter::add(
            engine,
            "amwall stealth-block-icmp-error",
            "amwall: Settings -> Rules -> Use stealth mode (block ICMP type 3)",
            layer,
            &SUBLAYER_KEY,
            Some(&PROVIDER_KEY),
            &icmp_stealth_conds,
            FilterAction::Block,
            persistent,
            Some(15),
        )?;
        ids.push(f.runtime_id());
        count += 1;
    }

    // TCP-RST silent-drop (the kernel's default behaviour on a
    // closed port is to RST; this filter routes the would-be RST
    // through the SILENT_DROP callout instead so the port reads
    // as filtered, not closed). Exempt loopback AND IPsec —
    // upstream wfp.c:2112 OR's IPSEC_SECURED into the same
    // FlagsNoneSet mask so encrypted traffic is never silenced.
    let tcp_rst_mask = loopback_mask | FWP_CONDITION_FLAG_IS_IPSEC_SECURED;
    let tcp_rst_conds = [FilterCondition::FlagsNoneSet(tcp_rst_mask)];
    for (layer, callout_key) in &[
        (
            FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD,
            FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP,
        ),
        (
            FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD,
            FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP,
        ),
    ] {
        let f = filter::add(
            engine,
            "amwall stealth-tcp-rst-silent-drop",
            "amwall: Settings -> Rules -> Use stealth mode (TCP-RST silent drop)",
            layer,
            &SUBLAYER_KEY,
            Some(&PROVIDER_KEY),
            &tcp_rst_conds,
            FilterAction::CalloutTerminating {
                callout_key: *callout_key,
            },
            persistent,
            Some(15),
        )?;
        ids.push(f.runtime_id());
        count += 1;
    }
    Ok(count)
}

/// Walk `apps` and install a Permit filter for each enabled
/// entry. File entries use `AppPath`; UWP entries use
/// `PackageSid`. Service-shaped entries still skip with
/// `skipped += 1` (M11 follow-up territory). Any underlying WFP
/// error short-circuits the whole walk so the caller's
/// accumulated counts stay accurate.
fn install_per_app_filters(
    engine: &WfpEngine,
    apps: &[crate::profile::App],
    persistent: bool,
    ids: &mut Vec<u64>,
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

        let conds = match app.kind() {
            AppKind::File => vec![crate::wfp::condition::FilterCondition::AppPath(
                app.path.clone(),
            )],
            AppKind::Uwp => {
                // app.path holds the SID string ("S-1-15-2-…").
                // Convert to raw bytes via ConvertStringSidToSidW
                // so the WFP `FWP_SID` condition has something to
                // point at. Mirrors upstream simplewall
                // packages.c:_app_package_getpackagebysid which
                // stores the SID-as-string and parses to bytes
                // at filter-add time.
                let sid_string = app.path.to_string_lossy().into_owned();
                match parse_sid_string(&sid_string) {
                    Some(bytes) => vec![
                        crate::wfp::condition::FilterCondition::PackageSid(bytes),
                    ],
                    None => {
                        // Malformed SID — surface but don't abort
                        // the rest of the install. Count as skipped
                        // so the user sees something didn't take.
                        eprintln!(
                            "amwall: per-app permit skipped: invalid UWP SID `{sid_string}`"
                        );
                        counts.skipped += 1;
                        continue;
                    }
                }
            }
            AppKind::Service => {
                // app.path holds the service short name
                // (e.g. "Dnscache"). Build the security descriptor
                // upstream uses for FWPM_CONDITION_ALE_USER_ID,
                // which keys on the service-specific SID — that's
                // how we distinguish svchost-hosted services from
                // each other even though they share the same exe.
                let svc_name = app.path.to_string_lossy();
                match service_security_descriptor(&svc_name) {
                    Some(bytes) => {
                        vec![
                            crate::wfp::condition::FilterCondition::ServiceSecurityDescriptor(
                                bytes,
                            ),
                        ]
                    }
                    None => {
                        eprintln!(
                            "amwall: per-service permit skipped for `{svc_name}` (could not resolve service SID)"
                        );
                        counts.skipped += 1;
                        continue;
                    }
                }
            }
        };

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
                Ok(f) => {
                    ids.push(f.runtime_id());
                    counts.added += 1;
                }
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
fn install_default_deny(
    engine: &WfpEngine,
    persistent: bool,
    ids: &mut Vec<u64>,
) -> Result<u32, InstallError> {
    let layers = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ];
    let mut count = 0u32;
    for layer in &layers {
        let f = filter::add(
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
        ids.push(f.runtime_id());
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
    ids: &mut Vec<u64>,
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

                    let f = filter::add(
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
                    ids.push(f.runtime_id());
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

    /// `parse_sid_string` round-trips a real well-known SID into
    /// a non-empty byte buffer of the expected length.
    /// `S-1-5-32-544` (BUILTIN\\Administrators) is a stable
    /// well-known SID with two subAuthority entries:
    ///
    /// - 1 byte revision
    /// - 1 byte subAuthorityCount = 2
    /// - 6 bytes IdentifierAuthority (NT_AUTHORITY = {0,0,0,0,0,5})
    /// - 2 × 4 bytes subAuthority (32, 544)
    ///
    /// 16 bytes total. The exact byte count locks in that we
    /// copied the whole structure, not just the header.
    #[test]
    fn parse_sid_string_round_trips_well_known_sid() {
        let bytes = parse_sid_string("S-1-5-32-544").expect("valid SID");
        assert_eq!(bytes.len(), 16);
        // Revision byte is always 1; subAuthorityCount byte is 2.
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1], 2);
    }

    /// `service_security_descriptor` returns a non-empty buffer
    /// for a well-known always-present service. `EventLog` ships
    /// with every Windows install since NT and is registered
    /// under `NT SERVICE\EventLog`. A successful round-trip means
    /// LookupAccountNameW resolved the service SID and
    /// BuildSecurityDescriptorW produced a valid self-relative
    /// SD — that's everything install_per_app_filters needs.
    #[test]
    fn service_security_descriptor_well_known_service() {
        let sd = service_security_descriptor("EventLog")
            .expect("EventLog service should resolve");
        // Self-relative SD has at least a 20-byte header
        // (SECURITY_DESCRIPTOR_RELATIVE) plus the DACL with one
        // ACE — total well over 32 bytes for any non-trivial SID.
        assert!(sd.len() >= 32, "SD too small: {}", sd.len());
        // Revision byte is always 1.
        assert_eq!(sd[0], 1);
    }

    #[test]
    fn service_security_descriptor_rejects_unknown_service() {
        // Service names can't contain spaces or special chars, so
        // this won't collide with any real service.
        assert!(
            service_security_descriptor("amwall_definitely_not_a_real_service_xyz").is_none()
        );
    }

    #[test]
    fn parse_sid_string_rejects_garbage() {
        assert!(parse_sid_string("not-a-sid").is_none());
        assert!(parse_sid_string("").is_none());
        // A real-looking SID with a malformed subAuthority — Win32
        // rejects this even though the prefix is right.
        assert!(parse_sid_string("S-1-15-2-").is_none());
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

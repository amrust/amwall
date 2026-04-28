// simplewall-rs — WFP filter primitive.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Wraps `FwpmFilterAdd0`. A filter is the actual block/permit rule
// that runs when traffic passes through `layer_key`. M1.4 binds the
// Add API with zero filter conditions (i.e. "match everything at the
// layer"); per-condition matching for app path / IP / port / protocol
// lands in M1.5.

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWPM_ACTION0, FWPM_DISPLAY_DATA0,
    FWPM_FILTER0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Rpc::UuidCreate;
use windows::core::{GUID, PWSTR};

use super::condition::{self, FilterCondition};
use super::{ERROR_SUCCESS, WfpEngine, WfpError};

/// Handle to an installed WFP filter. Volatile — removed when the
/// engine session ends. The `runtime_id` is the kernel-assigned
/// 64-bit filter id used for `FwpmFilterDeleteById0` and for matching
/// against the live filter table in `netsh wfp show filters`.
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    key: GUID,
    runtime_id: u64,
}

impl Filter {
    pub fn key(&self) -> GUID {
        self.key
    }
    /// Kernel-assigned id (returned via the `id` out-parameter of
    /// `FwpmFilterAdd0`). Distinct from the GUID `key` — both
    /// uniquely identify the filter, but APIs are split: `*ByKey`
    /// vs `*ById` style.
    pub fn runtime_id(&self) -> u64 {
        self.runtime_id
    }

    /// Remove this filter from the engine via `FwpmFilterDeleteByKey0`.
    ///
    /// Volatile filters are removed automatically when the engine
    /// session ends, so explicit deletion is only required for
    /// surgical removal (e.g. tearing down one rule out of many)
    /// or when the engine handle is going to outlive the rule. The
    /// kernel returns `FWP_E_FILTER_NOT_FOUND` (0x80320005) if the
    /// filter is already gone — surfaced as `WfpError::FilterDelete`.
    pub fn delete(&self, engine: &WfpEngine) -> Result<(), WfpError> {
        let status = unsafe { FwpmFilterDeleteByKey0(engine.raw(), &self.key) };
        if status != ERROR_SUCCESS {
            return Err(WfpError::FilterDelete(status));
        }
        Ok(())
    }
}

/// Filter action. M1.4 supports the two terminal actions. Callout
/// actions (which dispatch to a kernel-mode driver to make a
/// per-packet decision) are not used by upstream simplewall and are
/// out of scope.
#[derive(Debug, Clone, Copy)]
pub enum FilterAction {
    Block,
    Permit,
}

impl FilterAction {
    fn to_fwp(self) -> FWP_ACTION_TYPE {
        match self {
            Self::Block => FWP_ACTION_BLOCK,
            Self::Permit => FWP_ACTION_PERMIT,
        }
    }
}

/// Register a new volatile filter at `layer_key` under `sublayer_key`.
///
/// `conditions` describes the match clauses combined with AND
/// semantics — a filter matches a packet only when every condition
/// matches. An empty slice means "match all traffic at this layer."
///
/// Requires admin. Returns the filter key (GUID) and runtime id.
#[allow(clippy::too_many_arguments)]
pub fn add(
    engine: &WfpEngine,
    name: &str,
    description: &str,
    layer_key: &GUID,
    sublayer_key: &GUID,
    provider_key: Option<&GUID>,
    conditions: &[FilterCondition],
    action: FilterAction,
) -> Result<Filter, WfpError> {
    let mut key = GUID::zeroed();
    let rpc_status = unsafe { UuidCreate(&mut key) };
    if rpc_status.0 != 0 {
        return Err(WfpError::UuidCreate(rpc_status.0));
    }

    let mut name_buf: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut desc_buf: Vec<u16> = description
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Compile conditions into FWPM_FILTER_CONDITION0 + backing
    // pointer storage. `compiled` must outlive the FwpmFilterAdd0
    // call below — every pointer in compiled.as_native_slice()
    // references into either Box<T>-owned heap storage or the
    // WFP-heap app-id blobs released by Drop on `compiled`.
    let compiled = condition::compile(conditions)?;
    let cond_slice = compiled.as_native_slice();

    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.filterKey = key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_buf.as_mut_ptr()),
        description: PWSTR(desc_buf.as_mut_ptr()),
    };
    filter.layerKey = *layer_key;
    filter.subLayerKey = *sublayer_key;
    // weight stays FWP_EMPTY (zero-init) — kernel auto-assigns weight
    // in the sublayer. Explicit uint64 weight may be exposed later.
    filter.numFilterConditions = cond_slice.len() as u32;
    if !cond_slice.is_empty() {
        // FWPM_FILTER0::filterCondition is `*mut FWPM_FILTER_CONDITION0`.
        // The kernel reads but does not write through this pointer.
        filter.filterCondition = cond_slice.as_ptr() as *mut _;
    }
    filter.action = FWPM_ACTION0 {
        r#type: action.to_fwp(),
        ..unsafe { std::mem::zeroed() }
    };
    // providerKey is `*mut GUID`. The kernel reads but does not write
    // through this pointer; same justification as in sublayer::add.
    if let Some(pk) = provider_key {
        filter.providerKey = pk as *const GUID as *mut GUID;
    }

    let mut runtime_id: u64 = 0;
    let status = unsafe {
        FwpmFilterAdd0(
            engine.raw(),
            &filter,
            PSECURITY_DESCRIPTOR(std::ptr::null_mut()),
            Some(&mut runtime_id),
        )
    };
    drop(name_buf);
    drop(desc_buf);

    if status != ERROR_SUCCESS {
        return Err(WfpError::FilterAdd(status));
    }
    Ok(Filter { key, runtime_id })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::wfp::condition::{FilterCondition, IpProto};
    use crate::wfp::{provider, sublayer};
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    /// Live admin-only smoke test: end-to-end provider → sublayer →
    /// filter chain at the IPv4 outbound-connect ALE layer with a
    /// permit action and zero conditions (matches all traffic at the
    /// layer). Uses Permit (not Block) so even if the engine session
    /// somehow leaks the filter, it doesn't cut network access —
    /// fail-open beats fail-closed for a test.
    ///
    /// Run with `cargo test -- --ignored` from an elevated shell.
    #[test]
    #[ignore = "requires elevated shell to call FwpmFilterAdd0"]
    fn add_filter_admin_smoke() {
        let engine = WfpEngine::open().expect("engine open failed");
        let prov = provider::add(&engine, "simplewall-rs test", "test provider")
            .expect("provider add failed");
        let sub = sublayer::add(
            &engine,
            "simplewall-rs test sublayer",
            "test sublayer",
            0x4000,
            Some(&prov.key()),
        )
        .expect("sublayer add failed");
        let f = add(
            &engine,
            "simplewall-rs test filter",
            "permit-all at ALE_AUTH_CONNECT_V4",
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &sub.key(),
            Some(&prov.key()),
            &[],
            FilterAction::Permit,
        )
        .expect("FwpmFilterAdd0 failed");
        let k = f.key();
        assert_ne!(
            (k.data1, k.data2, k.data3, k.data4),
            (0, 0, 0, [0u8; 8]),
            "filter key was nil GUID"
        );
        assert_ne!(f.runtime_id(), 0, "filter runtime id was 0");
    }

    /// Live admin-only smoke test: filter with an AppPath condition
    /// matching a real always-present executable, plus a remote-port
    /// guard that won't fire on real traffic. Validates that the
    /// `FwpmGetAppIdFromFileName0` blob pointer survives through
    /// `FwpmFilterAdd0` and that `Drop` on the compiled conditions
    /// (which calls `FwpmFreeMemory0`) runs cleanly AFTER the kernel
    /// has finished consuming the pointer.
    #[test]
    #[ignore = "requires elevated shell to call FwpmFilterAdd0"]
    fn add_filter_with_app_path_admin_smoke() {
        use std::path::PathBuf;
        let engine = WfpEngine::open().expect("engine open failed");
        let prov = provider::add(&engine, "simplewall-rs test", "test provider")
            .expect("provider add failed");
        let sub = sublayer::add(
            &engine,
            "simplewall-rs apppath test sublayer",
            "test sublayer",
            0x4000,
            Some(&prov.key()),
        )
        .expect("sublayer add failed");
        let conds = [
            FilterCondition::AppPath(PathBuf::from(r"C:\Windows\System32\cmd.exe")),
            FilterCondition::RemotePort(65530),
        ];
        let f = add(
            &engine,
            "simplewall-rs apppath test filter",
            "permit cmd.exe outbound to remote port 65530",
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &sub.key(),
            Some(&prov.key()),
            &conds,
            FilterAction::Permit,
        )
        .expect("FwpmFilterAdd0 with AppPath failed");
        assert_ne!(f.runtime_id(), 0, "filter runtime id was 0");
    }

    /// Live admin-only smoke test: full install → delete cycle.
    /// Validates the explicit cleanup path on top of M1.4/M1.5's
    /// install-and-let-engine-clean-up path. After delete, a second
    /// delete returns `FWP_E_FILTER_NOT_FOUND` (0x80320005) which
    /// we surface as `WfpError::FilterDelete` — asserted here so
    /// double-delete behavior is locked in.
    #[test]
    #[ignore = "requires elevated shell"]
    fn install_then_delete_admin_smoke() {
        let engine = WfpEngine::open().expect("engine open failed");
        let prov = provider::add(&engine, "simplewall-rs test", "test provider")
            .expect("provider add failed");
        let sub = sublayer::add(
            &engine,
            "simplewall-rs delete test sublayer",
            "test sublayer",
            0x4000,
            Some(&prov.key()),
        )
        .expect("sublayer add failed");
        let f = add(
            &engine,
            "simplewall-rs delete test filter",
            "permit-all at ALE_AUTH_CONNECT_V4",
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &sub.key(),
            Some(&prov.key()),
            &[],
            FilterAction::Permit,
        )
        .expect("filter add failed");

        f.delete(&engine).expect("first delete failed");

        // Second delete must fail with FilterDelete(*) — proves the
        // first delete actually removed the filter rather than
        // succeeding by no-op.
        match f.delete(&engine) {
            Err(WfpError::FilterDelete(_)) => {} // expected: FWP_E_FILTER_NOT_FOUND
            Err(e) => panic!("expected FilterDelete error on double-delete, got {e:?}"),
            Ok(()) => panic!("double-delete unexpectedly succeeded"),
        }
    }

    /// Live admin-only smoke test: filter with TCP-protocol +
    /// remote-port-65530 + remote-CIDR conditions. Permit action so
    /// the filter never blocks legitimate traffic, and uses port
    /// 65530 + 198.51.100.0/24 (TEST-NET-2 documentation range,
    /// RFC 5737) which no real flow will hit. Validates that the
    /// FWPM_FILTER_CONDITION0 array round-trips correctly through the
    /// kernel's parameter validation.
    #[test]
    #[ignore = "requires elevated shell to call FwpmFilterAdd0"]
    fn add_filter_with_conditions_admin_smoke() {
        let engine = WfpEngine::open().expect("engine open failed");
        let prov = provider::add(&engine, "simplewall-rs test", "test provider")
            .expect("provider add failed");
        let sub = sublayer::add(
            &engine,
            "simplewall-rs cond test sublayer",
            "test sublayer",
            0x4000,
            Some(&prov.key()),
        )
        .expect("sublayer add failed");
        let conds = [
            FilterCondition::Protocol(IpProto::Tcp),
            FilterCondition::RemotePort(65530),
            FilterCondition::RemoteAddrV4 {
                addr: Ipv4Addr::new(198, 51, 100, 0),
                prefix: Some(24),
            },
        ];
        let f = add(
            &engine,
            "simplewall-rs cond test filter",
            "permit tcp:198.51.100.0/24:65530",
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &sub.key(),
            Some(&prov.key()),
            &conds,
            FilterAction::Permit,
        )
        .expect("FwpmFilterAdd0 with conditions failed");
        assert_ne!(f.runtime_id(), 0, "filter runtime id was 0");
    }
}

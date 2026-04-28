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
    FWPM_FILTER0, FwpmFilterAdd0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Rpc::UuidCreate;
use windows::core::{GUID, PWSTR};

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

/// Register a new volatile filter at `layer_key` under `sublayer_key`,
/// taking the given action on every match.
///
/// M1.4: zero filter conditions — the filter matches all traffic at
/// the chosen layer. M1.5 adds the conditions parameter.
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

    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.filterKey = key;
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_buf.as_mut_ptr()),
        description: PWSTR(desc_buf.as_mut_ptr()),
    };
    filter.layerKey = *layer_key;
    filter.subLayerKey = *sublayer_key;
    // weight stays FWP_EMPTY (zero-init) — kernel auto-assigns weight
    // in the sublayer. M1.5+ may expose explicit uint64 weight.
    // numFilterConditions=0, filterCondition=NULL — match all traffic.
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
    use super::*;
    use crate::wfp::{provider, sublayer};
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    /// Live admin-only smoke test: end-to-end provider → sublayer →
    /// filter chain at the IPv4 outbound-connect ALE layer with a
    /// permit action. Uses Permit (not Block) so even if the engine
    /// session somehow leaks the filter, it doesn't cut network
    /// access — fail-open beats fail-closed for a test.
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
}

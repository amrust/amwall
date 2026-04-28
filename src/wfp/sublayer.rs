// simplewall-rs — WFP sublayer primitive.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Wraps `FwpmSubLayerAdd0`. A sublayer groups filters at a single WFP
// layer and resolves their priority via a 16-bit weight. Upstream
// simplewall uses one sublayer per filter set so its filters can be
// enumerated and torn down by sublayer key.

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_SUBLAYER0, FwpmSubLayerAdd0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Rpc::UuidCreate;
use windows::core::{GUID, PWSTR};

use super::{ERROR_SUCCESS, WfpEngine, WfpError};

/// Handle to a registered WFP sublayer. Like `Provider`, this is
/// volatile — kernel removes it on engine session end. No explicit
/// `Drop` impl.
#[derive(Debug, Clone, Copy)]
pub struct Sublayer {
    key: GUID,
}

impl Sublayer {
    pub fn key(&self) -> GUID {
        self.key
    }
}

/// Register a new volatile sublayer.
///
/// Calls `FwpmSubLayerAdd0(engine, &sublayer, NULL)`. Requires admin.
///
/// `weight` is the sublayer's priority among siblings at the same
/// layer (higher = evaluated first). `provider_key`, if `Some`, ties
/// the sublayer to a previously-registered provider so enumeration
/// can find it later via the provider's GUID.
pub fn add(
    engine: &WfpEngine,
    name: &str,
    description: &str,
    weight: u16,
    provider_key: Option<&GUID>,
) -> Result<Sublayer, WfpError> {
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

    let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sublayer.subLayerKey = key;
    sublayer.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_buf.as_mut_ptr()),
        description: PWSTR(desc_buf.as_mut_ptr()),
    };
    sublayer.weight = weight;
    // FWPM_SUBLAYER0::providerKey is `*mut GUID`. The kernel reads but
    // does not write through this pointer; casting `&GUID` to
    // `*mut GUID` for a read-only callee is sound. The pointee
    // (`provider_key`) is borrowed for the duration of `add()`.
    if let Some(pk) = provider_key {
        sublayer.providerKey = pk as *const GUID as *mut GUID;
    }

    let status = unsafe {
        FwpmSubLayerAdd0(
            engine.raw(),
            &sublayer,
            PSECURITY_DESCRIPTOR(std::ptr::null_mut()),
        )
    };
    drop(name_buf);
    drop(desc_buf);

    if status != ERROR_SUCCESS {
        return Err(WfpError::SubLayerAdd(status));
    }
    Ok(Sublayer { key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::provider;

    #[test]
    #[ignore = "requires elevated shell to call FwpmSubLayerAdd0"]
    fn add_sublayer_admin_smoke() {
        let engine = WfpEngine::open().expect("engine open failed");
        let prov = provider::add(&engine, "simplewall-rs test", "test provider")
            .expect("provider add failed");
        let sub = add(
            &engine,
            "simplewall-rs test sublayer",
            "test sublayer",
            0x4000, // mid-range weight
            Some(&prov.key()),
        )
        .expect("FwpmSubLayerAdd0 failed");
        let k = sub.key();
        assert_ne!(
            (k.data1, k.data2, k.data3, k.data4),
            (0, 0, 0, [0u8; 8]),
            "sublayer key was nil GUID"
        );
    }
}

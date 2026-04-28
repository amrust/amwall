// simplewall-rs — WFP engine bindings.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Thin wrapper around the user-mode Windows Filtering Platform engine
// handle (`fwpuclnt.dll`). The engine is opened with a populated
// FWPM_SESSION0 — display data + session-key GUID + transaction
// timeout — matching upstream simplewall. The EPT_S_NOT_REGISTERED
// retry loop lands in M1.3.

#![cfg(windows)]

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_SESSION0, FwpmEngineClose0, FwpmEngineOpen0,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, UuidCreate};
use windows::core::{GUID, PWSTR};

const ERROR_SUCCESS: u32 = 0;

/// Display name shown in `netsh wfp show state` and similar tools when
/// the WFP session is enumerated. Matches upstream's `_r_app_getname()`.
const APP_NAME: &str = "simplewall-rs";

/// Per-transaction timeout for the WFP session, in milliseconds.
/// Matches upstream's `TRANSACTION_TIMEOUT` (`main.h:138`).
const TRANSACTION_TIMEOUT_MS: u32 = 9000;

#[derive(Debug)]
pub enum WfpError {
    /// `FwpmEngineOpen0` returned a non-zero Win32 error.
    Open(u32),
    /// `UuidCreate` returned a non-success RPC status. In practice this
    /// is unreachable in user mode — `UuidCreate` only fails if the
    /// system can't get a MAC address, and even then it falls back to
    /// a pseudo-random GUID and returns `RPC_S_UUID_LOCAL_ONLY`.
    UuidCreate(i32),
}

impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(s) => write!(f, "FwpmEngineOpen0 failed (Win32 error {s:#010x})"),
            Self::UuidCreate(s) => write!(f, "UuidCreate failed (RPC status {s})"),
        }
    }
}

impl std::error::Error for WfpError {}

/// RAII wrapper around a WFP engine handle.
///
/// On drop the handle is closed via `FwpmEngineClose0`. Close failures
/// during drop are logged via `eprintln!` (the upstream C version
/// terminates the process on a failed open — we treat close failures
/// as soft since the engine handle is process-scoped and BFE will
/// reclaim it when we exit).
pub struct WfpEngine {
    handle: HANDLE,
    session_key: GUID,
}

impl WfpEngine {
    /// Open a WFP engine handle bound to the local machine.
    ///
    /// Builds a `FWPM_SESSION0` with:
    /// - `displayData.name` / `displayData.description` = `"simplewall-rs"`
    /// - `sessionKey` = a freshly generated GUID (via `UuidCreate`)
    /// - `txnWaitTimeoutInMSec` = 9000 ms
    ///
    /// then calls `FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL,
    /// &session, &handle)`. Requires the Base Filtering Engine (BFE)
    /// service to be running; does NOT require administrator
    /// privileges (only filter mutations do).
    pub fn open() -> Result<Self, WfpError> {
        // Generate a per-session GUID. Filter / sublayer / provider
        // operations later in M1 will key off this so the running
        // process can identify its own filters in WFP enumerations.
        let mut session_key = GUID::zeroed();
        let rpc_status = unsafe { UuidCreate(&mut session_key) };
        if rpc_status.0 != 0 {
            return Err(WfpError::UuidCreate(rpc_status.0));
        }

        // Display-data buffer must outlive the FwpmEngineOpen0 call.
        // The kernel copies the strings into its own storage during
        // the call, so this Vec can be dropped at end of `open()`.
        let mut name_buf: Vec<u16> = APP_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let display_data = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name_buf.as_mut_ptr()),
            description: PWSTR(name_buf.as_mut_ptr()),
        };

        // Zero-init the rest (matches upstream's RtlZeroMemory),
        // then fill the fields we care about. processId / sid /
        // username / kernelMode / flags stay zero.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.sessionKey = session_key;
        session.displayData = display_data;
        session.txnWaitTimeoutInMSec = TRANSACTION_TIMEOUT_MS;

        let mut handle = HANDLE::default();
        let status = unsafe {
            FwpmEngineOpen0(
                windows::core::PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut handle,
            )
        };
        // name_buf is borrowed until here via the raw PWSTRs in
        // `session.displayData`. Keep it alive across the call.
        drop(name_buf);

        if status != ERROR_SUCCESS {
            return Err(WfpError::Open(status));
        }
        Ok(Self { handle, session_key })
    }

    /// Raw `HANDLE` for callers that need to pass it to other
    /// `Fwpm*` APIs. Lifetime is tied to `&self`.
    pub fn raw(&self) -> HANDLE {
        self.handle
    }

    /// Per-process session-key GUID, generated at `open()`.
    /// Filter / sublayer / provider records added against this engine
    /// will carry this key so this process can find its own state in
    /// WFP enumerations later.
    pub fn session_key(&self) -> GUID {
        self.session_key
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        let status = unsafe { FwpmEngineClose0(self.handle) };
        if status != ERROR_SUCCESS {
            eprintln!("simplewall-rs: FwpmEngineClose0 returned {status:#010x}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: open the engine with our session config, verify the
    /// handle is non-null, drop it. Hits real Win32 — requires the
    /// BFE service to be running, which it always is on a default
    /// Windows install.
    #[test]
    fn open_and_drop_default_engine() {
        let engine = WfpEngine::open()
            .expect("FwpmEngineOpen0 failed - is the BFE service running?");
        assert!(
            !engine.raw().is_invalid(),
            "FwpmEngineOpen0 returned ERROR_SUCCESS but the handle is invalid"
        );
    }

    /// Each `WfpEngine::open()` call should generate a distinct
    /// session-key GUID via `UuidCreate`. Two engines opened back-to-
    /// back must have different keys.
    #[test]
    fn session_keys_are_unique_per_open() {
        let a = WfpEngine::open().expect("first open failed");
        let b = WfpEngine::open().expect("second open failed");
        let key_a = a.session_key();
        let key_b = b.session_key();
        assert_ne!(
            (key_a.data1, key_a.data2, key_a.data3, key_a.data4),
            (key_b.data1, key_b.data2, key_b.data3, key_b.data4),
            "two consecutive opens produced the same session_key GUID"
        );
        // Both keys must be non-zero (UuidCreate failed silently otherwise).
        assert_ne!(
            (key_a.data1, key_a.data2, key_a.data3, key_a.data4),
            (0, 0, 0, [0u8; 8]),
            "session_key was all zeroes"
        );
    }
}

// simplewall-rs — WFP engine bindings.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Thin wrapper around the user-mode Windows Filtering Platform engine
// handle (`fwpuclnt.dll`). The engine is opened with a populated
// FWPM_SESSION0 — display data + session-key GUID + transaction
// timeout — and the open call retries on EPT_S_NOT_REGISTERED to
// tolerate the BFE service still warming up at boot.
//
// Windows-gating is applied at the parent module declaration in
// `lib.rs` (`#[cfg(windows)] pub mod wfp;`), so this file does not
// repeat the cfg attribute.

pub mod condition;
pub mod filter;
pub mod provider;
pub mod sublayer;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_SESSION0, FwpmEngineClose0, FwpmEngineOpen0,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, UuidCreate};
use windows::core::{GUID, PWSTR};

pub(super) const ERROR_SUCCESS: u32 = 0;

/// Display name shown in `netsh wfp show state` and similar tools when
/// the WFP session is enumerated. Matches upstream's `_r_app_getname()`.
const APP_NAME: &str = "simplewall-rs";

/// Per-transaction timeout for the WFP session, in milliseconds.
/// Matches upstream's `TRANSACTION_TIMEOUT` (`main.h:138`).
const TRANSACTION_TIMEOUT_MS: u32 = 9000;

/// RPC endpoint not registered. BFE returns this while the service is
/// still starting up (e.g. very early in boot). Numerically identical
/// to `windows::Win32::System::Rpc::EPT_S_NOT_REGISTERED.0 as u32`,
/// inlined as `u32` because `FwpmEngineOpen0` returns `u32`.
const EPT_S_NOT_REGISTERED: u32 = 1753;

/// Maximum attempts to open the engine before giving up. Matches
/// upstream's `attempts = 6` (`wfp.c:84`).
const OPEN_MAX_ATTEMPTS: u32 = 6;

/// Sleep between retry attempts. Matches upstream's `_r_sys_sleep
/// (500)` (`wfp.c:115`). Total worst-case wait = 6 × 500 ms = 3 s.
const OPEN_RETRY_SLEEP_MS: u64 = 500;

#[derive(Debug)]
pub enum WfpError {
    /// `FwpmEngineOpen0` returned a non-zero Win32 error.
    Open(u32),
    /// `UuidCreate` returned a non-success RPC status. In practice this
    /// is unreachable in user mode — `UuidCreate` only fails if the
    /// system can't get a MAC address, and even then it falls back to
    /// a pseudo-random GUID and returns `RPC_S_UUID_LOCAL_ONLY`.
    UuidCreate(i32),
    /// `FwpmProviderAdd0` returned a non-zero Win32 error. Common: 5
    /// (ERROR_ACCESS_DENIED) when the calling process is not running
    /// as administrator.
    ProviderAdd(u32),
    /// `FwpmSubLayerAdd0` returned a non-zero Win32 error. Same
    /// admin-elevation requirement as `ProviderAdd`.
    SubLayerAdd(u32),
    /// `FwpmFilterAdd0` returned a non-zero Win32 error. Same
    /// admin-elevation requirement as `ProviderAdd`.
    FilterAdd(u32),
}

impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(s) => write!(f, "FwpmEngineOpen0 failed (Win32 error {s:#010x})"),
            Self::UuidCreate(s) => write!(f, "UuidCreate failed (RPC status {s})"),
            Self::ProviderAdd(s) => write!(f, "FwpmProviderAdd0 failed (Win32 error {s:#010x})"),
            Self::SubLayerAdd(s) => write!(f, "FwpmSubLayerAdd0 failed (Win32 error {s:#010x})"),
            Self::FilterAdd(s) => write!(f, "FwpmFilterAdd0 failed (Win32 error {s:#010x})"),
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
    ///
    /// Retries up to `OPEN_MAX_ATTEMPTS` times with
    /// `OPEN_RETRY_SLEEP_MS` between attempts when BFE returns
    /// `EPT_S_NOT_REGISTERED` (service is still warming up). All
    /// other Win32 errors fail immediately. Worst-case block: 3 s.
    pub fn open() -> Result<Self, WfpError> {
        // Generate a per-session GUID. Filter / sublayer / provider
        // operations later in M1 will key off this so the running
        // process can identify its own filters in WFP enumerations.
        // Generated once, before the retry loop — matches upstream
        // wfp.c:89 (_r_math_generateguid runs before the do-while).
        let mut session_key = GUID::zeroed();
        let rpc_status = unsafe { UuidCreate(&mut session_key) };
        if rpc_status.0 != 0 {
            return Err(WfpError::UuidCreate(rpc_status.0));
        }

        // Display-data buffer must outlive every FwpmEngineOpen0
        // attempt in the retry loop. The kernel copies the strings
        // into its own storage during each call, so this Vec can be
        // freed at end of `open()`.
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
        // username / kernelMode / flags stay zero. Built once and
        // re-used across retries — the session description doesn't
        // change between attempts.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.sessionKey = session_key;
        session.displayData = display_data;
        session.txnWaitTimeoutInMSec = TRANSACTION_TIMEOUT_MS;

        let mut last_status = ERROR_SUCCESS;
        let mut handle = HANDLE::default();
        for attempt in 0..OPEN_MAX_ATTEMPTS {
            handle = HANDLE::default();
            last_status = unsafe {
                FwpmEngineOpen0(
                    windows::core::PCWSTR::null(),
                    RPC_C_AUTHN_WINNT,
                    None,
                    Some(&session),
                    &mut handle,
                )
            };
            if last_status == ERROR_SUCCESS {
                break;
            }
            // Only EPT_S_NOT_REGISTERED is worth waiting on — anything
            // else is a structural error (bad parameters, ACL denial,
            // etc.) and another sleep won't help. Match upstream's
            // discriminator at wfp.c:110.
            if last_status != EPT_S_NOT_REGISTERED {
                break;
            }
            // Don't sleep after the final attempt — pointless wait.
            if attempt + 1 < OPEN_MAX_ATTEMPTS {
                std::thread::sleep(std::time::Duration::from_millis(
                    OPEN_RETRY_SLEEP_MS,
                ));
            }
        }
        // name_buf is borrowed via the raw PWSTRs in
        // `session.displayData` until here. Keep it alive across the
        // entire retry loop.
        drop(name_buf);

        if last_status != ERROR_SUCCESS {
            return Err(WfpError::Open(last_status));
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

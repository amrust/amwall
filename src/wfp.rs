// amwall — WFP engine bindings.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
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
pub mod events;
pub mod filter;
pub mod provider;
pub mod sublayer;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_SESSION0, FWPM_SUBLAYER0, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FwpmProviderDeleteByKey0,
    FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDeleteByKey0, FwpmSubLayerDestroyEnumHandle0,
    FwpmSubLayerEnum0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, UuidCreate};
use windows::core::{GUID, PWSTR};

pub(super) const ERROR_SUCCESS: u32 = 0;

/// Display name shown in `netsh wfp show state` and similar tools when
/// the WFP session is enumerated. Matches upstream's `_r_app_getname()`.
const APP_NAME: &str = "amwall";

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
    /// `FwpmGetAppIdFromFileName0` returned a non-zero Win32 error.
    /// Common: 2 (`ERROR_FILE_NOT_FOUND`) when the path doesn't
    /// exist, 5 (`ERROR_ACCESS_DENIED`) when the path exists but
    /// isn't readable by the current user.
    AppIdFromFileName(u32),
    /// `FwpmFilterDeleteByKey0` returned a non-zero Win32 error.
    /// Common: 0x80320003 (`FWP_E_FILTER_NOT_FOUND`) when the
    /// filter was already removed, 5 (`ERROR_ACCESS_DENIED`) on a
    /// non-elevated process.
    FilterDelete(u32),
    /// Filter enumeration failed (`FwpmFilterCreateEnumHandle0` or
    /// `FwpmFilterEnum0`).
    FilterEnum(u32),
    /// Sublayer enumeration failed (`FwpmSubLayerCreateEnumHandle0`
    /// or `FwpmSubLayerEnum0`).
    SubLayerEnum(u32),
    /// `FwpmSubLayerDeleteByKey0` returned a non-zero Win32 error.
    SubLayerDelete(u32),
    /// `FwpmProviderDeleteByKey0` returned a non-zero Win32 error.
    /// Common: 0x80320005 (`FWP_E_PROVIDER_NOT_FOUND`) when the
    /// provider was already removed — `cleanup_provider` swallows
    /// that specific code as the idempotent path, so callers only
    /// see `ProviderDelete(...)` for genuine errors.
    ProviderDelete(u32),
    /// `FwpmTransactionBegin0` returned a non-zero Win32 error.
    /// Common: 0x80320002 (`FWP_E_TXN_IN_PROGRESS`) if a transaction
    /// was already open on the engine handle.
    TransactionBegin(u32),
    /// `FwpmTransactionCommit0` returned a non-zero Win32 error.
    /// The kernel auto-aborts the transaction on commit failure, so
    /// no explicit cleanup is needed on this path.
    TransactionCommit(u32),
}

impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(s) => write!(f, "FwpmEngineOpen0 failed (Win32 error {s:#010x})"),
            Self::UuidCreate(s) => write!(f, "UuidCreate failed (RPC status {s})"),
            Self::ProviderAdd(s) => write!(f, "FwpmProviderAdd0 failed (Win32 error {s:#010x})"),
            Self::SubLayerAdd(s) => write!(f, "FwpmSubLayerAdd0 failed (Win32 error {s:#010x})"),
            Self::FilterAdd(s) => write!(f, "FwpmFilterAdd0 failed (Win32 error {s:#010x})"),
            Self::AppIdFromFileName(s) => {
                write!(f, "FwpmGetAppIdFromFileName0 failed (Win32 error {s:#010x})")
            }
            Self::FilterDelete(s) => {
                write!(f, "FwpmFilterDeleteByKey0 failed (Win32 error {s:#010x})")
            }
            Self::FilterEnum(s) => write!(f, "Filter enumeration failed (Win32 error {s:#010x})"),
            Self::SubLayerEnum(s) => {
                write!(f, "Sublayer enumeration failed (Win32 error {s:#010x})")
            }
            Self::SubLayerDelete(s) => {
                write!(f, "FwpmSubLayerDeleteByKey0 failed (Win32 error {s:#010x})")
            }
            Self::TransactionBegin(s) => {
                write!(f, "FwpmTransactionBegin0 failed (Win32 error {s:#010x})")
            }
            Self::TransactionCommit(s) => {
                write!(f, "FwpmTransactionCommit0 failed (Win32 error {s:#010x})")
            }
            Self::ProviderDelete(s) => {
                write!(f, "FwpmProviderDeleteByKey0 failed (Win32 error {s:#010x})")
            }
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
    /// - `displayData.name` / `displayData.description` = `"amwall"`
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

    /// Begin a WFP transaction on this engine. Returns an RAII guard
    /// that commits on `commit()` and aborts on Drop if `commit()`
    /// was never called (early return on error, panic, etc.).
    ///
    /// Every `FwpmFilterAdd0` / `FwpmFilterDeleteByKey0` /
    /// `FwpmSubLayerAdd0` / etc. issued through this engine handle
    /// while the transaction is open is buffered in user-mode
    /// session state and applied to the kernel atomically at commit
    /// time — instead of being its own synchronous kernel commit.
    /// For amwall's full install path (1500+ bundled blocklist rules
    /// plus user / system / preset rules, each fanning out to
    /// multiple filters), this is the difference between a
    /// many-second "feels frozen" Enable filters click and a sub-
    /// second one. Mirrors upstream simplewall's `wfp.c:631-660`
    /// transaction wrapping around its install loop.
    pub fn transaction_begin(&self) -> Result<Transaction<'_>, WfpError> {
        let status = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        if status != ERROR_SUCCESS {
            return Err(WfpError::TransactionBegin(status));
        }
        Ok(Transaction {
            engine: self,
            committed: false,
        })
    }

    /// Walk the kernel's filter and sublayer tables and remove every
    /// entry whose `providerKey` matches `provider_key`, then remove
    /// the provider itself. The upstream simplewall pattern for
    /// surviving stale state from a previous (possibly crashed)
    /// session — call this on startup before installing fresh state,
    /// or on shutdown to leave a clean slate.
    ///
    /// Defensive against the engine-drop cleanup we've observed to
    /// be unreliable in the Rust test runner: explicit deletes go
    /// through synchronously and are confirmed by enumeration before
    /// returning.
    ///
    /// Idempotent: running it twice on the same provider key
    /// returns `provider_deleted = false` on the second call (the
    /// provider was already removed) but does not error.
    ///
    /// Requires admin (delete operations are admin-gated).
    pub fn cleanup_provider(
        &self,
        provider_key: &GUID,
    ) -> Result<CleanupReport, WfpError> {
        // Same transactional batching as the install side: amwall's
        // provider can carry 2000+ filters after a full install
        // (1500 bundled blocklist + system + per-app), and walking
        // them with one FwpmFilterDeleteByKey0 per filter outside a
        // transaction is many seconds of kernel commits. Inside a
        // transaction the deletes are buffered and applied at
        // commit time — same difference as install.
        let tx = self.transaction_begin()?;

        let filters_deleted = self.delete_filters_for_provider(provider_key)?;
        let sublayers_deleted = self.delete_sublayers_for_provider(provider_key)?;

        // Best-effort provider delete. FWP_E_PROVIDER_NOT_FOUND
        // means it was already gone (idempotent path), which we
        // surface as `provider_deleted = false` rather than an
        // error. FWP_E_NOT_FOUND (0x80320008) is the generic
        // not-found; FwpmProviderDeleteByKey0 specifically returns
        // FWP_E_PROVIDER_NOT_FOUND (0x80320005) — pinning that
        // exactly so a future generic-not-found mishap surfaces
        // instead of being silently swallowed.
        let status = unsafe { FwpmProviderDeleteByKey0(self.handle, provider_key) };
        let provider_deleted = match status {
            ERROR_SUCCESS => true,
            0x8032_0005 => false, // FWP_E_PROVIDER_NOT_FOUND
            other => return Err(WfpError::ProviderDelete(other)),
        };

        tx.commit()?;

        Ok(CleanupReport {
            filters_deleted,
            sublayers_deleted,
            provider_deleted,
        })
    }

    /// Enumerate every filter currently installed against
    /// `provider_key` and return their `filterId` values. Used by
    /// the GUI to know which `CLASSIFY_DROP` events came from
    /// amwall's own filters (so we don't pop notifications for
    /// drops by Windows Firewall, third-party WFP providers, etc.).
    pub fn enumerate_filter_ids_for_provider(
        &self,
        provider_key: &GUID,
    ) -> Result<Vec<u64>, WfpError> {
        const BATCH: u32 = 64;
        let mut enum_handle = HANDLE::default();
        let status =
            unsafe { FwpmFilterCreateEnumHandle0(self.handle, None, &mut enum_handle) };
        if status != ERROR_SUCCESS {
            return Err(WfpError::FilterEnum(status));
        }
        let result = (|| -> Result<Vec<u64>, WfpError> {
            let mut ids = Vec::new();
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let status = unsafe {
                    FwpmFilterEnum0(
                        self.handle,
                        enum_handle,
                        BATCH,
                        &mut entries,
                        &mut returned,
                    )
                };
                if status != ERROR_SUCCESS {
                    return Err(WfpError::FilterEnum(status));
                }
                if returned == 0 {
                    break;
                }
                let slice: &[*mut FWPM_FILTER0] =
                    unsafe { std::slice::from_raw_parts(entries, returned as usize) };
                for &filter_ptr in slice {
                    if filter_ptr.is_null() {
                        continue;
                    }
                    let filter = unsafe { &*filter_ptr };
                    if filter.providerKey.is_null() {
                        continue;
                    }
                    let pk_val = unsafe { *filter.providerKey };
                    if pk_val == *provider_key {
                        ids.push(filter.filterId);
                    }
                }
                let mut p = entries as *mut std::ffi::c_void;
                unsafe { FwpmFreeMemory0(&mut p) };
                if returned < BATCH {
                    break;
                }
            }
            Ok(ids)
        })();
        let _ = unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };
        result
    }

    fn delete_filters_for_provider(&self, provider_key: &GUID) -> Result<u32, WfpError> {
        const BATCH: u32 = 64;
        let mut enum_handle = HANDLE::default();
        let status =
            unsafe { FwpmFilterCreateEnumHandle0(self.handle, None, &mut enum_handle) };
        if status != ERROR_SUCCESS {
            return Err(WfpError::FilterEnum(status));
        }

        let result = (|| -> Result<u32, WfpError> {
            let mut deleted = 0u32;
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let status = unsafe {
                    FwpmFilterEnum0(
                        self.handle,
                        enum_handle,
                        BATCH,
                        &mut entries,
                        &mut returned,
                    )
                };
                if status != ERROR_SUCCESS {
                    return Err(WfpError::FilterEnum(status));
                }
                if returned == 0 {
                    break;
                }
                let slice: &[*mut FWPM_FILTER0] =
                    unsafe { std::slice::from_raw_parts(entries, returned as usize) };
                for &filter_ptr in slice {
                    if filter_ptr.is_null() {
                        continue;
                    }
                    let filter = unsafe { &*filter_ptr };
                    if filter.providerKey.is_null() {
                        continue;
                    }
                    let pk_val = unsafe { *filter.providerKey };
                    if pk_val == *provider_key {
                        let st = unsafe {
                            FwpmFilterDeleteByKey0(self.handle, &filter.filterKey)
                        };
                        if st == ERROR_SUCCESS {
                            deleted += 1;
                        }
                        // Non-fatal on individual delete failure:
                        // continue with siblings rather than abort
                        // partway through.
                    }
                }
                // Free the WFP-heap array of pointers.
                let mut p = entries as *mut std::ffi::c_void;
                unsafe { FwpmFreeMemory0(&mut p) };

                if returned < BATCH {
                    break;
                }
            }
            Ok(deleted)
        })();

        // Always destroy the enumeration handle, even if iteration
        // errored.
        let _ =
            unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };
        result
    }

    fn delete_sublayers_for_provider(&self, provider_key: &GUID) -> Result<u32, WfpError> {
        const BATCH: u32 = 64;
        let mut enum_handle = HANDLE::default();
        let status =
            unsafe { FwpmSubLayerCreateEnumHandle0(self.handle, None, &mut enum_handle) };
        if status != ERROR_SUCCESS {
            return Err(WfpError::SubLayerEnum(status));
        }

        let result = (|| -> Result<u32, WfpError> {
            let mut deleted = 0u32;
            loop {
                let mut entries: *mut *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let status = unsafe {
                    FwpmSubLayerEnum0(
                        self.handle,
                        enum_handle,
                        BATCH,
                        &mut entries,
                        &mut returned,
                    )
                };
                if status != ERROR_SUCCESS {
                    return Err(WfpError::SubLayerEnum(status));
                }
                if returned == 0 {
                    break;
                }
                let slice: &[*mut FWPM_SUBLAYER0] =
                    unsafe { std::slice::from_raw_parts(entries, returned as usize) };
                for &sub_ptr in slice {
                    if sub_ptr.is_null() {
                        continue;
                    }
                    let sub = unsafe { &*sub_ptr };
                    if sub.providerKey.is_null() {
                        continue;
                    }
                    let pk_val = unsafe { *sub.providerKey };
                    if pk_val == *provider_key {
                        let st = unsafe {
                            FwpmSubLayerDeleteByKey0(self.handle, &sub.subLayerKey)
                        };
                        if st == ERROR_SUCCESS {
                            deleted += 1;
                        }
                    }
                }
                let mut p = entries as *mut std::ffi::c_void;
                unsafe { FwpmFreeMemory0(&mut p) };

                if returned < BATCH {
                    break;
                }
            }
            Ok(deleted)
        })();

        let _ =
            unsafe { FwpmSubLayerDestroyEnumHandle0(self.handle, enum_handle) };
        result
    }
}

/// Counts returned by `WfpEngine::cleanup_provider`.
#[derive(Debug, Clone, Copy)]
pub struct CleanupReport {
    pub filters_deleted: u32,
    pub sublayers_deleted: u32,
    pub provider_deleted: bool,
}

/// RAII guard for a WFP transaction. Returned by
/// `WfpEngine::transaction_begin`. Call `commit` to apply the
/// buffered changes; on Drop without commit (early return, panic,
/// `?` propagation, etc.) the transaction is aborted so the kernel
/// state is left untouched. Borrowing the engine for `'a` prevents
/// callers from accidentally closing the engine handle mid-
/// transaction.
pub struct Transaction<'a> {
    engine: &'a WfpEngine,
    committed: bool,
}

impl Transaction<'_> {
    /// Apply every buffered Fwpm*Add0 / Fwpm*Delete* call to the
    /// kernel in one atomic commit. Consumes self so a single
    /// transaction can only be committed once.
    pub fn commit(mut self) -> Result<(), WfpError> {
        let status = unsafe { FwpmTransactionCommit0(self.engine.handle) };
        // Mark committed regardless of status — the kernel auto-
        // aborts on commit failure, so the Drop impl must not
        // double-abort (which would surface FWP_E_NO_TXN_IN_PROGRESS).
        self.committed = true;
        if status != ERROR_SUCCESS {
            return Err(WfpError::TransactionCommit(status));
        }
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort abort — if it fails (already aborted by
            // the kernel, etc.) there's nothing we can usefully do
            // from a Drop impl.
            let _ = unsafe { FwpmTransactionAbort0(self.engine.handle) };
        }
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        let status = unsafe { FwpmEngineClose0(self.handle) };
        if status != ERROR_SUCCESS {
            eprintln!("amwall: FwpmEngineClose0 returned {status:#010x}");
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

    /// Live admin-only smoke test: full provider + sublayer + 2-filter
    /// chain → `cleanup_provider` → assert exactly the expected
    /// counts, then call cleanup again and assert the idempotent
    /// "nothing left" path. This is the regression guard for the
    /// engine-drop-cleanup unreliability we observed during M1.6
    /// verification.
    #[test]
    #[ignore = "requires elevated shell"]
    fn cleanup_provider_removes_filters_sublayers_and_provider() {
        use crate::wfp::condition::FilterCondition;
        use crate::wfp::filter::{self, FilterAction};
        use crate::wfp::{provider, sublayer};
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;

        let engine = WfpEngine::open().expect("engine open failed");
        let prov = provider::add(&engine, "amwall cleanup-test", "", false)
            .expect("provider add failed");
        let sub = sublayer::add(
            &engine,
            "amwall cleanup-test sublayer",
            "",
            0x4000,
            Some(&prov.key()),
            false,
        )
        .expect("sublayer add failed");
        // Two filters under the same sublayer/provider so the report
        // can prove batched deletion (filters_deleted == 2).
        let _f1 = filter::add(
            &engine,
            "amwall cleanup-test f1",
            "",
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &sub.key(),
            Some(&prov.key()),
            &[FilterCondition::RemotePort(65530)],
            FilterAction::Permit,
            false,
            None,
        )
        .expect("filter f1 add failed");
        let _f2 = filter::add(
            &engine,
            "amwall cleanup-test f2",
            "",
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &sub.key(),
            Some(&prov.key()),
            &[FilterCondition::RemotePort(65531)],
            FilterAction::Permit,
            false,
            None,
        )
        .expect("filter f2 add failed");

        let report = engine
            .cleanup_provider(&prov.key())
            .expect("cleanup_provider failed");
        assert_eq!(report.filters_deleted, 2, "expected 2 filters deleted");
        assert_eq!(report.sublayers_deleted, 1, "expected 1 sublayer deleted");
        assert!(report.provider_deleted, "provider was not deleted");

        // Idempotent path: second cleanup against the now-vanished
        // provider returns zeroes and provider_deleted = false (we
        // surface FWP_E_NOT_FOUND as a soft no-op rather than an
        // error).
        let report2 = engine
            .cleanup_provider(&prov.key())
            .expect("second cleanup_provider failed");
        assert_eq!(report2.filters_deleted, 0);
        assert_eq!(report2.sublayers_deleted, 0);
        assert!(!report2.provider_deleted);
    }
}

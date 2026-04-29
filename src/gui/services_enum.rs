// amwall — Service Control Manager enumeration for the Services tab.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Walks SCM via `EnumServicesStatusExW(SERVICE_WIN32, SERVICE_STATE_ALL)`
// and resolves each service's executable image path through
// `QueryServiceConfigW`. Returns sorted `ServiceEntry`s for the
// Apps → Services tab to display.
//
// Only Win32 services are enumerated (drivers and kernel-mode are
// skipped). Both running and stopped are returned because the user
// may want to author a rule for a service that's not currently up.
//
// The SCM is opened with `SC_MANAGER_ENUMERATE_SERVICE`, the
// minimum required privilege — works without admin in a regular
// session. `QueryServiceConfigW` requires `SERVICE_QUERY_CONFIG`
// per service, also non-elevated.

#![cfg(windows)]

use std::path::PathBuf;

use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::Security::SC_HANDLE;
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::core::PCWSTR;

/// One row in the Services listview. `display_name` is what the
/// user sees in the Services snap-in (e.g. "Windows Audio");
/// `service_name` is the SCM key (e.g. "Audiosrv") and is what a
/// firewall rule needs to attach to. `image_path` is the resolved
/// executable backing the service — empty if QueryServiceConfig
/// failed or the service hosts itself in svchost.exe via a DLL,
/// which is the common case.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub service_name: String,
    pub display_name: String,
    pub image_path: PathBuf,
}

/// Enumerate every Win32 service registered with the SCM. Errors
/// are logged to stderr and produce an empty list rather than
/// bubbling — the Services tab degrading to "empty" is preferable
/// to crashing the GUI on a transient SCM RPC hiccup.
pub fn enumerate() -> Vec<ServiceEntry> {
    let scm = unsafe {
        OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE)
    };
    let scm = match scm {
        Ok(h) if !h.is_invalid() => h,
        Ok(_) => return Vec::new(),
        Err(e) => {
            eprintln!("amwall: services: OpenSCManagerW failed: {e}");
            return Vec::new();
        }
    };

    let mut entries = Vec::new();

    // Two-pass enumeration: first call with a small buffer to learn
    // the required size (returns ERROR_MORE_DATA), then allocate
    // and call again. EnumServicesStatusExW is variant-length: the
    // returned ENUM_SERVICE_STATUS_PROCESSW structs all live in the
    // first `bytes_needed` bytes, with name pointers indexing back
    // into the same buffer.
    let mut buf: Vec<u8> = vec![0u8; 64 * 1024]; // 64 KB initial
    let mut bytes_needed: u32 = 0;
    let mut services_returned: u32 = 0;
    let mut resume_handle: u32 = 0;

    loop {
        let res = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                PCWSTR::null(),
            )
        };

        let more = matches!(res.as_ref().err(), Some(e) if e.code().0 as u32 == ERROR_MORE_DATA.0);
        if res.is_err() && !more {
            eprintln!(
                "amwall: services: EnumServicesStatusExW failed: {:?}",
                res.err()
            );
            break;
        }

        // Decode the returned services from the current buffer slice.
        if services_returned > 0 {
            let svc_array = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
            for i in 0..services_returned as isize {
                let svc = unsafe { &*svc_array.offset(i) };
                let service_name = read_wide_ptr(svc.lpServiceName.0);
                let display_name = read_wide_ptr(svc.lpDisplayName.0);
                let image_path = query_service_image_path(scm, &service_name);
                entries.push(ServiceEntry {
                    service_name,
                    display_name,
                    image_path,
                });
            }
        }

        if !more {
            break;
        }
        // Need a bigger buffer, or more pages remain. ERROR_MORE_DATA
        // can mean either; resume_handle != 0 means "more pages",
        // bytes_needed > buf.len() means "need to grow".
        if (bytes_needed as usize) > buf.len() {
            buf.resize(bytes_needed as usize, 0);
        }
        if resume_handle == 0 {
            // No more pages even though MORE_DATA — defensive break
            // to avoid an infinite loop on a misbehaving SCM.
            break;
        }
    }

    unsafe {
        let _ = CloseServiceHandle(scm);
    }

    // Sort case-insensitively by display name so the listview is
    // stable across runs and matches the Services snap-in's sort.
    entries.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
    });

    entries
}

/// Decode a NUL-terminated wide string at `*p` to a Rust `String`.
/// Works for both PWSTR and PCWSTR sources — callers pass `pwstr.0`
/// or `pcwstr.0` as a `*const u16`.
fn read_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
            // 32 KB ceiling — guard against a runaway pointer into
            // the wrong region of memory. Service names are short.
            if len > 32 * 1024 {
                return String::new();
            }
        }
        let slice = std::slice::from_raw_parts(p, len);
        String::from_utf16_lossy(slice)
    }
}

fn query_service_image_path(scm: SC_HANDLE, name: &str) -> PathBuf {
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let svc = unsafe {
        OpenServiceW(scm, PCWSTR(wname.as_ptr()), SERVICE_QUERY_CONFIG)
    };
    let svc = match svc {
        Ok(h) if !h.is_invalid() => h,
        _ => return PathBuf::new(),
    };

    // QueryServiceConfigW is also variant-length. First call with
    // null buffer to get bytes_needed, then allocate.
    let mut bytes_needed: u32 = 0;
    let _ = unsafe { QueryServiceConfigW(svc, None, 0, &mut bytes_needed) };
    if bytes_needed == 0 {
        unsafe {
            let _ = CloseServiceHandle(svc);
        }
        return PathBuf::new();
    }
    let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];
    let cfg_ptr = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    let mut written: u32 = 0;
    let res = unsafe {
        QueryServiceConfigW(svc, Some(cfg_ptr), bytes_needed, &mut written)
    };
    let path = if res.is_ok() {
        let cfg = unsafe { &*cfg_ptr };
        let raw = read_wide_ptr(cfg.lpBinaryPathName.0);
        // SCM stores the launch command as a full command line —
        // strip trailing args so the Apps tab shows just the
        // executable. svchost-hosted services return e.g.
        // `C:\Windows\system32\svchost.exe -k LocalServiceNetwork`.
        if let Some(stripped) = strip_command_args(&raw) {
            PathBuf::from(stripped)
        } else {
            PathBuf::from(raw)
        }
    } else {
        PathBuf::new()
    };

    unsafe {
        let _ = CloseServiceHandle(svc);
    }
    path
}

/// Strip launch arguments from an SCM command line, returning the
/// executable path. Handles both quoted (`"C:\path with spaces.exe" /flag`)
/// and unquoted (`C:\nospaces.exe /flag`) forms. Returns `None` if
/// the input is empty.
fn strip_command_args(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    // Unquoted: take up to the first whitespace.
    let exe_end = trimmed
        .find(char::is_whitespace)
        .unwrap_or(trimmed.len());
    Some(trimmed[..exe_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_quoted_path_with_args() {
        assert_eq!(
            strip_command_args(r#""C:\Program Files\foo\bar.exe" -arg"#),
            Some(r"C:\Program Files\foo\bar.exe".to_string())
        );
    }

    #[test]
    fn strip_unquoted_path_with_args() {
        assert_eq!(
            strip_command_args(r"C:\Windows\system32\svchost.exe -k LocalServiceNetwork"),
            Some(r"C:\Windows\system32\svchost.exe".to_string())
        );
    }

    #[test]
    fn strip_bare_path() {
        assert_eq!(
            strip_command_args(r"C:\Windows\system32\foo.exe"),
            Some(r"C:\Windows\system32\foo.exe".to_string())
        );
    }

    #[test]
    fn strip_empty() {
        assert_eq!(strip_command_args(""), None);
        assert_eq!(strip_command_args("   "), None);
    }

    /// Live SCM enumeration. Doesn't assert specific services —
    /// service inventory differs between machines — but every
    /// Windows install has at least a handful, so a non-empty
    /// result is the bar.
    #[test]
    fn enumerate_returns_some_services() {
        let entries = enumerate();
        assert!(
            !entries.is_empty(),
            "SCM enumeration produced zero services — check SC_MANAGER_ENUMERATE_SERVICE access"
        );
        // Every entry should at minimum have a service name. Display
        // name can be blank (rare but possible for legacy services);
        // image path is best-effort.
        for e in &entries {
            assert!(!e.service_name.is_empty(), "service_name empty in {e:?}");
        }
    }
}

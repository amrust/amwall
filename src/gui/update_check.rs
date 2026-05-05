// amwall — silent update-check.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// On startup (when `Settings.check_updates` is on), pings GitHub's
// `releases/latest` API for amrust/amwall, compares the returned
// tag against `CARGO_PKG_VERSION`, and posts a custom message back
// to the main HWND if a newer version exists. The handler shows a
// "v1.2.3 is available — open the releases page?" Yes/No dialog;
// Yes opens the GitHub releases URL in the default browser.
//
// Explicitly NOT a self-updater: amwall never downloads or
// installs anything on its own. The user clicks through to GitHub
// and grabs the MSI from the release assets manually. This is
// intentional — a firewall that auto-updates is a firewall that
// can be MITM'd into installing whatever an attacker controls.
//
// HTTP via WinHttp (windows-rs's binding) rather than ureq /
// reqwest, so we don't add a TLS / async-runtime dep tree just
// for one API call. Failures (offline, rate limited, bad JSON)
// are swallowed silently — the user shouldn't see a prompt
// because "we couldn't ask GitHub today".

#![cfg(windows)]

use std::ffi::c_void;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpOpen, WinHttpOpenRequest, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest,
};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_USER};
use windows::core::PCWSTR;

use super::wide;

/// Posted to the main HWND when a newer release is available.
/// `wparam` carries a `Box<UpdateInfo>` cast to usize; the
/// handler reclaims and frees it.
pub const WM_USER_UPDATE_AVAILABLE: u32 = WM_USER + 0x150;

/// Posted to the main HWND when the manual "Check for updates"
/// menu finishes its check and concludes amwall is already on
/// the latest release. The auto-check at startup never posts
/// this — it stays quiet on no-update so the user isn't pestered
/// every launch. `wparam` carries a `Box<UpdateInfo>` whose
/// `latest_tag` is the tag matched against (handler shows it in
/// the "you're up to date" message).
pub const WM_USER_UPDATE_UPTODATE: u32 = WM_USER + 0x151;

/// Posted when the manual check failed to reach GitHub at all
/// (no DNS, no network, rate limited, malformed JSON, etc.).
/// Auto-check stays silent on errors; manual check tells the
/// user something went wrong so they can retry. `wparam = 0`,
/// `lparam = 0` — no payload; the message text is hard-coded
/// in the handler.
pub const WM_USER_UPDATE_ERROR: u32 = WM_USER + 0x152;

/// Payload heap-allocated by the worker, reclaimed by the wndproc.
/// Carries both the latest tag (for the dialog text) and the URL
/// to open if the user accepts.
pub struct UpdateInfo {
    pub latest_tag: String,
    pub releases_url: String,
}

/// GitHub repo coordinates. Hardcoded — amwall is its own
/// upstream, so this never changes.
const REPO_OWNER: &str = "amrust";
const REPO_NAME: &str = "amwall";

/// Auto-check variant — fires from `gui::run` at startup. Posts
/// `WM_USER_UPDATE_AVAILABLE` only when a newer release exists;
/// stays silent on "up to date" or "couldn't reach GitHub".
/// Designed so a user with `Settings.check_updates` on never
/// gets a "we couldn't check today" popup blocking their
/// launch — auto-check failures are noise, manual-check
/// failures are signal.
pub fn check_async(main_hwnd: HWND, current_version: &str) {
    spawn_check(main_hwnd, current_version, false);
}

/// Manual-check variant — fires from the `Help -> Check for
/// updates` menu item. Always reports something:
///
/// - newer release exists → `WM_USER_UPDATE_AVAILABLE` (same
///   payload + handler as the auto-check)
/// - already on the latest tag → `WM_USER_UPDATE_UPTODATE`
/// - couldn't reach GitHub at all → `WM_USER_UPDATE_ERROR`
///
/// The handler in main_window.rs shows a fitting MessageBox
/// per case, so the user always gets explicit feedback when
/// they asked. Mirrors the upstream simplewall menu entry's
/// expected behaviour: clicking "Check for updates" should
/// say something, not silently open the releases page.
pub fn check_async_manual(main_hwnd: HWND, current_version: &str) {
    spawn_check(main_hwnd, current_version, true);
}

fn spawn_check(main_hwnd: HWND, current_version: &str, manual: bool) {
    let current = current_version.to_string();
    // PostMessage is thread-safe; pass the HWND as a usize so the
    // closure is Send.
    let hwnd_raw = main_hwnd.0 as usize;
    std::thread::spawn(move || {
        let releases_url =
            format!("https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/latest");
        let Some(latest) = fetch_latest_tag(REPO_OWNER, REPO_NAME) else {
            // Couldn't even fetch the tag — surface only on
            // the manual path; auto-check stays silent.
            if manual {
                unsafe {
                    let _ = PostMessageW(
                        HWND(hwnd_raw as isize),
                        WM_USER_UPDATE_ERROR,
                        WPARAM(0),
                        LPARAM(0),
                    );
                }
            }
            return;
        };
        let newer = is_strictly_newer(&latest, &current);
        let msg = if newer {
            WM_USER_UPDATE_AVAILABLE
        } else if manual {
            WM_USER_UPDATE_UPTODATE
        } else {
            // Auto-check + already up to date = silently exit.
            return;
        };
        let info = Box::new(UpdateInfo {
            latest_tag: latest,
            releases_url,
        });
        let raw = Box::into_raw(info) as *mut c_void as usize;
        unsafe {
            // PostMessage may fail if the main window has been
            // destroyed (user quit while we were fetching). Reclaim
            // the box in that case so it doesn't leak.
            if PostMessageW(
                HWND(hwnd_raw as isize),
                msg,
                WPARAM(raw),
                LPARAM(0),
            )
            .is_err()
            {
                let _ = Box::from_raw(raw as *mut UpdateInfo);
            }
        }
    });
}

/// Hit `https://api.github.com/repos/<owner>/<name>/releases/latest`
/// and pull the `"tag_name"` value out of the JSON. Returns the
/// raw tag (e.g. "v1.2.3") so the caller's comparison can decide
/// whether to strip the leading `v`.
fn fetch_latest_tag(owner: &str, name: &str) -> Option<String> {
    let path = format!("/repos/{owner}/{name}/releases/latest");
    let body = http_get_https("api.github.com", 443, &path)?;
    parse_tag_name(&body)
}

/// Pull `"tag_name":"value"` out of a JSON blob using a literal
/// string search. Cheap and dependency-free; sufficient for the
/// well-known shape GitHub returns. Returns `None` if the field
/// is missing — caller treats that as "no update" rather than
/// surfacing an error to the user.
///
/// Doesn't try to handle escape sequences in the value because
/// GitHub release tags are restricted to safe characters in
/// practice (no quotes, no backslashes).
fn parse_tag_name(json: &str) -> Option<String> {
    let key = "\"tag_name\"";
    let key_idx = json.find(key)?;
    let after_key = &json[key_idx + key.len()..];
    // Skip whitespace and the colon.
    let colon_idx = after_key.find(':')?;
    let after_colon = &after_key[colon_idx + 1..];
    let quote_idx = after_colon.find('"')?;
    let after_open_quote = &after_colon[quote_idx + 1..];
    let close_idx = after_open_quote.find('"')?;
    let value = &after_open_quote[..close_idx];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Compare two version strings. `latest` and `current` may carry
/// a leading `v` (we strip both); each is then split on `.`,
/// numeric components compared lexicographically, non-numeric
/// segments treated as 0 (so a `1.0.0-rc1` tag compares as
/// `1.0.0`). Returns true iff `latest` is strictly greater.
///
/// Pre-release identifiers and build metadata are ignored —
/// keeps the comparison simple, and amwall releases don't use
/// either right now.
fn is_strictly_newer(latest: &str, current: &str) -> bool {
    let a = strip_v(latest);
    let b = strip_v(current);
    let parse = |s: &str| -> Vec<u32> {
        s.split('.')
            .map(|seg| seg.split(|c: char| !c.is_ascii_digit()).next().unwrap_or(""))
            .map(|seg| seg.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let av = parse(a);
    let bv = parse(b);
    let max_len = av.len().max(bv.len());
    for i in 0..max_len {
        let ai = *av.get(i).unwrap_or(&0);
        let bi = *bv.get(i).unwrap_or(&0);
        if ai != bi {
            return ai > bi;
        }
    }
    false
}

fn strip_v(s: &str) -> &str {
    s.strip_prefix('v').or_else(|| s.strip_prefix('V')).unwrap_or(s)
}

/// One-shot HTTPS GET. Returns the response body as a UTF-8
/// String, or `None` on any failure (no resolution, TLS reject,
/// non-2xx response, body too large, etc.). All HINTERNET
/// handles are closed regardless of which step failed.
fn http_get_https(host: &str, port: u16, path: &str) -> Option<String> {
    let user_agent = wide(&format!(
        "amwall/{} (+https://github.com/amrust/amwall)",
        env!("CARGO_PKG_VERSION")
    ));
    let whost = wide(host);
    let wpath = wide(path);
    let wmethod = wide("GET");

    unsafe {
        let session = WinHttpOpen(
            PCWSTR(user_agent.as_ptr()),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        );
        if session.is_null() {
            return None;
        }

        // RAII-style cleanup: close every handle we open as we
        // exit, regardless of which step failed. nested helper
        // closures keep the unwind chain explicit.
        let connect = WinHttpConnect(session, PCWSTR(whost.as_ptr()), port, 0);
        if connect.is_null() {
            let _ = WinHttpCloseHandle(session);
            return None;
        }

        let request = WinHttpOpenRequest(
            connect,
            PCWSTR(wmethod.as_ptr()),
            PCWSTR(wpath.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        );
        if request.is_null() {
            let _ = WinHttpCloseHandle(connect);
            let _ = WinHttpCloseHandle(session);
            return None;
        }

        let send_result = WinHttpSendRequest(request, None, None, 0, 0, 0);
        if send_result.is_err() {
            let _ = WinHttpCloseHandle(request);
            let _ = WinHttpCloseHandle(connect);
            let _ = WinHttpCloseHandle(session);
            return None;
        }

        let recv_result = WinHttpReceiveResponse(request, std::ptr::null_mut());
        if recv_result.is_err() {
            let _ = WinHttpCloseHandle(request);
            let _ = WinHttpCloseHandle(connect);
            let _ = WinHttpCloseHandle(session);
            return None;
        }

        // Read the body. Cap at 256 KB — GitHub's `releases/latest`
        // response is ~3 KB; anything dramatically larger means
        // we hit the wrong endpoint or a poisoned proxy. Bail.
        const MAX_BYTES: usize = 256 * 1024;
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 8192];
        loop {
            let mut bytes_read: u32 = 0;
            let read_result = WinHttpReadData(
                request,
                chunk.as_mut_ptr() as *mut c_void,
                chunk.len() as u32,
                &mut bytes_read,
            );
            if read_result.is_err() {
                let _ = WinHttpCloseHandle(request);
                let _ = WinHttpCloseHandle(connect);
                let _ = WinHttpCloseHandle(session);
                return None;
            }
            if bytes_read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..bytes_read as usize]);
            if buf.len() > MAX_BYTES {
                let _ = WinHttpCloseHandle(request);
                let _ = WinHttpCloseHandle(connect);
                let _ = WinHttpCloseHandle(session);
                return None;
            }
        }
        let _ = WinHttpCloseHandle(request);
        let _ = WinHttpCloseHandle(connect);
        let _ = WinHttpCloseHandle(session);

        String::from_utf8(buf).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tag_name_extracts_value() {
        let json = r#"{"url":"...","tag_name":"v1.2.3","name":"Release 1.2.3"}"#;
        assert_eq!(parse_tag_name(json), Some("v1.2.3".to_string()));
    }

    #[test]
    fn parse_tag_name_handles_whitespace_around_colon() {
        let json = r#"{ "tag_name" : "v0.0.1" }"#;
        assert_eq!(parse_tag_name(json), Some("v0.0.1".to_string()));
    }

    #[test]
    fn parse_tag_name_returns_none_when_missing() {
        let json = r#"{"name":"Release"}"#;
        assert_eq!(parse_tag_name(json), None);
    }

    #[test]
    fn parse_tag_name_returns_none_for_empty_value() {
        let json = r#"{"tag_name":""}"#;
        assert_eq!(parse_tag_name(json), None);
    }

    #[test]
    fn newer_when_higher_major() {
        assert!(is_strictly_newer("v2.0.0", "1.9.9"));
    }

    #[test]
    fn newer_when_higher_minor() {
        assert!(is_strictly_newer("v1.2.0", "v1.1.5"));
    }

    #[test]
    fn newer_when_higher_patch() {
        assert!(is_strictly_newer("v1.0.1", "1.0.0"));
    }

    #[test]
    fn not_newer_when_equal() {
        assert!(!is_strictly_newer("v1.0.0", "1.0.0"));
        assert!(!is_strictly_newer("v1.0.0", "v1.0.0"));
    }

    #[test]
    fn not_newer_when_lower() {
        assert!(!is_strictly_newer("v0.9.0", "1.0.0"));
        assert!(!is_strictly_newer("v1.0.0", "1.0.1"));
    }

    #[test]
    fn missing_components_treated_as_zero() {
        // "1.0" vs "1.0.0" — neither is newer.
        assert!(!is_strictly_newer("1.0", "1.0.0"));
        assert!(!is_strictly_newer("1.0.0", "1.0"));
        // "1.0.1" beats "1.0".
        assert!(is_strictly_newer("1.0.1", "1.0"));
    }

    #[test]
    fn pre_release_suffix_ignored() {
        // "1.0.0-rc1" parses as 1.0.0; same as plain 1.0.0.
        assert!(!is_strictly_newer("v1.0.0-rc1", "v1.0.0"));
    }

    #[test]
    fn strip_v_handles_both_cases() {
        assert_eq!(strip_v("v1.0.0"), "1.0.0");
        assert_eq!(strip_v("V1.0.0"), "1.0.0");
        assert_eq!(strip_v("1.0.0"), "1.0.0");
    }
}

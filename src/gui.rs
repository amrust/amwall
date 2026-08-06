// amwall — Win32 GUI entry point.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Direct Win32 via `windows-rs`. Programmatic UI (no .rc files).
// Layout matches upstream simplewall 3.8.7 — same menu structure,
// same eight tabs in the same order, same per-tab columns. See
// `main_window` for the structural rewrite; `app` for the in-memory
// state; `ids` for the IDM_* / IDC_* constants mirrored from
// upstream's resource.h.
//
// `run` enables Per-Monitor v2 DPI awareness up-front so the window
// is sharp on hi-DPI displays (4K @ 200%+ scaling), then drives the
// standard Win32 message loop until WM_QUIT.

pub mod app;
pub mod app_icons;
pub mod app_properties;
pub mod apps_context_menu;
pub mod net_log_context_menu;
pub mod rules_context_menu;
pub mod connect_dialog;
pub mod column_sizing;
pub mod connections;
pub mod net_meter;
pub mod dialogs;
pub mod dns_resolve;
pub mod event_log;
pub mod first_run_wizard;
pub mod font;
pub mod icons;
pub mod ids;
pub mod listview_groups;
pub mod main_window;
pub mod msg_slab;
pub mod notification;
pub mod rule_editor;
pub mod services_enum;
pub mod settings;
pub mod settings_dialog;
pub mod startup;
pub mod toolbar;
pub mod tray;
pub mod update_check;
pub mod uwp_enum;

use std::path::PathBuf;
use std::process::ExitCode;

use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::Input::KeyboardAndMouse::GetFocus;
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetDlgCtrlID, GetMessageW, LoadAcceleratorsW, MSG, PostQuitMessage,
    TranslateAcceleratorW, TranslateMessage,
};
use windows::core::PCWSTR;

use crate::profile::{self, Profile};
use app::App;

/// Cached process-elevation check. `IsUserAnAdmin()` is stable for the
/// process lifetime (UAC elevation is decided at launch), so cache it
/// in a `OnceLock`. Used by security gates that must fail safe when
/// amwall holds the admin token — e.g. refusing to execute a
/// user-writable log viewer, or to write a log outside the data dir.
/// Security audit finding D.
pub(crate) fn is_elevated() -> bool {
    static ELEVATED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ELEVATED.get_or_init(|| {
        use windows::Win32::UI::Shell::IsUserAnAdmin;
        unsafe { IsUserAnAdmin() }.as_bool()
    })
}

/// Entry point invoked from `main.rs` when no CLI subcommand is given.
/// Owns the lifetime of the `App` and drives the standard Win32
/// message loop until `WM_QUIT`.
///
/// `default_profile_path` is the same `%APPDATA%\amwall\profile.xml`
/// path the CLI uses; if the file isn't present yet, the GUI starts
/// with an empty `Profile`.
pub fn run(default_profile_path: PathBuf, force_show: bool) -> ExitCode {
    // Log elevation up front so the user can tell at a glance
    // whether filter-management actions will succeed (admin) or
    // bounce off ERROR_ACCESS_DENIED (user-mode). `IsUserAnAdmin`
    // returns TRUE only when the process is running with the
    // unfiltered admin token under UAC — i.e. true elevation.
    let admin = {
        use windows::Win32::UI::Shell::IsUserAnAdmin;
        let v = unsafe { IsUserAnAdmin() }.as_bool();
        eprintln!(
            "amwall: starting GUI ({})",
            if v {
                "elevated / admin"
            } else {
                "user mode — filter management + WFP event subscription will fail"
            }
        );
        v
    };

    // "Skip UAC warning" silent elevation. When the user has
    // previously enabled this option (one-time UAC prompt to
    // register a Task Scheduler task with RunLevel = HIGHEST),
    // we relaunch ourselves through that task and exit. The new
    // process spawns elevated without a UAC prompt — same trick
    // upstream simplewall uses (`_r_skipuac_run`).
    //
    // Skipped when we're already elevated (no need) or when the
    // task isn't registered (toggle was never enabled, or was
    // unenabled).
    let skipuac_registered = crate::skipuac::is_registered();
    let mut skipuac_failed = false;
    if !admin && skipuac_registered {
        match crate::skipuac::run_via_task() {
            Ok(()) => {
                eprintln!("amwall: relaunching elevated via skipuac task; exiting unelevated copy");
                return ExitCode::from(0);
            }
            Err(e) => {
                eprintln!(
                    "amwall: skipuac relaunch failed ({e}); continuing as unelevated GUI"
                );
                skipuac_failed = true;
            }
        }
    }

    // Still unelevated. Without the admin token the Base Filtering
    // Engine will not open, so filter management, the WFP event
    // subscription, connect prompts and the packets log are all dead —
    // amwall is a firewall that cannot firewall. Offer to restart with
    // rights rather than leaving the user in a silently crippled window
    // with only a status-bar hint (issue #12).
    //
    // Deliberately NOT solved by putting `requestedExecutionLevel
    // requireAdministrator` in the manifest: upstream simplewall ships
    // `asInvoker` (simplewall-master/src/res/manifest.xml:12) and we
    // match it, because a manifest requirement would force a UAC prompt
    // on every launch and would make the Skip-UAC feature — whose whole
    // purpose is to obtain rights *without* a prompt — meaningless.
    if should_offer_elevation(admin, skipuac_registered, skipuac_failed) && offer_elevation() {
        match relaunch_self_elevated(force_show) {
            Ok(()) => {
                eprintln!("amwall: relaunched elevated; exiting unelevated copy");
                return ExitCode::from(0);
            }
            Err(e) => {
                // Most often the user dismissed the UAC prompt. Carry
                // on unelevated — the status bar surfaces what is
                // unavailable, and File → Exit still works.
                eprintln!("amwall: elevation declined or failed ({e}); continuing unelevated");
            }
        }
    }

    // Per-Monitor v2 DPI awareness: hi-DPI displays (4K @ 200%+ scaling)
    // get sharp text and correctly-scaled controls. Must be set before
    // any HWND is created, otherwise Win32 caches "system DPI" mode.
    // Failure (e.g. older Windows that doesn't expose v2) is non-fatal —
    // we fall back to the system default scaling.
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    // Initialise COM in apartment-threaded mode so the standard Win32
    // file-open / file-save dialogs (IFileOpenDialog / IFileSaveDialog)
    // can be created from the GUI thread. STA is the right model for
    // single-threaded UI; MTA breaks the dialog's interaction with
    // shell objects. CoUninitialize at end of run pairs with this.
    // RPC_E_CHANGED_MODE (0x80010106) means COM is already initialised
    // in another mode — harmless, ignore.
    let com_initialized = unsafe {
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        hr.is_ok() || hr.0 == 0x8001_0106u32 as i32
    };

    let profile = match try_load_profile(&default_profile_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "amwall: warning — could not load {}: {e}; starting with empty profile.",
                default_profile_path.display(),
            );
            empty_profile()
        }
    };

    let settings_path = settings::default_settings_path();
    let mut settings = settings::Settings::load(&settings_path);

    // User overrides for bundled internal rules (System Rules,
    // Blocklist rules, preset User Rules). Empty file on fresh
    // install — every rule starts at its bundled `is_enabled`
    // default; the user's checkbox clicks populate it from there.
    let internal_rules_state_path =
        crate::internal_rules_state::default_state_path();
    let internal_rules_state =
        crate::internal_rules_state::InternalRulesState::load(&internal_rules_state_path);

    // Install-time language override. The MSI's WriteInstallerLocale
    // custom action writes the auto-applied transform's LCID to
    // %APPDATA%\amwall\installerlocale.txt. When that value differs
    // from `install_lcid_seen` in settings.txt — fresh install, upgrade,
    // or reinstall under a different system locale — overwrite `language`
    // with the install LCID's culture so the user sees the language they
    // installed in. Without this, a user who upgrades from a pre-
    // multilingual MSI keeps their old `language=en` even though they
    // just installed under e.g. Russian Windows.
    if let Some(install_lcid) = install_lcid_from_file() {
        if install_lcid != settings.install_lcid_seen {
            let mapped = lcid_to_available_locale(install_lcid);
            eprintln!(
                "amwall: install-lcid: {} != settings.install_lcid_seen ({}); overriding language={} (was `{}`)",
                install_lcid,
                settings.install_lcid_seen,
                mapped.as_deref().unwrap_or("<no available match>"),
                settings.language,
            );
            if let Some(locale) = mapped {
                settings.language = locale;
            }
            settings.install_lcid_seen = install_lcid;
            let _ = settings.save(&settings_path);
        } else {
            eprintln!(
                "amwall: install-lcid: {} matches settings.install_lcid_seen; respecting saved language `{}`",
                install_lcid, settings.language,
            );
        }
    }

    if !settings.language.is_empty() {
        rust_i18n::set_locale(&settings.language);
    } else if let Some(detected) = detect_system_locale() {
        rust_i18n::set_locale(&detected);
        settings.language = detected;
        let _ = settings.save(&settings_path);
    }

    // Bundled internal profile — `<rules_system>` + `<rules_blocklist>`
    // shipped with the binary. Same XML format as the user profile
    // so the same parser works. Failure here is fatal because we
    // built the .xml into our binary; if it's malformed the build
    // itself shipped a bug.
    let internal_xml = include_str!("../assets/profile_internal.xml");
    let internal_profile = match profile::parse_str(internal_xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "amwall: BUG: bundled profile_internal.xml \
                 failed to parse: {e}; system rules + blocklist tabs will be empty.",
            );
            empty_profile()
        }
    };

    let app = Box::new(App {
        profile: std::cell::RefCell::new(profile),
        profile_path: std::cell::RefCell::new(default_profile_path),
        internal_profile,
        settings: std::cell::RefCell::new(settings),
        settings_path: std::cell::RefCell::new(settings_path),
        internal_rules_state: std::cell::RefCell::new(internal_rules_state),
        internal_rules_state_path: std::cell::RefCell::new(
            internal_rules_state_path,
        ),
    });

    let hwnd = match main_window::create(app, force_show) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("amwall: failed to create main window: {e}");
            return ExitCode::from(1);
        }
    };
    // hwnd kept alive by Win32 until WM_DESTROY → PostQuitMessage.
    let _ = hwnd;

    // Load the accelerator table (Ctrl+T / Ctrl+P / F5 / etc.).
    // Failure is non-fatal — the menu still works without
    // shortcuts.
    let haccel = unsafe {
        let hi = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
        // IDR_MAIN_ACCEL = 300 in assets/amwall.rc.
        LoadAcceleratorsW(hi, PCWSTR(300usize as *const u16)).unwrap_or_default()
    };

    // Standard message loop with accelerator translation. The
    // accelerator translator runs first; if it consumed the
    // keystroke (returns nonzero), skip the regular dispatch.
    let mut msg = MSG::default();
    unsafe {
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
            // Skip accelerator translation while the search edit box has
            // focus, so Del / Ctrl+A / Ctrl+C / Enter edit the search text
            // normally instead of firing listview commands (Fable #33).
            let focus_is_search = {
                let f = GetFocus();
                f.0 != 0 && GetDlgCtrlID(f) == crate::gui::ids::IDC_SEARCH
            };
            if !focus_is_search
                && !haccel.is_invalid()
                && TranslateAcceleratorW(hwnd, haccel, &msg) != 0
            {
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if com_initialized {
        unsafe {
            CoUninitialize();
        }
    }

    ExitCode::from(msg.wParam.0 as u8)
}

pub(crate) fn detect_system_locale() -> Option<String> {
    let mut buf = [0u16; 85];
    let len = unsafe {
        windows::Win32::Globalization::GetUserDefaultLocaleName(&mut buf)
    };
    if len <= 0 {
        return None;
    }
    let name = String::from_utf16_lossy(&buf[..(len as usize).saturating_sub(1)]);
    match_available_locale(&name)
}

/// Find the closest locale we ship for a BCP-47 name like "ru-RU".
/// Tries exact match, then base language, then any regional variant
/// of the base. Used by both system-locale detection and the MSI
/// install-LCID override path.
fn match_available_locale(name: &str) -> Option<String> {
    let available: Vec<&str> = rust_i18n::available_locales!().to_vec();
    if available.contains(&name) {
        return Some(name.to_string());
    }
    let base = name.split('-').next().unwrap_or(name);
    if available.contains(&base) {
        return Some(base.to_string());
    }
    for loc in &available {
        if loc.starts_with(base) {
            return Some(loc.to_string());
        }
    }
    None
}

/// Read `<exe_dir>\installerlocale.txt` — written by the MSI's
/// InstallerLocaleFile component via `<IniFile>` at install time. The
/// file is INI-formatted by the standard WriteIniValues action:
///
/// ```text
/// [install]
/// lcid=1049
/// ```
///
/// `[UserLanguageID]` (the user's UI-language LCID at install time, set
/// by Windows itself, the same property Windows Installer uses to pick
/// which embedded transform to auto-apply) is written into the `lcid`
/// value. We tried two simpler shapes first and both failed: a plain
/// REG_SZ HKLM value with `Value="[ProductLanguage]"` was unreliable,
/// and a File component whose source content was rewritten per culture
/// by build-msi.ps1 was silently stripped from each transform by
/// `torch -t language`.
///
/// Returns None when the file is missing (portable mode, pre-
/// multilingual install, or user deleted it) or has no parseable
/// `lcid=` line. amwall calls this on every startup and overrides
/// `settings.language` whenever the value differs from
/// `install_lcid_seen`.
fn install_lcid_from_file() -> Option<u32> {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("amwall: install-lcid: current_exe() failed: {e}");
            return None;
        }
    };
    let path = match exe.parent() {
        Some(dir) => dir.join("installerlocale.txt"),
        None => {
            eprintln!("amwall: install-lcid: exe has no parent dir, skipping override");
            return None;
        }
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "amwall: install-lcid: {} not present (skipping override)",
                path.display()
            );
            return None;
        }
        Err(e) => {
            eprintln!(
                "amwall: install-lcid: read failed for {}: {e}",
                path.display()
            );
            return None;
        }
    };

    // Find the first `lcid=<digits>` line. Tolerant of section
    // headers, comments, surrounding whitespace, and Windows CRLF —
    // INI parsers vary, so do the minimum that actually works for
    // our file's known shape.
    for raw in content.lines() {
        let line = raw.trim();
        if let Some(value) = line.strip_prefix("lcid=") {
            let trimmed = value.trim();
            return match trimmed.parse::<u32>() {
                Ok(n) if n > 0 => {
                    eprintln!(
                        "amwall: install-lcid: read {n} from {}",
                        path.display()
                    );
                    Some(n)
                }
                Ok(_) => {
                    eprintln!(
                        "amwall: install-lcid: {} `lcid=` is 0, skipping override",
                        path.display()
                    );
                    None
                }
                Err(e) => {
                    eprintln!(
                        "amwall: install-lcid: {} `lcid={trimmed}` not parseable as u32: {e}",
                        path.display()
                    );
                    None
                }
            };
        }
    }
    eprintln!(
        "amwall: install-lcid: {} has no `lcid=` line, skipping override",
        path.display()
    );
    None
}

/// Map a Windows LCID (e.g. 1049) to the closest BCP-47 culture name
/// we ship a translation for (e.g. "ru" or "ru-RU"). Uses the system
/// `LCIDToLocaleName` for the LCID→name conversion, then runs the
/// same fuzzy match as system-locale detection.
fn lcid_to_available_locale(lcid: u32) -> Option<String> {
    let mut buf = [0u16; 85];
    let len = unsafe {
        windows::Win32::Globalization::LCIDToLocaleName(lcid, Some(&mut buf), 0)
    };
    if len <= 0 {
        return None;
    }
    let name = String::from_utf16_lossy(&buf[..(len as usize).saturating_sub(1)]);
    match_available_locale(&name)
}

fn try_load_profile(path: &std::path::Path) -> Result<Profile, Box<dyn std::error::Error>> {
    // Read bytes (not a String) so a simplewall compressed "profile2"
    // container decodes transparently; decode_profile_bytes returns plain
    // XML either way. Fable sweep finding #25.
    let raw = std::fs::read(path)?;
    let xml = profile::decode_profile_bytes(&raw)?;
    let p = profile::parse_str(&xml)?;
    Ok(p)
}

fn empty_profile() -> Profile {
    Profile {
        timestamp: 0,
        kind: profile::ProfileKind::User,
        version: 5,
        apps: Vec::new(),
        rule_configs: Vec::new(),
        system_rules: Vec::new(),
        custom_rules: Vec::new(),
        blocklist_rules: Vec::new(),
    }
}

/// Helper: convert a Rust `&str` to a NUL-terminated `Vec<u16>` for
/// passing to Win32 W-suffixed APIs. Used widely by main_window.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Helper: post a `WM_QUIT` to break out of the message loop. Used by
/// menu handlers and the close button.
#[inline]
pub(crate) fn post_quit(code: i32) {
    unsafe {
        PostQuitMessage(code);
    }
}

// ---- Runtime elevation (issue #12) ----------------------------------

/// Should startup offer to restart with administrator rights?
///
/// Pure so the policy is pinned by tests rather than by reading the
/// startup sequence. Offer only when we are genuinely stuck: not
/// already elevated, and the silent Skip-UAC route either is not armed
/// or has just failed. (When Skip-UAC works the process has already
/// re-launched and exited, so this is never reached in that case; the
/// parameter is kept so the decision is total rather than relying on
/// control flow.)
pub(crate) fn should_offer_elevation(
    is_admin: bool,
    skipuac_registered: bool,
    skipuac_failed: bool,
) -> bool {
    if is_admin {
        return false;
    }
    !skipuac_registered || skipuac_failed
}

/// Ask the user whether to restart elevated. `true` = yes.
///
/// Declining is a supported choice — upstream's manifest is
/// `asInvoker`, so an unelevated amwall must remain usable (read-only:
/// the app lists still populate, the window still runs). The user's
/// permanent escape from this prompt is Settings → Skip UAC, which
/// elevates silently on every later launch.
fn offer_elevation() -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONWARNING, MB_YESNO, MessageBoxW,
    };
    use windows::core::PCWSTR;
    let title = wide(&rust_i18n::t!("dialog.admin_required"));
    let body = wide(&rust_i18n::t!("message.elevate_offer_body"));
    let answer = unsafe {
        MessageBoxW(
            None,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONWARNING,
        )
    };
    answer == IDYES
}

/// Relaunch this exe elevated via the `runas` verb and return once the
/// child has *started*.
///
/// Unlike the CLI's `-install` elevation (`main.rs`), which blocks and
/// forwards the child's exit code because the caller needs the result,
/// the GUI hands over and quits immediately — waiting would leave a
/// dead unelevated process pinned for the entire session.
fn relaunch_self_elevated(force_show: bool) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let exe = std::env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;
    let exe_w = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    // Preserve `--show` so an explicitly-shown window stays shown; any
    // other argv means we are not on the GUI path at all.
    let params = wide(if force_show { "--show" } else { "" });

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };

    // Fails with ERROR_CANCELLED when the user dismisses the UAC
    // prompt — the common, non-exceptional case.
    unsafe { ShellExecuteExW(&mut sei) }
        .map_err(|e| format!("ShellExecuteExW(runas) failed: {e}"))?;

    if sei.hProcess.0 != 0 {
        // We do not wait; just release our handle to the child.
        let _ = unsafe { CloseHandle(sei.hProcess) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::should_offer_elevation;

    #[test]
    fn elevated_process_is_never_offered_elevation() {
        assert!(!should_offer_elevation(true, false, false));
        assert!(!should_offer_elevation(true, true, true));
    }

    #[test]
    fn unelevated_without_skipuac_is_offered() {
        // The reported case: plain double-click, no Skip-UAC task, so
        // nothing else is going to obtain rights for us.
        assert!(should_offer_elevation(false, false, false));
    }

    #[test]
    fn unelevated_with_working_skipuac_is_not_offered() {
        // Skip-UAC handles it silently; prompting would be the very
        // UAC interruption that feature exists to avoid.
        assert!(!should_offer_elevation(false, true, false));
    }

    #[test]
    fn unelevated_with_broken_skipuac_falls_back_to_the_offer() {
        // Task registered but firing it failed (deleted task, policy).
        // Without this the user would be stuck unelevated with no
        // prompt at all.
        assert!(should_offer_elevation(false, true, true));
    }
}

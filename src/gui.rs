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

#![cfg(windows)]

pub mod app;
pub mod app_icons;
pub mod app_properties;
pub mod apps_context_menu;
pub mod connect_dialog;
pub mod connections;
pub mod dialogs;
pub mod dns_resolve;
pub mod event_log;
pub mod first_run_wizard;
pub mod font;
pub mod icons;
pub mod ids;
pub mod listview_groups;
pub mod main_window;
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
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, LoadAcceleratorsW, MSG, PostQuitMessage, TranslateAcceleratorW,
    TranslateMessage,
};
use windows::core::PCWSTR;

use crate::profile::{self, Profile};
use app::App;

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
    if !admin && crate::skipuac::is_registered() {
        match crate::skipuac::run_via_task() {
            Ok(()) => {
                eprintln!("amwall: relaunching elevated via skipuac task; exiting unelevated copy");
                return ExitCode::from(0);
            }
            Err(e) => {
                eprintln!(
                    "amwall: skipuac relaunch failed ({e}); continuing as unelevated GUI"
                );
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

    // Install-time language override. The MSI writes the auto-applied
    // transform's LCID to HKLM\Software\amwall\InstallLcid. When that
    // value differs from `install_lcid_seen` in settings.txt — fresh
    // install, upgrade, or reinstall under a different system locale —
    // overwrite `language` with the install LCID's culture so the user
    // sees the language they installed in. Without this, a user who
    // upgrades from a pre-multilingual MSI keeps their old `language=en`
    // even though they just installed under e.g. Russian Windows.
    if let Some(install_lcid) = install_lcid_from_registry() {
        if install_lcid != settings.install_lcid_seen {
            if let Some(locale) = lcid_to_available_locale(install_lcid) {
                settings.language = locale;
            }
            settings.install_lcid_seen = install_lcid;
            let _ = settings.save(&settings_path);
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
            if !haccel.is_invalid()
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

fn detect_system_locale() -> Option<String> {
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

/// Read `HKLM\Software\amwall\InstallLcid` (REG_DWORD) — the LCID of
/// the language transform Windows Installer auto-applied at install
/// time. Returns None when the value is missing (portable mode,
/// pre-multilingual install, or admin scrubbed it). The key lives
/// under HKLM because the MSI is per-machine; any user can read it
/// without elevation.
fn install_lcid_from_registry() -> Option<u32> {
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };

    let subkey = wide(r"Software\amwall");
    let value_name = wide("InstallLcid");
    let mut hkey = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if status.is_err() {
        return None;
    }
    let mut data: u32 = 0;
    let mut data_size: u32 = std::mem::size_of::<u32>() as u32;
    let mut value_type = REG_VALUE_TYPE(0);
    let result = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut value_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut data_size),
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if result.is_ok() && data > 0 {
        Some(data)
    } else {
        None
    }
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
    let xml = std::fs::read_to_string(path)?;
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

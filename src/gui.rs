// simplewall-rs — Win32 GUI entry point.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
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
pub mod connections;
pub mod dialogs;
pub mod font;
pub mod icons;
pub mod ids;
pub mod main_window;
pub mod rule_editor;
pub mod settings;
pub mod settings_dialog;
pub mod toolbar;

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
/// `default_profile_path` is the same `%APPDATA%\simplewall-rs\profile.xml`
/// path the CLI uses; if the file isn't present yet, the GUI starts
/// with an empty `Profile`.
pub fn run(default_profile_path: PathBuf) -> ExitCode {
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
                "simplewall-rs: warning — could not load {}: {e}; starting with empty profile.",
                default_profile_path.display(),
            );
            empty_profile()
        }
    };

    let settings_path = settings::default_settings_path();
    let settings = settings::Settings::load(&settings_path);

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
                "simplewall-rs: BUG: bundled profile_internal.xml \
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

    let hwnd = match main_window::create(app) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("simplewall-rs: failed to create main window: {e}");
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
        // IDR_MAIN_ACCEL = 300 in assets/simplewall-rs.rc.
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

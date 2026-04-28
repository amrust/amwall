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
pub mod dialogs;
pub mod icons;
pub mod ids;
pub mod main_window;
pub mod toolbar;

use std::path::PathBuf;
use std::process::ExitCode;

use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, MSG, PostQuitMessage, TranslateMessage,
};

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

    let app = Box::new(App {
        profile: std::cell::RefCell::new(profile),
        profile_path: std::cell::RefCell::new(default_profile_path),
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

    // Standard message loop. GetMessageW returns 0 on WM_QUIT.
    let mut msg = MSG::default();
    unsafe {
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
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

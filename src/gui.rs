// simplewall-rs — Win32 GUI entry point.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Direct Win32 via `windows-rs`. Programmatic UI (no .rc files).
// Main window is created in `main_window`; this module owns the
// message-loop driver and wires the App state into the window
// class via the standard `GWLP_USERDATA` pattern.
//
// Architecture in one paragraph:
//   - `App` (in `app.rs`) holds the in-memory profile + any other
//     persistent UI state. The address of a heap-allocated `App`
//     is stuffed into the main window's `GWLP_USERDATA` slot at
//     `WM_NCCREATE` time and retrieved by every subsequent
//     message handler.
//   - The main window class registers a `wnd_proc` that fans out
//     to typed handlers (`on_create`, `on_command`, etc.).
//   - The ListView control showing the profile's custom rules is
//     a child of the main window; population is driven from the
//     `App` whenever the profile changes.
//
// Future M5 sub-milestones layer additional windows (rules editor,
// settings dialog, log tab) on top of this foundation.

#![cfg(windows)]

pub mod app;
pub mod main_window;

use std::path::PathBuf;
use std::process::ExitCode;

use windows::Win32::Foundation::HWND;
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
        profile,
        profile_path: default_profile_path,
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

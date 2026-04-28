// simplewall-rs — GUI app state.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.

use std::cell::RefCell;
use std::path::PathBuf;

use crate::profile::Profile;

use super::settings::Settings;

/// In-memory state for the running GUI. Heap-allocated as `Box<App>`
/// in `gui::run` and parked in the main window's `GWLP_USERDATA`
/// slot so every WndProc invocation can reach it.
///
/// Both fields are wrapped in `RefCell` because handlers receive
/// `&App` (via `state_ref`) and need to swap out the profile / path
/// when actions like Refresh or Open Profile fire. WndProc dispatch
/// is single-threaded per window so the runtime borrow checker
/// won't surprise us at runtime — borrows always finish inside one
/// message handler.
pub struct App {
    /// The currently-loaded profile. Refresh re-reads from disk;
    /// Open Profile… replaces wholesale.
    pub profile: RefCell<Profile>,
    /// Path the profile was loaded from (and where Save Profile…
    /// would write). Defaults to `%APPDATA%\simplewall-rs\profile.xml`,
    /// matching the CLI.
    pub profile_path: RefCell<PathBuf>,
    /// Persistent UI settings (View / Settings menu toggles).
    /// Mutated by the toggle handlers, saved back to
    /// `settings_path` after each change.
    pub settings: RefCell<Settings>,
    /// Path settings persist to —
    /// `%APPDATA%\simplewall-rs\settings.txt` by default.
    pub settings_path: RefCell<PathBuf>,
}

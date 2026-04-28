// simplewall-rs — GUI app state.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.

use std::path::PathBuf;

use crate::profile::Profile;

/// In-memory state for the running GUI. Heap-allocated as `Box<App>`
/// in `gui::run` and parked in the main window's `GWLP_USERDATA`
/// slot so every WndProc invocation can reach it.
///
/// Kept deliberately flat for now — direct field access in handlers,
/// no observers or callbacks. Subsequent M5 commits will layer in
/// dirty-tracking (for the "save?" prompt on close), undo stacks,
/// etc., but that's overkill for the read-only baseline this
/// commit lands.
pub struct App {
    /// The currently-loaded profile. Mutations from menu actions
    /// (Open Profile…, future Edit Rule…) replace fields on this
    /// struct in place; the main window re-populates its ListView
    /// from the new state via `repopulate_rule_list`.
    pub profile: Profile,
    /// Path the profile was loaded from (or where Save Profile
    /// will write). Defaults to the same
    /// `%APPDATA%\simplewall-rs\profile.xml` the CLI uses.
    pub profile_path: PathBuf,
}

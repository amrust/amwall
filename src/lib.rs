// amwall — library crate.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.

rust_i18n::i18n!("locales", fallback = "en");

pub mod internal_rules_state;
pub mod paths;
pub mod profile;
pub mod rules;

#[cfg(windows)]
pub mod hash;
#[cfg(windows)]
pub mod logging;

#[cfg(windows)]
pub mod diagnostics;
#[cfg(windows)]
pub mod gui;
#[cfg(windows)]
pub mod install;
#[cfg(windows)]
pub mod skipuac;
#[cfg(windows)]
pub mod wfp;

// simplewall-rs — library crate.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Module surface for the Rust port of simplewall. The companion binary
// (`src/main.rs`) is a thin entry point that opens the WFP engine and
// drives the rest of the library; everything testable lives here so
// integration tests in `tests/` and unit tests inside each module can
// exercise it without the full main flow.
//
// `wfp` is Windows-only (uses `windows-rs`), gated at this level so a
// non-Windows `cargo check` or `cargo doc` still produces a valid
// library. `profile` is pure-Rust XML I/O and compiles on every host.

pub mod profile;
pub mod rules;

#[cfg(windows)]
pub mod gui;
#[cfg(windows)]
pub mod install;
#[cfg(windows)]
pub mod wfp;

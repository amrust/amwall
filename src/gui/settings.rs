// simplewall-rs — persistent UI settings.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// User-toggleable preferences that survive app restarts. Lives in
// `%APPDATA%\simplewall-rs\settings.txt` as a tiny line-oriented
// key=value format — chosen over TOML/JSON specifically to avoid
// adding a serde-flavoured dependency for ~10 booleans.
//
// Format:
//   # comment line — ignored
//   <key>=<bool|str>
//
// Unrecognised keys are dropped on read (forward-compat: a future
// version might add a setting; an older version reading the new
// file just ignores it). Bad values fall back to the default.
//
// All fields are pub so handlers in `main_window` can both read
// (current state for the menu's checked/unchecked appearance) and
// write (when the user clicks a toggle). Caller is responsible for
// calling `save` after a mutation; we don't auto-flush on every
// change because batched updates (e.g. multiple toggles in one
// session) shouldn't each cost a disk write.

#![cfg(windows)]

use std::path::{Path, PathBuf};

/// All persistent UI settings. Defaults match upstream simplewall's
/// defaults so a user coming from upstream sees the same window on
/// first launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// View → Always on top.
    pub always_on_top: bool,
    /// View → Autosize columns. When on, listview columns expand
    /// to fit their content on each repopulate.
    pub autosize_columns: bool,
    /// View → Show search bar. Toggles the search edit band's
    /// visibility on the rebar.
    pub show_search_bar: bool,
    /// View → Show filenames only. Apps tab shows basename instead
    /// of full path.
    pub show_filenames_only: bool,
    /// View → Use dark theme. Cosmetic; wires up later when
    /// theming lands.
    pub use_dark_theme: bool,
    /// Settings → Load on system startup.
    pub load_on_startup: bool,
    /// Settings → Start minimized.
    pub start_minimized: bool,
    /// Settings → Skip UAC warning.
    pub skip_uac_warning: bool,
    /// Settings → Check for updates periodically.
    pub check_updates: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            always_on_top: false,
            autosize_columns: false,
            show_search_bar: true,
            show_filenames_only: true,
            use_dark_theme: false,
            load_on_startup: false,
            start_minimized: false,
            skip_uac_warning: false,
            check_updates: true,
        }
    }
}

impl Settings {
    /// Read the settings file at the given path. Missing file →
    /// defaults; unreadable file or parse errors also → defaults
    /// (with a warning to stderr) so a corrupt settings file never
    /// blocks startup.
    pub fn load(path: &Path) -> Self {
        let mut s = Self::default();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return s,
            Err(e) => {
                eprintln!(
                    "simplewall-rs: settings: read failed for {}: {e}",
                    path.display()
                );
                return s;
            }
        };
        for (lineno, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                eprintln!(
                    "simplewall-rs: settings: line {} ignored — no '=' separator",
                    lineno + 1
                );
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            apply_kv(&mut s, key, value);
        }
        s
    }

    /// Write the settings to disk in the line-oriented format,
    /// creating parent directories if necessary.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf = String::new();
        buf.push_str("# simplewall-rs settings — edited by hand at your own risk\n");
        kv(&mut buf, "always_on_top", self.always_on_top);
        kv(&mut buf, "autosize_columns", self.autosize_columns);
        kv(&mut buf, "show_search_bar", self.show_search_bar);
        kv(&mut buf, "show_filenames_only", self.show_filenames_only);
        kv(&mut buf, "use_dark_theme", self.use_dark_theme);
        kv(&mut buf, "load_on_startup", self.load_on_startup);
        kv(&mut buf, "start_minimized", self.start_minimized);
        kv(&mut buf, "skip_uac_warning", self.skip_uac_warning);
        kv(&mut buf, "check_updates", self.check_updates);
        std::fs::write(path, buf)
    }
}

fn apply_kv(s: &mut Settings, key: &str, value: &str) {
    let b = match parse_bool(value) {
        Some(b) => b,
        None => {
            eprintln!("simplewall-rs: settings: unrecognised value `{value}` for `{key}`");
            return;
        }
    };
    match key {
        "always_on_top" => s.always_on_top = b,
        "autosize_columns" => s.autosize_columns = b,
        "show_search_bar" => s.show_search_bar = b,
        "show_filenames_only" => s.show_filenames_only = b,
        "use_dark_theme" => s.use_dark_theme = b,
        "load_on_startup" => s.load_on_startup = b,
        "start_minimized" => s.start_minimized = b,
        "skip_uac_warning" => s.skip_uac_warning = b,
        "check_updates" => s.check_updates = b,
        // Forward-compat: silently ignore unknown keys.
        _ => {}
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn kv(buf: &mut String, key: &str, value: bool) {
    use std::fmt::Write;
    let _ = writeln!(buf, "{key}={value}");
}

/// Standard location: `%APPDATA%\simplewall-rs\settings.txt`,
/// matching the same pattern used by `default_profile_path` in the
/// CLI entry point. Falls back to a relative `settings.txt` when
/// %APPDATA% is unset (e.g. running as SYSTEM).
pub fn default_settings_path() -> PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        PathBuf::from(appdata)
            .join("simplewall-rs")
            .join("settings.txt")
    } else {
        PathBuf::from("settings.txt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_upstream_initial_state() {
        let s = Settings::default();
        assert!(s.show_search_bar);
        assert!(s.show_filenames_only);
        assert!(s.check_updates);
        assert!(!s.always_on_top);
        assert!(!s.use_dark_theme);
    }

    #[test]
    fn parse_bool_accepts_common_synonyms() {
        for t in ["true", "TRUE", "1", "yes", "on"] {
            assert_eq!(parse_bool(t), Some(true), "expected true for {t}");
        }
        for f in ["false", "FALSE", "0", "no", "off"] {
            assert_eq!(parse_bool(f), Some(false), "expected false for {f}");
        }
        assert_eq!(parse_bool(""), None);
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn round_trip_via_temp_file() {
        let dir = std::env::temp_dir().join("simplewall-rs-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings_round_trip.txt");
        let _ = std::fs::remove_file(&path);

        let s = Settings {
            always_on_top: true,
            autosize_columns: true,
            show_search_bar: false,
            ..Settings::default()
        };
        s.save(&path).expect("save should succeed");

        let loaded = Settings::load(&path);
        assert_eq!(loaded, s);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_yields_defaults() {
        let path = std::env::temp_dir().join("simplewall-rs-does-not-exist.txt");
        let _ = std::fs::remove_file(&path);
        let s = Settings::load(&path);
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let dir = std::env::temp_dir().join("simplewall-rs-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings_unknown.txt");
        std::fs::write(
            &path,
            "always_on_top=true\nfuture_setting=banana\nshow_search_bar=false\n",
        )
        .unwrap();
        let s = Settings::load(&path);
        assert!(s.always_on_top);
        assert!(!s.show_search_bar);
        let _ = std::fs::remove_file(&path);
    }
}

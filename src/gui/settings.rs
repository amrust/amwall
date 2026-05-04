// amwall — persistent UI settings.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// User-toggleable preferences that survive app restarts. Lives in
// `%APPDATA%\amwall\settings.txt` as a tiny line-oriented
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

/// Three-way blocklist toggle — matches upstream's tri-state
/// radio groups on the Settings → Blocklist page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlocklistMode {
    #[default]
    Disable,
    Allow,
    Block,
}

/// View → Layout. Maps to comctl32's `LV_VIEW_*` modes — the
/// listview's overall presentation. Mirrors upstream's
/// IDM_VIEW_DETAILS/_ICON/_TILE radio group at main.c:3337.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewType {
    /// `LV_VIEW_DETAILS` — multi-column report table. The default
    /// upstream and the only mode amwall has had since M5.
    #[default]
    Details,
    /// `LV_VIEW_ICON` — large square icons in a flow layout.
    Icon,
    /// `LV_VIEW_TILE` — icon + name + 2-line subtitle in a flow
    /// layout. Halfway between Details and Icon.
    Tile,
}

impl ViewType {
    pub fn as_str(self) -> &'static str {
        match self {
            ViewType::Details => "details",
            ViewType::Icon => "icon",
            ViewType::Tile => "tile",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "details" => Some(Self::Details),
            "icon" => Some(Self::Icon),
            "tile" => Some(Self::Tile),
            _ => None,
        }
    }
}

/// View → Size. Controls which system imagelist (16/32/48 px)
/// gets attached as `LVSIL_NORMAL` / `LVSIL_SMALL`. Upstream
/// IDM_SIZE_SMALL/_LARGE/_EXTRALARGE radio group at main.c:3365.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IconSize {
    /// 16×16 — default Details-mode size.
    #[default]
    Small,
    /// 32×32 — default Icon/Tile-mode size.
    Large,
    /// 48×48 — `SHIL_EXTRALARGE` from `SHGetImageList`.
    ExtraLarge,
}

impl IconSize {
    pub fn as_str(self) -> &'static str {
        match self {
            IconSize::Small => "small",
            IconSize::Large => "large",
            IconSize::ExtraLarge => "extralarge",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "small" => Some(Self::Small),
            "large" => Some(Self::Large),
            "extralarge" => Some(Self::ExtraLarge),
            _ => None,
        }
    }
}

impl BlocklistMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BlocklistMode::Disable => "disable",
            BlocklistMode::Allow => "allow",
            BlocklistMode::Block => "block",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "disable" => Some(Self::Disable),
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

/// All persistent UI settings. Defaults match upstream simplewall's
/// defaults so a user coming from upstream sees the same window on
/// first launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    // ---- View menu / window state ----
    /// View → Always on top.
    pub always_on_top: bool,
    /// View → Autosize columns.
    pub autosize_columns: bool,
    /// View → Show search bar.
    pub show_search_bar: bool,
    /// View → Show filenames only.
    pub show_filenames_only: bool,
    /// View → Use dark theme.
    pub use_dark_theme: bool,
    /// View → Layout (Details / Icon / Tile).
    pub view_type: ViewType,
    /// View → Size (Small / Large / ExtraLarge). Only renders
    /// visibly different in `Icon` and `Tile` view types; in
    /// `Details` the icon column is fixed at 16×16 regardless.
    pub icon_size: IconSize,

    // ---- Settings → General ----
    pub load_on_startup: bool,
    pub start_minimized: bool,
    pub skip_uac_warning: bool,
    pub check_updates: bool,
    /// Selected language code (e.g. "en", "ru"). Empty = system default.
    pub language: String,

    // ---- View → Font ----
    /// Custom font face name (e.g. "Consolas"). Empty falls back
    /// to the system message font (Segoe UI 9pt on Windows 10/11).
    pub font_face: String,
    /// Font height in LOGFONT units (negative = char-height, the
    /// `ChooseFont` convention). 0 = use the system default.
    pub font_height: i32,

    // ---- Settings → Interface (confirmations + tray) ----
    pub confirm_exit: bool,
    pub confirm_exit_timer: bool,
    pub confirm_log_clear: bool,
    pub confirm_allow: bool,
    pub tray_single_click: bool,

    // ---- Settings → Rules ----
    pub rule_block_outbound: bool,
    pub rule_block_inbound: bool,
    pub rule_allow_loopback: bool,
    pub rule_allow_6to4: bool,
    pub rule_allow_windows_update: bool,
    pub use_stealth_mode: bool,
    pub install_boottime_filters: bool,
    pub use_certificates: bool,
    pub use_hashes: bool,
    pub use_network_resolution: bool,

    // ---- Settings → Blocklist (tri-state radio groups) ----
    pub blocklist_spy: BlocklistMode,
    pub blocklist_update: BlocklistMode,
    pub blocklist_extra: BlocklistMode,

    // ---- Settings → Notifications ----
    pub enable_notifications: bool,
    pub notification_sound: bool,
    pub notification_fullscreen_silent: bool,
    pub notification_on_tray: bool,
    /// Seconds between similar notifications.
    pub notification_timeout: u32,
    /// Last user-dragged toast top-left in virtual-screen coords.
    /// `i32::MIN` is the unset sentinel — toast picks the default
    /// (bottom-right of the foreground window's monitor work area).
    /// Saved on drag-and-release, validated against the current
    /// monitor layout on every show. Signed because virtual-screen
    /// coords on multi-monitor setups can be negative (e.g. a
    /// secondary monitor positioned to the left of the primary).
    pub notification_x: i32,
    pub notification_y: i32,

    // ---- Settings → Logging ----
    pub enable_log: bool,
    pub log_path: String,
    /// Maximum log size in kilobytes.
    pub log_size_limit: u32,
    pub log_viewer: String,
    pub enable_ui_log: bool,

    // ---- Settings → Exclude ----
    pub exclude_blocklist: bool,
    pub exclude_custom: bool,
    pub exclude_stealth: bool,
    pub exclude_classify_allow: bool,

    // ---- First-run wizard (M9.4) ----
    /// Set to `true` after the first-run wizard has run (whether
    /// the user picked Import or Start fresh). Prevents the
    /// wizard from re-showing on every launch.
    pub first_run_done: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            always_on_top: false,
            autosize_columns: false,
            show_search_bar: true,
            show_filenames_only: true,
            use_dark_theme: false,
            view_type: ViewType::Details,
            icon_size: IconSize::Small,
            load_on_startup: false,
            start_minimized: false,
            skip_uac_warning: false,
            check_updates: true,
            language: String::new(),
            font_face: String::new(),
            font_height: 0,
            confirm_exit: true,
            confirm_exit_timer: true,
            confirm_log_clear: true,
            confirm_allow: true,
            tray_single_click: false,
            rule_block_outbound: false,
            rule_block_inbound: false,
            rule_allow_loopback: true,
            rule_allow_6to4: false,
            rule_allow_windows_update: false,
            use_stealth_mode: false,
            install_boottime_filters: false,
            use_certificates: false,
            use_hashes: false,
            use_network_resolution: false,
            // Match upstream simplewall's defaults: Spy = Block (the
            // WindowsSpyBlocker telemetry blocks are the headline
            // reason most users install simplewall in the first place);
            // Update = Disable (most users want Windows Update to
            // work); Extra = Disable (Microsoft Apps blocks).
            blocklist_spy: BlocklistMode::Block,
            blocklist_update: BlocklistMode::Disable,
            blocklist_extra: BlocklistMode::Disable,
            enable_notifications: true,
            notification_sound: true,
            notification_fullscreen_silent: false,
            notification_on_tray: false,
            notification_timeout: 30,
            notification_x: i32::MIN,
            notification_y: i32::MIN,
            enable_log: false,
            log_path: String::new(),
            log_size_limit: 4096,
            log_viewer: String::new(),
            enable_ui_log: false,
            exclude_blocklist: false,
            exclude_custom: false,
            exclude_stealth: false,
            exclude_classify_allow: false,
            first_run_done: false,
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
                    "amwall: settings: read failed for {}: {e}",
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
                    "amwall: settings: line {} ignored — no '=' separator",
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
        buf.push_str("# amwall settings — edited by hand at your own risk\n");
        kv(&mut buf, "always_on_top", self.always_on_top);
        kv(&mut buf, "autosize_columns", self.autosize_columns);
        kv(&mut buf, "show_search_bar", self.show_search_bar);
        kv(&mut buf, "show_filenames_only", self.show_filenames_only);
        kv(&mut buf, "use_dark_theme", self.use_dark_theme);
        kv_str(&mut buf, "view_type", self.view_type.as_str());
        kv_str(&mut buf, "icon_size", self.icon_size.as_str());
        kv(&mut buf, "load_on_startup", self.load_on_startup);
        kv(&mut buf, "start_minimized", self.start_minimized);
        kv(&mut buf, "skip_uac_warning", self.skip_uac_warning);
        kv(&mut buf, "check_updates", self.check_updates);
        kv_str(&mut buf, "language", &self.language);
        kv_str(&mut buf, "font_face", &self.font_face);
        kv_i32(&mut buf, "font_height", self.font_height);
        kv(&mut buf, "confirm_exit", self.confirm_exit);
        kv(&mut buf, "confirm_exit_timer", self.confirm_exit_timer);
        kv(&mut buf, "confirm_log_clear", self.confirm_log_clear);
        kv(&mut buf, "confirm_allow", self.confirm_allow);
        kv(&mut buf, "tray_single_click", self.tray_single_click);
        kv(&mut buf, "rule_block_outbound", self.rule_block_outbound);
        kv(&mut buf, "rule_block_inbound", self.rule_block_inbound);
        kv(&mut buf, "rule_allow_loopback", self.rule_allow_loopback);
        kv(&mut buf, "rule_allow_6to4", self.rule_allow_6to4);
        kv(
            &mut buf,
            "rule_allow_windows_update",
            self.rule_allow_windows_update,
        );
        kv(&mut buf, "use_stealth_mode", self.use_stealth_mode);
        kv(&mut buf, "install_boottime_filters", self.install_boottime_filters);
        kv(&mut buf, "use_certificates", self.use_certificates);
        kv(&mut buf, "use_hashes", self.use_hashes);
        kv(&mut buf, "use_network_resolution", self.use_network_resolution);
        kv_str(&mut buf, "blocklist_spy", self.blocklist_spy.as_str());
        kv_str(&mut buf, "blocklist_update", self.blocklist_update.as_str());
        kv_str(&mut buf, "blocklist_extra", self.blocklist_extra.as_str());
        kv(&mut buf, "enable_notifications", self.enable_notifications);
        kv(&mut buf, "notification_sound", self.notification_sound);
        kv(
            &mut buf,
            "notification_fullscreen_silent",
            self.notification_fullscreen_silent,
        );
        kv(&mut buf, "notification_on_tray", self.notification_on_tray);
        kv_u32(&mut buf, "notification_timeout", self.notification_timeout);
        kv_i32(&mut buf, "notification_x", self.notification_x);
        kv_i32(&mut buf, "notification_y", self.notification_y);
        kv(&mut buf, "enable_log", self.enable_log);
        kv_str(&mut buf, "log_path", &self.log_path);
        kv_u32(&mut buf, "log_size_limit", self.log_size_limit);
        kv_str(&mut buf, "log_viewer", &self.log_viewer);
        kv(&mut buf, "enable_ui_log", self.enable_ui_log);
        kv(&mut buf, "exclude_blocklist", self.exclude_blocklist);
        kv(&mut buf, "exclude_custom", self.exclude_custom);
        kv(&mut buf, "exclude_stealth", self.exclude_stealth);
        kv(&mut buf, "exclude_classify_allow", self.exclude_classify_allow);
        kv(&mut buf, "first_run_done", self.first_run_done);
        std::fs::write(path, buf)
    }
}

fn apply_kv(s: &mut Settings, key: &str, value: &str) {
    // String / numeric / enum keys first; they don't go through
    // parse_bool so handle before the bool branch.
    match key {
        "language" => {
            s.language = value.to_string();
            return;
        }
        "blocklist_spy" => {
            if let Some(m) = BlocklistMode::parse(value) {
                s.blocklist_spy = m;
            }
            return;
        }
        "blocklist_update" => {
            if let Some(m) = BlocklistMode::parse(value) {
                s.blocklist_update = m;
            }
            return;
        }
        "blocklist_extra" => {
            if let Some(m) = BlocklistMode::parse(value) {
                s.blocklist_extra = m;
            }
            return;
        }
        "view_type" => {
            if let Some(v) = ViewType::parse(value) {
                s.view_type = v;
            }
            return;
        }
        "icon_size" => {
            if let Some(v) = IconSize::parse(value) {
                s.icon_size = v;
            }
            return;
        }
        "notification_timeout" => {
            if let Ok(n) = value.parse::<u32>() {
                s.notification_timeout = n;
            }
            return;
        }
        "notification_x" => {
            if let Ok(n) = value.parse::<i32>() {
                s.notification_x = n;
            }
            return;
        }
        "notification_y" => {
            if let Ok(n) = value.parse::<i32>() {
                s.notification_y = n;
            }
            return;
        }
        "log_path" => {
            s.log_path = value.to_string();
            return;
        }
        "log_size_limit" => {
            if let Ok(n) = value.parse::<u32>() {
                s.log_size_limit = n;
            }
            return;
        }
        "log_viewer" => {
            s.log_viewer = value.to_string();
            return;
        }
        "font_face" => {
            s.font_face = value.to_string();
            return;
        }
        "font_height" => {
            if let Ok(n) = value.parse::<i32>() {
                s.font_height = n;
            }
            return;
        }
        _ => {}
    }
    let b = match parse_bool(value) {
        Some(b) => b,
        None => {
            eprintln!("amwall: settings: unrecognised value `{value}` for `{key}`");
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
        "confirm_exit" => s.confirm_exit = b,
        "confirm_exit_timer" => s.confirm_exit_timer = b,
        "confirm_log_clear" => s.confirm_log_clear = b,
        "confirm_allow" => s.confirm_allow = b,
        "tray_single_click" => s.tray_single_click = b,
        "rule_block_outbound" => s.rule_block_outbound = b,
        "rule_block_inbound" => s.rule_block_inbound = b,
        "rule_allow_loopback" => s.rule_allow_loopback = b,
        "rule_allow_6to4" => s.rule_allow_6to4 = b,
        "rule_allow_windows_update" => s.rule_allow_windows_update = b,
        "use_stealth_mode" => s.use_stealth_mode = b,
        "install_boottime_filters" => s.install_boottime_filters = b,
        "use_certificates" => s.use_certificates = b,
        "use_hashes" => s.use_hashes = b,
        "use_network_resolution" => s.use_network_resolution = b,
        "enable_notifications" => s.enable_notifications = b,
        "notification_sound" => s.notification_sound = b,
        "notification_fullscreen_silent" => s.notification_fullscreen_silent = b,
        "notification_on_tray" => s.notification_on_tray = b,
        "enable_log" => s.enable_log = b,
        "enable_ui_log" => s.enable_ui_log = b,
        "exclude_blocklist" => s.exclude_blocklist = b,
        "exclude_custom" => s.exclude_custom = b,
        "exclude_stealth" => s.exclude_stealth = b,
        "exclude_classify_allow" => s.exclude_classify_allow = b,
        "first_run_done" => s.first_run_done = b,
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

fn kv_str(buf: &mut String, key: &str, value: &str) {
    use std::fmt::Write;
    let _ = writeln!(buf, "{key}={value}");
}

fn kv_u32(buf: &mut String, key: &str, value: u32) {
    use std::fmt::Write;
    let _ = writeln!(buf, "{key}={value}");
}

fn kv_i32(buf: &mut String, key: &str, value: i32) {
    use std::fmt::Write;
    let _ = writeln!(buf, "{key}={value}");
}

/// Standard location: `%APPDATA%\amwall\settings.txt`,
/// matching the same pattern used by `default_profile_path` in the
/// CLI entry point. Falls back to a relative `settings.txt` when
/// %APPDATA% is unset (e.g. running as SYSTEM).
pub fn default_settings_path() -> PathBuf {
    crate::paths::settings_path()
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
        let dir = std::env::temp_dir().join("amwall-tests");
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
    fn notification_position_round_trips_negative_coords() {
        // On a multi-monitor setup with a secondary panel positioned
        // to the left of (or above) the primary, the virtual-screen
        // origin is offset and saved coords end up negative. Round-
        // trip must preserve sign.
        let dir = std::env::temp_dir().join("amwall-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings_notif_pos.txt");
        let _ = std::fs::remove_file(&path);

        let s = Settings {
            notification_x: -1024,
            notification_y: -50,
            ..Settings::default()
        };
        s.save(&path).expect("save should succeed");
        let loaded = Settings::load(&path);
        assert_eq!(loaded.notification_x, -1024);
        assert_eq!(loaded.notification_y, -50);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn notification_position_default_is_unset_sentinel() {
        // The default is `i32::MIN`, signalling "no position saved"
        // — toast must fall back to the bottom-right-of-foreground-
        // monitor default. A literal 0,0 would mean top-left, which
        // is an explicit user choice, so the sentinel can't be 0.
        let s = Settings::default();
        assert_eq!(s.notification_x, i32::MIN);
        assert_eq!(s.notification_y, i32::MIN);
    }

    #[test]
    fn missing_file_yields_defaults() {
        let path = std::env::temp_dir().join("amwall-does-not-exist.txt");
        let _ = std::fs::remove_file(&path);
        let s = Settings::load(&path);
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let dir = std::env::temp_dir().join("amwall-tests");
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

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
    /// GitHub release tag the user most recently dismissed an
    /// auto-check "update available" popup for. Empty = nothing
    /// dismissed. Auto-check (startup + hourly `TIMER_UPDATE_CHECK`)
    /// stays silent when `latest == update_dismissed_tag`, so a user
    /// who hit Yes or No on the popup once isn't pestered every hour
    /// about the same release. Manual `Help -> Check for updates`
    /// ignores this and always pops up — the user explicitly asked.
    /// When a strictly-newer tag ships, `dismissed != latest` again
    /// and the auto-popup resumes.
    pub update_dismissed_tag: String,
    /// Selected language code (e.g. "en", "ru"). Empty = system default.
    pub language: String,
    /// Last `[ProductLanguage]` LCID we saw written by the MSI installer
    /// to `HKLM\Software\amwall\InstallLcid`. When the install LCID
    /// changes (fresh install, upgrade, or reinstall after a transform
    /// change), startup overrides `language` with the install LCID's
    /// culture so the user sees the language they installed in. 0 = no
    /// install ever recorded — first launch under the multilingual MSI
    /// will trigger a one-time override even when settings.txt already
    /// has a stale `language=en` from a pre-multilingual install.
    pub install_lcid_seen: u32,

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
    /// Remembers whether filters were enabled when the user last
    /// closed amwall (or when they last clicked Enable / Disable).
    /// Drives the startup auto-enable: if true and the kernel has
    /// no amwall filters at launch, we install them silently. Set
    /// to false by Disable filters and Emergency reset so an
    /// explicit "off" choice survives the next launch instead of
    /// being immediately undone.
    pub filters_active_persisted: bool,
    pub use_certificates: bool,
    pub use_hashes: bool,
    pub use_network_resolution: bool,
    /// Auto-allow Microsoft-signed binaries on first connection
    /// without prompting. New feature beyond upstream simplewall
    /// — addresses the longstanding upstream issue where users
    /// have to Allow svchost / Experience Host / etc. one by
    /// one. When on, the auto-catalog flow checks the leaf
    /// signature subject; if it starts with "Microsoft ", the
    /// app is added with is_enabled=true (Allowed) and the
    /// connect prompt is skipped.
    pub auto_allow_microsoft_signed: bool,

    // ---- Settings → Highlighting (row colors, Fable #31) ----
    // Per-category enable flags + packed COLORREF colors, mirroring
    // upstream's [colors] INI section (IsHighlight* / Color* keys,
    // main.c:2116-2122). All enables default TRUE like upstream. The
    // colorizer (main_window::pick_app_row_color) gates each category on
    // its enable flag and reads the color from here.
    pub highlight_invalid: bool,
    pub highlight_special: bool,
    pub highlight_signed: bool,
    pub highlight_pico: bool,
    pub highlight_system: bool,
    pub highlight_connection: bool,
    pub highlight_undelete: bool,
    pub color_invalid: u32,
    pub color_special: u32,
    pub color_signed: u32,
    pub color_pico: u32,
    pub color_system: u32,
    pub color_connection: u32,
    pub color_undelete: u32,

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

    /// Saved main-window placement — the *normal* (restored) rectangle in
    /// virtual-screen pixels, plus whether the window was maximized on
    /// exit. Persisted on exit, restored on launch. Mirrors upstream
    /// simplewall `_r_window_restoreposition`/`_r_window_saveposition`
    /// (main.c:2201). `window_w <= 0 || window_h <= 0` means "unset" →
    /// the window falls back to `CW_USEDEFAULT`. Signed because
    /// virtual-screen coords are negative on multi-monitor layouts where a
    /// monitor sits left of / above the primary.
    pub window_x: i32,
    pub window_y: i32,
    pub window_w: i32,
    pub window_h: i32,
    pub window_maximized: bool,

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

/// Pack an (r, g, b) triple into a Win32 COLORREF (0x00BBGGRR). Matches
/// GDI's byte order, so a stored value drops straight into `clrTextBk`
/// and is interchangeable with `ChooseColorW`'s `rgbResult` — no
/// byte-swap anywhere. (Fable #31.)
pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            always_on_top: false,
            // Upstream default is ON (`_r_config_getboolean
            // (L"AutoSizeColumns", TRUE, …)`, listview.c:812). amwall
            // shipped it OFF, so localized headers stayed clipped at
            // their hardcoded English widths — issue #11.
            autosize_columns: true,
            show_search_bar: true,
            show_filenames_only: true,
            use_dark_theme: false,
            view_type: ViewType::Details,
            icon_size: IconSize::Small,
            load_on_startup: false,
            start_minimized: false,
            skip_uac_warning: false,
            check_updates: true,
            update_dismissed_tag: String::new(),
            language: String::new(),
            install_lcid_seen: 0,
            font_face: String::new(),
            font_height: 0,
            confirm_exit: true,
            confirm_exit_timer: true,
            confirm_log_clear: true,
            confirm_allow: true,
            tray_single_click: false,
            // Upstream simplewall defaults are all TRUE (messages.c:74-77,
            // wfp.c:1806/1965/2066/2390). block_outbound/inbound now select
            // the FW_WEIGHT_LOWEST catch-all's action (install_default_deny),
            // so ON = default-deny.
            rule_block_outbound: true,
            rule_block_inbound: true,
            rule_allow_loopback: true,
            rule_allow_6to4: true,
            rule_allow_windows_update: false,
            use_stealth_mode: true,
            // Default-on so amwall's filters survive a Windows
            // reboot or a process crash. Without this, BFE wipes
            // every non-persistent filter at boot and the user
            // has to launch amwall and click Enable again.
            install_boottime_filters: true,
            // Default-on so a fresh install starts with filtering
            // active on first launch (no need to click Enable).
            // Cleared by Disable filters / Emergency reset so an
            // explicit "off" choice is honoured next launch.
            filters_active_persisted: true,
            use_certificates: false,
            // Deliberate divergence from upstream (simplewall defaults
            // "check hashes" OFF): amwall defaults it ON so exe-swap /
            // tamper protection is active out of the box. When on,
            // `check_hash_drift` re-hashes allowed File apps at launch and
            // every 10 min and disables + un-permits any whose binary
            // changed on disk. The periodic I/O is the tradeoff. An
            // explicit off in settings.txt is still honoured.
            use_hashes: true,
            use_network_resolution: false,
            auto_allow_microsoft_signed: false,
            // Match upstream simplewall's defaults: Spy = Block (the
            // WindowsSpyBlocker telemetry blocks are the headline
            // reason most users install simplewall in the first place);
            // Update = Disable (most users want Windows Update to
            // work); Extra = Disable (Microsoft Apps blocks).
            // Highlighting (Fable #31): all categories on by default,
            // colors = upstream's LV_COLOR_* defaults (main.h:163-169).
            highlight_invalid: true,
            highlight_special: true,
            highlight_signed: true,
            highlight_pico: true,
            highlight_system: true,
            highlight_connection: true,
            highlight_undelete: true,
            color_invalid: rgb(255, 125, 148),
            color_special: rgb(255, 255, 170),
            color_signed: rgb(175, 228, 163),
            color_pico: rgb(51, 153, 255),
            color_system: rgb(151, 196, 251),
            color_connection: rgb(237, 224, 214),
            color_undelete: rgb(211, 211, 211),
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
            // Unset until the window is first closed: zero size ==
            // "no saved placement" (see `has_window_placement`).
            window_x: 0,
            window_y: 0,
            window_w: 0,
            window_h: 0,
            window_maximized: false,
            // M9.2 / v1.1.2 default-on: makes installed-mode bug
            // reports actionable (the packet log writes a per-event
            // record under `%APPDATA%\amwall\amwall.log`, alongside
            // the always-on session log under `\logs\`). Bounded by
            // `log_size_limit` (4 MiB), so stays small.
            enable_log: true,
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
    /// True when a usable main-window placement has been saved. A
    /// zero-or-negative width/height is the "unset" sentinel (fresh
    /// install, or a settings file written before this feature existed),
    /// in which case the window uses the system default position.
    pub fn has_window_placement(&self) -> bool {
        self.window_w > 0 && self.window_h > 0
    }

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
        let mut saw_filters_active_persisted = false;
        let mut saw_rules_catchall_v2 = false;
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
            if key == "filters_active_persisted" {
                saw_filters_active_persisted = true;
            }
            if key == "rules_catchall_v2" {
                saw_rules_catchall_v2 = true;
            }
            apply_kv(&mut s, key, value);
        }
        // v1.1.15 migration: if the file predates `filters_active_persisted`,
        // the user is upgrading from a build that defaulted
        // `install_boottime_filters = false`. Force it on so filters
        // survive the next reboot — matches the new default and keeps
        // upgraded installs from silently losing filter coverage.
        if !saw_filters_active_persisted && !s.install_boottime_filters {
            eprintln!(
                "amwall: settings: migrating install_boottime_filters false → true (v1.1.15)"
            );
            s.install_boottime_filters = true;
        }
        // Catch-all-action migration: files written before this model had
        // an unconditional default-deny catch-all, so rule_block_outbound
        // / rule_block_inbound were inert (always saved false by the old
        // default). Under the new model a saved false flips the catch-all
        // to Permit — fail open. Force both on once so an upgraded install
        // keeps the outbound/inbound coverage it actually had. (A user who
        // genuinely wants allow-all can turn them off afterwards; the marker
        // then persists their choice.)
        if !saw_rules_catchall_v2 && (!s.rule_block_outbound || !s.rule_block_inbound) {
            eprintln!(
                "amwall: settings: migrating rule_block_outbound/inbound → true (catch-all-action model)"
            );
            s.rule_block_outbound = true;
            s.rule_block_inbound = true;
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
        kv_str(&mut buf, "update_dismissed_tag", &self.update_dismissed_tag);
        kv_str(&mut buf, "language", &self.language);
        kv_u32(&mut buf, "install_lcid_seen", self.install_lcid_seen);
        kv_str(&mut buf, "font_face", &self.font_face);
        kv_i32(&mut buf, "font_height", self.font_height);
        kv(&mut buf, "confirm_exit", self.confirm_exit);
        kv(&mut buf, "confirm_exit_timer", self.confirm_exit_timer);
        kv(&mut buf, "confirm_log_clear", self.confirm_log_clear);
        kv(&mut buf, "confirm_allow", self.confirm_allow);
        kv(&mut buf, "tray_single_click", self.tray_single_click);
        kv(&mut buf, "rule_block_outbound", self.rule_block_outbound);
        kv(&mut buf, "rule_block_inbound", self.rule_block_inbound);
        // Schema marker: presence means this file was written with the
        // catch-all-action model (block_outbound/inbound select the
        // default-deny action). Absence triggers a one-time migration in
        // load() so upgraded installs don't fail open.
        kv(&mut buf, "rules_catchall_v2", true);
        kv(&mut buf, "rule_allow_loopback", self.rule_allow_loopback);
        kv(&mut buf, "rule_allow_6to4", self.rule_allow_6to4);
        kv(
            &mut buf,
            "rule_allow_windows_update",
            self.rule_allow_windows_update,
        );
        kv(&mut buf, "use_stealth_mode", self.use_stealth_mode);
        kv(&mut buf, "install_boottime_filters", self.install_boottime_filters);
        kv(&mut buf, "filters_active_persisted", self.filters_active_persisted);
        kv(&mut buf, "use_certificates", self.use_certificates);
        kv(&mut buf, "use_hashes", self.use_hashes);
        kv(&mut buf, "use_network_resolution", self.use_network_resolution);
        kv(
            &mut buf,
            "auto_allow_microsoft_signed",
            self.auto_allow_microsoft_signed,
        );
        kv(&mut buf, "highlight_invalid", self.highlight_invalid);
        kv(&mut buf, "highlight_special", self.highlight_special);
        kv(&mut buf, "highlight_signed", self.highlight_signed);
        kv(&mut buf, "highlight_pico", self.highlight_pico);
        kv(&mut buf, "highlight_system", self.highlight_system);
        kv(&mut buf, "highlight_connection", self.highlight_connection);
        kv(&mut buf, "highlight_undelete", self.highlight_undelete);
        kv_u32(&mut buf, "color_invalid", self.color_invalid);
        kv_u32(&mut buf, "color_special", self.color_special);
        kv_u32(&mut buf, "color_signed", self.color_signed);
        kv_u32(&mut buf, "color_pico", self.color_pico);
        kv_u32(&mut buf, "color_system", self.color_system);
        kv_u32(&mut buf, "color_connection", self.color_connection);
        kv_u32(&mut buf, "color_undelete", self.color_undelete);
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
        kv_i32(&mut buf, "window_x", self.window_x);
        kv_i32(&mut buf, "window_y", self.window_y);
        kv_i32(&mut buf, "window_w", self.window_w);
        kv_i32(&mut buf, "window_h", self.window_h);
        kv(&mut buf, "window_maximized", self.window_maximized);
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
        "update_dismissed_tag" => {
            s.update_dismissed_tag = value.to_string();
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
        "install_lcid_seen" => {
            if let Ok(n) = value.parse::<u32>() {
                s.install_lcid_seen = n;
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
        "window_x" => {
            if let Ok(n) = value.parse::<i32>() {
                s.window_x = n;
            }
            return;
        }
        "window_y" => {
            if let Ok(n) = value.parse::<i32>() {
                s.window_y = n;
            }
            return;
        }
        "window_w" => {
            if let Ok(n) = value.parse::<i32>() {
                s.window_w = n;
            }
            return;
        }
        "window_h" => {
            if let Ok(n) = value.parse::<i32>() {
                s.window_h = n;
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
        // Highlighting colors (Fable #31): packed COLORREF u32, stored
        // decimal. Parse permissively — a bad value keeps the default.
        "color_invalid" => {
            if let Ok(n) = value.parse::<u32>() {
                s.color_invalid = n;
            }
            return;
        }
        "color_special" => {
            if let Ok(n) = value.parse::<u32>() {
                s.color_special = n;
            }
            return;
        }
        "color_signed" => {
            if let Ok(n) = value.parse::<u32>() {
                s.color_signed = n;
            }
            return;
        }
        "color_pico" => {
            if let Ok(n) = value.parse::<u32>() {
                s.color_pico = n;
            }
            return;
        }
        "color_system" => {
            if let Ok(n) = value.parse::<u32>() {
                s.color_system = n;
            }
            return;
        }
        "color_connection" => {
            if let Ok(n) = value.parse::<u32>() {
                s.color_connection = n;
            }
            return;
        }
        "color_undelete" => {
            if let Ok(n) = value.parse::<u32>() {
                s.color_undelete = n;
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
        "window_maximized" => s.window_maximized = b,
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
        "filters_active_persisted" => s.filters_active_persisted = b,
        "use_certificates" => s.use_certificates = b,
        "use_hashes" => s.use_hashes = b,
        "use_network_resolution" => s.use_network_resolution = b,
        "auto_allow_microsoft_signed" => s.auto_allow_microsoft_signed = b,
        "highlight_invalid" => s.highlight_invalid = b,
        "highlight_special" => s.highlight_special = b,
        "highlight_signed" => s.highlight_signed = b,
        "highlight_pico" => s.highlight_pico = b,
        "highlight_system" => s.highlight_system = b,
        "highlight_connection" => s.highlight_connection = b,
        "highlight_undelete" => s.highlight_undelete = b,
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
    fn catchall_migration_forces_block_on_for_pre_marker_files() {
        // A file predating the catch-all-action model lacks the
        // `rules_catchall_v2` marker and carries the old inert `false`
        // block toggles. Load must force both on so the upgraded install
        // keeps the default-deny coverage the old always-block catch-all
        // provided (otherwise the catch-all flips to Permit — fail open).
        let dir = std::env::temp_dir().join("amwall-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings_catchall_migrate.txt");
        std::fs::write(&path, "rule_block_outbound=false\nrule_block_inbound=false\n")
            .unwrap();

        let loaded = Settings::load(&path);
        assert!(loaded.rule_block_outbound, "outbound must migrate to true");
        assert!(loaded.rule_block_inbound, "inbound must migrate to true");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn catchall_migration_preserves_explicit_off_when_marked() {
        // Once the marker is present the file is on the new model, so a
        // deliberate `false` (allow-all) is a real user choice and must be
        // preserved rather than re-forced on every load.
        let dir = std::env::temp_dir().join("amwall-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings_catchall_marked.txt");
        std::fs::write(
            &path,
            "rules_catchall_v2=true\nrule_block_outbound=false\nrule_block_inbound=false\n",
        )
        .unwrap();

        let loaded = Settings::load(&path);
        assert!(!loaded.rule_block_outbound, "explicit off must be kept");
        assert!(!loaded.rule_block_inbound, "explicit off must be kept");

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
    fn window_placement_is_unset_by_default() {
        // A fresh install (and any settings file written before this
        // feature existed) must report "no placement" so the window
        // uses the system default position instead of a bogus 0×0 rect.
        let s = Settings::default();
        assert!(!s.has_window_placement());
    }

    #[test]
    fn window_placement_round_trips_including_maximized_and_negative_coords() {
        // Guards the save-window-position feature end to end at the
        // persistence layer: this is the part that runs under `cargo
        // test`, so a regression that stops the geometry from being
        // written or read back fails the gate on every local build.
        // (The Win32 GetWindowPlacement/SetWindowPlacement side needs a
        // live window and is verified by an elevated run, not here.)
        let dir = std::env::temp_dir().join("amwall-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings_window_pos.txt");
        let _ = std::fs::remove_file(&path);

        // Negative left/top models a secondary monitor placed left of the
        // primary — the coords must survive with their sign intact.
        let s = Settings {
            window_x: -1440,
            window_y: -120,
            window_w: 1024,
            window_h: 768,
            window_maximized: true,
            ..Settings::default()
        };
        assert!(s.has_window_placement());

        s.save(&path).expect("save should succeed");
        let loaded = Settings::load(&path);
        assert_eq!(loaded.window_x, -1440);
        assert_eq!(loaded.window_y, -120);
        assert_eq!(loaded.window_w, 1024);
        assert_eq!(loaded.window_h, 768);
        assert!(loaded.window_maximized);
        assert!(loaded.has_window_placement());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn highlight_defaults_match_upstream_and_round_trip() {
        // Defaults: all categories on, upstream LV_COLOR_* colors
        // (main.h:163-169) packed as COLORREF 0x00BBGGRR. The v1.1.17
        // System color was a parity bug (220,232,250); it is now
        // (151,196,251).
        let d = Settings::default();
        assert!(d.highlight_invalid && d.highlight_system && d.highlight_undelete);
        assert_eq!(d.color_system, rgb(151, 196, 251));
        assert_eq!(d.color_invalid, rgb(255, 125, 148));
        assert_eq!(d.color_undelete, rgb(211, 211, 211));

        let dir = std::env::temp_dir().join("amwall-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings_highlight.txt");
        let _ = std::fs::remove_file(&path);
        let s = Settings {
            highlight_signed: false,
            color_signed: rgb(1, 2, 3),
            color_pico: 0x00AABBCC,
            ..Settings::default()
        };
        s.save(&path).expect("save should succeed");
        let loaded = Settings::load(&path);
        assert!(!loaded.highlight_signed);
        assert_eq!(loaded.color_signed, rgb(1, 2, 3));
        assert_eq!(loaded.color_pico, 0x00AABBCC);
        assert_eq!(loaded, s);
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

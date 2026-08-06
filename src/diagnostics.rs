// amwall — self-diagnostics report.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
//! `amwall.exe -diagnostics` — inspect what amwall *actually* resolves,
//! measures and installs on this machine, and print it.
//!
//! Why this exists: the things that break a firewall are invisible from
//! the outside. A per-app permit that silently failed to install looks
//! identical to one that worked; a clipped column header looks like a
//! design choice. Reproducing either on real hardware previously meant
//! clicking through the GUI and guessing. This mode answers the same
//! questions mechanically, in one command, and writes a file that can
//! be attached to a bug report.
//!
//! The report is plain text with stable `key = value` lines under
//! `[section]` headers, so it reads fine in a terminal and greps fine
//! in a script. Nothing here mutates state: no filters are added or
//! removed, no profile is written. The WFP section only *enumerates*,
//! and is skipped entirely when unelevated.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One app entry as diagnostics sees it.
pub struct AppRow {
    /// Exactly what `profile.xml` stores.
    pub stored: String,
    /// What `App::resolved_path` turns that into.
    pub resolved: String,
    /// File / Service / Uwp.
    pub kind: &'static str,
    /// Does the *stored* path reference an environment variable?
    ///
    /// Deliberately "contains `%`" rather than "resolution changed the
    /// string": an unknown variable expands to itself, so the
    /// changed-or-not test would report the one case that matters most
    /// — a variable that does not resolve — as not using variables at
    /// all, and hide it from the verdict.
    pub used_variables: bool,
    /// Does the resolved path name a real file? Meaningless for
    /// Service / UWP entries, which report `None`.
    pub exists: Option<bool>,
    pub is_enabled: bool,
}

impl AppRow {
    /// Would this entry get a per-app WFP permit installed?
    ///
    /// Mirrors the conditions in `install::install_per_app_filters`:
    /// disabled entries are skipped outright, and a File entry whose
    /// path does not name a real file fails
    /// `FwpmGetAppIdFromFileName0` and is counted as skipped.
    pub fn would_install_permit(&self) -> bool {
        self.is_enabled && self.exists.unwrap_or(true)
    }

    /// Did resolution actually rewrite the path?
    pub fn expanded(&self) -> bool {
        self.stored != self.resolved
    }

    /// The issue-#12 failure signature: the stored path references an
    /// environment variable that this machine could not expand, so the
    /// literal `%VAR%` reaches the filesystem and the WFP app-id call.
    ///
    /// Note what this is *not*: an entry that expanded cleanly but
    /// whose file is absent. That is an ordinary uninstalled app and
    /// happens to absolute paths too — it is reported separately and
    /// must never fail the verdict, or every profile with a stale entry
    /// would look broken.
    pub fn has_unexpanded_variable(&self) -> bool {
        self.used_variables && !self.expanded()
    }
}

/// One column's measured header, per tab.
pub struct ColumnRow {
    pub tab: &'static str,
    pub index: usize,
    pub label: String,
    /// Rendered width of the header text at the current DPI, plus the
    /// same icon-sized padding the real sizing pass adds.
    pub header_px: i32,
    /// The fixed width this column is created at.
    pub legacy_px: i32,
}

impl ColumnRow {
    /// Would the header be clipped if the column kept its fixed width?
    /// This is exactly what issue #11 reported in a non-English UI.
    pub fn would_clip(&self) -> bool {
        self.header_px > self.legacy_px
    }
}

/// Everything gathered. Rendering is separate and pure so the layout
/// can be tested without a machine to inspect.
pub struct Report {
    pub version: &'static str,
    pub elevated: bool,
    pub portable: bool,
    pub exe: String,
    pub data_dir: String,
    pub profile_path: String,
    pub profile_status: String,
    pub locale: String,
    pub dpi: u32,
    pub skipuac_registered: bool,
    pub would_offer_elevation: bool,
    pub autosize_columns: bool,
    pub apps: Vec<AppRow>,
    pub columns: Vec<ColumnRow>,
    /// `None` when unelevated (the engine cannot be opened at all).
    pub wfp: Option<WfpState>,
}

pub struct WfpState {
    pub engine_opened: bool,
    pub provider_present: bool,
    pub filter_count: usize,
    pub note: String,
}

// ---- gathering ------------------------------------------------------

/// Collect the report. Read-only with respect to every piece of state
/// amwall owns.
pub fn collect(profile_path: Option<PathBuf>) -> Report {
    let elevated = is_elevated();
    let profile_path = profile_path.unwrap_or_else(crate::paths::profile_path);

    // Resolve the language the same way the GUI does, so the column
    // measurements below reflect the headers this user actually sees.
    let locale = resolve_locale();

    let (apps, profile_status) = collect_apps(&profile_path);
    let dpi = system_dpi();
    let skipuac_registered = crate::skipuac::is_registered();

    Report {
        version: env!("CARGO_PKG_VERSION"),
        elevated,
        portable: crate::paths::is_portable(),
        exe: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".into()),
        data_dir: crate::paths::data_dir().display().to_string(),
        profile_path: profile_path.display().to_string(),
        profile_status,
        locale,
        dpi,
        skipuac_registered,
        would_offer_elevation: crate::gui::should_offer_elevation(
            elevated,
            skipuac_registered,
            false,
        ),
        autosize_columns: crate::gui::settings::Settings::load(&crate::paths::settings_path())
            .autosize_columns,
        apps,
        columns: measure_columns(dpi),
        wfp: if elevated { Some(collect_wfp()) } else { None },
    }
}

fn is_elevated() -> bool {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin() }.as_bool()
}

fn resolve_locale() -> String {
    let settings = crate::gui::settings::Settings::load(&crate::paths::settings_path());
    if !settings.language.is_empty() {
        rust_i18n::set_locale(&settings.language);
        return settings.language;
    }
    match crate::gui::detect_system_locale() {
        Some(d) => {
            rust_i18n::set_locale(&d);
            d
        }
        None => rust_i18n::locale().to_string(),
    }
}

fn collect_apps(profile_path: &Path) -> (Vec<AppRow>, String) {
    use crate::profile::AppKind;
    let bytes = match std::fs::read(profile_path) {
        Ok(b) => b,
        Err(e) => return (Vec::new(), format!("unreadable ({e})")),
    };
    let text = match crate::profile::decode_profile_bytes(&bytes) {
        Ok(t) => t,
        Err(e) => return (Vec::new(), format!("decode failed ({e:?})")),
    };
    let profile = match crate::profile::parse_str(&text) {
        Ok(p) => p,
        Err(e) => return (Vec::new(), format!("parse failed ({e:?})")),
    };
    let rows = profile
        .apps
        .iter()
        .map(|a| {
            let resolved = a.resolved_path();
            let kind = a.kind();
            AppRow {
                stored: a.path.display().to_string(),
                resolved: resolved.display().to_string(),
                kind: match kind {
                    AppKind::File => "file",
                    AppKind::Service => "service",
                    AppKind::Uwp => "uwp",
                },
                used_variables: a.path.to_string_lossy().contains('%'),
                exists: match kind {
                    AppKind::File => Some(resolved.is_file()),
                    _ => None,
                },
                is_enabled: a.is_enabled,
            }
        })
        .collect::<Vec<_>>();
    let status = format!("ok ({} entries)", rows.len());
    (rows, status)
}

/// Measure every tab's localized headers in an off-screen DC using the
/// system message font — the same font the listviews render with — so
/// the numbers match what the sizing pass computes at runtime, without
/// needing a window.
fn measure_columns(dpi: u32) -> Vec<ColumnRow> {
    use crate::gui::ids::{
        IDC_APPS_PROFILE, IDC_LOG, IDC_NETWORK, IDC_RULES_CUSTOM,
    };
    use windows::Win32::Graphics::Gdi::{
        CreateCompatibleDC, CreateFontIndirectW, DeleteDC, DeleteObject, GetTextExtentPoint32W,
        HGDIOBJ, SelectObject,
    };
    use windows::Win32::Foundation::SIZE;
    use windows::Win32::UI::HiDpi::GetSystemMetricsForDpi;
    use windows::Win32::UI::WindowsAndMessaging::{
        NONCLIENTMETRICSW, SM_CXSMICON, SPI_GETNONCLIENTMETRICS,
        SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SystemParametersInfoW,
    };

    let tabs: [(&'static str, i32); 4] = [
        ("apps", IDC_APPS_PROFILE),
        ("rules", IDC_RULES_CUSTOM),
        ("connections", IDC_NETWORK),
        ("log", IDC_LOG),
    ];

    let mut out = Vec::new();
    let hdc = unsafe { CreateCompatibleDC(None) };
    if hdc.is_invalid() {
        return out;
    }

    // System message font (Segoe UI 9pt on Win10/11).
    let mut ncm = NONCLIENTMETRICSW {
        cbSize: std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
        ..Default::default()
    };
    let font = unsafe {
        if SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
            Some(&mut ncm as *mut _ as *mut std::ffi::c_void),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
        .is_ok()
        {
            let f = CreateFontIndirectW(&ncm.lfMessageFont);
            if f.is_invalid() { None } else { Some(f) }
        } else {
            None
        }
    };
    let prev = font.map(|f| unsafe { SelectObject(hdc, HGDIOBJ(f.0)) });

    let spacing = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi) }.max(0);

    for (tab, id) in tabs {
        let Some(defs) = crate::gui::column_sizing::columns_for(id) else {
            continue;
        };
        for (index, def) in defs.iter().enumerate() {
            let label = def.label();
            let wide: Vec<u16> = label.encode_utf16().collect();
            let mut size = SIZE::default();
            if !wide.is_empty() {
                unsafe {
                    let _ = GetTextExtentPoint32W(hdc, &wide, &mut size);
                }
            }
            out.push(ColumnRow {
                tab,
                index,
                label,
                header_px: size.cx + spacing,
                legacy_px: (def.legacy_width as i64 * dpi as i64 / 96) as i32,
            });
        }
    }

    if let Some(prev) = prev {
        unsafe {
            SelectObject(hdc, prev);
        }
    }
    if let Some(f) = font {
        unsafe {
            let _ = DeleteObject(f);
        }
    }
    unsafe {
        let _ = DeleteDC(hdc);
    }
    out
}

/// Read-only look at the kernel. Enumerates amwall's own filters; adds
/// and deletes nothing.
fn collect_wfp() -> WfpState {
    let engine = match crate::wfp::WfpEngine::open() {
        Ok(e) => e,
        Err(e) => {
            return WfpState {
                engine_opened: false,
                provider_present: false,
                filter_count: 0,
                note: format!("FwpmEngineOpen0 failed: {e:?}"),
            };
        }
    };
    match engine.enumerate_filter_ids_for_provider(&crate::install::PROVIDER_KEY) {
        Ok(ids) => WfpState {
            engine_opened: true,
            provider_present: !ids.is_empty(),
            filter_count: ids.len(),
            note: if ids.is_empty() {
                "no amwall filters in the kernel (filters disabled, or not installed)".into()
            } else {
                "enumerated by providerKey".into()
            },
        },
        Err(e) => WfpState {
            engine_opened: true,
            provider_present: false,
            filter_count: 0,
            note: format!("filter enumeration failed: {e:?}"),
        },
    }
}

fn system_dpi() -> u32 {
    use windows::Win32::UI::HiDpi::GetDpiForSystem;
    let d = unsafe { GetDpiForSystem() };
    if d == 0 { 96 } else { d }
}

// ---- rendering (pure) -----------------------------------------------

/// Render the report. Pure — takes a gathered `Report` and returns the
/// text, so the format is unit-testable.
pub fn render(r: &Report) -> String {
    let mut s = String::with_capacity(8 * 1024);

    let _ = writeln!(s, "amwall diagnostics report");
    let _ = writeln!(s, "=========================");
    let _ = writeln!(s);

    let _ = writeln!(s, "[environment]");
    let _ = writeln!(s, "version              = {}", r.version);
    let _ = writeln!(s, "exe                  = {}", r.exe);
    let _ = writeln!(s, "mode                 = {}", if r.portable { "portable" } else { "installed" });
    let _ = writeln!(s, "data_dir             = {}", r.data_dir);
    let _ = writeln!(s, "profile_path         = {}", r.profile_path);
    let _ = writeln!(s, "profile              = {}", r.profile_status);
    let _ = writeln!(s, "locale               = {}", r.locale);
    let _ = writeln!(s, "system_dpi           = {}", r.dpi);
    let _ = writeln!(s);

    let _ = writeln!(s, "[elevation]");
    let _ = writeln!(s, "elevated             = {}", r.elevated);
    let _ = writeln!(s, "skipuac_registered   = {}", r.skipuac_registered);
    let _ = writeln!(s, "would_prompt_on_start= {}", r.would_offer_elevation);
    if !r.elevated {
        let _ = writeln!(
            s,
            "note                 = unelevated: the filtering engine cannot be opened, so \
             filter management, connection events, connect prompts and the packets log are \
             all unavailable"
        );
    }
    let _ = writeln!(s);

    render_apps(&mut s, r);
    render_columns(&mut s, r);
    render_wfp(&mut s, r);
    render_verdict(&mut s, r);
    s
}

fn render_apps(s: &mut String, r: &Report) {
    let files = r.apps.iter().filter(|a| a.kind == "file").count();
    let var = r.apps.iter().filter(|a| a.used_variables).count();
    let missing = r
        .apps
        .iter()
        .filter(|a| a.exists == Some(false))
        .count();
    let permits = r.apps.iter().filter(|a| a.would_install_permit()).count();

    let _ = writeln!(s, "[profile.apps]");
    let _ = writeln!(s, "total                = {}", r.apps.len());
    let _ = writeln!(s, "file_entries         = {files}");
    let _ = writeln!(s, "variable_paths       = {var}");
    let _ = writeln!(s, "unresolvable         = {missing}");
    let _ = writeln!(s, "would_get_permit     = {permits}");
    let _ = writeln!(s);
    if r.apps.is_empty() {
        let _ = writeln!(s, "(no app entries)");
        let _ = writeln!(s);
        return;
    }
    let _ = writeln!(
        s,
        "  {:<7} {:<8} {:<5} {:<7} path",
        "kind", "enabled", "vars", "exists"
    );
    for a in &r.apps {
        let _ = writeln!(
            s,
            "  {:<7} {:<8} {:<5} {:<7} {}",
            a.kind,
            a.is_enabled,
            a.used_variables,
            match a.exists {
                Some(true) => "yes",
                Some(false) => "NO",
                None => "n/a",
            },
            a.stored
        );
        if a.stored != a.resolved {
            let _ = writeln!(s, "        -> resolves to: {}", a.resolved);
        } else if a.used_variables {
            let _ = writeln!(
                s,
                "        -> UNRESOLVED: no such environment variable on this machine"
            );
        }
    }
    let _ = writeln!(s);
}

fn render_columns(s: &mut String, r: &Report) {
    let clipped: Vec<&ColumnRow> = r.columns.iter().filter(|c| c.would_clip()).collect();
    let _ = writeln!(s, "[columns]");
    let _ = writeln!(s, "autosize_columns     = {}", r.autosize_columns);
    let _ = writeln!(s, "measured             = {}", r.columns.len());
    let _ = writeln!(s, "would_clip_at_fixed  = {}", clipped.len());
    let _ = writeln!(s);
    if clipped.is_empty() {
        let _ = writeln!(
            s,
            "  (every localized header fits its fixed creation width in this language)"
        );
    } else {
        let _ = writeln!(
            s,
            "  headers wider than the fixed width they are created at — these are the ones"
        );
        let _ = writeln!(
            s,
            "  that appeared abbreviated before auto-sizing was fixed:"
        );
        for c in clipped {
            let _ = writeln!(
                s,
                "    {:<18} {:<24} needs {}px, created at {}px",
                format!("{}[{}]", c.tab, c.index),
                c.label,
                c.header_px,
                c.legacy_px
            );
        }
    }
    let _ = writeln!(s);
}

fn render_wfp(s: &mut String, r: &Report) {
    let _ = writeln!(s, "[wfp]");
    match &r.wfp {
        None => {
            let _ = writeln!(s, "skipped              = not elevated");
        }
        Some(w) => {
            let _ = writeln!(s, "engine_opened        = {}", w.engine_opened);
            let _ = writeln!(s, "provider_present     = {}", w.provider_present);
            let _ = writeln!(s, "amwall_filter_count  = {}", w.filter_count);
            let _ = writeln!(s, "note                 = {}", w.note);
        }
    }
    let _ = writeln!(s);
}

fn render_verdict(s: &mut String, r: &Report) {
    let _ = writeln!(s, "[verdict]");

    // Issue #12 — environment-variable app paths. The verdict is about
    // *expansion*, not existence: an entry that expands correctly but
    // points at an uninstalled app is normal and is reported below as
    // information, not as a failure.
    let var_apps: Vec<&AppRow> = r.apps.iter().filter(|a| a.used_variables).collect();
    if var_apps.is_empty() {
        let _ = writeln!(
            s,
            "env_var_paths        = N/A   (this profile has no %VAR% app paths to resolve)"
        );
    } else {
        let stuck: Vec<&&AppRow> = var_apps
            .iter()
            .filter(|a| a.has_unexpanded_variable())
            .collect();
        let verdict = if stuck.is_empty() { "PASS" } else { "FAIL" };
        let _ = writeln!(
            s,
            "env_var_paths        = {verdict}  ({} of {} variable-path entries expanded)",
            var_apps.len() - stuck.len(),
            var_apps.len()
        );
        for a in stuck {
            let _ = writeln!(
                s,
                "    did not expand: {}  (no such environment variable here)",
                a.stored
            );
        }
    }

    // Informational: resolved fine, file simply is not there. Applies
    // to plain absolute paths too, so it is never a verdict.
    let missing: Vec<&AppRow> = r
        .apps
        .iter()
        .filter(|a| a.exists == Some(false) && !a.has_unexpanded_variable())
        .collect();
    if !missing.is_empty() {
        let _ = writeln!(
            s,
            "missing_files        = INFO  ({} entr{} resolved but the file is not present — \
             normally an uninstalled app; it gets no permit)",
            missing.len(),
            if missing.len() == 1 { "y" } else { "ies" }
        );
        for a in missing {
            let _ = writeln!(s, "    not on disk: {}", a.resolved);
        }
    }

    // Issue #11 — localized column headers.
    let clipped = r.columns.iter().filter(|c| c.would_clip()).count();
    if r.columns.is_empty() {
        let _ = writeln!(s, "column_headers       = N/A   (measurement unavailable)");
    } else if r.autosize_columns {
        let _ = writeln!(
            s,
            "column_headers       = PASS  (auto-sizing is on; {clipped} header(s) need more than \
             their fixed width and will be widened)"
        );
    } else {
        let verdict = if clipped == 0 { "PASS" } else { "FAIL" };
        let _ = writeln!(
            s,
            "column_headers       = {verdict}  (auto-sizing is OFF and {clipped} header(s) would be clipped)"
        );
    }

    let _ = writeln!(
        s,
        "elevation            = {}",
        if r.elevated {
            "PASS  (running with administrator rights)".to_string()
        } else if r.would_offer_elevation {
            "WARN  (unelevated; startup will offer to restart as administrator)".to_string()
        } else {
            "WARN  (unelevated; Skip-UAC is armed and should have elevated silently)".to_string()
        }
    );
    let _ = writeln!(s);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(stored: &str, resolved: &str, kind: &'static str, exists: Option<bool>, enabled: bool) -> AppRow {
        AppRow {
            stored: stored.into(),
            resolved: resolved.into(),
            kind,
            used_variables: stored.contains('%'),
            exists,
            is_enabled: enabled,
        }
    }

    fn base_report(apps: Vec<AppRow>, columns: Vec<ColumnRow>, autosize: bool) -> Report {
        Report {
            version: "9.9.9",
            elevated: true,
            portable: false,
            exe: r"C:\amwall.exe".into(),
            data_dir: r"C:\data".into(),
            profile_path: r"C:\data\profile.xml".into(),
            profile_status: "ok".into(),
            locale: "en".into(),
            dpi: 96,
            skipuac_registered: false,
            would_offer_elevation: false,
            autosize_columns: autosize,
            apps,
            columns,
            wfp: None,
        }
    }

    #[test]
    fn a_resolved_variable_path_counts_as_expanded() {
        let a = app(
            r"%ProgramFiles%\App\app.exe",
            r"C:\Program Files\App\app.exe",
            "file",
            Some(true),
            true,
        );
        assert!(a.used_variables);
        assert!(a.expanded());
        assert!(!a.has_unexpanded_variable());
        assert!(a.would_install_permit());
    }

    #[test]
    fn an_unexpandable_variable_path_would_lose_its_permit() {
        // The pre-fix state, and what the report must shout about.
        let a = app(r"%NOPE%\app.exe", r"%NOPE%\app.exe", "file", Some(false), true);
        assert!(!a.would_install_permit());
        assert!(a.has_unexpanded_variable());
    }

    #[test]
    fn an_expanded_but_absent_file_is_not_an_env_var_failure() {
        // An uninstalled app. It legitimately gets no permit, but it is
        // NOT the issue-#12 bug and must not fail the verdict — every
        // profile accumulates stale entries.
        let a = app(
            r"%ProgramFiles%\Gone\gone.exe",
            r"C:\Program Files\Gone\gone.exe",
            "file",
            Some(false),
            true,
        );
        assert!(a.expanded());
        assert!(!a.has_unexpanded_variable());
        assert!(!a.would_install_permit());
    }

    #[test]
    fn an_unresolvable_variable_still_counts_as_a_variable_path() {
        // An unknown variable expands to itself, so a "did the string
        // change" test would classify the single most important
        // failure case as having no variables at all and drop it from
        // the verdict entirely.
        let a = app(r"%NOPE%\app.exe", r"%NOPE%\app.exe", "file", Some(false), true);
        assert!(
            a.used_variables,
            "an unresolved %VAR% path must still be counted as one"
        );
    }

    #[test]
    fn a_disabled_app_never_gets_a_permit() {
        let a = app(r"C:\a.exe", r"C:\a.exe", "file", Some(true), false);
        assert!(!a.would_install_permit());
    }

    #[test]
    fn service_and_uwp_entries_are_not_judged_on_file_existence() {
        let svc = app("Dnscache", "Dnscache", "service", None, true);
        assert!(svc.would_install_permit(), "a service has no file to find");
    }

    #[test]
    fn a_header_wider_than_its_fixed_width_is_reported_as_clipping() {
        let c = ColumnRow {
            tab: "rules",
            index: 2,
            label: "Richtung".into(),
            header_px: 96,
            legacy_px: 80,
        };
        assert!(c.would_clip());
    }

    #[test]
    fn a_header_that_fits_is_not_reported() {
        let c = ColumnRow {
            tab: "rules",
            index: 2,
            label: "Dir".into(),
            header_px: 40,
            legacy_px: 80,
        };
        assert!(!c.would_clip());
    }

    #[test]
    fn verdict_passes_when_every_variable_path_resolves() {
        let r = base_report(
            vec![app(r"%A%\x.exe", r"C:\x.exe", "file", Some(true), true)],
            vec![],
            true,
        );
        let out = render(&r);
        assert!(out.contains("env_var_paths        = PASS"), "{out}");
    }

    #[test]
    fn verdict_fails_and_names_the_entry_when_a_variable_does_not_expand() {
        let r = base_report(
            vec![
                app(r"%A%\x.exe", r"C:\x.exe", "file", Some(true), true),
                app(r"%B%\y.exe", r"%B%\y.exe", "file", Some(false), true),
            ],
            vec![],
            true,
        );
        let out = render(&r);
        assert!(out.contains("env_var_paths        = FAIL"), "{out}");
        assert!(out.contains(r"did not expand: %B%\y.exe"), "{out}");
    }

    #[test]
    fn an_uninstalled_app_does_not_fail_the_env_var_verdict() {
        // Expanded correctly, file gone. The verdict is about
        // expansion; the absence is reported as INFO.
        let r = base_report(
            vec![app(
                r"%A%\gone.exe",
                r"C:\gone.exe",
                "file",
                Some(false),
                true,
            )],
            vec![],
            true,
        );
        let out = render(&r);
        assert!(out.contains("env_var_paths        = PASS"), "{out}");
        assert!(out.contains("missing_files        = INFO"), "{out}");
        assert!(out.contains(r"not on disk: C:\gone.exe"), "{out}");
    }

    #[test]
    fn verdict_is_not_applicable_without_variable_paths() {
        let r = base_report(
            vec![app(r"C:\x.exe", r"C:\x.exe", "file", Some(true), true)],
            vec![],
            true,
        );
        assert!(render(&r).contains("env_var_paths        = N/A"));
    }

    #[test]
    fn clipped_headers_fail_the_verdict_only_when_autosize_is_off() {
        let clipping = || ColumnRow {
            tab: "rules",
            index: 2,
            label: "Richtung".into(),
            header_px: 96,
            legacy_px: 80,
        };
        let off = base_report(vec![], vec![clipping()], false);
        assert!(render(&off).contains("column_headers       = FAIL"));

        // With auto-sizing on, a wide header is fine — it gets widened.
        let on = base_report(vec![], vec![clipping()], true);
        assert!(render(&on).contains("column_headers       = PASS"));
    }

    #[test]
    fn report_records_when_wfp_was_skipped_for_lack_of_rights() {
        let mut r = base_report(vec![], vec![], true);
        r.elevated = false;
        r.would_offer_elevation = true;
        let out = render(&r);
        assert!(out.contains("skipped              = not elevated"), "{out}");
        assert!(out.contains("elevation            = WARN"), "{out}");
    }

    #[test]
    fn every_section_is_present() {
        let out = render(&base_report(vec![], vec![], true));
        for section in [
            "[environment]",
            "[elevation]",
            "[profile.apps]",
            "[columns]",
            "[wfp]",
            "[verdict]",
        ] {
            assert!(out.contains(section), "missing {section} in:\n{out}");
        }
    }
}

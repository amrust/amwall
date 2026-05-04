// amwall — right-click context menu for the Apps / Services / UWP tabs.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Posted from `WM_NOTIFY → NM_RCLICK` over any of slots 0..=2's
// listviews. Builds a popup with Allow / Block / Remove / Explore /
// Copy, dispatches the chosen command back through normal
// WM_COMMAND routing (via `TPM_RETURNCMD` so the menu's commands
// don't leak into background event handling).
//
// Why a per-item context object on `WndState`:
//
//   - The menu's command IDs are static (IDM_ALLOW etc.); we can't
//     bake "which row in which listview" into them. Storing the
//     resolved target on `WndState.context_target` lets the
//     handlers (`on_allow` / `on_block` / `on_remove` / `on_explore`)
//     read back what was right-clicked without re-walking the
//     listview.
//   - Lifetime is just one menu invocation: set on right-click,
//     consumed by the WM_COMMAND that the menu posts, cleared
//     after.

#![cfg(windows)]

use std::path::PathBuf;

use windows::Win32::Foundation::{HWND, POINT};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, MF_CHECKED, MF_GRAYED, MF_SEPARATOR,
    MF_STRING, MF_UNCHECKED, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
};
use windows::core::PCWSTR;

use super::ids::{
    IDC_APPS_PROFILE, IDC_APPS_SERVICE, IDC_APPS_UWP, IDM_ALLOW, IDM_BLOCK, IDM_COPY, IDM_EXPLORE,
    IDM_PROPERTIES, IDM_REMOVE_FROM_PROFILE,
};
use super::wide;

/// What the user right-clicked on. Captured at popup time and
/// stashed on `WndState.context_target` so the WM_COMMAND handler
/// (which has no access to the original NM_RCLICK lparam) can read
/// it back.
#[derive(Debug, Clone)]
pub struct ContextTarget {
    /// The listview the right-click came from
    /// (`IDC_APPS_PROFILE` / `IDC_APPS_SERVICE` / `IDC_APPS_UWP`).
    pub listview_id: i32,
    /// 0-based row index in the listview at the time of right-click.
    /// Used by handlers that need to repaint (LVM_UPDATE) or scroll
    /// (LVM_ENSUREVISIBLE) the affected row.
    pub row: i32,
    /// Display name shown in column 0 — what `Copy` puts on the
    /// clipboard.
    pub display_name: String,
    /// Resolved binary path the rule should attach to. Empty for
    /// UWP entries (which need package-family-name encoding the
    /// current `App` struct doesn't model — see M5.4c follow-up).
    pub binary_path: PathBuf,
    /// Whether an `App` entry already exists in the profile for
    /// this `binary_path`. Drives Allow / Block check marks and
    /// the visibility of `Remove from profile`.
    pub in_profile: bool,
    /// If `in_profile`, the current `is_enabled` flag; ignored
    /// otherwise. Drives which of Allow / Block carries the check.
    pub current_is_enabled: bool,
}

/// Show the context menu at the cursor and return the selected
/// command ID (or `None` if the user dismissed without picking).
/// The caller is responsible for dispatching the command via
/// SendMessage(WM_COMMAND) — keeping the dispatch in `main_window`'s
/// existing WM_COMMAND handler avoids a second routing path.
pub fn show(hwnd: HWND, target: &ContextTarget) -> Option<u16> {
    let menu = unsafe { CreatePopupMenu() }.ok()?;

    let is_uwp = target.listview_id == IDC_APPS_UWP;

    // Properties — opens the rule editor for this app. Default item
    // (bolded). Only meaningful for entries that have or could have
    // an App backing them; for UWP we'd need the package-family-
    // name path, so gray it out for now.
    append_string(menu, IDM_PROPERTIES, "Properties\tEnter", target.in_profile && !is_uwp);

    append_separator(menu);

    // Allow / Block toggle. Check marks reflect the current is_enabled
    // state when the entry is already in the profile. UWP gets
    // grayed out — no path-only identifier model yet.
    let (allow_check, block_check) = match (target.in_profile, target.current_is_enabled) {
        (true, true) => (MF_CHECKED.0, MF_UNCHECKED.0),
        (true, false) => (MF_UNCHECKED.0, MF_CHECKED.0),
        _ => (MF_UNCHECKED.0, MF_UNCHECKED.0),
    };
    append_string_with_state(menu, IDM_ALLOW, "Allow", MF_STRING.0 | allow_check, !is_uwp);
    append_string_with_state(menu, IDM_BLOCK, "Block", MF_STRING.0 | block_check, !is_uwp);

    if target.in_profile {
        append_separator(menu);
        append_string(menu, IDM_REMOVE_FROM_PROFILE, "Remove from profile\tDel", true);
    }

    append_separator(menu);

    // Explore — open the binary's containing folder in Explorer.
    // Disabled when no path is known (UWP without a discovered
    // entry point, or a service that QueryServiceConfig couldn't
    // resolve).
    let can_explore = !target.binary_path.as_os_str().is_empty();
    append_string(menu, IDM_EXPLORE, "Explore (open folder)\tCtrl+E", can_explore);

    append_string(menu, IDM_COPY, "Copy name\tCtrl+C", true);

    let mut pt = POINT::default();
    unsafe {
        let _ = GetCursorPos(&mut pt);
    }

    // TPM_RETURNCMD makes TrackPopupMenu return the chosen command
    // synchronously instead of posting WM_COMMAND. Cleaner here:
    // the caller decides where to route, and we don't need the
    // menu's commands to interleave with regular event processing.
    let cmd = unsafe {
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_RETURNCMD,
            pt.x,
            pt.y,
            0,
            hwnd,
            None,
        )
    };

    unsafe {
        let _ = DestroyMenu(menu);
    }

    if cmd.0 == 0 { None } else { Some(cmd.0 as u16) }
}

fn append_string(
    menu: windows::Win32::UI::WindowsAndMessaging::HMENU,
    id: u16,
    text: &str,
    enabled: bool,
) {
    let flags = if enabled {
        MF_STRING.0
    } else {
        MF_STRING.0 | MF_GRAYED.0
    };
    let mut wbuf = wide(text);
    unsafe {
        let _ = AppendMenuW(
            menu,
            windows::Win32::UI::WindowsAndMessaging::MENU_ITEM_FLAGS(flags),
            id as usize,
            PCWSTR(wbuf.as_mut_ptr()),
        );
    }
}

fn append_string_with_state(
    menu: windows::Win32::UI::WindowsAndMessaging::HMENU,
    id: u16,
    text: &str,
    flags: u32,
    enabled: bool,
) {
    let final_flags = if enabled { flags } else { flags | MF_GRAYED.0 };
    let mut wbuf = wide(text);
    unsafe {
        let _ = AppendMenuW(
            menu,
            windows::Win32::UI::WindowsAndMessaging::MENU_ITEM_FLAGS(final_flags),
            id as usize,
            PCWSTR(wbuf.as_mut_ptr()),
        );
    }
}

fn append_separator(menu: windows::Win32::UI::WindowsAndMessaging::HMENU) {
    unsafe {
        let _ = AppendMenuW(
            menu,
            MF_SEPARATOR,
            0,
            PCWSTR::null(),
        );
    }
}

/// Resolve the user's right-clicked row into a `ContextTarget`.
///
/// `row` is the listview row index (kept on the target so handlers
/// that need to repaint that specific row have it); `source_idx`
/// is the original index in the underlying source slice
/// (`profile.apps` / `services` / `uwp_packages`) that the
/// populator stamped into `LVITEMW.lParam`. The two parted ways
/// when the M9.4 AppKind filter started skipping rows during
/// populate; `lParam` is the only reliable way to round-trip
/// row → source.
pub fn target_from_source(
    listview_id: i32,
    row: i32,
    source_idx: usize,
    profile: &crate::profile::Profile,
    services: &[super::services_enum::ServiceEntry],
    uwp_packages: &[super::uwp_enum::PackageEntry],
) -> Option<ContextTarget> {
    if row < 0 {
        return None;
    }
    match listview_id {
        IDC_APPS_PROFILE => {
            let app = profile.apps.get(source_idx)?;
            Some(ContextTarget {
                listview_id,
                row,
                display_name: app
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| app.path.display().to_string()),
                binary_path: app.path.clone(),
                in_profile: true,
                current_is_enabled: app.is_enabled,
            })
        }
        IDC_APPS_SERVICE => {
            let svc = services.get(source_idx)?;
            let display = if svc.display_name.is_empty() {
                svc.service_name.clone()
            } else {
                svc.display_name.clone()
            };
            // Identifier is the service short name (e.g.
            // "Dnscache"), not its image path. Upstream simplewall
            // stores service rows the same way (profile.c:441 —
            // anything without a path separator and without the
            // "S-1-" SID prefix is classified DATA_APP_SERVICE).
            // The install path then derives a service-specific SID
            // from the name (`NT SERVICE\<name>`) and emits a
            // FWPM_CONDITION_ALE_USER_ID filter, which is what
            // distinguishes svchost-hosted services from each
            // other.
            let svc_path = std::path::PathBuf::from(&svc.service_name);
            let existing = profile.apps.iter().find(|a| a.path == svc_path);
            Some(ContextTarget {
                listview_id,
                row,
                display_name: display,
                binary_path: svc_path,
                in_profile: existing.is_some(),
                current_is_enabled: existing.map(|a| a.is_enabled).unwrap_or(false),
            })
        }
        IDC_APPS_UWP => {
            let pkg = uwp_packages.get(source_idx)?;
            // UWP rows identify by package SID — the textual
            // `S-1-15-2-…` form upstream simplewall stores in
            // profile.xml's `<item path="…" />`. Routing the SID
            // through `binary_path` (which is path-shaped only by
            // type — `App::kind_for` reclassifies on the SID
            // prefix) lets the right-click handlers reuse the
            // same upsert path as File and Service rows.
            //
            // If `package_sid` is None (registry hive partially
            // corrupt or no PackageSid value) the row degrades
            // gracefully: display still works, but Allow/Block
            // can't add it to the profile because there's
            // nothing to install a filter against.
            let sid = match &pkg.package_sid {
                Some(s) => std::path::PathBuf::from(s),
                None => std::path::PathBuf::new(),
            };
            let existing = profile.apps.iter().find(|a| a.path == sid);
            Some(ContextTarget {
                listview_id,
                row,
                display_name: pkg.display_name.clone(),
                binary_path: sid,
                in_profile: existing.is_some(),
                current_is_enabled: existing.map(|a| a.is_enabled).unwrap_or(false),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{App, Profile, ProfileKind};

    fn fixture_profile(apps: Vec<App>) -> Profile {
        Profile {
            timestamp: 0,
            kind: ProfileKind::User,
            version: 5,
            apps,
            rule_configs: Vec::new(),
            system_rules: Vec::new(),
            custom_rules: Vec::new(),
            blocklist_rules: Vec::new(),
        }
    }

    fn sample_app(path: &str, is_enabled: bool) -> App {
        App {
            path: PathBuf::from(path),
            is_enabled,
            is_silent: false,
            is_undeletable: false,
            timestamp: 0,
            timer: 0,
            hash: None,
            comment: None,
        }
    }

    #[test]
    fn profile_row_yields_in_profile_target() {
        let profile = fixture_profile(vec![sample_app(r"C:\foo.exe", true)]);
        let tgt = target_from_source(IDC_APPS_PROFILE, 0, 0, &profile, &[], &[]).unwrap();
        assert_eq!(tgt.binary_path, PathBuf::from(r"C:\foo.exe"));
        assert!(tgt.in_profile);
        assert!(tgt.current_is_enabled);
        assert_eq!(tgt.display_name, "foo.exe");
    }

    #[test]
    fn service_row_routes_through_short_name_not_image_path() {
        // Two services sharing svchost.exe: only the matching
        // service-NAME entry should mark in_profile=true. This
        // is the parity behaviour upstream gets via the
        // service-SID security descriptor — multiple svchost
        // services don't collide.
        let svc = super::super::services_enum::ServiceEntry {
            service_name: "Audiosrv".into(),
            display_name: "Windows Audio".into(),
            image_path: PathBuf::from(r"C:\Windows\system32\svchost.exe"),
        };
        let profile = fixture_profile(vec![
            // An old svchost-as-path entry — should NOT match.
            sample_app(r"C:\Windows\system32\svchost.exe", false),
            // The new service-name-as-path entry — should match.
            sample_app("Audiosrv", true),
        ]);
        let tgt =
            target_from_source(IDC_APPS_SERVICE, 0, 0, &profile, std::slice::from_ref(&svc), &[])
                .unwrap();
        assert_eq!(tgt.binary_path, PathBuf::from("Audiosrv"));
        assert!(tgt.in_profile);
        assert!(tgt.current_is_enabled, "matched the service-name entry, not svchost");
        assert_eq!(tgt.display_name, "Windows Audio");
    }

    #[test]
    fn service_with_no_matching_profile_app() {
        let svc = super::super::services_enum::ServiceEntry {
            service_name: "Foo".into(),
            display_name: "Foo Service".into(),
            image_path: PathBuf::from(r"C:\foo\foo.exe"),
        };
        let profile = fixture_profile(Vec::new());
        let tgt =
            target_from_source(IDC_APPS_SERVICE, 0, 0, &profile, std::slice::from_ref(&svc), &[])
                .unwrap();
        assert!(!tgt.in_profile);
    }

    #[test]
    fn uwp_row_with_sid_routes_through_binary_path() {
        let sid = "S-1-15-2-3110756066-2507771734-389907848-353554127-1230786711-3973453966-120447785";
        let pkg = super::super::uwp_enum::PackageEntry {
            display_name: "Calculator".into(),
            package_full_name: "Microsoft.WindowsCalculator_11.x_x64__abc".into(),
            install_path: PathBuf::from(r"C:\Program Files\WindowsApps\foo"),
            package_sid: Some(sid.to_string()),
        };
        let profile = fixture_profile(Vec::new());
        let tgt =
            target_from_source(IDC_APPS_UWP, 0, 0, &profile, &[], std::slice::from_ref(&pkg))
                .unwrap();
        assert!(!tgt.in_profile);
        assert_eq!(tgt.binary_path, PathBuf::from(sid));
        assert_eq!(tgt.display_name, "Calculator");
    }

    #[test]
    fn uwp_row_without_sid_degrades_to_empty_path() {
        let pkg = super::super::uwp_enum::PackageEntry {
            display_name: "BrokenHive".into(),
            package_full_name: "Some.Broken.Package_x_y__z".into(),
            install_path: PathBuf::new(),
            package_sid: None,
        };
        let profile = fixture_profile(Vec::new());
        let tgt =
            target_from_source(IDC_APPS_UWP, 0, 0, &profile, &[], std::slice::from_ref(&pkg))
                .unwrap();
        assert!(!tgt.in_profile);
        assert!(tgt.binary_path.as_os_str().is_empty());
    }

    #[test]
    fn out_of_range_row_yields_none() {
        let profile = fixture_profile(Vec::new());
        assert!(target_from_source(IDC_APPS_PROFILE, 0, 0, &profile, &[], &[]).is_none());
        assert!(target_from_source(IDC_APPS_PROFILE, -1, 0, &profile, &[], &[]).is_none());
    }

    #[test]
    fn source_idx_decoupled_from_row() {
        // Same listview row (e.g. row 0) can resolve to a
        // different App when the populator filtered earlier
        // entries — that's exactly the bug the lParam round-
        // trip fixes. Two-app profile, source_idx=1 must
        // return the second App regardless of `row`.
        let profile = fixture_profile(vec![
            sample_app(r"C:\first.exe", true),
            sample_app(r"C:\second.exe", false),
        ]);
        let tgt = target_from_source(IDC_APPS_PROFILE, 0, 1, &profile, &[], &[]).unwrap();
        assert_eq!(tgt.binary_path, PathBuf::from(r"C:\second.exe"));
        assert!(!tgt.current_is_enabled);
    }

    #[test]
    fn unknown_listview_id_yields_none() {
        let profile = fixture_profile(Vec::new());
        assert!(target_from_source(99999, 0, 0, &profile, &[], &[]).is_none());
    }
}

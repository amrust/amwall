// amwall — listview group helpers (M5.4d).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Wraps the LVM_ENABLEGROUPVIEW / LVM_INSERTGROUP / LVM_SETGROUPINFO
// surface so the populators can attach grouped headers to apps and
// rules listviews without touching the comctl `LVGROUP` struct
// directly. Group IDs are stable u32-friendly integers — when
// inserting items, populators set `LVITEMW.iGroupId` to one of the
// constants below to file the row under the right header.
//
// What the user sees: each header reads "<Title> (group_count/total)"
// with a collapsible chevron, matching upstream simplewall's
// presentation. Refreshing the per-header counts after a populate
// uses LVM_SETGROUPINFO with LVGF_HEADER so existing rows don't
// have to be re-inserted.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    LIST_VIEW_GROUP_STATE_FLAGS, LVGF_GROUPID, LVGF_HEADER, LVGF_STATE, LVGROUP,
    LVGS_COLLAPSIBLE, LVM_ENABLEGROUPVIEW, LVM_INSERTGROUP, LVM_SETGROUPINFO,
};
use windows::Win32::UI::WindowsAndMessaging::SendMessageW;
use windows::core::PWSTR;

use crate::profile::{App, Rule};

// ---- Group IDs ----
//
// Apps tabs (slots 0..=2) — modelled after upstream's
// IDS_GROUP_ALLOWED / TIMER / SPECIAL / BLOCKED / BLOCKED (silent).
// `Special` is a placeholder for now (amwall doesn't yet flag
// system-managed apps); items never resolve to it but we reserve
// the id so the visual layout matches upstream.
pub const GROUP_APP_ALLOWED: i32 = 0;
pub const GROUP_APP_TIMER: i32 = 1;
pub const GROUP_APP_SPECIAL: i32 = 2;
pub const GROUP_APP_BLOCKED: i32 = 3;
pub const GROUP_APP_BLOCKED_SILENT: i32 = 4;

// Rules tabs (slots 3..=5).
pub const GROUP_RULE_ENABLED: i32 = 0;
pub const GROUP_RULE_DISABLED: i32 = 1;

/// Where an `App` belongs in the apps-tab group layout. amwall's
/// default-deny posture means "no rule" maps to BLOCKED at the
/// caller's discretion — this helper only inspects the App's own
/// flags.
pub fn app_group_id(app: &App) -> i32 {
    if app.timer > 0 {
        return GROUP_APP_TIMER;
    }
    if app.is_enabled {
        return GROUP_APP_ALLOWED;
    }
    if app.is_silent {
        return GROUP_APP_BLOCKED_SILENT;
    }
    GROUP_APP_BLOCKED
}

/// Where a `Rule` belongs in the rules-tab group layout.
pub fn rule_group_id(rule: &Rule) -> i32 {
    if rule.is_enabled {
        GROUP_RULE_ENABLED
    } else {
        GROUP_RULE_DISABLED
    }
}

/// Turn group view on for the given listview. Idempotent — safe to
/// call multiple times.
pub fn enable(lv: HWND) {
    unsafe {
        SendMessageW(lv, LVM_ENABLEGROUPVIEW, WPARAM(1), LPARAM(0));
    }
}

/// Insert a single group header. `wide_header` must outlive the
/// call; comctl copies the string out before returning. Returns
/// the inserted group's index, or `-1` on failure.
pub fn insert(lv: HWND, group_id: i32, wide_header: &mut [u16]) -> i32 {
    let mut group = LVGROUP {
        cbSize: std::mem::size_of::<LVGROUP>() as u32,
        // LVGF_STATE is required for `state` to be applied — without
        // it, the LVGS_COLLAPSIBLE bit is ignored and the chevron
        // never appears (caught on first M5.4d test run).
        mask: LVGF_HEADER | LVGF_GROUPID | LVGF_STATE,
        pszHeader: PWSTR(wide_header.as_mut_ptr()),
        iGroupId: group_id,
        // Upstream marks every group LVGS_COLLAPSIBLE so the user
        // can hide buckets they don't care about (e.g. collapsing
        // Blocked when reviewing only Allowed).
        state: LVGS_COLLAPSIBLE,
        stateMask: LVGS_COLLAPSIBLE,
        ..Default::default()
    };
    let res = unsafe {
        SendMessageW(
            lv,
            LVM_INSERTGROUP,
            WPARAM(usize::MAX),
            LPARAM(&mut group as *mut LVGROUP as isize),
        )
    };
    res.0 as i32
}

/// Replace a group header's text without disturbing its items.
/// Used to re-render counts after a populate without re-inserting.
pub fn set_header(lv: HWND, group_id: i32, wide_header: &mut [u16]) {
    let mut group = LVGROUP {
        cbSize: std::mem::size_of::<LVGROUP>() as u32,
        mask: LVGF_HEADER,
        pszHeader: PWSTR(wide_header.as_mut_ptr()),
        // SETGROUPINFO addresses the group by its id (passed in
        // wparam), not by header lookup.
        iGroupId: group_id,
        state: LIST_VIEW_GROUP_STATE_FLAGS::default(),
        stateMask: LIST_VIEW_GROUP_STATE_FLAGS::default(),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_SETGROUPINFO,
            WPARAM(group_id as usize),
            LPARAM(&mut group as *mut LVGROUP as isize),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Action, Direction};
    use std::path::PathBuf;

    fn sample_app(is_enabled: bool, is_silent: bool, timer: i64) -> App {
        App {
            path: PathBuf::from(r"C:\foo.exe"),
            is_enabled,
            is_silent,
            is_undeletable: false,
            timestamp: 0,
            timer,
            hash: None,
            comment: None,
        }
    }

    fn sample_rule(is_enabled: bool) -> Rule {
        Rule {
            name: "test".into(),
            remote: None,
            local: None,
            direction: Direction::Outbound,
            action: Action::Block,
            protocol: None,
            address_family: None,
            apps: None,
            is_services: false,
            is_enabled,
            os_version: None,
            comment: None,
        }
    }

    #[test]
    fn timer_takes_priority_over_enabled() {
        let app = sample_app(true, false, 1700000000);
        assert_eq!(app_group_id(&app), GROUP_APP_TIMER);
    }

    #[test]
    fn enabled_no_timer_is_allowed() {
        let app = sample_app(true, false, 0);
        assert_eq!(app_group_id(&app), GROUP_APP_ALLOWED);
    }

    #[test]
    fn disabled_silent_is_blocked_silent() {
        let app = sample_app(false, true, 0);
        assert_eq!(app_group_id(&app), GROUP_APP_BLOCKED_SILENT);
    }

    #[test]
    fn disabled_loud_is_blocked() {
        let app = sample_app(false, false, 0);
        assert_eq!(app_group_id(&app), GROUP_APP_BLOCKED);
    }

    #[test]
    fn rule_enabled_disabled_split() {
        assert_eq!(rule_group_id(&sample_rule(true)), GROUP_RULE_ENABLED);
        assert_eq!(rule_group_id(&sample_rule(false)), GROUP_RULE_DISABLED);
    }
}

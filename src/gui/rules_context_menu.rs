// amwall — right-click context menu for the Rules tabs (Fable #27).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Posted from `WM_NOTIFY → NM_RCLICK` over the Blocklist / System /
// Custom rules listviews. Mirrors upstream simplewall's rules-tab menu
// (messages.c:622-675): Add (Custom only) / Edit (bold default) /
// Delete (Custom only, grayed on read-only) / Check / Uncheck / Select
// all / Copy / Copy-value. The chosen command is returned via
// TPM_RETURNCMD and dispatched by `main_window::on_rules_context_menu`
// through a dedicated, tab-aware match — NOT through on_command, so the
// shared ids (IDM_COPY / IDM_PROPERTIES / IDM_DELETE) act on the Rules
// tab rather than the Apps handlers.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, POINT};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, HMENU, MENU_ITEM_FLAGS, MF_GRAYED,
    MF_SEPARATOR, MF_STRING, SetMenuDefaultItem, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
};
use windows::core::PCWSTR;

use rust_i18n::t;

use super::ids::{
    IDM_CHECK, IDM_COPY, IDM_COPY_VALUE, IDM_DELETE, IDM_OPENRULESEDITOR, IDM_PROPERTIES,
    IDM_SELECT_ALL, IDM_UNCHECK,
};
use super::wide;

/// What the user right-clicked on the Rules tab. Built by
/// `on_rules_context_menu` from the clicked row.
pub struct RulesContextTarget {
    pub listview_id: i32,
    pub row: i32,
    /// Clicked column index (for "Copy value").
    pub column: i32,
    /// Whether this is the Custom (user) rules tab — gates Add / Delete.
    pub is_custom: bool,
    /// Whether the clicked rule can be edited/deleted — true only for a
    /// user-added Custom rule (preset/system/blocklist rows are
    /// read-only). Gates Delete and, for now, Edit (amwall's editor
    /// can't open built-in rules — an honest interim vs upstream, which
    /// opens a read-only editor for those).
    pub is_deletable: bool,
    /// Clicked cell text — the "Copy value" label; None/empty hides it.
    pub column_text: Option<String>,
}

fn append_string(menu: HMENU, id: u16, text: &str, enabled: bool) {
    let flags = if enabled {
        MF_STRING.0
    } else {
        MF_STRING.0 | MF_GRAYED.0
    };
    let w = wide(text);
    unsafe {
        let _ = AppendMenuW(menu, MENU_ITEM_FLAGS(flags), id as usize, PCWSTR(w.as_ptr()));
    }
}

fn append_sep(menu: HMENU) {
    unsafe {
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    }
}

/// Build + show the Rules context menu; return the chosen command id.
pub fn show(hwnd: HWND, target: &RulesContextTarget) -> Option<u16> {
    let menu = unsafe { CreatePopupMenu() }.ok()?;

    if target.is_custom {
        append_string(menu, IDM_OPENRULESEDITOR, &t!("context.add"), true);
    }
    // Edit is the default (bold) action; enabled only for editable rows.
    let edit_enabled = target.is_deletable;
    append_string(menu, IDM_PROPERTIES, &t!("context.edit"), edit_enabled);
    if target.is_custom {
        append_string(menu, IDM_DELETE, &t!("context.delete"), target.is_deletable);
    }

    append_sep(menu);
    append_string(menu, IDM_CHECK, &t!("context.check"), true);
    append_string(menu, IDM_UNCHECK, &t!("context.uncheck"), true);

    append_sep(menu);
    append_string(menu, IDM_SELECT_ALL, &t!("context.select_all"), true);

    append_sep(menu);
    append_string(menu, IDM_COPY, &t!("context.copy_row"), true);
    if let Some(val) = target.column_text.as_deref() {
        if !val.is_empty() {
            let label = t!("context.copy_value", value = val);
            append_string(menu, IDM_COPY_VALUE, &label, true);
        }
    }

    if edit_enabled {
        unsafe {
            let _ = SetMenuDefaultItem(menu, IDM_PROPERTIES as u32, 0);
        }
    }

    let mut pt = POINT::default();
    unsafe {
        let _ = GetCursorPos(&mut pt);
    }
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

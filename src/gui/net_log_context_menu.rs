// amwall — right-click context menus for the Network + Log tabs (Fable #27).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Posted from `WM_NOTIFY → NM_RCLICK` over the Connections (IDC_NETWORK)
// and Packets-log (IDC_LOG) listviews. Mirrors upstream simplewall's
// per-listview menus (messages.c:677-784). The chosen command is
// returned via TPM_RETURNCMD and dispatched by the main-window handler
// through a dedicated tab-aware match, so the shared ids act on the
// Network / Log tab rather than the Apps handlers.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, POINT};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, HMENU, MENU_ITEM_FLAGS, MF_GRAYED,
    MF_SEPARATOR, MF_STRING, SetMenuDefaultItem, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
};
use windows::core::PCWSTR;

use rust_i18n::t;

use super::ids::{
    IDM_CLOSE_CONNECTION, IDM_COPY, IDM_COPY_VALUE, IDM_EXPLORE, IDM_OPENRULESEDITOR,
    IDM_SELECT_ALL, IDM_SHOW_IN_LIST, IDM_TRAY_LOGCLEAR,
};
use super::wide;

/// Right-clicked Network-tab row context (Fable #27).
pub struct NetContextTarget {
    /// Whether the owning process's image path resolved — gates
    /// Show-in-list / Explore / Create-rule.
    pub has_path: bool,
    /// Whether the connection can be torn down (IPv4 established TCP).
    pub is_closable: bool,
    pub column: i32,
    pub column_text: Option<String>,
}

/// Right-clicked Log-tab row context (Fable #27).
pub struct LogContextTarget {
    pub has_path: bool,
    pub column: i32,
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

fn append_copy_value(menu: HMENU, column_text: &Option<String>) {
    if let Some(val) = column_text.as_deref() {
        if !val.is_empty() {
            let label = t!("context.copy_value", value = val);
            append_string(menu, IDM_COPY_VALUE, &label, true);
        }
    }
}

fn track(menu: HMENU, hwnd: HWND) -> Option<u16> {
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

/// Network menu: Show-in-list (default) / Create-rule / Explore /
/// Close-connection / Select-all / Copy / Copy-value.
pub fn show_network(hwnd: HWND, target: &NetContextTarget) -> Option<u16> {
    let menu = unsafe { CreatePopupMenu() }.ok()?;
    append_string(menu, IDM_SHOW_IN_LIST, &t!("context.show_in_list"), target.has_path);
    append_string(menu, IDM_OPENRULESEDITOR, &t!("context.create_rule"), target.has_path);
    append_sep(menu);
    append_string(menu, IDM_EXPLORE, &t!("context.explore"), target.has_path);
    append_string(
        menu,
        IDM_CLOSE_CONNECTION,
        &t!("context.close_connection"),
        target.is_closable,
    );
    append_sep(menu);
    append_string(menu, IDM_SELECT_ALL, &t!("context.select_all"), true);
    append_sep(menu);
    append_string(menu, IDM_COPY, &t!("context.copy_row"), true);
    append_copy_value(menu, &target.column_text);
    if target.has_path {
        unsafe {
            let _ = SetMenuDefaultItem(menu, IDM_SHOW_IN_LIST as u32, 0);
        }
    }
    track(menu, hwnd)
}

/// Log menu: Show-in-list (default) / Create-rule / Explore / Clear-log
/// / Select-all / Copy / Copy-value.
pub fn show_log(hwnd: HWND, target: &LogContextTarget) -> Option<u16> {
    let menu = unsafe { CreatePopupMenu() }.ok()?;
    append_string(menu, IDM_SHOW_IN_LIST, &t!("context.show_in_list"), target.has_path);
    append_string(menu, IDM_OPENRULESEDITOR, &t!("context.create_rule"), target.has_path);
    append_sep(menu);
    append_string(menu, IDM_EXPLORE, &t!("context.explore"), target.has_path);
    append_string(menu, IDM_TRAY_LOGCLEAR, &t!("context.clear_log"), true);
    append_sep(menu);
    append_string(menu, IDM_SELECT_ALL, &t!("context.select_all"), true);
    append_sep(menu);
    append_string(menu, IDM_COPY, &t!("context.copy_row"), true);
    append_copy_value(menu, &target.column_text);
    if target.has_path {
        unsafe {
            let _ = SetMenuDefaultItem(menu, IDM_SHOW_IN_LIST as u32, 0);
        }
    }
    track(menu, hwnd)
}

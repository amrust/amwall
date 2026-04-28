// simplewall-rs — modal rule editor.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// 1:1 port of upstream simplewall's IDD_EDITOR dialog stack
// (resource.rc:250-366 + editor.c). Implementation uses native
// Win32 dialog templates compiled into the binary via the .rc
// + DialogBoxParamW / CreateDialogParamW. The Win32 dialog
// manager handles font (DS_SHELLFONT -> Segoe UI on Win10+),
// Tab navigation, IDOK/IDCANCEL routing, control sizing in
// dialog units, and modal-loop pumping for free.
//
// Public surface stays the same as the previous CreateWindowEx-
// based version:
//
//   pub fn open(parent, initial: Option<&Rule>, available_apps) -> Option<Rule>
//
// Internally:
//   - Templates: assets/simplewall-rs.rc defines IDD_EDITOR,
//     IDD_EDITOR_GENERAL, IDD_EDITOR_RULE, IDD_EDITOR_APPS,
//     IDD_EDITOR_ADDRULE.
//   - Each tab is a child dialog (IDD_EDITOR_GENERAL etc.)
//     created with CreateDialogParamW and parented to the tab
//     control's content area.
//   - Modal pump is DialogBoxParamW; we exit via EndDialog with
//     the IDOK/IDCANCEL convention.
//   - Result transport: state pointer stored in GWLP_USERDATA;
//     on IDOK the dialog populates state.result with the edited
//     rule before EndDialog.

#![cfg(windows)]

use std::cell::RefCell;

use windows::Win32::Foundation::{HWND, LPARAM, RECT, WPARAM};
use windows::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, LIST_VIEW_ITEM_STATE_FLAGS, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT,
    LVCOLUMNW, LVIF_STATE, LVIF_TEXT, LVIS_STATEIMAGEMASK, LVITEMW, LVM_DELETEITEM,
    LVM_GETITEMSTATE, LVM_GETITEMTEXTW, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW,
    LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMTEXTW, LVNI_SELECTED,
    LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, NMHDR, TCIF_TEXT, TCITEMW,
    TCM_ADJUSTRECT, TCM_GETCURSEL, TCM_INSERTITEMW, TCN_SELCHANGE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL, CreateDialogParamW,
    DialogBoxParamW, EndDialog, GWLP_USERDATA, GetClientRect, GetDlgItem, GetWindowLongPtrW,
    IDCANCEL, IDOK, MoveWindow, SW_HIDE, SW_SHOW, SendDlgItemMessageW, SendMessageW,
    SetWindowLongPtrW, ShowWindow, WM_COMMAND, WM_INITDIALOG, WM_NOTIFY, WM_SIZE,
};
use windows::core::PCWSTR;

use crate::profile::{Action, AddressFamily, App as ProfileApp, Direction, Rule};

use super::wide;

// ---- Resource IDs hand-synced with assets/simplewall-rs.rc ----

const IDD_EDITOR: u16 = 102;
const IDD_EDITOR_GENERAL: u16 = 103;
const IDD_EDITOR_RULE: u16 = 104;
const IDD_EDITOR_APPS: u16 = 105;
const IDD_EDITOR_ADDRULE: u16 = 106;

const IDC_TAB: i32 = 105;
const IDC_ENABLE_CHK: i32 = 250;
const IDC_SAVE: i32 = 1;
const IDC_CLOSE: i32 = 2;

const IDC_RULE_NAME_ID: i32 = 210;
const IDC_RULE_COMMENT_ID: i32 = 214;
const IDC_RULE_PROTOCOL_ID: i32 = 217;
const IDC_RULE_VERSION_ID: i32 = 219;
const IDC_RULE_DIRECTION_ID: i32 = 201;
const IDC_RULE_ACTION_ID: i32 = 261;

const IDC_RULE_REMOTE_ID: i32 = 222;
const IDC_RULE_REMOTE_ADD: i32 = 223;
const IDC_RULE_REMOTE_EDIT: i32 = 224;
const IDC_RULE_REMOTE_DELETE: i32 = 225;
const IDC_RULE_LOCAL_ID: i32 = 227;
const IDC_RULE_LOCAL_ADD: i32 = 228;
const IDC_RULE_LOCAL_EDIT: i32 = 229;
const IDC_RULE_LOCAL_DELETE: i32 = 230;

const IDC_RULE_APPS_ID: i32 = 231;
const IDC_RULE_ID: i32 = 221; // Edit on the AddRule sub-dialog.
const IDC_RULE_ID_HINT: i32 = 239;

/// Convert a numeric resource id into the PCWSTR form Win32
/// expects (`MAKEINTRESOURCE` macro).
fn make_int_resource(id: u16) -> PCWSTR {
    PCWSTR(id as usize as *const u16)
}

/// Per-dialog state, parked in the parent dialog's GWLP_USERDATA.
struct DialogState {
    initial: RefCell<Rule>,
    /// Populated on IDOK before EndDialog returns.
    result: RefCell<Option<Rule>>,
    /// Apps available for the Apps tab (full path is the
    /// identity; basename is the displayed string).
    apps_paths: Vec<String>,

    /// HWNDs of the three tab pages (child dialogs).
    page_general: HWND,
    page_rule: HWND,
    page_apps: HWND,
}

/// Show the modal rule-editor dialog.
///
/// `initial` = `None` opens an Add Rule dialog (blank); `Some(r)`
/// prefills from `r` for Edit. `available_apps` is the caller's
/// `profile.apps` slice — populates the Apps tab. Returns
/// `Some(rule)` on Save, `None` on Close / X / Esc.
pub fn open(parent: HWND, initial: Option<&Rule>, available_apps: &[ProfileApp]) -> Option<Rule> {
    let initial_rule = match initial {
        Some(r) => r.clone(),
        None => Rule {
            name: String::new(),
            remote: None,
            local: None,
            direction: Direction::Outbound,
            action: Action::Permit,
            protocol: None,
            address_family: None,
            apps: None,
            is_services: false,
            is_enabled: true,
            os_version: None,
            comment: None,
        },
    };

    let apps_paths: Vec<String> = available_apps
        .iter()
        .map(|a| a.path.display().to_string())
        .collect();

    let state = Box::new(DialogState {
        initial: RefCell::new(initial_rule),
        result: RefCell::new(None),
        apps_paths,
        page_general: HWND::default(),
        page_rule: HWND::default(),
        page_apps: HWND::default(),
    });
    let state_ptr = Box::into_raw(state);

    unsafe {
        let hi = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
            .ok()?;
        let result_id = DialogBoxParamW(
            hi,
            make_int_resource(IDD_EDITOR),
            parent,
            Some(parent_dlg_proc),
            LPARAM(state_ptr as isize),
        );
        let state = Box::from_raw(state_ptr);
        if result_id == IDOK.0 as isize {
            state.result.into_inner()
        } else {
            None
        }
    }
}

unsafe extern "system" fn parent_dlg_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
            }
            on_init_parent(hwnd);
            1 // TRUE = let the dialog manager set the default focus.
        }
        WM_SIZE => {
            on_size_parent(hwnd);
            0
        }
        WM_NOTIFY => {
            let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
            if nmhdr.idFrom == IDC_TAB as usize && nmhdr.code == TCN_SELCHANGE {
                on_tab_change(hwnd);
            }
            0
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            match id {
                IDC_SAVE => on_save(hwnd),
                IDC_CLOSE => unsafe {
                    let _ = EndDialog(hwnd, IDCANCEL.0 as isize);
                },
                _ => {}
            }
            0
        }
        _ => 0,
    }
}

unsafe fn state_mut<'a>(hwnd: HWND) -> Option<&'a mut DialogState> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut DialogState;
    if raw.is_null() { None } else { Some(unsafe { &mut *raw }) }
}

unsafe fn state_ref<'a>(hwnd: HWND) -> Option<&'a DialogState> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const DialogState;
    if raw.is_null() { None } else { Some(unsafe { &*raw }) }
}

fn on_init_parent(hwnd: HWND) {
    let state = match unsafe { state_mut(hwnd) } {
        Some(s) => s,
        None => return,
    };

    // Insert the three tab labels.
    let labels = ["General", "Rule", "Apps"];
    for (i, label) in labels.iter().enumerate() {
        let mut buf = wide(label);
        let item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: windows::core::PWSTR(buf.as_mut_ptr()),
            ..Default::default()
        };
        unsafe {
            SendDlgItemMessageW(
                hwnd,
                IDC_TAB,
                TCM_INSERTITEMW,
                WPARAM(i),
                LPARAM(&item as *const _ as isize),
            );
        }
    }

    // Create one child dialog per tab page. Each is a modeless
    // dialog (CreateDialogParamW); we show/hide them on tab
    // selection. The state pointer rides through lParam so each
    // page's dlg-proc can also reach the shared state.
    let raw = state as *mut DialogState as isize;
    let hi = match unsafe {
        windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
    } {
        Ok(h) => h,
        Err(_) => return,
    };
    state.page_general = unsafe {
        CreateDialogParamW(
            hi,
            make_int_resource(IDD_EDITOR_GENERAL),
            hwnd,
            Some(general_dlg_proc),
            LPARAM(raw),
        )
    };
    state.page_rule = unsafe {
        CreateDialogParamW(
            hi,
            make_int_resource(IDD_EDITOR_RULE),
            hwnd,
            Some(rule_dlg_proc),
            LPARAM(raw),
        )
    };
    state.page_apps = unsafe {
        CreateDialogParamW(
            hi,
            make_int_resource(IDD_EDITOR_APPS),
            hwnd,
            Some(apps_dlg_proc),
            LPARAM(raw),
        )
    };

    // Initial enable-rule checkbox state.
    let initial = state.initial.borrow();
    let check = if initial.is_enabled { BST_CHECKED.0 } else { BST_UNCHECKED.0 };
    unsafe {
        SendDlgItemMessageW(
            hwnd,
            IDC_ENABLE_CHK,
            BM_SETCHECK,
            WPARAM(check as usize),
            LPARAM(0),
        );
    }
    drop(initial);

    on_size_parent(hwnd);
    on_tab_change(hwnd);
}

fn on_size_parent(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    // Tab control is the only direct child we need to resize on
    // WM_SIZE; the Save/Close buttons + Enable checkbox stay at
    // their dialog-template positions because we don't move them.
    // Tab content rect drives where the tab pages live.
    let tab = unsafe { GetDlgItem(hwnd, IDC_TAB) };
    if tab.0 == 0 {
        return;
    }
    let mut client = RECT::default();
    if unsafe { GetClientRect(hwnd, &mut client) }.is_err() {
        return;
    }
    let total_w = client.right - client.left;
    let total_h = client.bottom - client.top;
    // Reserve 38px at the bottom for the Enable checkbox + Save +
    // Close. Matches the dialog template's spacing.
    let bottom_strip = 38;
    unsafe {
        let _ = MoveWindow(tab, 0, 0, total_w, total_h - bottom_strip, true);
    }

    // Position each tab page inside the tab control's content rect.
    let mut content = RECT {
        left: 0,
        top: 0,
        right: total_w,
        bottom: total_h - bottom_strip,
    };
    unsafe {
        SendMessageW(
            tab,
            TCM_ADJUSTRECT,
            WPARAM(0),
            LPARAM(&mut content as *mut _ as isize),
        );
    }
    let cw = content.right - content.left;
    let ch = content.bottom - content.top;
    for &page in &[state.page_general, state.page_rule, state.page_apps] {
        if page.0 == 0 {
            continue;
        }
        unsafe {
            let _ = MoveWindow(page, content.left, content.top, cw, ch, true);
        }
    }
    // Apps listview column width tracks pane width.
    if state.page_apps.0 != 0 {
        let lv = unsafe { GetDlgItem(state.page_apps, IDC_RULE_APPS_ID) };
        if lv.0 != 0 {
            unsafe {
                SendMessageW(
                    lv,
                    LVM_SETCOLUMNWIDTH,
                    WPARAM(0),
                    LPARAM((cw - 24) as isize),
                );
            }
        }
    }
}

fn on_tab_change(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let sel = unsafe {
        SendDlgItemMessageW(hwnd, IDC_TAB, TCM_GETCURSEL, WPARAM(0), LPARAM(0))
    }
    .0 as isize;
    let sel_slot = if sel < 0 { 0 } else { sel as usize };
    let pages = [state.page_general, state.page_rule, state.page_apps];
    for (i, &p) in pages.iter().enumerate() {
        if p.0 == 0 {
            continue;
        }
        unsafe {
            let _ = ShowWindow(p, if i == sel_slot { SW_SHOW } else { SW_HIDE });
        }
    }
}

fn on_save(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let g = state.page_general;
    let r = state.page_rule;
    let a = state.page_apps;
    if g.0 == 0 || r.0 == 0 || a.0 == 0 {
        return;
    }

    let name = read_dlg_edit(g, IDC_RULE_NAME_ID);
    if name.trim().is_empty() {
        unsafe {
            use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
            let edit = GetDlgItem(g, IDC_RULE_NAME_ID);
            let _ = SetFocus(edit);
        }
        return;
    }
    let comment = some_if_nonempty(read_dlg_edit(g, IDC_RULE_COMMENT_ID));
    let protocol = match read_combo_index(g, IDC_RULE_PROTOCOL_ID) {
        1 => Some(6),
        2 => Some(17),
        3 => Some(1),
        4 => Some(58),
        _ => None,
    };
    let address_family = match read_combo_index(g, IDC_RULE_VERSION_ID) {
        1 => Some(AddressFamily::Ipv4),
        2 => Some(AddressFamily::Ipv6),
        _ => None,
    };
    let direction = match read_combo_index(g, IDC_RULE_DIRECTION_ID) {
        1 => Direction::Inbound,
        2 => Direction::Any,
        _ => Direction::Outbound,
    };
    let action = match read_combo_index(g, IDC_RULE_ACTION_ID) {
        1 => Action::Block,
        _ => Action::Permit,
    };
    let remote = some_if_nonempty(join_listview(r, IDC_RULE_REMOTE_ID));
    let local = some_if_nonempty(join_listview(r, IDC_RULE_LOCAL_ID));
    let apps = some_if_nonempty(collect_checked_apps(a, &state.apps_paths));
    let is_enabled = read_check(hwnd, IDC_ENABLE_CHK);

    let initial = state.initial.borrow();
    let new_rule = Rule {
        name,
        remote,
        local,
        direction,
        action,
        protocol,
        address_family,
        apps,
        is_services: initial.is_services,
        is_enabled,
        os_version: initial.os_version.clone(),
        comment,
    };
    drop(initial);
    *state.result.borrow_mut() = Some(new_rule);
    unsafe {
        let _ = EndDialog(hwnd, IDOK.0 as isize);
    }
}

// ===========================================================================
// General tab dlg-proc: prefill controls + bubble up state pointer.
// ===========================================================================

unsafe extern "system" fn general_dlg_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    if msg == WM_INITDIALOG {
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
        }
        let raw = lparam.0 as *const DialogState;
        if !raw.is_null() {
            let state = unsafe { &*raw };
            let initial = state.initial.borrow();
            unsafe {
                use windows::Win32::UI::WindowsAndMessaging::SetDlgItemTextW;
                let name = wide(&initial.name);
                let _ = SetDlgItemTextW(hwnd, IDC_RULE_NAME_ID, PCWSTR(name.as_ptr()));
                let comments = wide(initial.comment.as_deref().unwrap_or(""));
                let _ = SetDlgItemTextW(hwnd, IDC_RULE_COMMENT_ID, PCWSTR(comments.as_ptr()));
            }
            // Populate combos.
            populate_dlg_combo(
                hwnd,
                IDC_RULE_PROTOCOL_ID,
                &["Any", "TCP", "UDP", "ICMP", "ICMPv6"],
            );
            let proto_idx = match initial.protocol {
                None => 0,
                Some(6) => 1,
                Some(17) => 2,
                Some(1) => 3,
                Some(58) => 4,
                Some(_) => 0,
            };
            unsafe {
                SendDlgItemMessageW(
                    hwnd,
                    IDC_RULE_PROTOCOL_ID,
                    CB_SETCURSEL,
                    WPARAM(proto_idx),
                    LPARAM(0),
                );
            }
            populate_dlg_combo(hwnd, IDC_RULE_VERSION_ID, &["Any", "IPv4", "IPv6"]);
            let family_idx = match initial.address_family {
                None => 0,
                Some(AddressFamily::Ipv4) => 1,
                Some(AddressFamily::Ipv6) => 2,
                Some(AddressFamily::Other(_)) => 0,
            };
            unsafe {
                SendDlgItemMessageW(
                    hwnd,
                    IDC_RULE_VERSION_ID,
                    CB_SETCURSEL,
                    WPARAM(family_idx),
                    LPARAM(0),
                );
            }
            populate_dlg_combo(
                hwnd,
                IDC_RULE_DIRECTION_ID,
                &["Outbound", "Inbound", "Both"],
            );
            let dir_idx = match initial.direction {
                Direction::Outbound => 0,
                Direction::Inbound => 1,
                Direction::Any => 2,
                Direction::Other(_) => 0,
            };
            unsafe {
                SendDlgItemMessageW(
                    hwnd,
                    IDC_RULE_DIRECTION_ID,
                    CB_SETCURSEL,
                    WPARAM(dir_idx),
                    LPARAM(0),
                );
            }
            populate_dlg_combo(hwnd, IDC_RULE_ACTION_ID, &["Allow", "Block"]);
            let action_idx = match initial.action {
                Action::Permit => 0,
                Action::Block => 1,
            };
            unsafe {
                SendDlgItemMessageW(
                    hwnd,
                    IDC_RULE_ACTION_ID,
                    CB_SETCURSEL,
                    WPARAM(action_idx),
                    LPARAM(0),
                );
            }
        }
        return 1;
    }
    0
}

// ===========================================================================
// Rule tab dlg-proc: prefill listviews + handle Add/Edit/Delete buttons.
// ===========================================================================

unsafe extern "system" fn rule_dlg_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
            }
            let raw = lparam.0 as *const DialogState;
            if !raw.is_null() {
                let state = unsafe { &*raw };
                let initial = state.initial.borrow();
                init_rule_listview(hwnd, IDC_RULE_REMOTE_ID, initial.remote.as_deref());
                init_rule_listview(hwnd, IDC_RULE_LOCAL_ID, initial.local.as_deref());
            }
            1
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            match id {
                IDC_RULE_REMOTE_ADD => add_rule_entry(hwnd, IDC_RULE_REMOTE_ID),
                IDC_RULE_REMOTE_EDIT => edit_rule_entry(hwnd, IDC_RULE_REMOTE_ID),
                IDC_RULE_REMOTE_DELETE => delete_rule_entry(hwnd, IDC_RULE_REMOTE_ID),
                IDC_RULE_LOCAL_ADD => add_rule_entry(hwnd, IDC_RULE_LOCAL_ID),
                IDC_RULE_LOCAL_EDIT => edit_rule_entry(hwnd, IDC_RULE_LOCAL_ID),
                IDC_RULE_LOCAL_DELETE => delete_rule_entry(hwnd, IDC_RULE_LOCAL_ID),
                _ => {}
            }
            0
        }
        _ => 0,
    }
}

fn init_rule_listview(parent: HWND, id: i32, initial_str: Option<&str>) {
    let lv = unsafe { GetDlgItem(parent, id) };
    if lv.0 == 0 {
        return;
    }
    unsafe {
        SendMessageW(
            lv,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(0),
            LPARAM((LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT) as isize),
        );
    }
    // Single column spanning the visible width.
    let mut buf = wide("Entry");
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH,
        fmt: LVCFMT_LEFT,
        cx: 600, // big; LVS_NOCOLUMNHEADER hides it anyway.
        pszText: windows::core::PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_INSERTCOLUMNW,
            WPARAM(0),
            LPARAM(&col as *const _ as isize),
        );
    }
    if let Some(s) = initial_str {
        for entry in s.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            insert_listview_row(lv, entry);
        }
    }
}

fn add_rule_entry(parent: HWND, lv_id: i32) {
    let lv = unsafe { GetDlgItem(parent, lv_id) };
    if lv.0 == 0 {
        return;
    }
    if let Some(text) = open_addrule_dialog(parent, "") {
        insert_listview_row(lv, &text);
    }
}

fn edit_rule_entry(parent: HWND, lv_id: i32) {
    let lv = unsafe { GetDlgItem(parent, lv_id) };
    if lv.0 == 0 {
        return;
    }
    let idx = unsafe {
        SendMessageW(
            lv,
            LVM_GETNEXTITEM,
            WPARAM(usize::MAX),
            LPARAM(LVNI_SELECTED as isize),
        )
    }
    .0;
    if idx < 0 {
        return;
    }
    let existing = read_listview_row(lv, idx as i32);
    if let Some(new_text) = open_addrule_dialog(parent, &existing) {
        let mut buf = wide(&new_text);
        let item = LVITEMW {
            mask: LVIF_TEXT,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: windows::core::PWSTR(buf.as_mut_ptr()),
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                lv,
                LVM_SETITEMTEXTW,
                WPARAM(idx as usize),
                LPARAM(&item as *const _ as isize),
            );
        }
    }
}

fn delete_rule_entry(parent: HWND, lv_id: i32) {
    let lv = unsafe { GetDlgItem(parent, lv_id) };
    if lv.0 == 0 {
        return;
    }
    let idx = unsafe {
        SendMessageW(
            lv,
            LVM_GETNEXTITEM,
            WPARAM(usize::MAX),
            LPARAM(LVNI_SELECTED as isize),
        )
    }
    .0;
    if idx < 0 {
        return;
    }
    unsafe {
        SendMessageW(lv, LVM_DELETEITEM, WPARAM(idx as usize), LPARAM(0));
    }
}

// ===========================================================================
// Apps tab dlg-proc: populate listview from the caller's app list.
// ===========================================================================

unsafe extern "system" fn apps_dlg_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    if msg == WM_INITDIALOG {
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
        }
        let raw = lparam.0 as *const DialogState;
        if !raw.is_null() {
            let state = unsafe { &*raw };
            let initial = state.initial.borrow();
            populate_apps_listview(
                hwnd,
                IDC_RULE_APPS_ID,
                &state.apps_paths,
                initial.apps.as_deref(),
            );
        }
        return 1;
    }
    0
}

fn populate_apps_listview(parent: HWND, id: i32, paths: &[String], initial_apps: Option<&str>) {
    let lv = unsafe { GetDlgItem(parent, id) };
    if lv.0 == 0 {
        return;
    }
    unsafe {
        SendMessageW(
            lv,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(0),
            LPARAM(
                (LVS_EX_CHECKBOXES | LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT) as isize,
            ),
        );
    }
    let mut buf = wide("Application");
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH,
        fmt: LVCFMT_LEFT,
        cx: 400,
        pszText: windows::core::PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_INSERTCOLUMNW,
            WPARAM(0),
            LPARAM(&col as *const _ as isize),
        );
    }

    let initial: Vec<&str> = match initial_apps {
        Some(s) => s.split('|').map(str::trim).collect(),
        None => Vec::new(),
    };
    for (idx, path) in paths.iter().enumerate() {
        let basename = std::path::Path::new(path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        let mut text = wide(&basename);
        let checked = initial.contains(&path.as_str());
        let state_image = if checked { 2u32 } else { 1u32 };
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: windows::core::PWSTR(text.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                lv,
                LVM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&item as *const _ as isize),
            );
        }
    }
}

fn collect_checked_apps(pane: HWND, paths: &[String]) -> String {
    let lv = unsafe { GetDlgItem(pane, IDC_RULE_APPS_ID) };
    if lv.0 == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    for (idx, path) in paths.iter().enumerate() {
        let state = unsafe {
            SendMessageW(
                lv,
                LVM_GETITEMSTATE,
                WPARAM(idx),
                LPARAM(LVIS_STATEIMAGEMASK.0 as isize),
            )
        }
        .0 as u32;
        if ((state >> 12) & 0xF) == 2 {
            out.push(path.clone());
        }
    }
    out.join("|")
}

// ===========================================================================
// Add/Edit-fragment sub-dialog (IDD_EDITOR_ADDRULE).
// ===========================================================================

const ADDRULE_HINT_TEXT: &str = "Examples:\r\n\
    192.168.1.1                IP address\r\n\
    192.168.1.0/24             CIDR block\r\n\
    192.168.1.1-192.168.1.10   IP range\r\n\
    443                        port\r\n\
    [::1]:80                   IPv6 with port\r\n\
    443; 80; 8080              multiple entries (separator)";

struct AddRuleState {
    initial: String,
    result: RefCell<Option<String>>,
}

fn open_addrule_dialog(parent: HWND, initial: &str) -> Option<String> {
    let state = Box::new(AddRuleState {
        initial: initial.to_string(),
        result: RefCell::new(None),
    });
    let state_ptr = Box::into_raw(state);
    unsafe {
        let hi = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
            .ok()?;
        let r = DialogBoxParamW(
            hi,
            make_int_resource(IDD_EDITOR_ADDRULE),
            parent,
            Some(addrule_dlg_proc),
            LPARAM(state_ptr as isize),
        );
        let state = Box::from_raw(state_ptr);
        if r == IDOK.0 as isize {
            state.result.into_inner()
        } else {
            None
        }
    }
}

unsafe extern "system" fn addrule_dlg_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
            }
            let raw = lparam.0 as *const AddRuleState;
            if !raw.is_null() {
                let s = unsafe { &*raw };
                use windows::Win32::UI::WindowsAndMessaging::SetDlgItemTextW;
                let initial = wide(&s.initial);
                let _ = unsafe {
                    SetDlgItemTextW(hwnd, IDC_RULE_ID, PCWSTR(initial.as_ptr()))
                };
                let hint = wide(ADDRULE_HINT_TEXT);
                let _ = unsafe {
                    SetDlgItemTextW(hwnd, IDC_RULE_ID_HINT, PCWSTR(hint.as_ptr()))
                };
            }
            1
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            match id {
                IDC_SAVE => {
                    let raw = unsafe {
                        GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const AddRuleState
                    };
                    if !raw.is_null() {
                        let s = unsafe { &*raw };
                        let txt = read_dlg_edit(hwnd, IDC_RULE_ID);
                        if !txt.trim().is_empty() {
                            *s.result.borrow_mut() = Some(txt);
                        }
                    }
                    unsafe {
                        let _ = EndDialog(hwnd, IDOK.0 as isize);
                    }
                }
                IDC_CLOSE => unsafe {
                    let _ = EndDialog(hwnd, IDCANCEL.0 as isize);
                },
                _ => {}
            }
            0
        }
        _ => 0,
    }
}

// ===========================================================================
// Common helpers.
// ===========================================================================

fn populate_dlg_combo(parent: HWND, id: i32, items: &[&str]) {
    for item in items {
        let buf = wide(item);
        unsafe {
            SendDlgItemMessageW(
                parent,
                id,
                CB_ADDSTRING,
                WPARAM(0),
                LPARAM(buf.as_ptr() as isize),
            );
        }
    }
}

fn read_dlg_edit(parent: HWND, id: i32) -> String {
    use windows::Win32::UI::WindowsAndMessaging::GetDlgItemTextW;
    let mut buf = [0u16; 4096];
    let n = unsafe { GetDlgItemTextW(parent, id, &mut buf) } as usize;
    String::from_utf16_lossy(&buf[..n])
}

fn read_combo_index(parent: HWND, id: i32) -> usize {
    let r = unsafe { SendDlgItemMessageW(parent, id, CB_GETCURSEL, WPARAM(0), LPARAM(0)) };
    if r.0 < 0 { 0 } else { r.0 as usize }
}

fn read_check(parent: HWND, id: i32) -> bool {
    let r = unsafe { SendDlgItemMessageW(parent, id, BM_GETCHECK, WPARAM(0), LPARAM(0)) };
    r.0 == BST_CHECKED.0 as isize
}

fn some_if_nonempty(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

fn join_listview(parent: HWND, lv_id: i32) -> String {
    let lv = unsafe { GetDlgItem(parent, lv_id) };
    if lv.0 == 0 {
        return String::new();
    }
    let count =
        unsafe { SendMessageW(lv, lvm_getitemcount(), WPARAM(0), LPARAM(0)) }.0 as i32;
    let mut parts = Vec::with_capacity(count as usize);
    for i in 0..count {
        parts.push(read_listview_row(lv, i));
    }
    parts.join("; ")
}

fn insert_listview_row(lv: HWND, text: &str) {
    let mut buf = wide(text);
    let count =
        unsafe { SendMessageW(lv, lvm_getitemcount(), WPARAM(0), LPARAM(0)) }.0 as i32;
    let item = LVITEMW {
        mask: LVIF_TEXT,
        iItem: count,
        iSubItem: 0,
        pszText: windows::core::PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_INSERTITEMW,
            WPARAM(0),
            LPARAM(&item as *const _ as isize),
        );
    }
}

fn read_listview_row(lv: HWND, row: i32) -> String {
    let mut buf = [0u16; 512];
    let item = LVITEMW {
        iItem: row,
        iSubItem: 0,
        pszText: windows::core::PWSTR(buf.as_mut_ptr()),
        cchTextMax: buf.len() as i32,
        ..Default::default()
    };
    let n = unsafe {
        SendMessageW(
            lv,
            LVM_GETITEMTEXTW,
            WPARAM(row as usize),
            LPARAM(&item as *const _ as isize),
        )
    }
    .0 as usize;
    String::from_utf16_lossy(&buf[..n.min(buf.len())])
}

#[inline]
const fn lvm_getitemcount() -> u32 {
    0x1004 // LVM_GETITEMCOUNT — not re-exported by windows-rs 0.54.
}

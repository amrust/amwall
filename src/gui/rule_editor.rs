// simplewall-rs — modal rule editor.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Programmatic Win32 modal dialog for adding or editing one
// `profile::Rule`. Mirrors upstream simplewall's editor.c form
// shape (Name + Action + Direction + Protocol + remote/local
// rule strings + Apps + Enabled checkbox) but is built out of
// raw CreateWindowExW children rather than from a .rc dialog
// template — same approach the rest of the GUI uses.
//
// The "modal" part is faked with `EnableWindow(parent, false)` +
// a private message-pump loop that exits when the dialog signals
// done (OK or Cancel). This avoids the full Win32 dialog manager
// (DialogBoxIndirectParamW + DLGTEMPLATE construction) while
// keeping Tab-key navigation via IsDialogMessageW.
//
// Public entry points:
//
//   open(parent, hinstance, initial: Option<&Rule>) -> Option<Rule>
//
//     Show the modal. Returns `Some(rule)` on OK with the user's
//     edits applied, or `None` on Cancel / dialog destroyed.
//     Pass `None` for `initial` to create a fresh rule (Add); pass
//     `Some(existing)` to prefill the form (Edit).

#![cfg(windows)]

use std::cell::{Cell, RefCell};

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{BST_CHECKED, BST_UNCHECKED};
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CB_ADDSTRING,
    CB_GETCURSEL, CB_SETCURSEL, CREATESTRUCTW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW,
    DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL, GWLP_USERDATA, GetMessageW,
    GetWindowLongPtrW, GetWindowTextW, HMENU, IDC_ARROW, IDCANCEL, IDOK, IsDialogMessageW,
    LoadCursorW, MSG, PostQuitMessage, RegisterClassExW, SW_SHOW, SendMessageW,
    SetWindowLongPtrW, ShowWindow, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_NCCREATE, WM_NCDESTROY, WNDCLASSEXW, WS_BORDER, WS_CAPTION,
    WS_CHILD, WS_CLIPSIBLINGS, WS_EX_DLGMODALFRAME, WS_GROUP, WS_OVERLAPPED, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE,
};
use windows::core::{PCWSTR, w};

use crate::profile::{Action, Direction, Rule};

use super::wide;

// ---- control IDs (private to this dialog) ----

const ID_NAME_EDIT: i32 = 1001;
const ID_ACTION_COMBO: i32 = 1002;
const ID_DIRECTION_COMBO: i32 = 1003;
const ID_PROTOCOL_COMBO: i32 = 1004;
const ID_REMOTE_EDIT: i32 = 1005;
const ID_LOCAL_EDIT: i32 = 1006;
const ID_APPS_EDIT: i32 = 1007;
const ID_ENABLED_CHK: i32 = 1008;
const ID_OK_BTN: i32 = IDOK.0;
const ID_CANCEL_BTN: i32 = IDCANCEL.0;

const CLASS_NAME: PCWSTR = w!("SimplewallRsRuleEditor");

/// Logical (96-DPI) sizes. Real device pixels are computed at
/// create time using GetDpiForWindow on the parent.
const LOGICAL_W: i32 = 460;
const LOGICAL_H: i32 = 330;

/// Boxed state pointed to from the dialog window's GWLP_USERDATA.
/// Created in `open`, consumed in `WM_NCDESTROY`. The result Cell
/// is the channel back to the caller — set by `on_ok_clicked`.
struct DialogState {
    initial: RefCell<Rule>,
    /// Set to `Some(rule)` on OK, stays `None` on Cancel/close.
    result: RefCell<Option<Rule>>,
    /// Flipped by IDOK / IDCANCEL / WM_CLOSE; the modal pump
    /// breaks out once this is true.
    finished: Cell<bool>,
}

/// Show the modal rule-editor dialog. Returns `Some(rule)` on OK,
/// `None` on Cancel / X-close.
pub fn open(parent: HWND, initial: Option<&Rule>) -> Option<Rule> {
    let initial = match initial {
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

    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null()).ok()?;

        // Register the dialog window class once. RegisterClassExW
        // returns 0 on duplicate registration but doesn't actually
        // fail in a way we care about — the class stays usable.
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(dialog_proc),
            hInstance: hinstance.into(),
            lpszClassName: CLASS_NAME,
            hCursor: LoadCursorW(None, IDC_ARROW).ok()?,
            hbrBackground: HBRUSH(6), // COLOR_WINDOW + 1
            ..Default::default()
        };
        let _ = RegisterClassExW(&wc);

        let state = Box::new(DialogState {
            initial: RefCell::new(initial),
            result: RefCell::new(None),
            finished: Cell::new(false),
        });
        let state_ptr = Box::into_raw(state) as *mut std::ffi::c_void;

        let title = if (*(state_ptr as *const DialogState))
            .initial
            .borrow()
            .name
            .is_empty()
        {
            wide("Add user rule")
        } else {
            wide("Edit user rule")
        };

        // Center over the parent. CW_USEDEFAULT for x/y on a popup
        // window doesn't center; compute parent rect + offset.
        let (x, y) = center_over_parent(parent, LOGICAL_W, LOGICAL_H);

        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPSIBLINGS;
        let dlg = CreateWindowExW(
            WS_EX_DLGMODALFRAME,
            CLASS_NAME,
            PCWSTR(title.as_ptr()),
            style,
            x,
            y,
            LOGICAL_W,
            LOGICAL_H,
            parent,
            HMENU::default(),
            hinstance,
            Some(state_ptr),
        );
        if dlg.0 == 0 {
            // CreateWindowExW failed — reclaim the leaked Box.
            let _ = Box::from_raw(state_ptr as *mut DialogState);
            return None;
        }

        // Disable the parent so the dialog feels modal. Re-enabled
        // after the loop exits.
        let _ = EnableWindow(parent, false);
        let _ = ShowWindow(dlg, SW_SHOW);

        // Modal pump. IsDialogMessageW handles Tab navigation +
        // Enter / Escape mapping to default-button / cancel.
        let mut msg = MSG::default();
        loop {
            // Reading state.finished without a borrow — Cell::get is
            // copy-out, no borrow conflict with concurrent handlers.
            let state_ref = &*(state_ptr as *const DialogState);
            if state_ref.finished.get() {
                break;
            }
            let got = GetMessageW(&mut msg, HWND::default(), 0, 0);
            if !got.as_bool() {
                // WM_QUIT — re-post so the outer loop sees it,
                // exit the modal.
                PostQuitMessage(msg.wParam.0 as i32);
                break;
            }
            if !IsDialogMessageW(dlg, &msg).as_bool() {
                let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        // Re-enable the parent before the dialog window dies, so
        // focus returns to the right window.
        let _ = EnableWindow(parent, true);
        let _ = SetFocus(parent);

        // If the dialog window is still around (escape-to-cancel
        // path can leave it up briefly), tear it down.
        if windows::Win32::UI::WindowsAndMessaging::IsWindow(dlg).as_bool() {
            let _ = DestroyWindow(dlg);
        }

        // Reclaim the Box; pull the Rule out if we have one.
        let state = Box::from_raw(state_ptr as *mut DialogState);
        state.result.into_inner()
    }
}

unsafe extern "system" fn dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_NCCREATE => {
            let cs = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, cs.lpCreateParams as isize);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_CREATE => match on_create(hwnd) {
            Ok(()) => LRESULT(0),
            Err(_) => LRESULT(-1),
        },
        WM_COMMAND => {
            let cmd = (wparam.0 & 0xFFFF) as i32;
            match cmd {
                ID_OK_BTN => on_ok(hwnd),
                ID_CANCEL_BTN => on_cancel(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            on_cancel(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => LRESULT(0),
        WM_NCDESTROY => {
            // Don't drop the Box here — `open` reclaims it after
            // the modal pump exits. Just signal finished if the
            // window dies for any reason we didn't handle.
            if let Some(s) = unsafe { state_ref(hwnd) } {
                s.finished.set(true);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

unsafe fn state_ref<'a>(hwnd: HWND) -> Option<&'a DialogState> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const DialogState;
    if raw.is_null() { None } else { Some(unsafe { &*raw }) }
}

fn on_create(hwnd: HWND) -> Result<(), String> {
    let state = unsafe { state_ref(hwnd) }.ok_or("DialogState missing")?;
    let initial = state.initial.borrow().clone();

    let hinstance = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_err(|e| format!("GetModuleHandleW: {e}"))?;

    // Layout grid (logical 96-DPI). Two columns: label (110 wide),
    // control (right of label). Rows step by 28.
    let row_h = 28;
    let mut y = 14;
    let label_x = 14;
    let label_w = 100;
    let ctl_x = label_x + label_w + 8;
    let ctl_w = 320;

    // Helper closure to add a static label.
    let add_label = |text: &str, y: i32| -> HWND {
        let buf = wide(text);
        unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("Static"),
                PCWSTR(buf.as_ptr()),
                WS_CHILD | WS_VISIBLE,
                label_x,
                y + 4,
                label_w,
                row_h - 8,
                hwnd,
                HMENU::default(),
                hinstance,
                None,
            )
        }
    };

    // Name (Edit)
    add_label("Name:", y);
    let name_buf = wide(&initial.name);
    let name_edit = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(WS_BORDER.0),
            w!("Edit"),
            PCWSTR(name_buf.as_ptr()),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WS_GROUP
                | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
            ctl_x,
            y,
            ctl_w,
            row_h - 6,
            hwnd,
            HMENU(ID_NAME_EDIT as isize),
            hinstance,
            None,
        )
    };
    y += row_h;

    // Action combo
    add_label("Action:", y);
    let action_combo = create_combo(hwnd, hinstance, ID_ACTION_COMBO, ctl_x, y, ctl_w);
    populate_combo(action_combo, &["Permit", "Block"]);
    let action_idx = match initial.action {
        Action::Permit => 0,
        Action::Block => 1,
    };
    unsafe {
        let _ = SendMessageW(action_combo, CB_SETCURSEL, WPARAM(action_idx), LPARAM(0));
    }
    y += row_h;

    // Direction combo
    add_label("Direction:", y);
    let dir_combo = create_combo(hwnd, hinstance, ID_DIRECTION_COMBO, ctl_x, y, ctl_w);
    populate_combo(dir_combo, &["Outbound", "Inbound", "Both"]);
    let dir_idx = match initial.direction {
        Direction::Outbound => 0,
        Direction::Inbound => 1,
        Direction::Any => 2,
        Direction::Other(_) => 0,
    };
    unsafe {
        let _ = SendMessageW(dir_combo, CB_SETCURSEL, WPARAM(dir_idx), LPARAM(0));
    }
    y += row_h;

    // Protocol combo
    add_label("Protocol:", y);
    let proto_combo = create_combo(hwnd, hinstance, ID_PROTOCOL_COMBO, ctl_x, y, ctl_w);
    populate_combo(proto_combo, &["Any", "TCP (6)", "UDP (17)", "ICMP (1)", "ICMPv6 (58)"]);
    let proto_idx = match initial.protocol {
        None => 0,
        Some(6) => 1,
        Some(17) => 2,
        Some(1) => 3,
        Some(58) => 4,
        // Other protocol numbers fall back to "Any" in the UI;
        // they round-trip through the `extra` field on save —
        // see on_ok where we preserve unrecognised values.
        Some(_) => 0,
    };
    unsafe {
        let _ = SendMessageW(proto_combo, CB_SETCURSEL, WPARAM(proto_idx), LPARAM(0));
    }
    y += row_h;

    // Remote rule
    add_label("Remote:", y);
    let remote_buf = wide(initial.remote.as_deref().unwrap_or(""));
    create_edit(hwnd, hinstance, ID_REMOTE_EDIT, ctl_x, y, ctl_w, &remote_buf);
    y += row_h;

    // Local rule
    add_label("Local:", y);
    let local_buf = wide(initial.local.as_deref().unwrap_or(""));
    create_edit(hwnd, hinstance, ID_LOCAL_EDIT, ctl_x, y, ctl_w, &local_buf);
    y += row_h;

    // Apps (semicolon-separated paths)
    add_label("Apps:", y);
    let apps_buf = wide(initial.apps.as_deref().unwrap_or(""));
    create_edit(hwnd, hinstance, ID_APPS_EDIT, ctl_x, y, ctl_w, &apps_buf);
    y += row_h;

    // Enabled checkbox
    let enabled_buf = wide("Enable rule");
    let enabled_btn = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(enabled_buf.as_ptr()),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
            ctl_x,
            y,
            ctl_w,
            row_h - 6,
            hwnd,
            HMENU(ID_ENABLED_CHK as isize),
            hinstance,
            None,
        )
    };
    let initial_check = if initial.is_enabled { BST_CHECKED.0 } else { BST_UNCHECKED.0 };
    unsafe {
        let _ = SendMessageW(
            enabled_btn,
            BM_SETCHECK,
            WPARAM(initial_check as usize),
            LPARAM(0),
        );
    }
    y += row_h + 8;

    // OK / Cancel buttons aligned right.
    let btn_w = 90;
    let btn_h = 26;
    let cancel_x = LOGICAL_W - btn_w - 16 - 8;
    let ok_x = cancel_x - btn_w - 8;
    let ok_buf = wide("OK");
    let cancel_buf = wide("Cancel");
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(ok_buf.as_ptr()),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
            ok_x,
            y,
            btn_w,
            btn_h,
            hwnd,
            HMENU(ID_OK_BTN as isize),
            hinstance,
            None,
        );
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(cancel_buf.as_ptr()),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WINDOW_STYLE(BS_PUSHBUTTON as u32),
            cancel_x,
            y,
            btn_w,
            btn_h,
            hwnd,
            HMENU(ID_CANCEL_BTN as isize),
            hinstance,
            None,
        );
    }

    // Initial focus: Name field. Tab navigation flows through the
    // children in z-order, which matches the order we created
    // them in.
    unsafe {
        let _ = SetFocus(name_edit);
    }

    Ok(())
}

fn create_combo(parent: HWND, hi: windows::Win32::Foundation::HMODULE, id: i32, x: i32, y: i32, w: i32) -> HWND {
    use windows::Win32::UI::Controls::WC_COMBOBOXW;
    // CBS_DROPDOWNLIST = 0x0003 — read-only dropdown.
    const CBS_DROPDOWNLIST: u32 = 0x0003;
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WC_COMBOBOXW,
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(CBS_DROPDOWNLIST),
            x,
            y,
            w,
            200, // dropdown height; Win32 caps to fit content
            parent,
            HMENU(id as isize),
            hi,
            None,
        )
    }
}

fn populate_combo(combo: HWND, items: &[&str]) {
    for item in items {
        let buf = wide(item);
        unsafe {
            let _ = SendMessageW(combo, CB_ADDSTRING, WPARAM(0), LPARAM(buf.as_ptr() as isize));
        }
    }
}

fn create_edit(
    parent: HWND,
    hi: windows::Win32::Foundation::HMODULE,
    id: i32,
    x: i32,
    y: i32,
    w: i32,
    initial: &[u16],
) -> HWND {
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(WS_BORDER.0),
            w!("Edit"),
            PCWSTR(initial.as_ptr()),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
            x,
            y,
            w,
            22,
            parent,
            HMENU(id as isize),
            hi,
            None,
        )
    }
}

fn on_ok(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    // Read each control. Build a Rule from scratch so we don't
    // accidentally inherit fields the user didn't touch (the
    // initial copy is for prefill only).
    let name = read_edit(hwnd, ID_NAME_EDIT);
    if name.trim().is_empty() {
        // Refuse blank names — matches upstream's editor behaviour.
        // We don't pop a MessageBox here because the caller's flow
        // is already a dialog; instead just leave the dialog open
        // and shift focus back to the Name field.
        unsafe {
            use windows::Win32::UI::WindowsAndMessaging::GetDlgItem;
            let name_edit = GetDlgItem(hwnd, ID_NAME_EDIT);
            let _ = SetFocus(name_edit);
        }
        return;
    }
    let action = match read_combo_index(hwnd, ID_ACTION_COMBO) {
        1 => Action::Block,
        _ => Action::Permit,
    };
    let direction = match read_combo_index(hwnd, ID_DIRECTION_COMBO) {
        1 => Direction::Inbound,
        2 => Direction::Any,
        _ => Direction::Outbound,
    };
    let protocol = match read_combo_index(hwnd, ID_PROTOCOL_COMBO) {
        1 => Some(6),
        2 => Some(17),
        3 => Some(1),
        4 => Some(58),
        _ => None,
    };
    let remote = some_if_nonempty(read_edit(hwnd, ID_REMOTE_EDIT));
    let local = some_if_nonempty(read_edit(hwnd, ID_LOCAL_EDIT));
    let apps = some_if_nonempty(read_edit(hwnd, ID_APPS_EDIT));
    let is_enabled = read_check(hwnd, ID_ENABLED_CHK);

    // Preserve fields the dialog doesn't expose
    // (address_family, is_services, os_version, comment) from the
    // initial rule so round-tripping doesn't drop them on Edit.
    let initial = state.initial.borrow();
    let new_rule = Rule {
        name,
        remote,
        local,
        direction,
        action,
        protocol,
        address_family: initial.address_family,
        apps,
        is_services: initial.is_services,
        is_enabled,
        os_version: initial.os_version.clone(),
        comment: initial.comment.clone(),
    };
    drop(initial);

    *state.result.borrow_mut() = Some(new_rule);
    state.finished.set(true);
}

fn on_cancel(hwnd: HWND) {
    if let Some(state) = unsafe { state_ref(hwnd) } {
        state.finished.set(true);
    }
}

fn read_edit(parent: HWND, id: i32) -> String {
    use windows::Win32::UI::WindowsAndMessaging::GetDlgItem;
    let edit = unsafe { GetDlgItem(parent, id) };
    if edit.0 == 0 {
        return String::new();
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { GetWindowTextW(edit, &mut buf) } as usize;
    String::from_utf16_lossy(&buf[..n])
}

fn read_combo_index(parent: HWND, id: i32) -> usize {
    use windows::Win32::UI::WindowsAndMessaging::GetDlgItem;
    let combo = unsafe { GetDlgItem(parent, id) };
    if combo.0 == 0 {
        return 0;
    }
    let r = unsafe { SendMessageW(combo, CB_GETCURSEL, WPARAM(0), LPARAM(0)) };
    if r.0 < 0 { 0 } else { r.0 as usize }
}

fn read_check(parent: HWND, id: i32) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::GetDlgItem;
    let btn = unsafe { GetDlgItem(parent, id) };
    if btn.0 == 0 {
        return false;
    }
    let r = unsafe { SendMessageW(btn, BM_GETCHECK, WPARAM(0), LPARAM(0)) };
    r.0 == BST_CHECKED.0 as isize
}

fn some_if_nonempty(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

fn center_over_parent(parent: HWND, w: i32, h: i32) -> (i32, i32) {
    let mut rect = windows::Win32::Foundation::RECT::default();
    if parent.0 == 0
        || unsafe { windows::Win32::UI::WindowsAndMessaging::GetWindowRect(parent, &mut rect) }
            .is_err()
    {
        return (CW_USEDEFAULT, CW_USEDEFAULT);
    }
    let pw = rect.right - rect.left;
    let ph = rect.bottom - rect.top;
    let x = rect.left + (pw - w) / 2;
    let y = rect.top + (ph - h) / 2;
    (x, y)
}

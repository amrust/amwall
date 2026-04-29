// amwall — App properties modal dialog.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Shown when the user picks Properties on a row in any of the
// Apps / Services / UWP tabs (M5.4c follow-up). Backed by a Win32
// dialog template (`IDD_APP_PROPERTIES` in assets/amwall.rc) so the
// dialog manager handles font, tab navigation, and modal pumping;
// this module is just the data-bind + IDOK / IDCANCEL plumbing.
//
// Mirrors upstream simplewall's Apps-tab editor in spirit (small,
// fixed-size, modal, Save/Close buttons) but trimmed to the
// fields amwall's `App` struct actually carries today: path
// (read-only), comment, is_enabled, is_silent. The "Rules
// applying to this app" tab from upstream's editor is deferred
// to a future scope that needs rule-resolution machinery.
//
//   pub fn open(parent: HWND, app: &App) -> Option<App>
//
// Returns `Some(updated)` if the user clicks Save with edits, or
// `None` on Close / window-X / unchanged.

#![cfg(windows)]

use std::cell::RefCell;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{BST_CHECKED, BST_UNCHECKED};
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, DialogBoxParamW, EndDialog, GWLP_USERDATA, GetDlgItem,
    GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, IDCANCEL, IDOK, SendMessageW,
    SetWindowLongPtrW, SetWindowTextW, WM_COMMAND, WM_INITDIALOG,
};
use windows::core::PCWSTR;

use crate::profile::App as ProfileApp;

use super::wide;

const IDD_APP_PROPERTIES: u16 = 110;

const IDC_APPPROP_PATH_ID: i32 = 1100;
const IDC_APPPROP_COMMENT_ID: i32 = 1101;
const IDC_APPPROP_ENABLED_CHK: i32 = 1102;
const IDC_APPPROP_SILENT_CHK: i32 = 1103;
const IDC_SAVE: i32 = 1; // IDOK
const IDC_CLOSE: i32 = 2; // IDCANCEL

/// Dialog state pointed to by GWLP_USERDATA. Holds the original
/// app and a slot for the edited version on Save.
struct DialogState {
    initial: ProfileApp,
    result: RefCell<Option<ProfileApp>>,
}

/// Open the App properties modal. Returns `Some(updated_app)` if
/// the user clicked Save with changes, otherwise `None`.
pub fn open(parent: HWND, app: &ProfileApp) -> Option<ProfileApp> {
    let state = DialogState {
        initial: app.clone(),
        result: RefCell::new(None),
    };
    let state_ptr = &state as *const DialogState as isize;

    let hi = unsafe { GetModuleHandleW(PCWSTR::null()) }.ok()?;
    unsafe {
        DialogBoxParamW(
            hi,
            PCWSTR(IDD_APP_PROPERTIES as usize as *const u16),
            parent,
            Some(dialog_proc),
            LPARAM(state_ptr),
        );
    }

    state.result.into_inner()
}

unsafe extern "system" fn dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            // Stash the state pointer for the rest of the dialog's
            // lifetime — every other message reads it back via
            // GetWindowLongPtr.
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
            }
            let state = unsafe { &*(lparam.0 as *const DialogState) };

            // Path: read-only edit, single-line. Show the full path;
            // truncation is handled by the edit's horizontal scroll.
            set_dlg_text(hwnd, IDC_APPPROP_PATH_ID, &state.initial.path.display().to_string());
            set_dlg_text(
                hwnd,
                IDC_APPPROP_COMMENT_ID,
                state.initial.comment.as_deref().unwrap_or(""),
            );
            set_dlg_check(hwnd, IDC_APPPROP_ENABLED_CHK, state.initial.is_enabled);
            set_dlg_check(hwnd, IDC_APPPROP_SILENT_CHK, state.initial.is_silent);

            1 // TRUE — let the dialog manager pick the default focus.
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            match id {
                IDC_SAVE => {
                    let state = unsafe { read_state(hwnd) };
                    if let Some(state) = state {
                        let mut updated = state.initial.clone();
                        updated.comment = match read_dlg_text(hwnd, IDC_APPPROP_COMMENT_ID) {
                            s if s.is_empty() => None,
                            s => Some(s),
                        };
                        updated.is_enabled = read_dlg_check(hwnd, IDC_APPPROP_ENABLED_CHK);
                        updated.is_silent = read_dlg_check(hwnd, IDC_APPPROP_SILENT_CHK);
                        if updated != state.initial {
                            *state.result.borrow_mut() = Some(updated);
                        }
                    }
                    unsafe {
                        let _ = EndDialog(hwnd, IDOK.0 as isize);
                    }
                    1
                }
                IDC_CLOSE => {
                    unsafe {
                        let _ = EndDialog(hwnd, IDCANCEL.0 as isize);
                    }
                    1
                }
                _ => 0,
            }
        }
        _ => 0,
    }
}

unsafe fn read_state(hwnd: HWND) -> Option<&'static DialogState> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
    if raw == 0 {
        return None;
    }
    Some(unsafe { &*(raw as *const DialogState) })
}

fn set_dlg_text(hwnd: HWND, id: i32, text: &str) {
    let ctrl = unsafe { GetDlgItem(hwnd, id) };
    if ctrl.0 == 0 {
        return;
    }
    let mut wbuf = wide(text);
    unsafe {
        let _ = SetWindowTextW(ctrl, PCWSTR(wbuf.as_mut_ptr()));
    }
}

fn read_dlg_text(hwnd: HWND, id: i32) -> String {
    let ctrl = unsafe { GetDlgItem(hwnd, id) };
    if ctrl.0 == 0 {
        return String::new();
    }
    let len = unsafe { GetWindowTextLengthW(ctrl) } as usize;
    if len == 0 {
        return String::new();
    }
    let mut buf = vec![0u16; len + 1];
    let n = unsafe { GetWindowTextW(ctrl, &mut buf) } as usize;
    String::from_utf16_lossy(&buf[..n])
}

fn set_dlg_check(hwnd: HWND, id: i32, on: bool) {
    let ctrl = unsafe { GetDlgItem(hwnd, id) };
    if ctrl.0 == 0 {
        return;
    }
    let v = if on { BST_CHECKED.0 } else { BST_UNCHECKED.0 };
    unsafe {
        SendMessageW(ctrl, BM_SETCHECK, WPARAM(v as usize), LPARAM(0));
    }
}

fn read_dlg_check(hwnd: HWND, id: i32) -> bool {
    let ctrl = unsafe { GetDlgItem(hwnd, id) };
    if ctrl.0 == 0 {
        return false;
    }
    let v = unsafe { SendMessageW(ctrl, BM_GETCHECK, WPARAM(0), LPARAM(0)) };
    v.0 == BST_CHECKED.0 as isize
}

// simplewall-rs — modal Settings dialog.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// 1:1 port of upstream's Settings property sheet
// (resource.rc:368-523). Eight tabs total — General / Interface /
// Highlighting / Rules / Blocklist / Notifications / Logging /
// Exclude. The parent IDD_SETTINGS dialog hosts a tab control +
// Save/Close; each tab is a child dialog (IDD_SETTINGS_*).
//
// Same dialog-template approach as the rule editor (rule_editor.rs)
// — DialogBoxParamW for the modal pump, CreateDialogParamW per
// tab page, font/Tab-nav handled by the Win32 dialog manager.
//
// Persistence: every control round-trips through the `Settings`
// struct (gui/settings.rs). Several controls drive features that
// haven't been implemented yet (notification timeout, log file
// writes, blocklist mode application, etc.) — those persist
// to settings.txt but don't visibly do anything until M6+/M7+
// land. The visual dialog matches upstream regardless, so users
// migrating from upstream see the same options.

#![cfg(windows)]

use std::cell::RefCell;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, NMHDR, TCIF_TEXT, TCITEMW, TCM_GETCURSEL, TCM_INSERTITEMW,
    TCN_SELCHANGE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, CreateDialogParamW, DialogBoxParamW, EndDialog, GWLP_USERDATA,
    GetClientRect, GetDlgItem, GetWindowLongPtrW, IDCANCEL, IDOK, MoveWindow, SW_HIDE, SW_SHOW,
    SendDlgItemMessageW, SendMessageW, SetWindowLongPtrW, ShowWindow, WM_COMMAND, WM_INITDIALOG,
    WM_NOTIFY, WM_SIZE,
};
use windows::core::PCWSTR;

use super::settings::{BlocklistMode, Settings};
use super::wide;

// ---- Resource IDs hand-synced with assets/simplewall-rs.rc ----

const IDD_SETTINGS: u16 = 200;
const IDD_SETTINGS_GENERAL: u16 = 201;
const IDD_SETTINGS_INTERFACE: u16 = 202;
const IDD_SETTINGS_HIGHLIGHTING: u16 = 203;
const IDD_SETTINGS_RULES: u16 = 204;
const IDD_SETTINGS_BLOCKLIST: u16 = 205;
const IDD_SETTINGS_NOTIFICATIONS: u16 = 206;
const IDD_SETTINGS_LOGGING: u16 = 207;
const IDD_SETTINGS_EXCLUDE: u16 = 208;

const IDC_SETTINGS_TAB: i32 = 700;
const IDC_SETTINGS_SAVE: i32 = 1;
const IDC_SETTINGS_CLOSE: i32 = 2;

// General
const IDC_ALWAYSONTOP_CHK: i32 = 720;
const IDC_LOADONSTARTUP_CHK: i32 = 721;
const IDC_STARTMINIMIZED_CHK: i32 = 722;
const IDC_SKIPUACWARNING_CHK: i32 = 723;
const IDC_CHECKUPDATES_CHK: i32 = 724;
// Interface
const IDC_CONFIRMEXIT_CHK: i32 = 730;
const IDC_CONFIRMEXITTIMER_CHK: i32 = 731;
const IDC_CONFIRMLOGCLEAR_CHK: i32 = 732;
const IDC_CONFIRMALLOW_CHK: i32 = 733;
const IDC_TRAYICONSINGLECLICK_CHK: i32 = 734;
// Rules
const IDC_S_RULE_BLOCKOUTBOUND: i32 = 750;
const IDC_S_RULE_BLOCKINBOUND: i32 = 751;
const IDC_S_RULE_ALLOWLOOPBACK: i32 = 752;
const IDC_S_RULE_ALLOW6TO4: i32 = 753;
const IDC_USESTEALTHMODE_CHK: i32 = 754;
const IDC_INSTALLBOOTTIMEFILTERS_CHK: i32 = 755;
const IDC_USECERTIFICATES_CHK: i32 = 756;
const IDC_USEHASHES_CHK: i32 = 757;
const IDC_USENETWORKRESOLUTION_CHK: i32 = 758;
// Blocklist (3 radio groups, 3 buttons each)
const IDC_S_BLOCKLIST_SPY_DISABLE: i32 = 760;
const IDC_S_BLOCKLIST_SPY_ALLOW: i32 = 761;
const IDC_S_BLOCKLIST_SPY_BLOCK: i32 = 762;
const IDC_S_BLOCKLIST_UPDATE_DISABLE: i32 = 770;
const IDC_S_BLOCKLIST_UPDATE_ALLOW: i32 = 771;
const IDC_S_BLOCKLIST_UPDATE_BLOCK: i32 = 772;
const IDC_S_BLOCKLIST_EXTRA_DISABLE: i32 = 780;
const IDC_S_BLOCKLIST_EXTRA_ALLOW: i32 = 781;
const IDC_S_BLOCKLIST_EXTRA_BLOCK: i32 = 782;
// Notifications
const IDC_ENABLENOTIFICATIONS_CHK: i32 = 790;
const IDC_NOTIFICATIONSOUND_CHK: i32 = 791;
const IDC_NOTIF_FULLSCREEN_CHK: i32 = 792;
const IDC_NOTIFICATIONONTRAY_CHK: i32 = 793;
const IDC_NOTIFICATIONTIMEOUT_CTRL: i32 = 794;
// Logging
const IDC_ENABLELOG_CHK: i32 = 800;
const IDC_LOGPATH: i32 = 801;
const IDC_LOGSIZELIMIT_CTRL: i32 = 803;
const IDC_LOGVIEWER: i32 = 804;
const IDC_ENABLEUILOG_CHK: i32 = 806;
// Exclude
const IDC_EXCLUDEBLOCKLIST_CHK: i32 = 810;
const IDC_EXCLUDECUSTOM_CHK: i32 = 811;
const IDC_EXCLUDESTEALTH_CHK: i32 = 812;
const IDC_EXCLUDECLASSIFYALLOW_CHK: i32 = 813;

fn make_int_resource(id: u16) -> PCWSTR {
    PCWSTR(id as usize as *const u16)
}

struct DialogState {
    initial: RefCell<Settings>,
    result: RefCell<Option<Settings>>,
    pages: [HWND; 8],
}

/// Open the modal Settings dialog. Returns the modified
/// `Settings` on Save, `None` on Close.
pub fn open(parent: HWND, initial: &Settings) -> Option<Settings> {
    let state = Box::new(DialogState {
        initial: RefCell::new(initial.clone()),
        result: RefCell::new(None),
        pages: [HWND::default(); 8],
    });
    let state_ptr = Box::into_raw(state);
    unsafe {
        let hi = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
            .ok()?;
        let r = DialogBoxParamW(
            hi,
            make_int_resource(IDD_SETTINGS),
            parent,
            Some(parent_dlg_proc),
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
            1
        }
        WM_SIZE => {
            on_size_parent(hwnd);
            0
        }
        WM_NOTIFY => {
            let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
            if nmhdr.idFrom == IDC_SETTINGS_TAB as usize && nmhdr.code == TCN_SELCHANGE {
                on_tab_change(hwnd);
            }
            0
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            match id {
                IDC_SETTINGS_SAVE => on_save(hwnd),
                IDC_SETTINGS_CLOSE => unsafe {
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
    let labels = [
        "General",
        "Interface",
        "Highlighting",
        "Rules",
        "Blocklist",
        "Notifications",
        "Logging",
        "Exclude",
    ];
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
                IDC_SETTINGS_TAB,
                TCM_INSERTITEMW,
                WPARAM(i),
                LPARAM(&item as *const _ as isize),
            );
        }
    }

    let raw = state as *mut DialogState as isize;
    let hi = match unsafe {
        windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
    } {
        Ok(h) => h,
        Err(_) => return,
    };
    let templates = [
        IDD_SETTINGS_GENERAL,
        IDD_SETTINGS_INTERFACE,
        IDD_SETTINGS_HIGHLIGHTING,
        IDD_SETTINGS_RULES,
        IDD_SETTINGS_BLOCKLIST,
        IDD_SETTINGS_NOTIFICATIONS,
        IDD_SETTINGS_LOGGING,
        IDD_SETTINGS_EXCLUDE,
    ];
    let procs: [windows::Win32::UI::WindowsAndMessaging::DLGPROC; 8] = [
        Some(general_proc),
        Some(interface_proc),
        Some(highlighting_proc),
        Some(rules_proc),
        Some(blocklist_proc),
        Some(notifications_proc),
        Some(logging_proc),
        Some(exclude_proc),
    ];
    for (i, &tpl) in templates.iter().enumerate() {
        state.pages[i] = unsafe {
            CreateDialogParamW(hi, make_int_resource(tpl), hwnd, procs[i], LPARAM(raw))
        };
    }

    on_size_parent(hwnd);
    on_tab_change(hwnd);
}

fn on_size_parent(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let tab = unsafe { GetDlgItem(hwnd, IDC_SETTINGS_TAB) };
    if tab.0 == 0 {
        return;
    }
    let mut client = windows::Win32::Foundation::RECT::default();
    if unsafe { GetClientRect(hwnd, &mut client) }.is_err() {
        return;
    }
    let total_w = client.right - client.left;
    let total_h = client.bottom - client.top;
    let bottom_strip = 32;
    unsafe {
        let _ = MoveWindow(tab, 0, 0, total_w, total_h - bottom_strip, true);
    }
    let mut content = windows::Win32::Foundation::RECT {
        left: 0,
        top: 0,
        right: total_w,
        bottom: total_h - bottom_strip,
    };
    unsafe {
        use windows::Win32::UI::Controls::TCM_ADJUSTRECT;
        SendMessageW(
            tab,
            TCM_ADJUSTRECT,
            WPARAM(0),
            LPARAM(&mut content as *mut _ as isize),
        );
    }
    let cw = content.right - content.left;
    let ch = content.bottom - content.top;
    for &p in &state.pages {
        if p.0 != 0 {
            unsafe {
                let _ = MoveWindow(p, content.left, content.top, cw, ch, true);
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
        SendDlgItemMessageW(hwnd, IDC_SETTINGS_TAB, TCM_GETCURSEL, WPARAM(0), LPARAM(0))
    }
    .0 as isize;
    let sel_slot = if sel < 0 { 0 } else { sel as usize };
    for (i, &p) in state.pages.iter().enumerate() {
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
    // Start from the initial snapshot so fields the dialog
    // doesn't expose (current view-menu state, etc.) round-trip
    // unchanged.
    let mut s = state.initial.borrow().clone();
    let pages = state.pages;

    // ---- General ----
    let p = pages[0];
    s.always_on_top = read_check(p, IDC_ALWAYSONTOP_CHK);
    s.load_on_startup = read_check(p, IDC_LOADONSTARTUP_CHK);
    s.start_minimized = read_check(p, IDC_STARTMINIMIZED_CHK);
    s.skip_uac_warning = read_check(p, IDC_SKIPUACWARNING_CHK);
    s.check_updates = read_check(p, IDC_CHECKUPDATES_CHK);

    // ---- Interface ----
    let p = pages[1];
    s.confirm_exit = read_check(p, IDC_CONFIRMEXIT_CHK);
    s.confirm_exit_timer = read_check(p, IDC_CONFIRMEXITTIMER_CHK);
    s.confirm_log_clear = read_check(p, IDC_CONFIRMLOGCLEAR_CHK);
    s.confirm_allow = read_check(p, IDC_CONFIRMALLOW_CHK);
    s.tray_single_click = read_check(p, IDC_TRAYICONSINGLECLICK_CHK);

    // ---- Highlighting (no editable controls yet) ----

    // ---- Rules ----
    let p = pages[3];
    s.rule_block_outbound = read_check(p, IDC_S_RULE_BLOCKOUTBOUND);
    s.rule_block_inbound = read_check(p, IDC_S_RULE_BLOCKINBOUND);
    s.rule_allow_loopback = read_check(p, IDC_S_RULE_ALLOWLOOPBACK);
    s.rule_allow_6to4 = read_check(p, IDC_S_RULE_ALLOW6TO4);
    s.use_stealth_mode = read_check(p, IDC_USESTEALTHMODE_CHK);
    s.install_boottime_filters = read_check(p, IDC_INSTALLBOOTTIMEFILTERS_CHK);
    s.use_certificates = read_check(p, IDC_USECERTIFICATES_CHK);
    s.use_hashes = read_check(p, IDC_USEHASHES_CHK);
    s.use_network_resolution = read_check(p, IDC_USENETWORKRESOLUTION_CHK);

    // ---- Blocklist (radio groups) ----
    let p = pages[4];
    s.blocklist_spy = read_radio_blocklist(
        p,
        IDC_S_BLOCKLIST_SPY_DISABLE,
        IDC_S_BLOCKLIST_SPY_ALLOW,
        IDC_S_BLOCKLIST_SPY_BLOCK,
    );
    s.blocklist_update = read_radio_blocklist(
        p,
        IDC_S_BLOCKLIST_UPDATE_DISABLE,
        IDC_S_BLOCKLIST_UPDATE_ALLOW,
        IDC_S_BLOCKLIST_UPDATE_BLOCK,
    );
    s.blocklist_extra = read_radio_blocklist(
        p,
        IDC_S_BLOCKLIST_EXTRA_DISABLE,
        IDC_S_BLOCKLIST_EXTRA_ALLOW,
        IDC_S_BLOCKLIST_EXTRA_BLOCK,
    );

    // ---- Notifications ----
    let p = pages[5];
    s.enable_notifications = read_check(p, IDC_ENABLENOTIFICATIONS_CHK);
    s.notification_sound = read_check(p, IDC_NOTIFICATIONSOUND_CHK);
    s.notification_fullscreen_silent = read_check(p, IDC_NOTIF_FULLSCREEN_CHK);
    s.notification_on_tray = read_check(p, IDC_NOTIFICATIONONTRAY_CHK);
    s.notification_timeout = read_u32(p, IDC_NOTIFICATIONTIMEOUT_CTRL).unwrap_or(s.notification_timeout);

    // ---- Logging ----
    let p = pages[6];
    s.enable_log = read_check(p, IDC_ENABLELOG_CHK);
    s.log_path = read_edit(p, IDC_LOGPATH);
    s.log_size_limit = read_u32(p, IDC_LOGSIZELIMIT_CTRL).unwrap_or(s.log_size_limit);
    s.log_viewer = read_edit(p, IDC_LOGVIEWER);
    s.enable_ui_log = read_check(p, IDC_ENABLEUILOG_CHK);

    // ---- Exclude ----
    let p = pages[7];
    s.exclude_blocklist = read_check(p, IDC_EXCLUDEBLOCKLIST_CHK);
    s.exclude_custom = read_check(p, IDC_EXCLUDECUSTOM_CHK);
    s.exclude_stealth = read_check(p, IDC_EXCLUDESTEALTH_CHK);
    s.exclude_classify_allow = read_check(p, IDC_EXCLUDECLASSIFYALLOW_CHK);

    *state.result.borrow_mut() = Some(s);
    unsafe {
        let _ = EndDialog(hwnd, IDOK.0 as isize);
    }
}

// =================================================================
// Per-page dlg-procs — each just prefills its controls from
// `state.initial` on WM_INITDIALOG. Save reads them back.
// =================================================================

unsafe extern "system" fn general_proc(
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
            let s = state.initial.borrow();
            set_check(hwnd, IDC_ALWAYSONTOP_CHK, s.always_on_top);
            set_check(hwnd, IDC_LOADONSTARTUP_CHK, s.load_on_startup);
            set_check(hwnd, IDC_STARTMINIMIZED_CHK, s.start_minimized);
            set_check(hwnd, IDC_SKIPUACWARNING_CHK, s.skip_uac_warning);
            set_check(hwnd, IDC_CHECKUPDATES_CHK, s.check_updates);
        }
        return 1;
    }
    0
}

unsafe extern "system" fn interface_proc(
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
            let s = unsafe { &*raw }.initial.borrow();
            set_check(hwnd, IDC_CONFIRMEXIT_CHK, s.confirm_exit);
            set_check(hwnd, IDC_CONFIRMEXITTIMER_CHK, s.confirm_exit_timer);
            set_check(hwnd, IDC_CONFIRMLOGCLEAR_CHK, s.confirm_log_clear);
            set_check(hwnd, IDC_CONFIRMALLOW_CHK, s.confirm_allow);
            set_check(hwnd, IDC_TRAYICONSINGLECLICK_CHK, s.tray_single_click);
        }
        return 1;
    }
    0
}

unsafe extern "system" fn highlighting_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    if msg == WM_INITDIALOG {
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
        }
        // Color editing UI lands in M5.9 polish; the page renders
        // for layout parity with upstream but the listview stays
        // empty for now.
        return 1;
    }
    0
}

unsafe extern "system" fn rules_proc(
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
            let s = unsafe { &*raw }.initial.borrow();
            set_check(hwnd, IDC_S_RULE_BLOCKOUTBOUND, s.rule_block_outbound);
            set_check(hwnd, IDC_S_RULE_BLOCKINBOUND, s.rule_block_inbound);
            set_check(hwnd, IDC_S_RULE_ALLOWLOOPBACK, s.rule_allow_loopback);
            set_check(hwnd, IDC_S_RULE_ALLOW6TO4, s.rule_allow_6to4);
            set_check(hwnd, IDC_USESTEALTHMODE_CHK, s.use_stealth_mode);
            set_check(hwnd, IDC_INSTALLBOOTTIMEFILTERS_CHK, s.install_boottime_filters);
            set_check(hwnd, IDC_USECERTIFICATES_CHK, s.use_certificates);
            set_check(hwnd, IDC_USEHASHES_CHK, s.use_hashes);
            set_check(hwnd, IDC_USENETWORKRESOLUTION_CHK, s.use_network_resolution);
        }
        return 1;
    }
    0
}

unsafe extern "system" fn blocklist_proc(
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
            let s = unsafe { &*raw }.initial.borrow();
            set_radio_blocklist(
                hwnd,
                s.blocklist_spy,
                IDC_S_BLOCKLIST_SPY_DISABLE,
                IDC_S_BLOCKLIST_SPY_ALLOW,
                IDC_S_BLOCKLIST_SPY_BLOCK,
            );
            set_radio_blocklist(
                hwnd,
                s.blocklist_update,
                IDC_S_BLOCKLIST_UPDATE_DISABLE,
                IDC_S_BLOCKLIST_UPDATE_ALLOW,
                IDC_S_BLOCKLIST_UPDATE_BLOCK,
            );
            set_radio_blocklist(
                hwnd,
                s.blocklist_extra,
                IDC_S_BLOCKLIST_EXTRA_DISABLE,
                IDC_S_BLOCKLIST_EXTRA_ALLOW,
                IDC_S_BLOCKLIST_EXTRA_BLOCK,
            );
        }
        return 1;
    }
    0
}

unsafe extern "system" fn notifications_proc(
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
            let s = unsafe { &*raw }.initial.borrow();
            set_check(hwnd, IDC_ENABLENOTIFICATIONS_CHK, s.enable_notifications);
            set_check(hwnd, IDC_NOTIFICATIONSOUND_CHK, s.notification_sound);
            set_check(hwnd, IDC_NOTIF_FULLSCREEN_CHK, s.notification_fullscreen_silent);
            set_check(hwnd, IDC_NOTIFICATIONONTRAY_CHK, s.notification_on_tray);
            set_edit(hwnd, IDC_NOTIFICATIONTIMEOUT_CTRL, &s.notification_timeout.to_string());
        }
        return 1;
    }
    0
}

unsafe extern "system" fn logging_proc(
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
            let s = unsafe { &*raw }.initial.borrow();
            set_check(hwnd, IDC_ENABLELOG_CHK, s.enable_log);
            set_edit(hwnd, IDC_LOGPATH, &s.log_path);
            set_edit(hwnd, IDC_LOGSIZELIMIT_CTRL, &s.log_size_limit.to_string());
            set_edit(hwnd, IDC_LOGVIEWER, &s.log_viewer);
            set_check(hwnd, IDC_ENABLEUILOG_CHK, s.enable_ui_log);
        }
        return 1;
    }
    0
}

unsafe extern "system" fn exclude_proc(
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
            let s = unsafe { &*raw }.initial.borrow();
            set_check(hwnd, IDC_EXCLUDEBLOCKLIST_CHK, s.exclude_blocklist);
            set_check(hwnd, IDC_EXCLUDECUSTOM_CHK, s.exclude_custom);
            set_check(hwnd, IDC_EXCLUDESTEALTH_CHK, s.exclude_stealth);
            set_check(hwnd, IDC_EXCLUDECLASSIFYALLOW_CHK, s.exclude_classify_allow);
        }
        return 1;
    }
    0
}

// =================================================================
// Helpers.
// =================================================================

fn set_check(parent: HWND, id: i32, checked: bool) {
    let state = if checked { BST_CHECKED.0 } else { BST_UNCHECKED.0 };
    unsafe {
        SendDlgItemMessageW(
            parent,
            id,
            BM_SETCHECK,
            WPARAM(state as usize),
            LPARAM(0),
        );
    }
}

fn read_check(parent: HWND, id: i32) -> bool {
    if parent.0 == 0 {
        return false;
    }
    let r = unsafe { SendDlgItemMessageW(parent, id, BM_GETCHECK, WPARAM(0), LPARAM(0)) };
    r.0 == BST_CHECKED.0 as isize
}

fn set_radio_blocklist(parent: HWND, mode: BlocklistMode, dis: i32, allow: i32, block: i32) {
    set_check(parent, dis, matches!(mode, BlocklistMode::Disable));
    set_check(parent, allow, matches!(mode, BlocklistMode::Allow));
    set_check(parent, block, matches!(mode, BlocklistMode::Block));
}

fn read_radio_blocklist(parent: HWND, _dis: i32, allow: i32, block: i32) -> BlocklistMode {
    // The "Disable" branch is the default — both an unselected
    // group (no radio checked) and an explicit Disable-checked
    // map to BlocklistMode::Disable, so we don't need to read
    // it back; just check the two non-default options.
    if read_check(parent, allow) {
        BlocklistMode::Allow
    } else if read_check(parent, block) {
        BlocklistMode::Block
    } else {
        BlocklistMode::Disable
    }
}

fn set_edit(parent: HWND, id: i32, text: &str) {
    use windows::Win32::UI::WindowsAndMessaging::SetDlgItemTextW;
    let buf = wide(text);
    let _ = unsafe { SetDlgItemTextW(parent, id, PCWSTR(buf.as_ptr())) };
}

fn read_edit(parent: HWND, id: i32) -> String {
    use windows::Win32::UI::WindowsAndMessaging::GetDlgItemTextW;
    if parent.0 == 0 {
        return String::new();
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { GetDlgItemTextW(parent, id, &mut buf) } as usize;
    String::from_utf16_lossy(&buf[..n])
}

fn read_u32(parent: HWND, id: i32) -> Option<u32> {
    let s = read_edit(parent, id);
    s.trim().parse::<u32>().ok()
}

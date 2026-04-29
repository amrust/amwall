// amwall — Settings property sheet.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Eight tabs total — General / Interface / Highlighting / Rules /
// Blocklist / Notifications / Logging / Exclude.
//
// Built on the Win32 PropertySheet API. Earlier versions used a
// custom IDD_SETTINGS dialog hosting a SysTabControl32 + 8
// CreateDialogParamW'd page dialogs, which had a paint bug where
// switching tabs (and resizing) left the page's template controls
// invisible until each was hover hot-tracked. The system property
// sheet orchestrates page show/hide and paint internally, so the
// bug doesn't surface there. PropertySheet also caps the dialog
// to its template size automatically — no resize, matching upstream
// simplewall's behavior.
//
// Persistence: each page proc populates its controls from the
// `initial` snapshot on WM_INITDIALOG, and writes them back to
// `result` on PSN_APPLY. Pages the user never visits aren't
// created (lazy init), so their fields in `result` keep the
// initial values — correct: nothing changed, nothing to save.

#![cfg(windows)]

use std::cell::RefCell;
use std::mem::size_of;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, NMHDR, PROPSHEETHEADERW_V2, PROPSHEETPAGEW, PSH_NOAPPLYNOW,
    PSH_NOCONTEXTHELP, PSH_PROPSHEETPAGE, PSP_DEFAULT, PSP_USETITLE, PropertySheetW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, DLGPROC, DWLP_MSGRESULT, GWLP_USERDATA, GetWindowLongPtrW,
    SendDlgItemMessageW, SetWindowLongPtrW, WINDOW_LONG_PTR_INDEX, WM_INITDIALOG, WM_NOTIFY,
};
use windows::core::PCWSTR;

use super::settings::{BlocklistMode, Settings};
use super::wide;

// ---- Resource IDs hand-synced with assets/amwall.rc ----

const IDD_SETTINGS_GENERAL: u16 = 201;
const IDD_SETTINGS_INTERFACE: u16 = 202;
const IDD_SETTINGS_HIGHLIGHTING: u16 = 203;
const IDD_SETTINGS_RULES: u16 = 204;
const IDD_SETTINGS_BLOCKLIST: u16 = 205;
const IDD_SETTINGS_NOTIFICATIONS: u16 = 206;
const IDD_SETTINGS_LOGGING: u16 = 207;
const IDD_SETTINGS_EXCLUDE: u16 = 208;

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

/// Shared between all 8 pages via `PROPSHEETPAGEW.lParam`. Each page
/// reads `initial` on WM_INITDIALOG and writes to `result` on
/// PSN_APPLY. Unvisited pages keep `result` at its initial-clone
/// state.
struct DialogState {
    initial: Settings,
    result: RefCell<Settings>,
}

/// Open the modal Settings property sheet. Returns the modified
/// `Settings` on OK, `None` on Cancel.
pub fn open(parent: HWND, initial: &Settings) -> Option<Settings> {
    let state = Box::new(DialogState {
        initial: initial.clone(),
        result: RefCell::new(initial.clone()),
    });
    let state_ptr = Box::into_raw(state);
    let raw = state_ptr as isize;

    let hi = match unsafe {
        windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
    } {
        Ok(h) => h,
        Err(_) => {
            // Reclaim the box so it doesn't leak.
            unsafe {
                let _ = Box::from_raw(state_ptr);
            }
            return None;
        }
    };

    let templates: [u16; 8] = [
        IDD_SETTINGS_GENERAL,
        IDD_SETTINGS_INTERFACE,
        IDD_SETTINGS_HIGHLIGHTING,
        IDD_SETTINGS_RULES,
        IDD_SETTINGS_BLOCKLIST,
        IDD_SETTINGS_NOTIFICATIONS,
        IDD_SETTINGS_LOGGING,
        IDD_SETTINGS_EXCLUDE,
    ];
    let procs: [DLGPROC; 8] = [
        Some(general_proc),
        Some(interface_proc),
        Some(highlighting_proc),
        Some(rules_proc),
        Some(blocklist_proc),
        Some(notifications_proc),
        Some(logging_proc),
        Some(exclude_proc),
    ];
    let titles = [
        "General",
        "Interface",
        "Highlighting",
        "Rules",
        "Blocklist",
        "Notifications",
        "Logging",
        "Exclude",
    ];
    // Tab labels: PropertySheet reads `pszTitle` (when PSP_USETITLE
    // is set) for each tab. Our IDD_SETTINGS_* dialog templates have
    // no CAPTION, so without PSP_USETITLE the tabs render blank.
    // Title buffers must outlive PropertySheetW — keep them in a
    // Vec parallel to `pages`.
    let title_buffers: Vec<Vec<u16>> = titles.iter().map(|t| wide(t)).collect();

    let mut pages: Vec<PROPSHEETPAGEW> = Vec::with_capacity(8);
    for i in 0..8 {
        let mut psp: PROPSHEETPAGEW = unsafe { std::mem::zeroed() };
        psp.dwSize = size_of::<PROPSHEETPAGEW>() as u32;
        psp.dwFlags = PSP_DEFAULT | PSP_USETITLE;
        psp.hInstance = hi.into();
        psp.Anonymous1.pszTemplate = make_int_resource(templates[i]);
        psp.Anonymous2.pszIcon = PCWSTR::null();
        psp.pszTitle = PCWSTR(title_buffers[i].as_ptr());
        psp.pfnDlgProc = procs[i];
        psp.lParam = LPARAM(raw);
        pages.push(psp);
    }

    let caption = wide("Settings");

    let mut header: PROPSHEETHEADERW_V2 = unsafe { std::mem::zeroed() };
    header.dwSize = size_of::<PROPSHEETHEADERW_V2>() as u32;
    header.dwFlags = PSH_PROPSHEETPAGE | PSH_NOAPPLYNOW | PSH_NOCONTEXTHELP;
    header.hwndParent = parent;
    header.hInstance = hi.into();
    header.pszCaption = PCWSTR(caption.as_ptr());
    header.nPages = pages.len() as u32;
    header.Anonymous2.nStartPage = 0;
    header.Anonymous3.ppsp = pages.as_mut_ptr();

    let result = unsafe { PropertySheetW(&mut header) };

    let state = unsafe { Box::from_raw(state_ptr) };
    if result > 0 {
        Some(state.result.into_inner())
    } else {
        None
    }
}

/// Recover the `DialogState` pointer that the page proc parked in
/// `GWLP_USERDATA` on WM_INITDIALOG.
unsafe fn state_ref<'a>(hwnd: HWND) -> Option<&'a DialogState> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const DialogState;
    if raw.is_null() { None } else { Some(unsafe { &*raw }) }
}

/// Pull the shared `DialogState` pointer out of `lparam` (which on
/// PropertySheet WM_INITDIALOG points at the `PROPSHEETPAGEW` we
/// supplied) and park it in the page's `GWLP_USERDATA` for later
/// retrieval on PSN_APPLY.
unsafe fn install_state(hwnd: HWND, lparam: LPARAM) -> Option<&'static DialogState> {
    let psp = lparam.0 as *const PROPSHEETPAGEW;
    if psp.is_null() {
        return None;
    }
    let raw = unsafe { (*psp).lParam.0 };
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, raw);
    }
    let ptr = raw as *const DialogState;
    if ptr.is_null() { None } else { Some(unsafe { &*ptr }) }
}

/// Inspect a WM_NOTIFY message; if it's PSN_APPLY, return TRUE so
/// the page proc can run its save logic. Otherwise FALSE.
fn is_psn_apply(lparam: LPARAM) -> bool {
    use windows::Win32::UI::Controls::PSN_APPLY;
    let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
    nmhdr.code == PSN_APPLY
}

/// Tell PropertySheet "this page accepted the apply" (PSNRET_NOERROR
/// = 0, the default). Returning TRUE from the proc with
/// DWLP_MSGRESULT = 0 is the standard way to commit.
unsafe fn accept_apply(hwnd: HWND) {
    unsafe {
        SetWindowLongPtrW(hwnd, WINDOW_LONG_PTR_INDEX(DWLP_MSGRESULT as i32), 0);
    }
}

// =================================================================
// Per-page dlg procs.
//
// Each one:
//   - WM_INITDIALOG  → install_state, populate controls from initial
//   - WM_NOTIFY/PSN_APPLY  → read controls back into result
// =================================================================

unsafe extern "system" fn general_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                let s = &state.initial;
                set_check(hwnd, IDC_ALWAYSONTOP_CHK, s.always_on_top);
                set_check(hwnd, IDC_LOADONSTARTUP_CHK, s.load_on_startup);
                set_check(hwnd, IDC_STARTMINIMIZED_CHK, s.start_minimized);
                set_check(hwnd, IDC_SKIPUACWARNING_CHK, s.skip_uac_warning);
                set_check(hwnd, IDC_CHECKUPDATES_CHK, s.check_updates);
            }
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let mut s = state.result.borrow_mut();
                s.always_on_top = read_check(hwnd, IDC_ALWAYSONTOP_CHK);
                s.load_on_startup = read_check(hwnd, IDC_LOADONSTARTUP_CHK);
                s.start_minimized = read_check(hwnd, IDC_STARTMINIMIZED_CHK);
                s.skip_uac_warning = read_check(hwnd, IDC_SKIPUACWARNING_CHK);
                s.check_updates = read_check(hwnd, IDC_CHECKUPDATES_CHK);
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

unsafe extern "system" fn interface_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                let s = &state.initial;
                set_check(hwnd, IDC_CONFIRMEXIT_CHK, s.confirm_exit);
                set_check(hwnd, IDC_CONFIRMEXITTIMER_CHK, s.confirm_exit_timer);
                set_check(hwnd, IDC_CONFIRMLOGCLEAR_CHK, s.confirm_log_clear);
                set_check(hwnd, IDC_CONFIRMALLOW_CHK, s.confirm_allow);
                set_check(hwnd, IDC_TRAYICONSINGLECLICK_CHK, s.tray_single_click);
            }
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let mut s = state.result.borrow_mut();
                s.confirm_exit = read_check(hwnd, IDC_CONFIRMEXIT_CHK);
                s.confirm_exit_timer = read_check(hwnd, IDC_CONFIRMEXITTIMER_CHK);
                s.confirm_log_clear = read_check(hwnd, IDC_CONFIRMLOGCLEAR_CHK);
                s.confirm_allow = read_check(hwnd, IDC_CONFIRMALLOW_CHK);
                s.tray_single_click = read_check(hwnd, IDC_TRAYICONSINGLECLICK_CHK);
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

unsafe extern "system" fn highlighting_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            // Color editing UI lands in M5.9 polish; the page renders
            // for layout parity with upstream but the listview stays
            // empty for now. Still install_state so PSN_APPLY (no-op
            // here) finds the pointer.
            let _ = unsafe { install_state(hwnd, lparam) };
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

unsafe extern "system" fn rules_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                let s = &state.initial;
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
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let mut s = state.result.borrow_mut();
                s.rule_block_outbound = read_check(hwnd, IDC_S_RULE_BLOCKOUTBOUND);
                s.rule_block_inbound = read_check(hwnd, IDC_S_RULE_BLOCKINBOUND);
                s.rule_allow_loopback = read_check(hwnd, IDC_S_RULE_ALLOWLOOPBACK);
                s.rule_allow_6to4 = read_check(hwnd, IDC_S_RULE_ALLOW6TO4);
                s.use_stealth_mode = read_check(hwnd, IDC_USESTEALTHMODE_CHK);
                s.install_boottime_filters = read_check(hwnd, IDC_INSTALLBOOTTIMEFILTERS_CHK);
                s.use_certificates = read_check(hwnd, IDC_USECERTIFICATES_CHK);
                s.use_hashes = read_check(hwnd, IDC_USEHASHES_CHK);
                s.use_network_resolution = read_check(hwnd, IDC_USENETWORKRESOLUTION_CHK);
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

unsafe extern "system" fn blocklist_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                let s = &state.initial;
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
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let mut s = state.result.borrow_mut();
                s.blocklist_spy = read_radio_blocklist(
                    hwnd,
                    IDC_S_BLOCKLIST_SPY_DISABLE,
                    IDC_S_BLOCKLIST_SPY_ALLOW,
                    IDC_S_BLOCKLIST_SPY_BLOCK,
                );
                s.blocklist_update = read_radio_blocklist(
                    hwnd,
                    IDC_S_BLOCKLIST_UPDATE_DISABLE,
                    IDC_S_BLOCKLIST_UPDATE_ALLOW,
                    IDC_S_BLOCKLIST_UPDATE_BLOCK,
                );
                s.blocklist_extra = read_radio_blocklist(
                    hwnd,
                    IDC_S_BLOCKLIST_EXTRA_DISABLE,
                    IDC_S_BLOCKLIST_EXTRA_ALLOW,
                    IDC_S_BLOCKLIST_EXTRA_BLOCK,
                );
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

unsafe extern "system" fn notifications_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                let s = &state.initial;
                set_check(hwnd, IDC_ENABLENOTIFICATIONS_CHK, s.enable_notifications);
                set_check(hwnd, IDC_NOTIFICATIONSOUND_CHK, s.notification_sound);
                set_check(hwnd, IDC_NOTIF_FULLSCREEN_CHK, s.notification_fullscreen_silent);
                set_check(hwnd, IDC_NOTIFICATIONONTRAY_CHK, s.notification_on_tray);
                set_edit(hwnd, IDC_NOTIFICATIONTIMEOUT_CTRL, &s.notification_timeout.to_string());
            }
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let mut s = state.result.borrow_mut();
                s.enable_notifications = read_check(hwnd, IDC_ENABLENOTIFICATIONS_CHK);
                s.notification_sound = read_check(hwnd, IDC_NOTIFICATIONSOUND_CHK);
                s.notification_fullscreen_silent = read_check(hwnd, IDC_NOTIF_FULLSCREEN_CHK);
                s.notification_on_tray = read_check(hwnd, IDC_NOTIFICATIONONTRAY_CHK);
                if let Some(v) = read_u32(hwnd, IDC_NOTIFICATIONTIMEOUT_CTRL) {
                    s.notification_timeout = v;
                }
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

unsafe extern "system" fn logging_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                let s = &state.initial;
                set_check(hwnd, IDC_ENABLELOG_CHK, s.enable_log);
                set_edit(hwnd, IDC_LOGPATH, &s.log_path);
                set_edit(hwnd, IDC_LOGSIZELIMIT_CTRL, &s.log_size_limit.to_string());
                set_edit(hwnd, IDC_LOGVIEWER, &s.log_viewer);
                set_check(hwnd, IDC_ENABLEUILOG_CHK, s.enable_ui_log);
            }
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let mut s = state.result.borrow_mut();
                s.enable_log = read_check(hwnd, IDC_ENABLELOG_CHK);
                s.log_path = read_edit(hwnd, IDC_LOGPATH);
                if let Some(v) = read_u32(hwnd, IDC_LOGSIZELIMIT_CTRL) {
                    s.log_size_limit = v;
                }
                s.log_viewer = read_edit(hwnd, IDC_LOGVIEWER);
                s.enable_ui_log = read_check(hwnd, IDC_ENABLEUILOG_CHK);
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

unsafe extern "system" fn exclude_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                let s = &state.initial;
                set_check(hwnd, IDC_EXCLUDEBLOCKLIST_CHK, s.exclude_blocklist);
                set_check(hwnd, IDC_EXCLUDECUSTOM_CHK, s.exclude_custom);
                set_check(hwnd, IDC_EXCLUDESTEALTH_CHK, s.exclude_stealth);
                set_check(hwnd, IDC_EXCLUDECLASSIFYALLOW_CHK, s.exclude_classify_allow);
            }
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let mut s = state.result.borrow_mut();
                s.exclude_blocklist = read_check(hwnd, IDC_EXCLUDEBLOCKLIST_CHK);
                s.exclude_custom = read_check(hwnd, IDC_EXCLUDECUSTOM_CHK);
                s.exclude_stealth = read_check(hwnd, IDC_EXCLUDESTEALTH_CHK);
                s.exclude_classify_allow = read_check(hwnd, IDC_EXCLUDECLASSIFYALLOW_CHK);
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
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

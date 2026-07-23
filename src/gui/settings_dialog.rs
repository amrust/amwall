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

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::Dialogs::{
    CC_FULLOPEN, CC_RGBINIT, CHOOSECOLORW, ChooseColorW,
};
use windows::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, CDDS_ITEMPREPAINT, CDDS_PREPAINT, CDRF_DODEFAULT, CDRF_NEWFONT,
    CDRF_NOTIFYITEMDRAW, LIST_VIEW_ITEM_STATE_FLAGS, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCOLUMNW,
    LVIF_STATE, LVIF_TEXT, LVIS_STATEIMAGEMASK, LVITEMW, LVM_GETITEMSTATE, LVM_INSERTCOLUMNW,
    LVM_INSERTITEMW, LVM_REDRAWITEMS, LVM_SETEXTENDEDLISTVIEWSTYLE,
    LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, NM_CUSTOMDRAW, NM_DBLCLK,
    NMHDR, NMITEMACTIVATE, NMLVCUSTOMDRAW, PROPSHEETHEADERW_V2, PROPSHEETPAGEW, PSH_NOAPPLYNOW,
    PSH_NOCONTEXTHELP, PSH_PROPSHEETPAGE, PSP_DEFAULT, PSP_USETITLE, PropertySheetW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, DLGPROC, DWLP_MSGRESULT, GWLP_USERDATA, GetDlgItem,
    GetWindowLongPtrW, SendDlgItemMessageW, SendMessageW, SetWindowLongPtrW, WINDOW_LONG_PTR_INDEX,
    WM_INITDIALOG, WM_NOTIFY,
};
use windows::core::{PCWSTR, PWSTR};

use rust_i18n::t;

use super::settings::{BlocklistMode, Settings};
use super::wide;

fn set_text(hwnd: HWND, id: i32, key: &str) {
    let s = t!(key);
    let w = wide(&s);
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::SetDlgItemTextW(
            hwnd, id, PCWSTR(w.as_ptr()),
        );
    }
}

#[allow(dead_code)]
fn set_caption(hwnd: HWND, key: &str) {
    let s = t!(key);
    let w = wide(&s);
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowTextW(
            hwnd, PCWSTR(w.as_ptr()),
        );
    }
}

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
const IDC_LANGUAGE: i32 = 725;
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

// Groupbox / label IDs added for localization (synced with amwall.rc 900+)
const IDC_GRP_GENERAL_CONFIG: i32 = 726;
const IDC_GRP_LANGUAGE: i32 = 727;
const IDC_LBL_SELECT_LANGUAGE: i32 = 728;
const IDC_GRP_CONFIRMATIONS: i32 = 735;
const IDC_GRP_TRAYICON: i32 = 736;
const IDC_COLORS: i32 = 740;
const IDC_GRP_HIGHLIGHTING: i32 = 741;
const IDC_LBL_HIGHLIGHT_HINT: i32 = 742;
const IDC_GRP_CONNECTIONS: i32 = 900;
const IDC_GRP_SECURITY: i32 = 901;
const IDC_GRP_ADVANCED: i32 = 902;
const IDC_GRP_BLOCKLIST_SPY: i32 = 903;
const IDC_GRP_BLOCKLIST_UPDATE: i32 = 904;
const IDC_GRP_BLOCKLIST_EXTRA: i32 = 905;
const IDC_GRP_NOTIFICATIONS: i32 = 906;
const IDC_LBL_NOTIF_TIMEOUT: i32 = 907;
const IDC_GRP_PACKETS_LOG: i32 = 908;
const IDC_LBL_MAX_LOG_SIZE: i32 = 909;
const IDC_GRP_LOG_VIEWER: i32 = 910;
const IDC_GRP_LOG_UI: i32 = 911;
const IDC_GRP_EXCLUDE_NOTIF: i32 = 912;
const IDC_GRP_EXCLUDE_LOG: i32 = 913;

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
    language_codes: RefCell<Vec<String>>,
}

/// Open the modal Settings property sheet. Returns the modified
/// `Settings` on OK, `None` on Cancel.
pub fn open(parent: HWND, initial: &Settings) -> Option<Settings> {
    let state = Box::new(DialogState {
        initial: initial.clone(),
        result: RefCell::new(initial.clone()),
        language_codes: RefCell::new(Vec::new()),
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
    let titles: [String; 8] = [
        rust_i18n::t!("settings_tab.general").into(),
        rust_i18n::t!("settings_tab.interface").into(),
        rust_i18n::t!("settings_tab.highlighting").into(),
        rust_i18n::t!("settings_tab.rules").into(),
        rust_i18n::t!("settings_tab.blocklist").into(),
        rust_i18n::t!("settings_tab.notifications").into(),
        rust_i18n::t!("settings_tab.logging").into(),
        rust_i18n::t!("settings_tab.exclude").into(),
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

    let caption = wide(&rust_i18n::t!("dialog.settings_title"));

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
                populate_language_combo(hwnd, &s.language, state);

                set_text(hwnd, IDC_GRP_GENERAL_CONFIG, "rc_general.group_config");
                set_text(hwnd, IDC_ALWAYSONTOP_CHK, "rc_general.always_on_top");
                set_text(hwnd, IDC_LOADONSTARTUP_CHK, "rc_general.load_on_startup");
                set_text(hwnd, IDC_STARTMINIMIZED_CHK, "rc_general.start_minimized");
                set_text(hwnd, IDC_SKIPUACWARNING_CHK, "rc_general.skip_uac");
                set_text(hwnd, IDC_CHECKUPDATES_CHK, "rc_general.check_updates");
                set_text(hwnd, IDC_GRP_LANGUAGE, "rc_general.group_language");
                set_text(hwnd, IDC_LBL_SELECT_LANGUAGE, "rc_general.select_language");
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
                s.language = read_language_combo(hwnd, state);
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        _ => 0,
    }
}

fn locale_display_name(code: &str) -> String {
    let name = match code {
        "ar" => "العربية",
        "az" => "Azərbaycanca",
        "be" => "Беларуская",
        "bg" => "Български",
        "ca" => "Català",
        "cs" => "Čeština",
        "da" => "Dansk",
        "de" => "Deutsch",
        "el" => "Ελληνικά",
        "en" => "English",
        "es" => "Español",
        "et" => "Eesti",
        "fa" => "فارسی",
        "fi" => "Suomi",
        "fr" => "Français",
        "he" => "עברית",
        "hi" => "हिन्दी",
        "hr" => "Hrvatski",
        "hu" => "Magyar",
        "hy" => "Հայերեն",
        "id" => "Bahasa Indonesia",
        "it" => "Italiano",
        "ja" => "日本語",
        "ka" => "ქართული",
        "kk" => "Қазақша",
        "ko" => "한국어",
        "ky" => "Кыргызча",
        "lt" => "Lietuvių",
        "lv" => "Latviešu",
        "nl" => "Nederlands",
        "no" => "Norsk",
        "pl" => "Polski",
        "pt" => "Português",
        "pt-BR" => "Português (Brasil)",
        "ro" => "Română",
        "ru" => "Русский",
        "sk" => "Slovenčina",
        "sl" => "Slovenščina",
        "sr" => "Српски",
        "sr-Latn" => "Srpski (latinica)",
        "sv" => "Svenska",
        "th" => "ไทย",
        "tr" => "Türkçe",
        "uk" => "Українська",
        "vi" => "Tiếng Việt",
        "zh" => "中文",
        "zh-CN" => "简体中文",
        "zh-TW" => "正體中文",
        _ => code,
    };
    format!("{name} ({code})")
}

fn populate_language_combo(hwnd: HWND, current: &str, state: &DialogState) {
    use windows::Win32::UI::WindowsAndMessaging::{
        CB_ADDSTRING, CB_RESETCONTENT, CB_SETCURSEL,
    };

    let combo = unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, IDC_LANGUAGE)
    };
    if combo.0 == 0 {
        return;
    }

    unsafe {
        windows::Win32::UI::WindowsAndMessaging::SendMessageW(
            combo,
            CB_RESETCONTENT,
            WPARAM(0),
            LPARAM(0),
        );
    }

    let mut codes: Vec<String> = rust_i18n::available_locales!()
        .iter()
        .map(|s| s.to_string())
        .collect();
    codes.sort_by(|a, b| {
        locale_display_name(a)
            .to_lowercase()
            .cmp(&locale_display_name(b).to_lowercase())
    });

    let mut labels: Vec<String> = vec!["(System default)".to_string()];
    let mut code_list: Vec<String> = vec![String::new()];
    for code in &codes {
        labels.push(locale_display_name(code));
        code_list.push(code.clone());
    }

    let mut sel: usize = 0;
    for (idx, label) in labels.iter().enumerate() {
        let mut wbuf = wide(label);
        unsafe {
            windows::Win32::UI::WindowsAndMessaging::SendMessageW(
                combo,
                CB_ADDSTRING,
                WPARAM(0),
                LPARAM(wbuf.as_mut_ptr() as isize),
            );
        }
        if idx > 0 && current.eq_ignore_ascii_case(&code_list[idx]) {
            sel = idx;
        }
    }

    unsafe {
        windows::Win32::UI::WindowsAndMessaging::SendMessageW(
            combo,
            CB_SETCURSEL,
            WPARAM(sel),
            LPARAM(0),
        );
    }
    *state.language_codes.borrow_mut() = code_list;
}

fn read_language_combo(hwnd: HWND, state: &DialogState) -> String {
    let combo = unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, IDC_LANGUAGE)
    };
    if combo.0 == 0 {
        return String::new();
    }

    let sel = unsafe {
        windows::Win32::UI::WindowsAndMessaging::SendMessageW(
            combo,
            windows::Win32::UI::WindowsAndMessaging::CB_GETCURSEL,
            WPARAM(0),
            LPARAM(0),
        )
    }
    .0 as isize;
    if sel <= 0 {
        return String::new();
    }

    let codes = state.language_codes.borrow();
    codes.get(sel as usize).cloned().unwrap_or_default()
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

                set_text(hwnd, IDC_GRP_CONFIRMATIONS, "rc_interface.group_confirm");
                set_text(hwnd, IDC_CONFIRMEXIT_CHK, "rc_interface.confirm_exit");
                set_text(hwnd, IDC_CONFIRMEXITTIMER_CHK, "rc_interface.confirm_exit_timer");
                set_text(hwnd, IDC_CONFIRMLOGCLEAR_CHK, "rc_interface.confirm_log_clear");
                set_text(hwnd, IDC_CONFIRMALLOW_CHK, "rc_interface.confirm_allow");
                set_text(hwnd, IDC_GRP_TRAYICON, "rc_interface.group_tray");
                set_text(hwnd, IDC_TRAYICONSINGLECLICK_CHK, "rc_interface.tray_single_click");
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

// ---- Highlighting page: the 7 row-color categories (Fable #31) ----
//
// Order matches upstream's _app_addcolor calls (main.c:2116-2122) and
// the row order in the IDC_COLORS listview: row index == category index.
const HIGHLIGHT_LABELS: [&str; 7] = [
    "rc_highlight.invalid",
    "rc_highlight.special",
    "rc_highlight.signed",
    "rc_highlight.pico",
    "rc_highlight.system",
    "rc_highlight.connection",
    "rc_highlight.undelete",
];

/// The current (result) color for category `idx`, packed COLORREF.
fn highlight_color(s: &Settings, idx: usize) -> u32 {
    match idx {
        0 => s.color_invalid,
        1 => s.color_special,
        2 => s.color_signed,
        3 => s.color_pico,
        4 => s.color_system,
        5 => s.color_connection,
        6 => s.color_undelete,
        _ => 0,
    }
}

fn set_highlight_color(s: &mut Settings, idx: usize, c: u32) {
    match idx {
        0 => s.color_invalid = c,
        1 => s.color_special = c,
        2 => s.color_signed = c,
        3 => s.color_pico = c,
        4 => s.color_system = c,
        5 => s.color_connection = c,
        6 => s.color_undelete = c,
        _ => {}
    }
}

fn highlight_enabled(s: &Settings, idx: usize) -> bool {
    match idx {
        0 => s.highlight_invalid,
        1 => s.highlight_special,
        2 => s.highlight_signed,
        3 => s.highlight_pico,
        4 => s.highlight_system,
        5 => s.highlight_connection,
        6 => s.highlight_undelete,
        _ => false,
    }
}

fn set_highlight_enabled(s: &mut Settings, idx: usize, on: bool) {
    match idx {
        0 => s.highlight_invalid = on,
        1 => s.highlight_special = on,
        2 => s.highlight_signed = on,
        3 => s.highlight_pico = on,
        4 => s.highlight_system = on,
        5 => s.highlight_connection = on,
        6 => s.highlight_undelete = on,
        _ => {}
    }
}

/// The Highlighting page. A checkbox-listview (IDC_COLORS) lists the 7
/// categories; the checkbox toggles the category's enable flag and a
/// double-click opens ChooseColorW to recolor it. Each row paints in
/// its own color via NM_CUSTOMDRAW so the user sees a live swatch.
/// Enables are read back on PSN_APPLY; colors are written live into
/// `result` by the picker (discarded wholesale on Cancel). Mirrors
/// upstream main.c:672-718 / 1276-1361 / messages.c:1081-1088.
unsafe extern "system" fn highlighting_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Some(state) = unsafe { install_state(hwnd, lparam) } {
                set_text(hwnd, IDC_GRP_HIGHLIGHTING, "rc_highlight.group");
                set_text(hwnd, IDC_LBL_HIGHLIGHT_HINT, "rc_highlight.hint");
                let lv = unsafe { GetDlgItem(hwnd, IDC_COLORS) };
                if lv.0 != 0 {
                    unsafe {
                        SendMessageW(
                            lv,
                            LVM_SETEXTENDEDLISTVIEWSTYLE,
                            WPARAM(0),
                            LPARAM(
                                (LVS_EX_CHECKBOXES
                                    | LVS_EX_DOUBLEBUFFER
                                    | LVS_EX_FULLROWSELECT)
                                    as isize,
                            ),
                        );
                    }
                    // Single full-width, header-less column.
                    let mut colbuf = wide("");
                    let col = LVCOLUMNW {
                        mask: LVCF_TEXT | LVCF_WIDTH,
                        fmt: LVCFMT_LEFT,
                        cx: 320,
                        pszText: PWSTR(colbuf.as_mut_ptr()),
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
                    let s = &state.initial;
                    for (idx, key) in HIGHLIGHT_LABELS.iter().enumerate() {
                        let mut text = wide(&t!(*key));
                        let state_image = if highlight_enabled(s, idx) { 2u32 } else { 1u32 };
                        let item = LVITEMW {
                            mask: LVIF_TEXT | LVIF_STATE,
                            iItem: idx as i32,
                            iSubItem: 0,
                            pszText: PWSTR(text.as_mut_ptr()),
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
            }
            1
        }
        WM_NOTIFY if is_psn_apply(lparam) => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let lv = unsafe { GetDlgItem(hwnd, IDC_COLORS) };
                if lv.0 != 0 {
                    let mut s = state.result.borrow_mut();
                    for idx in 0..HIGHLIGHT_LABELS.len() {
                        let st = unsafe {
                            SendMessageW(
                                lv,
                                LVM_GETITEMSTATE,
                                WPARAM(idx),
                                LPARAM(LVIS_STATEIMAGEMASK.0 as isize),
                            )
                        }
                        .0 as u32;
                        set_highlight_enabled(&mut s, idx, ((st >> 12) & 0xF) == 2);
                    }
                }
            }
            unsafe { accept_apply(hwnd) };
            1
        }
        WM_NOTIFY => {
            let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
            if nmhdr.idFrom != IDC_COLORS as usize {
                return 0;
            }
            match nmhdr.code {
                // Paint each row in its category's current color so the
                // listview doubles as a live swatch (messages.c:1081-1088).
                NM_CUSTOMDRAW => {
                    let nmlv = unsafe { &mut *(lparam.0 as *mut NMLVCUSTOMDRAW) };
                    let cdrf = match nmlv.nmcd.dwDrawStage {
                        x if x == CDDS_PREPAINT => CDRF_NOTIFYITEMDRAW,
                        x if x == CDDS_ITEMPREPAINT => {
                            let row = nmlv.nmcd.dwItemSpec;
                            if let Some(state) = unsafe { state_ref(hwnd) } {
                                if row < HIGHLIGHT_LABELS.len() {
                                    let c = highlight_color(&state.result.borrow(), row);
                                    nmlv.clrTextBk = COLORREF(c);
                                    CDRF_NEWFONT
                                } else {
                                    CDRF_DODEFAULT
                                }
                            } else {
                                CDRF_DODEFAULT
                            }
                        }
                        _ => CDRF_DODEFAULT,
                    };
                    unsafe {
                        SetWindowLongPtrW(
                            hwnd,
                            WINDOW_LONG_PTR_INDEX(DWLP_MSGRESULT as i32),
                            cdrf as isize,
                        );
                    }
                    1
                }
                // Double-click a row → pick a new color for that category.
                NM_DBLCLK => {
                    let nmia = unsafe { &*(lparam.0 as *const NMITEMACTIVATE) };
                    let row = nmia.iItem;
                    if row < 0 || row as usize >= HIGHLIGHT_LABELS.len() {
                        return 0;
                    }
                    let row = row as usize;
                    let Some(state) = (unsafe { state_ref(hwnd) }) else {
                        return 0;
                    };
                    // Read the current color WITHOUT holding the borrow
                    // across the modal ChooseColorW (which pumps messages
                    // and would re-enter our NM_CUSTOMDRAW borrow()).
                    let current = highlight_color(&state.result.borrow(), row);
                    // Custom-color palette seeded with the 7 defaults so
                    // the user can restore any category's stock color.
                    let defaults = Settings::default();
                    let mut custom: [COLORREF; 16] = [COLORREF(0); 16];
                    for (i, slot) in custom
                        .iter_mut()
                        .take(HIGHLIGHT_LABELS.len())
                        .enumerate()
                    {
                        *slot = COLORREF(highlight_color(&defaults, i));
                    }
                    let mut cc = CHOOSECOLORW {
                        lStructSize: size_of::<CHOOSECOLORW>() as u32,
                        hwndOwner: hwnd,
                        rgbResult: COLORREF(current),
                        lpCustColors: custom.as_mut_ptr(),
                        Flags: CC_RGBINIT | CC_FULLOPEN,
                        ..Default::default()
                    };
                    let picked = unsafe { ChooseColorW(&mut cc) }.as_bool();
                    if picked {
                        let new = cc.rgbResult.0 & 0x00FF_FFFF;
                        set_highlight_color(&mut state.result.borrow_mut(), row, new);
                        let lv = unsafe { GetDlgItem(hwnd, IDC_COLORS) };
                        if lv.0 != 0 {
                            unsafe {
                                SendMessageW(
                                    lv,
                                    LVM_REDRAWITEMS,
                                    WPARAM(row),
                                    LPARAM(row as isize),
                                );
                            }
                        }
                    }
                    1
                }
                _ => 0,
            }
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

                set_text(hwnd, IDC_GRP_CONNECTIONS, "rc_rules.group_connections");
                set_text(hwnd, IDC_S_RULE_BLOCKOUTBOUND, "rc_rules.block_outbound");
                set_text(hwnd, IDC_S_RULE_BLOCKINBOUND, "rc_rules.block_inbound");
                set_text(hwnd, IDC_S_RULE_ALLOWLOOPBACK, "rc_rules.allow_loopback");
                set_text(hwnd, IDC_S_RULE_ALLOW6TO4, "rc_rules.allow_6to4");
                set_text(hwnd, IDC_GRP_SECURITY, "rc_rules.group_security");
                set_text(hwnd, IDC_USESTEALTHMODE_CHK, "rc_rules.stealth_mode");
                set_text(hwnd, IDC_INSTALLBOOTTIMEFILTERS_CHK, "rc_rules.boottime_filters");
                set_text(hwnd, IDC_GRP_ADVANCED, "rc_rules.group_advanced");
                set_text(hwnd, IDC_USECERTIFICATES_CHK, "rc_rules.check_signatures");
                set_text(hwnd, IDC_USEHASHES_CHK, "rc_rules.use_hashes");
                set_text(hwnd, IDC_USENETWORKRESOLUTION_CHK, "rc_rules.resolve_addresses");
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

                set_text(hwnd, IDC_GRP_BLOCKLIST_SPY, "rc_blocklist.group_spy");
                set_text(hwnd, IDC_GRP_BLOCKLIST_UPDATE, "rc_blocklist.group_update");
                set_text(hwnd, IDC_GRP_BLOCKLIST_EXTRA, "rc_blocklist.group_apps");
                set_text(hwnd, IDC_S_BLOCKLIST_SPY_DISABLE, "blocklist.disable");
                set_text(hwnd, IDC_S_BLOCKLIST_SPY_ALLOW, "blocklist.allow");
                set_text(hwnd, IDC_S_BLOCKLIST_SPY_BLOCK, "blocklist.block");
                set_text(hwnd, IDC_S_BLOCKLIST_UPDATE_DISABLE, "blocklist.disable");
                set_text(hwnd, IDC_S_BLOCKLIST_UPDATE_ALLOW, "blocklist.allow");
                set_text(hwnd, IDC_S_BLOCKLIST_UPDATE_BLOCK, "blocklist.block");
                set_text(hwnd, IDC_S_BLOCKLIST_EXTRA_DISABLE, "blocklist.disable");
                set_text(hwnd, IDC_S_BLOCKLIST_EXTRA_ALLOW, "blocklist.allow");
                set_text(hwnd, IDC_S_BLOCKLIST_EXTRA_BLOCK, "blocklist.block");
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

                set_text(hwnd, IDC_GRP_NOTIFICATIONS, "rc_notifications.group");
                set_text(hwnd, IDC_ENABLENOTIFICATIONS_CHK, "rc_notifications.enable");
                set_text(hwnd, IDC_NOTIFICATIONSOUND_CHK, "rc_notifications.sound");
                set_text(hwnd, IDC_NOTIF_FULLSCREEN_CHK, "rc_notifications.fullscreen");
                set_text(hwnd, IDC_NOTIFICATIONONTRAY_CHK, "rc_notifications.on_tray");
                set_text(hwnd, IDC_LBL_NOTIF_TIMEOUT, "rc_notifications.timeout");
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

                set_text(hwnd, IDC_GRP_PACKETS_LOG, "rc_logging.group_log");
                set_text(hwnd, IDC_ENABLELOG_CHK, "rc_logging.enable");
                set_text(hwnd, IDC_LBL_MAX_LOG_SIZE, "rc_logging.max_size");
                set_text(hwnd, IDC_GRP_LOG_VIEWER, "rc_logging.group_viewer");
                set_text(hwnd, IDC_GRP_LOG_UI, "rc_logging.group_ui");
                set_text(hwnd, IDC_ENABLEUILOG_CHK, "rc_logging.enable_ui");
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

                set_text(hwnd, IDC_GRP_EXCLUDE_NOTIF, "rc_exclude.group_notif");
                set_text(hwnd, IDC_EXCLUDEBLOCKLIST_CHK, "rc_exclude.blocklist");
                set_text(hwnd, IDC_EXCLUDECUSTOM_CHK, "rc_exclude.user_rules");
                set_text(hwnd, IDC_GRP_EXCLUDE_LOG, "rc_exclude.group_log");
                set_text(hwnd, IDC_EXCLUDESTEALTH_CHK, "rc_exclude.stealth");
                set_text(hwnd, IDC_EXCLUDECLASSIFYALLOW_CHK, "rc_exclude.allowed");
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
    // CheckRadioButton is the canonical Win32 idiom for radio
    // groups: it unchecks every button in the [first..=last] id
    // range and checks the chosen one in a single call. Plain
    // BM_SETCHECK on each radio individually leaves AUTORADIOBUTTON's
    // internal "current group member" state out of sync, which
    // shows up as the visual dot not appearing on reload even
    // though the underlying check state is correct.
    use windows::Win32::UI::Controls::CheckRadioButton;
    let pick = match mode {
        BlocklistMode::Disable => dis,
        BlocklistMode::Allow => allow,
        BlocklistMode::Block => block,
    };
    let lo = dis.min(allow).min(block);
    let hi = dis.max(allow).max(block);
    unsafe {
        let _ = CheckRadioButton(parent, lo, hi, pick);
    }
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

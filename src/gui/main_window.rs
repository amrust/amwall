// simplewall-rs — main window class + WndProc.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Programmatic Win32 (no .rc resources). Layout mirrors upstream
// simplewall 3.8.7 exactly — same menu structure (File / Edit / View /
// Settings / Blocklist / Help), same eight tabs in the same order
// (Apps / Services / UWP apps / Blocklist / System rules / User rules /
// Connections / Packets log), same column sets per tab. The point of
// matching upstream this closely is that anyone who's used the
// original sees the same UI here without retraining.
//
// One Win32 trick worth knowing: tab controls don't host their own
// children. Each tab's contents are siblings of the tab control, all
// children of the main window — we show/hide them when the user
// switches tabs. So `_listviews[8]` are siblings, not children, of
// `_tab`. `TabCtrl_AdjustRect` (TCM_ADJUSTRECT) is the supported way
// to compute the inner content rect.
//
// State plumbing follows the standard Win32-via-Rust pattern:
//   - `create` heap-allocates a `WndState` (caller passes us the
//     `Box<App>`; we wrap it).
//   - `WM_NCCREATE` parks the WndState pointer in `GWLP_USERDATA`.
//   - Every other handler reads it back via `GetWindowLongPtrW`.
//   - `WM_NCDESTROY` reclaims the Box so it drops cleanly.
//
// Panics inside a WndProc would unwind through Win32 (UB across the
// FFI boundary), so handlers use `match`/`Result`, not `?`/`expect`.

use std::cell::Cell;

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{HBRUSH, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_COOL_CLASSES, ICC_LISTVIEW_CLASSES, ICC_TAB_CLASSES, INITCOMMONCONTROLSEX,
    InitCommonControlsEx, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCFMT_RIGHT, LVCOLUMNW,
    LVIF_TEXT, LVITEMW, LVM_DELETEALLITEMS, LVM_INSERTCOLUMNW, LVM_INSERTITEMW,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMTEXTW, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER,
    LVS_EX_FULLROWSELECT, LVS_REPORT, LVS_SHOWSELALWAYS, NMHDR, SBARS_TOOLTIPS, SB_SETPARTS,
    SB_SETTEXTW, STATUSCLASSNAMEW, TCIF_TEXT, TCITEMW, TCM_ADJUSTRECT, TCM_GETCURSEL,
    TCM_INSERTITEMW, TCN_SELCHANGE, WC_LISTVIEWW, WC_TABCONTROLW,
};
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CREATESTRUCTW, CW_USEDEFAULT, CreateMenu, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyWindow, GWLP_USERDATA, GetClientRect, GetWindowLongPtrW, HMENU,
    IDC_ARROW, LoadCursorW, MF_POPUP, MF_SEPARATOR, MF_STRING, MoveWindow, RegisterClassExW,
    SW_HIDE, SW_SHOW, SW_SHOWNORMAL, SendMessageW, SetWindowLongPtrW, ShowWindow,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_NCCREATE,
    WM_NCDESTROY, WM_NOTIFY, WM_SIZE, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN,
    WS_CLIPSIBLINGS, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR, w};

use super::app::App;
use super::ids::{
    IDC_APPS_PROFILE, IDC_APPS_SERVICE, IDC_APPS_UWP, IDC_LOG, IDC_NETWORK,
    IDC_RULES_BLOCKLIST, IDC_RULES_CUSTOM, IDC_RULES_SYSTEM, IDC_STATUSBAR, IDC_TAB,
    IDM_ABOUT, IDM_ADD_FILE, IDM_ALWAYSONTOP_CHK, IDM_AUTOSIZECOLUMNS_CHK,
    IDM_BLOCKLIST_EXTRA_ALLOW, IDM_BLOCKLIST_EXTRA_BLOCK, IDM_BLOCKLIST_EXTRA_DISABLE,
    IDM_BLOCKLIST_SPY_ALLOW, IDM_BLOCKLIST_SPY_BLOCK, IDM_BLOCKLIST_SPY_DISABLE,
    IDM_BLOCKLIST_UPDATE_ALLOW, IDM_BLOCKLIST_UPDATE_BLOCK, IDM_BLOCKLIST_UPDATE_DISABLE,
    IDM_CHECKUPDATES, IDM_CHECKUPDATES_CHK, IDM_EXIT, IDM_EXPORT, IDM_FONT, IDM_IMPORT,
    IDM_LOADONSTARTUP_CHK, IDM_LOGCLEAR, IDM_PURGE_TIMERS, IDM_PURGE_UNUSED, IDM_REFRESH,
    IDM_RELEASES, IDM_RULE_ALLOW6TO4, IDM_RULE_ALLOWLOOPBACK, IDM_RULE_ALLOWWINDOWSUPDATE,
    IDM_RULE_BLOCKINBOUND, IDM_RULE_BLOCKOUTBOUND, IDM_SETTINGS, IDM_SHOWFILENAMESONLY_CHK,
    IDM_SHOWSEARCHBAR_CHK, IDM_SKIPUACWARNING_CHK, IDM_STARTMINIMIZED_CHK, IDM_USEDARKTHEME_CHK,
    IDM_WEBSITE, TAB_LISTVIEW_IDS,
};
use super::toolbar::{self, Toolbar};
use super::{post_quit, wide};

/// Window class name. Win32 uses this string to look up our class
/// registration.
const CLASS_NAME: PCWSTR = w!("SimplewallRsMainWindow");

/// Reference DPI (96 DPI = 100% scaling). Windows reports actual DPI
/// via `GetDpiForWindow`; we scale our hardcoded pixel values by
/// `actual_dpi / REFERENCE_DPI`. So a 900px-wide window at 225%
/// scaling becomes 900 * 2.25 = 2025px.
const REFERENCE_DPI: u32 = 96;

/// Logical (96-DPI) initial window dimensions. Real pixels are computed
/// in `create` once we know the monitor DPI.
const LOGICAL_INITIAL_W: i32 = 900;
const LOGICAL_INITIAL_H: i32 = 600;

/// Logical column widths per tab type. Real pixel widths are
/// computed at WM_CREATE time. Negative values in upstream were
/// "percent-of-rect" hints; we translate them to fixed logical
/// widths for the M5.2 baseline (M5.4 will revisit auto-sizing).
const APPS_COL_WIDTHS: &[i32] = &[280, 100]; // Name, Added
const RULES_COL_WIDTHS: &[i32] = &[280, 80, 80]; // Name, Protocol, Direction
const NETWORK_COL_WIDTHS: &[i32] = &[
    180, // Name
    110, // Address (Source)
    140, // Host (Source)
    60,  // Port (Source)
    110, // Address (Destination)
    140, // Host (Destination)
    60,  // Port (Destination)
    70,  // Protocol
    70,  // State
];
const LOG_COL_WIDTHS: &[i32] = &[
    50,  // #
    140, // Name
    110, // Date
    110, // Address (Source)
    120, // Host (Source)
    60,  // Port (Source)
    110, // Address (Destination)
    120, // Host (Destination)
    60,  // Port (Destination)
    70,  // Protocol
    70,  // Direction
    140, // Filter
];

/// Per-window state pointed to from `GWLP_USERDATA`. Holds the App
/// (heap-allocated by `gui::run`) plus cached child HWNDs and the
/// last-known DPI. We cache the toolbar/listview/status HWNDs to
/// avoid `GetDlgItem` lookups on every WM_SIZE.
struct WndState {
    app: Box<App>,
    /// HWND of the rebar (toolbar + search edit container). Cached
    /// so WM_SIZE can forward height queries without `GetDlgItem`.
    rebar: Cell<HWND>,
    /// HWND of the tab control. `Cell` because we set it in WM_CREATE
    /// from a `&WndState` (`GWLP_USERDATA` only hands us a `*const`).
    tab: Cell<HWND>,
    /// HWNDs of the eight tab listviews, in `TAB_LISTVIEW_IDS` order.
    listviews: [Cell<HWND>; 8],
    /// HWND of the status bar.
    status: Cell<HWND>,
    /// Monitor DPI as last reported by `GetDpiForWindow`. Cached so
    /// non-WM_DPICHANGED handlers can scale without another syscall.
    dpi: Cell<u32>,
}

impl WndState {
    fn new(app: Box<App>) -> Self {
        Self {
            app,
            rebar: Cell::new(HWND::default()),
            tab: Cell::new(HWND::default()),
            listviews: [
                Cell::new(HWND::default()),
                Cell::new(HWND::default()),
                Cell::new(HWND::default()),
                Cell::new(HWND::default()),
                Cell::new(HWND::default()),
                Cell::new(HWND::default()),
                Cell::new(HWND::default()),
                Cell::new(HWND::default()),
            ],
            status: Cell::new(HWND::default()),
            dpi: Cell::new(REFERENCE_DPI),
        }
    }
}

/// Register the window class, create the main window, show it.
/// Ownership of `app` is transferred into the window's
/// `GWLP_USERDATA` and reclaimed on `WM_NCDESTROY`.
pub fn create(app: Box<App>) -> Result<HWND, String> {
    unsafe {
        // ComCtl32 v6: tab/listview/status/toolbar/rebar all live in
        // comctl32 and need this initialiser before first use. The
        // application manifest pulls in v6 visual styles; this call
        // wakes each class up. Rebar (the M5.3 toolbar container) is
        // gated behind ICC_COOL_CLASSES, separate from ICC_BAR_CLASSES
        // which only covers toolbar/status/trackbar — easy to miss
        // until RB_INSERTBANDW silently fails.
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES
                | ICC_TAB_CLASSES
                | ICC_BAR_CLASSES
                | ICC_COOL_CLASSES,
        };
        if !InitCommonControlsEx(&icc).as_bool() {
            return Err("InitCommonControlsEx failed".into());
        }

        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance.into(),
            lpszClassName: CLASS_NAME,
            hCursor: LoadCursorW(None, IDC_ARROW)
                .map_err(|e| format!("LoadCursorW failed: {e}"))?,
            // COLOR_WINDOW + 1 — Win32's "use this system color as
            // the brush" idiom. The +1 is required by the API.
            hbrBackground: HBRUSH(6),
            ..Default::default()
        };
        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            return Err("RegisterClassExW failed".into());
        }

        // Wrap the App in WndState and pass the raw pointer through
        // CreateWindowExW. Consumed by WM_NCCREATE; reclaimed by
        // WM_NCDESTROY.
        let state = Box::new(WndState::new(app));
        let state_ptr = Box::into_raw(state) as *mut std::ffi::c_void;

        let menu = build_main_menu().ok_or("build_main_menu failed")?;
        let title = wide("simplewall-rs");
        // Initial size in logical pixels — Win32 will create the
        // window at system DPI. We re-apply per-monitor DPI scaling
        // in WM_CREATE/WM_SIZE.
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            CLASS_NAME,
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            LOGICAL_INITIAL_W,
            LOGICAL_INITIAL_H,
            None,
            menu,
            hinstance,
            Some(state_ptr),
        );
        if hwnd.0 == 0 {
            // State leaked here, but we're failing creation entirely;
            // process exit reaps it.
            return Err("CreateWindowExW failed".into());
        }

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);
        Ok(hwnd)
    }
}

/// Build the top menu bar, mirroring upstream's IDM_MAIN structure
/// (resource.rc:40-144). Only IDM_EXIT is wired up in M5.2; the rest
/// emit a console diag and are left for their respective milestones.
fn build_main_menu() -> Option<HMENU> {
    unsafe {
        let menu = CreateMenu().ok()?;

        // ---- File ----
        let file = CreatePopupMenu().ok()?;
        append_string(file, IDM_SETTINGS, "&Settings\tCtrl+P");
        append_separator(file);
        append_string(file, IDM_ADD_FILE, "&Add app…\tCtrl+O");
        append_separator(file);
        append_string(file, IDM_IMPORT, "&Import…");
        append_string(file, IDM_EXPORT, "&Export…");
        append_separator(file);
        append_string(file, IDM_EXIT, "E&xit");
        append_popup(menu, file, "&File");

        // ---- Edit ----
        let edit = CreatePopupMenu().ok()?;
        append_string(edit, IDM_PURGE_UNUSED, "Purge &unused apps");
        append_string(edit, IDM_PURGE_TIMERS, "Purge &timers");
        append_separator(edit);
        append_string(edit, IDM_LOGCLEAR, "&Clear log");
        append_separator(edit);
        append_string(edit, IDM_REFRESH, "&Refresh\tF5");
        append_popup(menu, edit, "&Edit");

        // ---- View ----
        let view = CreatePopupMenu().ok()?;
        append_string(view, IDM_ALWAYSONTOP_CHK, "Always on &top");
        append_string(view, IDM_USEDARKTHEME_CHK, "Use &dark theme");
        append_string(view, IDM_AUTOSIZECOLUMNS_CHK, "&Autosize columns");
        append_string(view, IDM_SHOWFILENAMESONLY_CHK, "Show &filenames only");
        append_string(view, IDM_SHOWSEARCHBAR_CHK, "Show &search bar");
        append_separator(view);
        append_string(view, IDM_FONT, "&Font…");
        append_popup(menu, view, "&View");

        // ---- Settings ----
        let settings = CreatePopupMenu().ok()?;
        append_string(settings, IDM_LOADONSTARTUP_CHK, "&Load on system startup");
        append_string(settings, IDM_STARTMINIMIZED_CHK, "Start &minimized");
        append_string(settings, IDM_SKIPUACWARNING_CHK, "Skip UAC warning");
        append_string(settings, IDM_CHECKUPDATES_CHK, "Check for &updates");
        append_separator(settings);

        let rules = CreatePopupMenu().ok()?;
        append_string(rules, IDM_RULE_BLOCKOUTBOUND, "Block &outbound for all");
        append_string(rules, IDM_RULE_BLOCKINBOUND, "Block &inbound for all");
        append_separator(rules);
        append_string(rules, IDM_RULE_ALLOWLOOPBACK, "Allow &loopback");
        append_string(rules, IDM_RULE_ALLOW6TO4, "Allow IPv6 (&6to4)");
        append_string(
            rules,
            IDM_RULE_ALLOWWINDOWSUPDATE,
            "Allow &Windows Update",
        );
        append_popup(settings, rules, "&Rules");
        append_popup(menu, settings, "&Settings");

        // ---- Blocklist ----
        let blocklist = CreatePopupMenu().ok()?;

        let spy = CreatePopupMenu().ok()?;
        append_string(spy, IDM_BLOCKLIST_SPY_DISABLE, "&Disable");
        append_string(spy, IDM_BLOCKLIST_SPY_ALLOW, "&Allow");
        append_string(spy, IDM_BLOCKLIST_SPY_BLOCK, "&Block");
        append_popup(blocklist, spy, "Microsoft &spying and telemetry");

        let update = CreatePopupMenu().ok()?;
        append_string(update, IDM_BLOCKLIST_UPDATE_DISABLE, "&Disable");
        append_string(update, IDM_BLOCKLIST_UPDATE_ALLOW, "&Allow");
        append_string(update, IDM_BLOCKLIST_UPDATE_BLOCK, "&Block");
        append_popup(blocklist, update, "Microsoft &Update");

        let extra = CreatePopupMenu().ok()?;
        append_string(extra, IDM_BLOCKLIST_EXTRA_DISABLE, "&Disable");
        append_string(extra, IDM_BLOCKLIST_EXTRA_ALLOW, "&Allow");
        append_string(extra, IDM_BLOCKLIST_EXTRA_BLOCK, "&Block");
        append_popup(blocklist, extra, "Microsoft &applications");

        append_popup(menu, blocklist, "&Blocklist");

        // ---- Help ----
        let help = CreatePopupMenu().ok()?;
        append_string(help, IDM_WEBSITE, "&Website");
        append_string(help, IDM_CHECKUPDATES, "&Check for updates");
        append_string(help, IDM_ABOUT, "&About");
        append_popup(menu, help, "&Help");

        Some(menu)
    }
}

unsafe fn append_string(menu: HMENU, id: u16, label: &str) {
    let buf = wide(label);
    unsafe {
        let _ = AppendMenuW(menu, MF_STRING, id as usize, PCWSTR(buf.as_ptr()));
    }
}

unsafe fn append_separator(menu: HMENU) {
    unsafe {
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    }
}

unsafe fn append_popup(parent: HMENU, child: HMENU, label: &str) {
    let buf = wide(label);
    unsafe {
        let _ = AppendMenuW(
            parent,
            MF_POPUP,
            child.0 as usize,
            PCWSTR(buf.as_ptr()),
        );
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_NCCREATE => {
            // CREATESTRUCTW.lpCreateParams holds the WndState pointer
            // we passed via lpParam. Park it into GWLP_USERDATA so
            // every later message can find it.
            let cs = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
            let state_ptr = cs.lpCreateParams;
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_CREATE => match on_create(hwnd) {
            Ok(()) => LRESULT(0),
            Err(e) => {
                eprintln!("simplewall-rs: WM_CREATE failed: {e}");
                LRESULT(-1)
            }
        },
        WM_SIZE => {
            on_size(hwnd);
            LRESULT(0)
        }
        WM_NOTIFY => {
            // TCN_SELCHANGE: user clicked a different tab. Show the
            // matching listview, hide the others.
            let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
            if nmhdr.idFrom == IDC_TAB as usize && nmhdr.code == TCN_SELCHANGE {
                on_tab_change(hwnd);
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            on_command(hwnd, wparam.0 as u32 & 0xFFFF);
            LRESULT(0)
        }
        WM_DESTROY => {
            post_quit(0);
            LRESULT(0)
        }
        WM_NCDESTROY => {
            // Reclaim WndState so it (and the App inside) drops.
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut WndState;
            if !raw.is_null() {
                unsafe {
                    let _ = Box::from_raw(raw);
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// `WM_CREATE`: build the tab control, the eight tab listviews, and
/// the status bar; populate the User rules tab from
/// `app.profile.custom_rules`.
fn on_create(hwnd: HWND) -> Result<(), String> {
    let state = unsafe { state_ref(hwnd) }.ok_or("WndState missing in WM_CREATE")?;

    // Pick up the actual DPI now that we have an HWND. M5.2 applies
    // it once at create + WM_SIZE; full WM_DPICHANGED handling
    // (window-rect adjust on monitor change) is M5.9 polish.
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    state.dpi.set(if dpi == 0 { REFERENCE_DPI } else { dpi });

    // Rebar with toolbar + search edit lives at the top, just under
    // the menu bar. Created before the tab control so its HWND is
    // available when the layout pass needs the rebar height.
    let Toolbar { rebar, .. } = toolbar::create(hwnd, state.dpi.get())?;
    state.rebar.set(rebar);

    // Tab control — listviews are siblings, not children.
    let tab = create_tab_control(hwnd)?;
    state.tab.set(tab);
    insert_tabs(tab)?;

    // Per-tab listviews. Created in TAB_LISTVIEW_IDS order, all
    // hidden initially; the `on_tab_change` call at the end shows
    // the one matching the selected tab.
    for (slot, &id) in TAB_LISTVIEW_IDS.iter().enumerate() {
        let lv = create_tab_listview(hwnd, id)?;
        configure_listview(lv, id, state.dpi.get())?;
        state.listviews[slot].set(lv);
    }

    // Status bar at the bottom. Two parts: filter state, item count.
    let status = create_status_bar(hwnd)?;
    state.status.set(status);
    set_status_text(status, 0, "Filters are disabled.");
    set_status_text(status, 1, "");

    // Initial population: only User rules tab is fed from the profile.
    populate_user_rules(state);

    // Triggers on_size (which lays out children) and on_tab_change.
    on_size(hwnd);
    on_tab_change(hwnd);

    Ok(())
}

/// `WM_SIZE`: lay out rebar + tab + status bar. The rebar pins to
/// the top, the status bar to the bottom, and the tab control fills
/// the space between. The status bar and rebar self-size when
/// forwarded WM_SIZE.
fn on_size(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };

    let mut client = RECT::default();
    if unsafe { GetClientRect(hwnd, &mut client) }.is_err() {
        return;
    }
    let total_w = client.right - client.left;
    let total_h = client.bottom - client.top;

    // Rebar self-sizes on forwarded WM_SIZE. Read its height back
    // afterwards so the tab control knows where to start.
    let rebar = state.rebar.get();
    let mut rebar_h = 0;
    if rebar.0 != 0 {
        unsafe {
            // Forward WM_SIZE; the rebar uses lParam packed width
            // (LOWORD) and height (HIWORD) but tolerates 0 here.
            let _ = SendMessageW(rebar, WM_SIZE, WPARAM(0), LPARAM(0));
            let _ = MoveWindow(rebar, 0, 0, total_w, 0, true);
        }
        rebar_h = toolbar::rebar_height(rebar);
    }

    // Status bar pins to bottom and self-sizes too.
    let status = state.status.get();
    let mut status_h = 0;
    if status.0 != 0 {
        unsafe {
            let _ = SendMessageW(status, WM_SIZE, WPARAM(0), LPARAM(0));
            let mut sr = RECT::default();
            if GetClientRect(status, &mut sr).is_ok() {
                status_h = sr.bottom - sr.top;
            }
        }
        update_status_parts(status, total_w);
    }

    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let tab_y = rebar_h;
    let tab_h = (total_h - rebar_h - status_h).max(0);
    unsafe {
        let _ = MoveWindow(tab, 0, tab_y, total_w, tab_h, true);
    }

    // Per-tab listviews fill the tab control's content area.
    let mut content = RECT {
        left: 0,
        top: tab_y,
        right: total_w,
        bottom: tab_y + tab_h,
    };
    unsafe {
        // TCM_ADJUSTRECT with wParam=0 = "shrink rect to content area".
        let _ = SendMessageW(
            tab,
            TCM_ADJUSTRECT,
            WPARAM(0),
            LPARAM(&mut content as *mut _ as isize),
        );
    }
    let cw = content.right - content.left;
    let ch = content.bottom - content.top;
    for slot in 0..TAB_LISTVIEW_IDS.len() {
        let lv = state.listviews[slot].get();
        if lv.0 == 0 {
            continue;
        }
        unsafe {
            let _ = MoveWindow(lv, content.left, content.top, cw, ch, true);
        }
    }
}

/// Show the listview matching the currently-selected tab; hide the
/// rest. Called once at startup and from WM_NOTIFY/TCN_SELCHANGE.
fn on_tab_change(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel =
        unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let sel_slot = if sel < 0 { 0 } else { sel as usize };

    for (slot, lv_cell) in state.listviews.iter().enumerate() {
        let lv = lv_cell.get();
        if lv.0 == 0 {
            continue;
        }
        unsafe {
            let _ = ShowWindow(lv, if slot == sel_slot { SW_SHOW } else { SW_HIDE });
        }
    }

    // Update the right-hand status bar segment with the selected
    // tab's item count.
    let lv = state.listviews[sel_slot].get();
    if lv.0 != 0 && state.status.get().0 != 0 {
        let count =
            unsafe { SendMessageW(lv, windows_lvm_getitemcount(), WPARAM(0), LPARAM(0)) }.0;
        let text = if count == 0 {
            "Empty.".to_string()
        } else {
            format!("Total: {count}")
        };
        set_status_text(state.status.get(), 1, &text);
    }
}

/// `WM_COMMAND` dispatch. M5.3 wires File → Exit and the toolbar's
/// Releases button (which opens our GitHub releases page in the
/// default browser); the rest log a TODO line and ship with their
/// feature milestones.
fn on_command(hwnd: HWND, id: u32) {
    let id = id as u16;
    match id {
        IDM_EXIT => unsafe {
            let _ = DestroyWindow(hwnd);
        },
        IDM_RELEASES => open_releases_page(hwnd),
        other => eprintln!("simplewall-rs: menu id {other} not yet wired up"),
    }
}

/// Open https://github.com/simplewall-rs/simplewall-rs/releases in
/// the system's default browser. Replaces upstream's PayPal donate
/// flow — same toolbar slot, friendlier action.
fn open_releases_page(hwnd: HWND) {
    // ShellExecuteW returns a HINSTANCE > 32 on success; <= 32 is
    // an error code. We don't surface failure beyond a stderr line
    // because the user-visible failure mode (browser doesn't open)
    // is already self-explanatory.
    let url = w!("https://github.com/simplewall-rs/simplewall-rs/releases");
    let verb = w!("open");
    let result = unsafe {
        ShellExecuteW(hwnd, verb, url, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL)
    };
    if result.0 as usize <= 32 {
        eprintln!("simplewall-rs: ShellExecuteW(releases) failed: code {}", result.0);
    }
}

// ---- tab control ----

fn create_tab_control(parent: HWND) -> Result<HWND, String> {
    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WC_TABCONTROLW,
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
            0,
            0,
            0,
            0,
            parent,
            HMENU(IDC_TAB as isize),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            return Err("CreateWindowExW(WC_TABCONTROL) failed".into());
        }
        Ok(hwnd)
    }
}

fn insert_tabs(tab: HWND) -> Result<(), String> {
    // Same order + labels as upstream `_app_addwindowtabs`. Hardcoded
    // English now; M8 will route through a localization table.
    let labels: [(i32, &str); 8] = [
        (IDC_APPS_PROFILE, "Apps"),
        (IDC_APPS_SERVICE, "Services"),
        (IDC_APPS_UWP, "UWP apps"),
        (IDC_RULES_BLOCKLIST, "Blocklist"),
        (IDC_RULES_SYSTEM, "System rules"),
        (IDC_RULES_CUSTOM, "User rules"),
        (IDC_NETWORK, "Connections"),
        (IDC_LOG, "Packets log"),
    ];
    for (idx, (_id, label)) in labels.iter().enumerate() {
        let mut buf = wide(label);
        let item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: PWSTR(buf.as_mut_ptr()),
            ..Default::default()
        };
        let res = unsafe {
            SendMessageW(
                tab,
                TCM_INSERTITEMW,
                WPARAM(idx),
                LPARAM(&item as *const _ as isize),
            )
        };
        if res.0 == -1 {
            return Err(format!("TCM_INSERTITEM failed at index {idx}"));
        }
    }
    Ok(())
}

// ---- listviews ----

fn create_tab_listview(parent: HWND, id: i32) -> Result<HWND, String> {
    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
        // Created hidden — `on_tab_change` reveals the right one.
        let style = WS_CHILD | WS_BORDER | WINDOW_STYLE(LVS_REPORT | LVS_SHOWSELALWAYS);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WC_LISTVIEWW,
            PCWSTR::null(),
            style,
            0,
            0,
            0,
            0,
            parent,
            HMENU(id as isize),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            return Err(format!("CreateWindowExW(WC_LISTVIEW id={id}) failed"));
        }
        Ok(hwnd)
    }
}

/// Per-tab listview configuration: extended style flags + columns.
/// Mirrors upstream's `_app_tabs_init` switch in main.c:1968-2024.
fn configure_listview(lv: HWND, id: i32, dpi: u32) -> Result<(), String> {
    // Extended styles: double-buffer + full-row select for all,
    // checkboxes only for the apps + rules tabs.
    let mut ext = LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT;
    let is_apps_or_rules = (IDC_APPS_PROFILE..=IDC_RULES_CUSTOM).contains(&id);
    if is_apps_or_rules {
        ext |= LVS_EX_CHECKBOXES;
    }
    unsafe {
        let _ = SendMessageW(
            lv,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(0),
            LPARAM(ext as isize),
        );
    }

    // Columns. Per upstream messages.c:385-465.
    match id {
        IDC_APPS_PROFILE | IDC_APPS_SERVICE | IDC_APPS_UWP => {
            add_column(lv, 0, "Name", scale_dpi(APPS_COL_WIDTHS[0], dpi), false)?;
            add_column(lv, 1, "Added", scale_dpi(APPS_COL_WIDTHS[1], dpi), true)?;
        }
        IDC_RULES_BLOCKLIST | IDC_RULES_SYSTEM | IDC_RULES_CUSTOM => {
            add_column(lv, 0, "Name", scale_dpi(RULES_COL_WIDTHS[0], dpi), false)?;
            add_column(
                lv,
                1,
                "Protocol",
                scale_dpi(RULES_COL_WIDTHS[1], dpi),
                true,
            )?;
            add_column(
                lv,
                2,
                "Direction",
                scale_dpi(RULES_COL_WIDTHS[2], dpi),
                true,
            )?;
        }
        IDC_NETWORK => {
            let cols = [
                "Name",
                "Address (Source)",
                "Host (Source)",
                "Port (Source)",
                "Address (Destination)",
                "Host (Destination)",
                "Port (Destination)",
                "Protocol",
                "State",
            ];
            for (i, label) in cols.iter().enumerate() {
                let right = matches!(i, 3 | 6 | 7 | 8);
                add_column(lv, i as i32, label, scale_dpi(NETWORK_COL_WIDTHS[i], dpi), right)?;
            }
        }
        IDC_LOG => {
            let cols = [
                "#",
                "Name",
                "Date",
                "Address (Source)",
                "Host (Source)",
                "Port (Source)",
                "Address (Destination)",
                "Host (Destination)",
                "Port (Destination)",
                "Protocol",
                "Direction",
                "Filter",
            ];
            for (i, label) in cols.iter().enumerate() {
                let right = matches!(i, 0 | 5 | 8);
                add_column(lv, i as i32, label, scale_dpi(LOG_COL_WIDTHS[i], dpi), right)?;
            }
        }
        other => return Err(format!("unknown listview id {other}")),
    }

    Ok(())
}

fn add_column(
    lv: HWND,
    idx: i32,
    label: &str,
    width: i32,
    right_align: bool,
) -> Result<(), String> {
    let mut buf = wide(label);
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH,
        fmt: if right_align {
            LVCFMT_RIGHT
        } else {
            LVCFMT_LEFT
        },
        cx: width,
        pszText: PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    let res = unsafe {
        SendMessageW(
            lv,
            LVM_INSERTCOLUMNW,
            WPARAM(idx as usize),
            LPARAM(&col as *const _ as isize),
        )
    };
    if res.0 == -1 {
        return Err(format!("LVM_INSERTCOLUMN failed at index {idx}"));
    }
    Ok(())
}

/// Wipe the User rules ListView and re-fill from the current
/// profile's custom rules. This is the only tab driven by the
/// in-memory profile in M5.2 — the others stay empty until M5.4
/// (Apps tabs from `profile.apps`) and M6 (Connections / Log).
fn populate_user_rules(state: &WndState) {
    use crate::profile::{Action, Direction};

    // Index 5 in TAB_LISTVIEW_IDS is IDC_RULES_CUSTOM.
    let lv = state.listviews[5].get();
    if lv.0 == 0 {
        return;
    }

    unsafe {
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }

    for (idx, rule) in state.app.profile.custom_rules.iter().enumerate() {
        let mut name_buf = wide(&rule.name);
        let item = LVITEMW {
            mask: LVIF_TEXT,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            ..Default::default()
        };
        let _ = unsafe {
            SendMessageW(
                lv,
                LVM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&item as *const _ as isize),
            )
        };

        let protocol = match rule.protocol {
            Some(1) => "ICMP".to_string(),
            Some(6) => "TCP".to_string(),
            Some(17) => "UDP".to_string(),
            Some(58) => "ICMPv6".to_string(),
            Some(other) => other.to_string(),
            None => "Any".to_string(),
        };
        let direction = match rule.direction {
            Direction::Outbound => "Outbound",
            Direction::Inbound => "Inbound",
            Direction::Any => "Both",
            Direction::Other(_) => "Other",
        };
        // M5.2 doesn't surface action in the columns (matches upstream's
        // 3-column layout), but a future tooltip / detail pane can use it.
        let _ = match rule.action {
            Action::Permit => "Permit",
            Action::Block => "Block",
        };

        set_subitem(lv, idx as i32, 1, &protocol);
        set_subitem(lv, idx as i32, 2, direction);
    }
}

fn set_subitem(lv: HWND, row: i32, sub: i32, text: &str) {
    let mut buf = wide(text);
    let item = LVITEMW {
        mask: LVIF_TEXT,
        iItem: row,
        iSubItem: sub,
        pszText: PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        let _ = SendMessageW(
            lv,
            LVM_SETITEMTEXTW,
            WPARAM(row as usize),
            LPARAM(&item as *const _ as isize),
        );
    }
}

// ---- status bar ----

fn create_status_bar(parent: HWND) -> Result<HWND, String> {
    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            STATUSCLASSNAMEW,
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(SBARS_TOOLTIPS),
            0,
            0,
            0,
            0,
            parent,
            HMENU(IDC_STATUSBAR as isize),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            return Err("CreateWindowExW(STATUSCLASSNAME) failed".into());
        }
        Ok(hwnd)
    }
}

/// Two-segment status bar: filter state on the left (60% of width),
/// item count on the right.
fn update_status_parts(status: HWND, total_w: i32) {
    if total_w <= 0 {
        return;
    }
    let split = (total_w * 60) / 100;
    // SB_SETPARTS takes a `*const i32` of right-edge X coordinates.
    // The last entry is -1 = "stretch to end".
    let parts: [i32; 2] = [split, -1];
    unsafe {
        let _ = SendMessageW(
            status,
            SB_SETPARTS,
            WPARAM(parts.len()),
            LPARAM(parts.as_ptr() as isize),
        );
    }
}

fn set_status_text(status: HWND, part: u16, text: &str) {
    let buf = wide(text);
    unsafe {
        let _ = SendMessageW(
            status,
            SB_SETTEXTW,
            WPARAM(part as usize),
            LPARAM(buf.as_ptr() as isize),
        );
    }
}

// ---- helpers ----

unsafe fn state_ref<'a>(hwnd: HWND) -> Option<&'a WndState> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const WndState;
    if raw.is_null() {
        None
    } else {
        Some(unsafe { &*raw })
    }
}

/// Logical → device pixels: `logical * (dpi / 96)`. Use `i64`
/// intermediates so `logical * dpi` can't overflow at extreme zooms.
fn scale_dpi(logical: i32, dpi: u32) -> i32 {
    let n = logical as i64 * dpi as i64;
    let d = REFERENCE_DPI as i64;
    (n / d) as i32
}

/// LVM_GETITEMCOUNT isn't re-exported under a stable name in
/// `windows-rs` 0.54's Controls module; the underlying message id is
/// 0x1004 (LVM_FIRST + 4). Inlined here to avoid a feature flag
/// chase. If a future `windows-rs` upgrade exposes the constant
/// directly, this can be replaced.
#[inline]
const fn windows_lvm_getitemcount() -> u32 {
    0x1004
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_dpi_identity_at_96() {
        assert_eq!(scale_dpi(100, 96), 100);
        assert_eq!(scale_dpi(900, 96), 900);
    }

    #[test]
    fn scale_dpi_225_percent() {
        // Common 4K-at-225% case: 100 logical → 225 device.
        assert_eq!(scale_dpi(100, 216), 225);
    }

    #[test]
    fn scale_dpi_handles_zero_logical() {
        assert_eq!(scale_dpi(0, 192), 0);
    }
}

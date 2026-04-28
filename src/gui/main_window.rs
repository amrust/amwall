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

use windows::Win32::Foundation::{FILETIME, HWND, LPARAM, LRESULT, RECT, SYSTEMTIME, WPARAM};
use windows::Win32::Graphics::Gdi::{HBRUSH, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_COOL_CLASSES, ICC_LISTVIEW_CLASSES, ICC_TAB_CLASSES, INITCOMMONCONTROLSEX,
    InitCommonControlsEx, LIST_VIEW_ITEM_STATE_FLAGS, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT,
    LVCFMT_RIGHT, LVCOLUMNW, LVIF_STATE, LVIF_TEXT, LVIS_STATEIMAGEMASK, LVITEMW,
    LVM_DELETEALLITEMS, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW,
    LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMTEXTW, LVN_KEYDOWN,
    LVNI_SELECTED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_REPORT,
    LVS_SHOWSELALWAYS, NM_DBLCLK, NMHDR, NMLVKEYDOWN,
    NMTBGETINFOTIPW, SBARS_TOOLTIPS, SB_SETPARTS, SB_SETTEXTW, STATUSCLASSNAMEW,
    TBN_GETINFOTIPW, TCIF_TEXT, TCITEMW, TCM_ADJUSTRECT, TCM_GETCURSEL, TCM_INSERTITEMW,
    TCN_SELCHANGE, WC_LISTVIEWW, WC_TABCONTROLW,
};
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::VK_DELETE;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CREATESTRUCTW, CW_USEDEFAULT, CheckMenuItem, CreateMenu, CreatePopupMenu,
    CreateWindowExW, DefWindowProcW, DestroyWindow, GWLP_USERDATA, GetClientRect, GetMenu,
    GetWindowLongPtrW, HMENU, HWND_NOTOPMOST, HWND_TOPMOST, IDC_ARROW, KillTimer, LoadCursorW,
    MB_ICONERROR, MB_OK, MF_BYCOMMAND, MF_CHECKED, MF_POPUP, MF_SEPARATOR, MF_STRING, MF_UNCHECKED,
    MessageBoxW, MoveWindow, RegisterClassExW, SW_HIDE, SW_SHOW, SW_SHOWNORMAL, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SendMessageW, SetTimer, SetWindowLongPtrW, SetWindowPos,
    ShowWindow, WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_DPICHANGED,
    WM_NCCREATE, WM_NCDESTROY, WM_NOTIFY, WM_SIZE, WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CHILD,
    WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR, w};

use super::app::App;
use super::ids::{
    IDC_APPS_PROFILE, IDC_APPS_SERVICE, IDC_APPS_UWP, IDC_LOG, IDC_NETWORK,
    IDC_RULES_BLOCKLIST, IDC_RULES_CUSTOM, IDC_RULES_SYSTEM, IDC_SEARCH, IDC_STATUSBAR, IDC_TAB,
    IDM_ABOUT, IDM_ADD_FILE, IDM_ALWAYSONTOP_CHK, IDM_AUTOSIZECOLUMNS_CHK,
    IDM_BLOCKLIST_EXTRA_ALLOW, IDM_BLOCKLIST_EXTRA_BLOCK, IDM_BLOCKLIST_EXTRA_DISABLE,
    IDM_BLOCKLIST_SPY_ALLOW, IDM_BLOCKLIST_SPY_BLOCK, IDM_BLOCKLIST_SPY_DISABLE,
    IDM_BLOCKLIST_UPDATE_ALLOW, IDM_BLOCKLIST_UPDATE_BLOCK, IDM_BLOCKLIST_UPDATE_DISABLE,
    IDM_CHECKUPDATES, IDM_CHECKUPDATES_CHK, IDM_EXIT, IDM_EXPORT, IDM_FONT, IDM_IMPORT,
    IDM_LOADONSTARTUP_CHK, IDM_LOGCLEAR, IDM_OPENRULESEDITOR, IDM_PURGE_TIMERS,
    IDM_PURGE_UNUSED, IDM_REFRESH, IDM_RELEASES, IDM_RULE_ALLOW6TO4, IDM_RULE_ALLOWLOOPBACK,
    IDM_RULE_ALLOWWINDOWSUPDATE, IDM_RULE_BLOCKINBOUND, IDM_RULE_BLOCKOUTBOUND, IDM_SETTINGS,
    IDM_SHOWFILENAMESONLY_CHK, IDM_SHOWSEARCHBAR_CHK, IDM_SKIPUACWARNING_CHK,
    IDM_STARTMINIMIZED_CHK, IDM_TRAY_ENABLELOG_CHK, IDM_TRAY_ENABLENOTIFICATIONS_CHK,
    IDM_TRAY_ENABLEUILOG_CHK, IDM_TRAY_LOGCLEAR, IDM_TRAY_LOGSHOW, IDM_TRAY_START,
    IDM_USEDARKTHEME_CHK, IDM_WEBSITE, TAB_LISTVIEW_IDS,
};
use super::dialogs;
use super::toolbar::{self, Toolbar};
use super::{post_quit, wide};

/// Window class name. Win32 uses this string to look up our class
/// registration.
const CLASS_NAME: PCWSTR = w!("SimplewallRsMainWindow");

/// Win32 timer id used to drive Connections-tab live refresh.
/// Distinct from any IDC_* control id since Win32 routes timers
/// through the same WM_TIMER queue.
const TIMER_CONNECTIONS_REFRESH: usize = 9001;

/// Refresh interval for the Connections tab in milliseconds.
/// 2 seconds matches upstream's `_app_network_refresh_timer`.
const CONNECTIONS_REFRESH_MS: u32 = 2000;

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

        let title = wide(&format_window_title(&app.profile_path.borrow()));

        // Wrap the App in WndState and pass the raw pointer through
        // CreateWindowExW. Consumed by WM_NCCREATE; reclaimed by
        // WM_NCDESTROY.
        let state = Box::new(WndState::new(app));
        let state_ptr = Box::into_raw(state) as *mut std::ffi::c_void;

        let menu = build_main_menu().ok_or("build_main_menu failed")?;
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
            let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
            // TCN_SELCHANGE: user clicked a different tab — show
            // the matching listview, hide the others.
            if nmhdr.idFrom == IDC_TAB as usize && nmhdr.code == TCN_SELCHANGE {
                on_tab_change(hwnd);
            }
            // TBN_GETINFOTIPW: toolbar wants tooltip text for a
            // button. Fill in the NMTBGETINFOTIPW->pszText buffer
            // with our hardcoded English description.
            if nmhdr.code == TBN_GETINFOTIPW {
                let info = unsafe { &mut *(lparam.0 as *mut NMTBGETINFOTIPW) };
                fill_toolbar_tooltip(info);
            }
            // NM_DBLCLK on the User rules listview opens the rule
            // editor for the clicked row.
            if nmhdr.idFrom == IDC_RULES_CUSTOM as usize && nmhdr.code == NM_DBLCLK {
                on_edit_selected_rule(hwnd);
            }
            // Delete key on the User rules listview removes the
            // selected row (with confirm).
            if nmhdr.idFrom == IDC_RULES_CUSTOM as usize && nmhdr.code == LVN_KEYDOWN {
                let kd = unsafe { &*(lparam.0 as *const NMLVKEYDOWN) };
                if kd.wVKey == VK_DELETE.0 {
                    on_delete_selected_rule(hwnd);
                }
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            on_command(hwnd, wparam.0 as u32 & 0xFFFF);
            LRESULT(0)
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, wparam, lparam);
            LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_CONNECTIONS_REFRESH {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    populate_connections_tab(state);
                }
            }
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

    // Populate the tabs that are driven from `profile.*`. Apps tab
    // gets the user's per-application list (with checkbox + Added
    // timestamp); User rules tab gets the custom rules. System
    // Rules + Blocklist come from the bundled internal profile.
    // Services / UWP need separate enumeration sources (Win32 SCM
    // and Package Manager respectively); Connections + Log are
    // M5.7+ work.
    populate_apps_tab(state);
    populate_user_rules(state);
    populate_internal_rules(state, IDC_RULES_SYSTEM);
    populate_internal_rules(state, IDC_RULES_BLOCKLIST);

    // Apply persisted UI settings: menu checks + always-on-top +
    // search-bar visibility. After this the window mirrors what
    // the user left set last time.
    apply_initial_settings(hwnd, state);

    // Triggers on_size (which lays out children) and on_tab_change.
    on_size(hwnd);
    on_tab_change(hwnd);

    Ok(())
}

/// One-shot at startup: walk the persisted Settings, set the
/// matching menu check marks, apply window-level effects
/// (always-on-top, search-bar visibility).
fn apply_initial_settings(hwnd: HWND, state: &WndState) {
    let s = state.app.settings.borrow();
    let pairs = [
        (IDM_ALWAYSONTOP_CHK, s.always_on_top),
        (IDM_AUTOSIZECOLUMNS_CHK, s.autosize_columns),
        (IDM_SHOWSEARCHBAR_CHK, s.show_search_bar),
        (IDM_SHOWFILENAMESONLY_CHK, s.show_filenames_only),
        (IDM_USEDARKTHEME_CHK, s.use_dark_theme),
        (IDM_LOADONSTARTUP_CHK, s.load_on_startup),
        (IDM_STARTMINIMIZED_CHK, s.start_minimized),
        (IDM_SKIPUACWARNING_CHK, s.skip_uac_warning),
        (IDM_CHECKUPDATES_CHK, s.check_updates),
    ];
    for (id, v) in pairs {
        set_menu_check(hwnd, id, v);
    }
    if s.always_on_top {
        apply_always_on_top(hwnd, true);
    }
    if !s.show_search_bar {
        apply_search_bar_visibility(hwnd, false);
    }
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

/// `WM_DPICHANGED`: user dragged the window onto a monitor with a
/// different scaling factor. Win32 hands us:
///   - LOWORD(wparam) = new X DPI (Y matches; we use X).
///   - lparam = pointer to RECT with the suggested new window
///     position+size preserving the window's logical size on the
///     new monitor.
///
/// We update the cached DPI, move the window to the suggested rect,
/// then re-issue the column-width scaling so the listview content
/// stays readable at the new ratio. WM_SIZE fires automatically off
/// SetWindowPos and re-lays out the children.
fn on_dpi_changed(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let new_dpi = (wparam.0 & 0xFFFF) as u32;
    let new_dpi = if new_dpi == 0 { REFERENCE_DPI } else { new_dpi };
    state.dpi.set(new_dpi);

    let suggested = unsafe { &*(lparam.0 as *const RECT) };
    unsafe {
        let _ = SetWindowPos(
            hwnd,
            HWND::default(),
            suggested.left,
            suggested.top,
            suggested.right - suggested.left,
            suggested.bottom - suggested.top,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }

    // Re-scale all per-tab listview columns to the new DPI so the
    // content doesn't end up squished or stretched.
    for (slot, &id) in TAB_LISTVIEW_IDS.iter().enumerate() {
        let lv = state.listviews[slot].get();
        if lv.0 == 0 {
            continue;
        }
        rescale_listview_columns(lv, id, new_dpi);
    }
}

/// Re-issue LVM_SETCOLUMNWIDTH for every column on this listview
/// using the new DPI. Mirrors the per-tab column-width tables used
/// by `configure_listview`.
fn rescale_listview_columns(lv: HWND, id: i32, dpi: u32) {
    let widths: &[i32] = match id {
        IDC_APPS_PROFILE | IDC_APPS_SERVICE | IDC_APPS_UWP => APPS_COL_WIDTHS,
        IDC_RULES_BLOCKLIST | IDC_RULES_SYSTEM | IDC_RULES_CUSTOM => RULES_COL_WIDTHS,
        IDC_NETWORK => NETWORK_COL_WIDTHS,
        IDC_LOG => LOG_COL_WIDTHS,
        _ => return,
    };
    for (i, &logical) in widths.iter().enumerate() {
        let pixels = scale_dpi(logical, dpi);
        unsafe {
            let _ = SendMessageW(
                lv,
                LVM_SETCOLUMNWIDTH,
                WPARAM(i),
                LPARAM(pixels as isize),
            );
        }
    }
}

/// Show the listview matching the currently-selected tab; hide the
/// rest. Called once at startup and from WM_NOTIFY/TCN_SELCHANGE.
/// Also starts/stops the Connections-tab refresh timer so we only
/// poll IP Helper when the user is actually looking at it.
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

    // Index 6 in TAB_LISTVIEW_IDS is IDC_NETWORK (Connections tab).
    let on_network = sel_slot == 6;
    if on_network {
        // Populate immediately so the user doesn't wait for the
        // first timer tick, then arm the periodic refresh.
        populate_connections_tab(state);
        unsafe {
            SetTimer(hwnd, TIMER_CONNECTIONS_REFRESH, CONNECTIONS_REFRESH_MS, None);
        }
    } else {
        // Stop polling when the user navigates away — avoids
        // hammering IP Helper for tabs the user can't see.
        unsafe {
            let _ = KillTimer(hwnd, TIMER_CONNECTIONS_REFRESH);
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

/// `WM_COMMAND` dispatch.
fn on_command(hwnd: HWND, id: u32) {
    let id = id as u16;
    match id {
        IDM_EXIT => unsafe {
            let _ = DestroyWindow(hwnd);
        },
        IDM_RELEASES => open_releases_page(hwnd),
        IDM_REFRESH => on_refresh(hwnd),
        IDM_IMPORT => on_import(hwnd),
        IDM_EXPORT => on_export(hwnd),
        IDM_ABOUT => on_about(hwnd),
        IDM_WEBSITE => open_website(hwnd),
        IDM_CHECKUPDATES => open_releases_page(hwnd),

        // Toggleable View / Settings menu items. Each handler
        // flips the matching field in `state.app.settings`,
        // persists, updates the menu's check mark, and applies
        // any visible side-effect (e.g. always-on-top).
        IDM_ALWAYSONTOP_CHK
        | IDM_AUTOSIZECOLUMNS_CHK
        | IDM_SHOWSEARCHBAR_CHK
        | IDM_SHOWFILENAMESONLY_CHK
        | IDM_USEDARKTHEME_CHK
        | IDM_LOADONSTARTUP_CHK
        | IDM_STARTMINIMIZED_CHK
        | IDM_SKIPUACWARNING_CHK
        | IDM_CHECKUPDATES_CHK => on_toggle(hwnd, id),

        IDM_TRAY_START => on_enable_filters(hwnd),
        IDM_OPENRULESEDITOR => on_create_rule(hwnd),

        other => eprintln!("simplewall-rs: menu id {other} not yet wired up"),
    }
}

/// Flip the `Settings` field tied to this menu id, persist, update
/// the menu's check mark, apply any window-level side effect.
fn on_toggle(hwnd: HWND, id: u16) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let new_value = {
        let mut s = state.app.settings.borrow_mut();
        let field = match id {
            IDM_ALWAYSONTOP_CHK => &mut s.always_on_top,
            IDM_AUTOSIZECOLUMNS_CHK => &mut s.autosize_columns,
            IDM_SHOWSEARCHBAR_CHK => &mut s.show_search_bar,
            IDM_SHOWFILENAMESONLY_CHK => &mut s.show_filenames_only,
            IDM_USEDARKTHEME_CHK => &mut s.use_dark_theme,
            IDM_LOADONSTARTUP_CHK => &mut s.load_on_startup,
            IDM_STARTMINIMIZED_CHK => &mut s.start_minimized,
            IDM_SKIPUACWARNING_CHK => &mut s.skip_uac_warning,
            IDM_CHECKUPDATES_CHK => &mut s.check_updates,
            _ => return,
        };
        *field = !*field;
        *field
    };

    set_menu_check(hwnd, id, new_value);

    // Persist immediately. A failure to write isn't user-visible
    // beyond the stderr line — the in-memory state still reflects
    // the toggle, just won't survive restart.
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!(
            "simplewall-rs: settings: save failed for {}: {e}",
            path.display()
        );
    }

    // Visual side effects.
    match id {
        IDM_ALWAYSONTOP_CHK => apply_always_on_top(hwnd, new_value),
        IDM_SHOWSEARCHBAR_CHK => apply_search_bar_visibility(hwnd, new_value),
        IDM_SHOWFILENAMESONLY_CHK => {
            // Filename / full-path display affects Apps tab rendering.
            populate_apps_tab(state);
        }
        IDM_AUTOSIZECOLUMNS_CHK => {
            if new_value {
                autosize_active_listview_columns(state);
            }
        }
        // The remaining toggles are display-only at boot time
        // (load_on_startup wires into the registry on a future
        // commit; dark theme is M5.9; etc.) — flipping the menu
        // check is the entire visible behaviour for now.
        _ => {}
    }
}

/// File → Toolbar Enable filters: install the current profile via
/// the same `install_profile` path the CLI uses. Requires admin;
/// if not elevated we surface a friendly error instead of crashing
/// when WFP refuses the call.
fn on_enable_filters(hwnd: HWND) {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    if !unsafe { IsUserAnAdmin() }.as_bool() {
        let title = wide("Administrator required");
        let body = wide(
            "Filter management requires Administrator privileges.\n\n\
             Close simplewall-rs and re-launch from an elevated shell\n\
             (right-click \u{2192} \"Run as administrator\").",
        );
        unsafe {
            MessageBoxW(
                hwnd,
                PCWSTR(body.as_ptr()),
                PCWSTR(title.as_ptr()),
                MB_OK | MB_ICONERROR,
            );
        }
        return;
    }

    let engine = match crate::wfp::WfpEngine::open() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("simplewall-rs: WfpEngine::open failed: {e}");
            set_status_text(state.status.get(), 0, "Failed to open WFP engine.");
            return;
        }
    };
    let report = match crate::install::install_profile(
        &engine,
        &state.app.profile.borrow(),
        true, // persistent: reboots keep the filters
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("simplewall-rs: install_profile failed: {e}");
            set_status_text(state.status.get(), 0, "Filter install failed.");
            return;
        }
    };
    set_status_text(state.status.get(), 0, "Filters are enabled.");
    set_status_text(
        state.status.get(),
        1,
        &format!(
            "{} filter(s) installed, {} skipped.",
            report.filters_added, report.rules_skipped
        ),
    );
}

/// Mark a menu item as checked or unchecked. We get the top-level
/// menu via GetMenu(hwnd) and let CheckMenuItem walk the nested
/// popups via MF_BYCOMMAND.
fn set_menu_check(hwnd: HWND, id: u16, checked: bool) {
    let menu = unsafe { GetMenu(hwnd) };
    if menu.0 == 0 {
        return;
    }
    let flag = if checked { MF_CHECKED } else { MF_UNCHECKED };
    unsafe {
        let _ = CheckMenuItem(menu, id as u32, (MF_BYCOMMAND | flag).0);
    }
}

/// Toggle HWND_TOPMOST / HWND_NOTOPMOST without resizing or moving
/// the window. SWP_NOMOVE | SWP_NOSIZE keeps the rect untouched.
fn apply_always_on_top(hwnd: HWND, on: bool) {
    let after = if on { HWND_TOPMOST } else { HWND_NOTOPMOST };
    unsafe {
        let _ = SetWindowPos(hwnd, after, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

/// Show or hide the rebar's search edit. Simplest visible
/// behaviour for now; keeps the rebar band layout intact —
/// upstream uses RB_SHOWBAND to collapse the band entirely, which
/// can land later when we revisit search-bar polish.
fn apply_search_bar_visibility(hwnd: HWND, visible: bool) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    // The search edit is a child of the rebar; its HWND is
    // GetDlgItem(rebar, IDC_SEARCH). We look it up rather than
    // caching because it's a one-off operation.
    use windows::Win32::UI::WindowsAndMessaging::GetDlgItem;
    let rebar = state.rebar.get();
    if rebar.0 == 0 {
        return;
    }
    let search = unsafe { GetDlgItem(rebar, IDC_SEARCH) };
    if search.0 != 0 {
        unsafe {
            let _ = ShowWindow(search, if visible { SW_SHOW } else { SW_HIDE });
        }
    }
}

/// Auto-size every column on the currently-visible listview to
/// fit its widest cell. LVSCW_AUTOSIZE = -1.
fn autosize_active_listview_columns(state: &WndState) {
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel =
        unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let slot = if sel < 0 { 0 } else { sel as usize };
    let lv = state.listviews[slot].get();
    if lv.0 == 0 {
        return;
    }
    // Cap at 8 columns — Apps/Rules/Network/Log all fit.
    for col in 0..12 {
        unsafe {
            let _ = SendMessageW(
                lv,
                LVM_SETCOLUMNWIDTH,
                WPARAM(col),
                LPARAM(-1), // LVSCW_AUTOSIZE
            );
        }
    }
}

/// Toolbar "Create rule" / Edit menu equivalent: open the rule
/// editor on a fresh blank rule. On OK, append to
/// `profile.custom_rules`, persist, repopulate the User rules tab.
fn on_create_rule(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let new_rule = match super::rule_editor::open(hwnd, None) {
        Some(r) => r,
        None => return, // Cancel
    };
    state.app.profile.borrow_mut().custom_rules.push(new_rule);
    save_profile_to_disk(state);
    populate_user_rules(state);
    on_tab_change(hwnd);
    set_status_text(state.status.get(), 0, "Rule added.");
}

/// Double-click handler for the User rules listview — opens the
/// editor pre-filled with the clicked row's rule. On OK, swap the
/// rule in place; persist and repopulate.
fn on_edit_selected_rule(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = state.listviews[5].get(); // index 5 = IDC_RULES_CUSTOM
    if lv.0 == 0 {
        return;
    }
    let idx = unsafe {
        SendMessageW(
            lv,
            LVM_GETNEXTITEM,
            WPARAM(usize::MAX), // -1 = start from before first item
            LPARAM(LVNI_SELECTED as isize),
        )
    }
    .0;
    if idx < 0 {
        return;
    }
    let idx = idx as usize;

    // Clone for the editor — we need the borrow to drop before
    // calling open() (which pumps Win32 messages and could
    // re-entrantly touch the profile).
    let existing = match state.app.profile.borrow().custom_rules.get(idx) {
        Some(r) => r.clone(),
        None => return,
    };

    let updated = match super::rule_editor::open(hwnd, Some(&existing)) {
        Some(r) => r,
        None => return,
    };
    if let Some(slot) = state.app.profile.borrow_mut().custom_rules.get_mut(idx) {
        *slot = updated;
    }
    save_profile_to_disk(state);
    populate_user_rules(state);
    on_tab_change(hwnd);
    set_status_text(state.status.get(), 0, "Rule updated.");
}

/// Delete-key handler for the User rules listview — confirm,
/// then remove the selected row. Persist + repopulate.
fn on_delete_selected_rule(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONQUESTION, MB_YESNO, IDYES};
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = state.listviews[5].get();
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
    let idx = idx as usize;

    let title = wide("Delete rule");
    let rule_name = state
        .app
        .profile
        .borrow()
        .custom_rules
        .get(idx)
        .map(|r| r.name.clone())
        .unwrap_or_default();
    let body = wide(&format!("Delete the rule \"{rule_name}\"?"));
    let answer = unsafe {
        MessageBoxW(
            hwnd,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONQUESTION,
        )
    };
    if answer != IDYES {
        return;
    }

    {
        let mut profile = state.app.profile.borrow_mut();
        if idx < profile.custom_rules.len() {
            profile.custom_rules.remove(idx);
        }
    }
    save_profile_to_disk(state);
    populate_user_rules(state);
    on_tab_change(hwnd);
    set_status_text(state.status.get(), 0, "Rule deleted.");
}

/// Serialise the current in-memory profile back to its source
/// path. Used after every Add/Edit/Delete so changes survive a
/// restart even before the user explicitly hits Save / Export.
/// Failures log to stderr + status bar; the in-memory edit
/// stands either way (the user can still re-save via
/// File > Export).
fn save_profile_to_disk(state: &WndState) {
    let path = state.app.profile_path.borrow().clone();
    let xml = crate::profile::to_string(&state.app.profile.borrow());
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, xml) {
        eprintln!(
            "simplewall-rs: profile auto-save failed for {}: {e}",
            path.display()
        );
        set_status_text(state.status.get(), 0, "Auto-save failed.");
    }
}

/// File → Import: pick a `.xml` profile, parse it, swap it in as
/// the active profile, repopulate the listviews, and update the
/// title bar to reflect the new path.
fn on_import(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let Some(path) = dialogs::open_profile(hwnd) else {
        return;
    };
    let xml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "simplewall-rs: import: read failed for {}: {e}",
                path.display()
            );
            set_status_text(state.status.get(), 0, "Import failed: read error.");
            return;
        }
    };
    let new_profile = match crate::profile::parse_str(&xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("simplewall-rs: import: parse failed: {e}");
            set_status_text(state.status.get(), 0, "Import failed: parse error.");
            return;
        }
    };
    state.app.profile.replace(new_profile);
    state.app.profile_path.replace(path.clone());
    populate_apps_tab(state);
    populate_user_rules(state);
    on_tab_change(hwnd);
    set_window_title(hwnd, &path);
    set_status_text(state.status.get(), 0, "Imported.");
}

/// File → Export: pick a destination, serialize the current
/// profile to XML, write it. After a successful save we update the
/// active profile_path + title bar so subsequent Refresh/Save
/// targets the new path.
fn on_export(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    // Suggest the current filename so quick "save a copy" flows
    // don't make the user retype it.
    let default_name = state
        .app
        .profile_path
        .borrow()
        .file_name()
        .map(|s| s.to_string_lossy().into_owned());
    let Some(target) = dialogs::save_profile(hwnd, default_name.as_deref()) else {
        return;
    };

    let xml = crate::profile::to_string(&state.app.profile.borrow());
    if let Err(e) = std::fs::write(&target, xml) {
        eprintln!(
            "simplewall-rs: export: write failed for {}: {e}",
            target.display()
        );
        set_status_text(state.status.get(), 0, "Export failed: write error.");
        return;
    }
    state.app.profile_path.replace(target.clone());
    set_window_title(hwnd, &target);
    set_status_text(state.status.get(), 0, "Exported.");
}

/// Reload the current profile from disk and re-populate the
/// listviews. Triggered by Edit → Refresh and the toolbar's
/// Refresh button. If the file is missing or malformed, leave the
/// in-memory profile untouched and surface the error on the status
/// bar so the user notices.
fn on_refresh(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let path = state.app.profile_path.borrow().clone();
    let xml = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "simplewall-rs: refresh: read failed for {}: {e}",
                path.display(),
            );
            set_status_text(state.status.get(), 0, "Refresh failed: read error.");
            return;
        }
    };
    let new_profile = match crate::profile::parse_str(&xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("simplewall-rs: refresh: parse failed: {e}");
            set_status_text(state.status.get(), 0, "Refresh failed: parse error.");
            return;
        }
    };
    state.app.profile.replace(new_profile);
    populate_apps_tab(state);
    populate_user_rules(state);
    on_tab_change(hwnd); // refresh status-bar item count
    set_status_text(state.status.get(), 0, "Profile reloaded.");
}

/// Fill in the tooltip text for a toolbar button. The toolbar
/// notifies us with `TBN_GETINFOTIPW` carrying `iItem` (the
/// button's command ID) and a writeable `pszText` / `cchTextMax`
/// buffer. We copy the matching tooltip into the buffer; if the
/// button isn't recognised we leave the buffer untouched (Win32
/// then falls back to the button label).
fn fill_toolbar_tooltip(info: &mut NMTBGETINFOTIPW) {
    let text = match info.iItem as u16 {
        IDM_TRAY_START => "Enable filters (Ctrl+T)",
        IDM_OPENRULESEDITOR => "Create a new user rule",
        IDM_TRAY_ENABLENOTIFICATIONS_CHK => "Enable notifications for blocked traffic",
        IDM_TRAY_ENABLELOG_CHK => "Log blocked traffic to a file",
        IDM_TRAY_ENABLEUILOG_CHK => "Show packets log in the UI",
        IDM_REFRESH => "Reload the profile from disk (F5)",
        IDM_SETTINGS => "Open Settings",
        IDM_TRAY_LOGSHOW => "Open the packets log file",
        IDM_TRAY_LOGCLEAR => "Clear the packets log",
        IDM_RELEASES => "Open the GitHub releases page",
        _ => return,
    };
    // Win32 caller already allocated the buffer; we just memcpy
    // up to cchTextMax-1 wide chars + a trailing NUL.
    if info.pszText.is_null() || info.cchTextMax <= 0 {
        return;
    }
    let wide: Vec<u16> = text.encode_utf16().collect();
    let max = (info.cchTextMax as usize).saturating_sub(1);
    let n = wide.len().min(max);
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), info.pszText.0, n);
        *info.pszText.0.add(n) = 0;
    }
}

/// Open the project's main GitHub page (Help → Website).
fn open_website(hwnd: HWND) {
    shell_open_url(hwnd, w!("https://github.com/amrust/simplewall-rs"));
}

/// Help → About: modern TaskDialog with version, copyright, GPL
/// notice, and a clickable repo link. ENABLE_HYPERLINKS routes
/// link clicks to our callback which fires ShellExecuteW.
fn on_about(hwnd: HWND) {
    use windows::Win32::UI::Controls::{
        TASKDIALOG_FLAGS, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOGCONFIG_1,
        TDCBF_OK_BUTTON, TDF_ENABLE_HYPERLINKS, TaskDialogIndirect,
    };

    let title = wide("About simplewall-rs");
    let main_instr = wide("simplewall-rs");
    let version = env!("CARGO_PKG_VERSION");
    let content_str = format!(
        concat!(
            "Version {version}\n",
            "\n",
            "A Rust port of simplewall, a Windows Filtering Platform (WFP) firewall.\n",
            "\n",
            "Copyright \u{00A9} 2026 simplewall-rs contributors.\n",
            "Licensed under the GNU General Public License v3.0 or later.\n",
            "\n",
            "Original simplewall \u{00A9} 2016\u{2013}2026 Henry++.\n",
            "\n",
            "<a href=\"https://github.com/amrust/simplewall-rs\">",
            "github.com/amrust/simplewall-rs</a>",
        ),
        version = version,
    );
    let content = wide(&content_str);

    let cfg = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: hwnd,
        dwFlags: TASKDIALOG_FLAGS(TDF_ENABLE_HYPERLINKS.0),
        dwCommonButtons: TDCBF_OK_BUTTON,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(main_instr.as_ptr()),
        pszContent: PCWSTR(content.as_ptr()),
        pfCallback: Some(about_dialog_callback),
        Anonymous1: TASKDIALOGCONFIG_0::default(),
        Anonymous2: TASKDIALOGCONFIG_1::default(),
        ..Default::default()
    };

    unsafe {
        let _ = TaskDialogIndirect(&cfg, None, None, None);
    }
}

/// TaskDialog notification callback. We only care about
/// TDN_HYPERLINK_CLICKED — when the user clicks the GitHub link
/// in the About box, route it through ShellExecuteW so it opens
/// in their default browser.
unsafe extern "system" fn about_dialog_callback(
    hwnd: HWND,
    msg: windows::Win32::UI::Controls::TASKDIALOG_NOTIFICATIONS,
    _wparam: WPARAM,
    lparam: LPARAM,
    _ref_data: isize,
) -> windows::core::HRESULT {
    use windows::Win32::UI::Controls::TDN_HYPERLINK_CLICKED;
    if msg == TDN_HYPERLINK_CLICKED {
        let url_ptr = lparam.0 as *const u16;
        if !url_ptr.is_null() {
            unsafe {
                let _ = ShellExecuteW(
                    hwnd,
                    w!("open"),
                    PCWSTR(url_ptr),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    SW_SHOWNORMAL,
                );
            }
        }
    }
    windows::core::HRESULT(0) // S_OK
}

/// Open https://github.com/amrust/simplewall-rs/releases in
/// the system's default browser. Replaces upstream's PayPal donate
/// flow — same toolbar slot, friendlier action.
fn open_releases_page(hwnd: HWND) {
    shell_open_url(
        hwnd,
        w!("https://github.com/amrust/simplewall-rs/releases"),
    );
}

/// Pop the user's default browser at `url`. ShellExecuteW returns
/// a HINSTANCE > 32 on success and an error code <= 32 on
/// failure. We don't surface failure beyond a stderr line since
/// the user-visible failure mode (browser doesn't open) is
/// already self-explanatory.
fn shell_open_url(hwnd: HWND, url: PCWSTR) {
    let result = unsafe {
        ShellExecuteW(hwnd, w!("open"), url, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL)
    };
    if result.0 as usize <= 32 {
        eprintln!("simplewall-rs: ShellExecuteW failed: code {}", result.0);
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
/// profile's custom rules. The Apps / Services / UWP / Blocklist /
/// System rules / Connections / Log tabs follow their own
/// populators (Apps from `profile.apps`; the rest are M6+).
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

    let profile = state.app.profile.borrow();
    for (idx, rule) in profile.custom_rules.iter().enumerate() {
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

/// Wipe the Apps ListView (IDC_APPS_PROFILE) and re-fill from
/// `profile.apps`. Each row carries:
///   col 0  - filename (basename of the .exe path)
///   col 1  - "Added" timestamp formatted as local-time
///            "yyyy-MM-dd HH:mm:ss"
///   checkbox state - reflects `App.is_enabled`.
///
/// Toggling the checkbox is wired in a follow-up (it mutates the
/// in-memory App.is_enabled; actual filter (re-)install fires off
/// an Apply or the Enable filters toolbar button).
fn populate_apps_tab(state: &WndState) {
    // Index 0 in TAB_LISTVIEW_IDS is IDC_APPS_PROFILE.
    let lv = state.listviews[0].get();
    if lv.0 == 0 {
        return;
    }

    unsafe {
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }

    let profile = state.app.profile.borrow();
    for (idx, app) in profile.apps.iter().enumerate() {
        // File name only by default — full path is too long for
        // the column. View → Show filenames only is on by default
        // upstream and we'll pick that up when settings persistence
        // wires the toggle.
        let display_name = app
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| app.path.display().to_string());
        let mut name_buf = wide(&display_name);

        // INDEXTOSTATEIMAGEMASK(2) = checked, (1) = unchecked.
        // The state image bits live in the high nibble of `state`
        // (mask LVIS_STATEIMAGEMASK). LVIF_STATE in `mask` plus the
        // matching `stateMask` is the documented way to set this
        // alongside the row insert.
        let state_image_index = if app.is_enabled { 2u32 } else { 1u32 };
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image_index << 12),
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

        let added = if app.timestamp > 0 {
            format_timestamp_local(app.timestamp)
        } else {
            String::new()
        };
        set_subitem(lv, idx as i32, 1, &added);
    }
}

/// Convert a Unix timestamp (seconds since 1970-01-01 UTC) into a
/// local-time string formatted as "yyyy-MM-dd HH:mm:ss". Returns
/// an empty string if any of the three Win32 conversions fail —
/// callers treat empty as "no timestamp" for display purposes, so
/// silent failure is acceptable here.
fn format_timestamp_local(unix_ts: i64) -> String {
    // FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC.
    // Unix epoch is 1970-01-01 UTC = 11_644_473_600 seconds later =
    // 116_444_736_000_000_000 hundred-nanosecond ticks.
    if unix_ts < 0 {
        return String::new();
    }
    let ticks = (unix_ts as u64).saturating_mul(10_000_000) + 116_444_736_000_000_000u64;
    let ft = FILETIME {
        dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    if unsafe { FileTimeToSystemTime(&ft, &mut utc) }.is_err() {
        return String::new();
    }
    let mut local = SYSTEMTIME::default();
    if unsafe { SystemTimeToTzSpecificLocalTime(None, &utc, &mut local) }.is_err() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond,
    )
}

/// Populate the Connections tab (`IDC_NETWORK`) from a fresh
/// IP Helper enumeration. Each row covers the 9 columns set up
/// in `configure_listview` for IDC_NETWORK:
///   Name | Address(Source) | Host(Source) | Port(Source) |
///   Address(Destination) | Host(Destination) | Port(Destination) |
///   Protocol | State
/// Host(Source) / Host(Destination) are blank for now — DNS
/// reverse-resolution is async and would block the UI thread.
fn populate_connections_tab(state: &WndState) {
    // Index 6 in TAB_LISTVIEW_IDS is IDC_NETWORK.
    let lv = state.listviews[6].get();
    if lv.0 == 0 {
        return;
    }
    let conns = super::connections::enumerate();

    unsafe {
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }
    for (idx, c) in conns.iter().enumerate() {
        let mut name_buf = wide(&c.process);
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
        set_subitem(lv, idx as i32, 1, &c.local.ip.to_string());
        // col 2 (Host source) intentionally empty — see fn doc.
        set_subitem(lv, idx as i32, 3, &c.local.port.to_string());
        let remote_addr = if c.remote.ip.is_unspecified() {
            String::new()
        } else {
            c.remote.ip.to_string()
        };
        set_subitem(lv, idx as i32, 4, &remote_addr);
        // col 5 (Host destination) intentionally empty.
        let remote_port = if c.remote.port == 0 {
            String::new()
        } else {
            c.remote.port.to_string()
        };
        set_subitem(lv, idx as i32, 6, &remote_port);
        set_subitem(lv, idx as i32, 7, c.protocol.label());
        set_subitem(lv, idx as i32, 8, c.state);
    }
}

/// Populate one of the two internal-profile listviews
/// (`IDC_RULES_SYSTEM` or `IDC_RULES_BLOCKLIST`) from the bundled
/// `internal_profile`. Same column shape as the user rules tab —
/// Name / Protocol / Direction — and same rule struct, just a
/// different source slice.
///
/// Each row's checkbox is initially set from `Rule.is_enabled` so
/// users can see at a glance which built-in rules are active. The
/// `rule_configs` overrides aren't applied yet — that's M5.5 (the
/// rules editor's "edit override" path).
fn populate_internal_rules(state: &WndState, id: i32) {
    use crate::profile::{Direction, Rule};

    let slot = match id {
        IDC_RULES_BLOCKLIST => 3, // index in TAB_LISTVIEW_IDS
        IDC_RULES_SYSTEM => 4,
        _ => return,
    };
    let lv = state.listviews[slot].get();
    if lv.0 == 0 {
        return;
    }

    unsafe {
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }

    let rules: &[Rule] = match id {
        IDC_RULES_BLOCKLIST => &state.app.internal_profile.blocklist_rules,
        IDC_RULES_SYSTEM => &state.app.internal_profile.system_rules,
        _ => return,
    };

    for (idx, rule) in rules.iter().enumerate() {
        let mut name_buf = wide(&rule.name);
        let state_image = if rule.is_enabled { 2u32 } else { 1u32 };
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
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

/// Build the main-window title string from the loaded profile's
/// path: `simplewall-rs — <path>`. Em-dash (U+2014) for the
/// separator, matching upstream's title-bar style. The path goes
/// through `Path::display()` so non-UTF-8 path components (rare on
/// Windows but possible) round-trip lossily without panicking.
fn format_window_title(path: &std::path::Path) -> String {
    format!("simplewall-rs \u{2014} {}", path.display())
}

/// Replace the main window's title, e.g. after Open Profile…
/// switches the loaded profile. Public-in-module so other
/// handlers (Open / Save As / future Refresh) can call it.
#[allow(dead_code)]
pub(super) fn set_window_title(hwnd: HWND, path: &std::path::Path) {
    let title = wide(&format_window_title(path));
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowTextW(
            hwnd,
            PCWSTR(title.as_ptr()),
        );
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

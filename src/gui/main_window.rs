// amwall — main window class + WndProc.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
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
use windows::Win32::Graphics::Gdi::{DeleteObject, HBRUSH, HFONT, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_COOL_CLASSES, ICC_LISTVIEW_CLASSES, ICC_TAB_CLASSES, INITCOMMONCONTROLSEX,
    InitCommonControlsEx, LIST_VIEW_ITEM_STATE_FLAGS, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT,
    LVCFMT_RIGHT, LVCOLUMNW, LVIF_GROUPID, LVIF_PARAM, LVIF_STATE, LVIF_TEXT, LVIS_STATEIMAGEMASK,
    LVITEMW,
    LVM_DELETEALLITEMS, LVM_GETITEM, LVM_GETITEMCOUNT, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW,
    LVM_INSERTITEMW, LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMTEXTW,
    LVN_KEYDOWN,
    LVNI_SELECTED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_REPORT,
    LVS_SHOWSELALWAYS, NM_DBLCLK, NM_RCLICK, NMHDR, NMITEMACTIVATE, NMLVKEYDOWN,
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
    WM_ENTERSIZEMOVE, WM_EXITSIZEMOVE, WM_NCCREATE, WM_NCDESTROY, WM_NOTIFY, WM_SHOWWINDOW,
    WM_SIZE, WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CHILD,
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
    IDM_ALLOW, IDM_BLOCK, IDM_BLOCKLIST_UPDATE_ALLOW, IDM_BLOCKLIST_UPDATE_BLOCK,
    IDM_BLOCKLIST_UPDATE_DISABLE, IDM_CHECKUPDATES, IDM_CHECKUPDATES_CHK, IDM_COPY, IDM_EXIT,
    IDM_EXPLORE, IDM_EXPORT, IDM_FONT, IDM_IMPORT,
    IDM_LOADONSTARTUP_CHK, IDM_LOGCLEAR, IDM_OPENRULESEDITOR, IDM_PROPERTIES, IDM_PURGE_TIMERS,
    IDM_REMOVE_FROM_PROFILE,
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
const CLASS_NAME: PCWSTR = w!("AmwallMainWindow");

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
/// in `create` once we know the monitor DPI. Width chosen to fit the
/// full toolbar (last button "Releases" ends around x=870 device px at
/// 96 DPI) plus the window's non-client frame on either side, with a
/// little margin so the toolbar doesn't wrap to a second row at the
/// default size.
const LOGICAL_INITIAL_W: i32 = 1024;
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
    /// HWND of the toolbar (the action-buttons row). Cached so
    /// `on_size` can MoveWindow it directly without `GetDlgItem`.
    toolbar: Cell<HWND>,
    /// HWND of the search edit. Lives directly under the toolbar.
    search: Cell<HWND>,
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
    /// Cached HFONT for the system message font (Segoe UI 9pt on
    /// modern Windows). Loaded once at WM_CREATE and broadcast to
    /// every child via WM_SETFONT — `CreateWindowEx`-built
    /// controls otherwise default to the legacy bitmap "System"
    /// font and render without anti-aliasing.
    /// Deleted on WM_NCDESTROY.
    font: Cell<HFONT>,
    /// Current substring entered in the rebar's search edit. The
    /// populator helpers read this and skip rows whose name
    /// doesn't contain it (case-insensitive). Empty string = no
    /// filtering.
    search_text: std::cell::RefCell<String>,

    // ---- WFP net-event subscription (M5.10 / M6.1) ----
    //
    // Drop order matters: `event_subscription` must drop BEFORE
    // `event_engine` so unsubscribe runs against a still-open
    // engine handle. Rust drops fields in declaration order,
    // hence subscription before rx before engine.
    event_subscription:
        std::cell::RefCell<Option<crate::wfp::events::EventSubscription>>,
    event_rx: std::cell::RefCell<
        Option<std::sync::mpsc::Receiver<crate::wfp::events::NetEvent>>,
    >,
    /// Owner of the WFP engine handle the event subscription
    /// borrows from. `Option` because subscribe can fail (most
    /// commonly: not running as admin) and we want the GUI to
    /// keep working with an empty Packets log tab in that case.
    event_engine: std::cell::RefCell<Option<crate::wfp::WfpEngine>>,
    /// Capped ring of decoded events for the Packets log tab.
    /// New events get pushed at the back; if the buffer is full,
    /// the oldest is dropped. `EVENT_LOG_CAP` rows is enough to
    /// see recent activity without unbounded memory growth.
    event_log: std::cell::RefCell<std::collections::VecDeque<crate::wfp::events::NetEvent>>,
    /// File-backed event log writer (M6.3). Lazily opens / rotates
    /// the on-disk log per `Settings.enable_log` + `log_path` +
    /// `log_size_limit`. Mirrors the in-memory `event_log` ring,
    /// but persists across app restarts.
    event_log_writer: std::cell::RefCell<super::event_log::EventLogWriter>,
    /// `true` between WM_ENTERSIZEMOVE and WM_EXITSIZEMOVE — i.e.
    /// while the user is actively dragging the resize edge. We
    /// suppress paint on the listviews during the drag (single
    /// MoveWindow with bRepaint=FALSE; the LVS_EX_DOUBLEBUFFER
    /// content remains visible at the old size), and re-fire a
    /// clean jiggle-repaint once at WM_EXITSIZEMOVE. Otherwise
    /// the per-pixel WM_SIZE flood coalesces paints and lands
    /// the listview in a half-painted state.
    resizing: Cell<bool>,
    /// `filterId`s of every filter currently installed under
    /// amwall's `PROVIDER_KEY`. Drop-packet toast is gated on
    /// `event.filter_id ∈ this set` so we don't pop notifications
    /// for Windows Firewall / third-party WFP-provider drops.
    /// Populated at WM_CREATE and refreshed after every successful
    /// install / uninstall.
    amwall_filter_ids: std::cell::RefCell<std::collections::HashSet<u64>>,
    /// `true` when amwall has filters live in WFP (i.e.
    /// `amwall_filter_ids` is non-empty). Drives the toolbar
    /// "Enable filters" ↔ "Disable filters" toggle.
    filters_active: Cell<bool>,
    /// Cached SCM enumeration for the Apps → Services tab. Populated
    /// on WM_CREATE and refreshed by IDM_REFRESH (F5). Kept in
    /// memory so tab-switch + search-filter repaints don't re-walk
    /// SCM for every keystroke.
    services: std::cell::RefCell<Vec<super::services_enum::ServiceEntry>>,
    /// Cached registry walk of installed UWP packages for the Apps
    /// → UWP tab. Same population/refresh model as `services`.
    uwp_packages: std::cell::RefCell<Vec<super::uwp_enum::PackageEntry>>,
    /// Most recently right-clicked listview row, set on NM_RCLICK
    /// before the popup menu shows and consumed by the IDM_*
    /// handlers. None after the menu dismisses (or never opened).
    context_target: std::cell::RefCell<Option<super::apps_context_menu::ContextTarget>>,
}

impl WndState {
    fn new(app: Box<App>) -> Self {
        Self {
            app,
            toolbar: Cell::new(HWND::default()),
            search: Cell::new(HWND::default()),
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
            font: Cell::new(HFONT::default()),
            search_text: std::cell::RefCell::new(String::new()),
            event_subscription: std::cell::RefCell::new(None),
            event_rx: std::cell::RefCell::new(None),
            event_engine: std::cell::RefCell::new(None),
            event_log: std::cell::RefCell::new(std::collections::VecDeque::new()),
            event_log_writer: std::cell::RefCell::new(
                super::event_log::EventLogWriter::new(),
            ),
            resizing: Cell::new(false),
            amwall_filter_ids: std::cell::RefCell::new(std::collections::HashSet::new()),
            filters_active: Cell::new(false),
            services: std::cell::RefCell::new(Vec::new()),
            uwp_packages: std::cell::RefCell::new(Vec::new()),
            context_target: std::cell::RefCell::new(None),
        }
    }
}

/// Maximum number of events kept in `WndState.event_log`. Older
/// events are dropped as new ones arrive.
const EVENT_LOG_CAP: usize = 1000;

/// Win32 timer id for the event-drain pump. Picks up any
/// callback-pushed events from `event_rx` and appends them to
/// `event_log`, refreshing the listview if the Log tab is visible.
const TIMER_EVENT_DRAIN: usize = 9002;

/// How often to drain the event channel, in milliseconds. 500 ms is
/// frequent enough to feel live without burning CPU when no events
/// are firing.
const EVENT_DRAIN_INTERVAL_MS: u32 = 500;

/// One-shot timer that fires `EVENT_RESIZE_CLEANUP_MS` after the
/// last WM_SIZE — at which point the user has stopped dragging
/// and we can safely do the listview-jiggle repaint without
/// fighting the live-drag paint flood. More reliable than
/// WM_EXITSIZEMOVE, which doesn't fire under Aero Snap and can
/// be missed in other edge cases.
const TIMER_RESIZE_CLEANUP: usize = 9003;
const RESIZE_CLEANUP_MS: u32 = 100;

/// One-shot timer fired shortly after `LVN_GROUPINFO` reports a
/// group state change (typically the user clicking a collapse
/// chevron). Mirrors `TIMER_RESIZE_CLEANUP` — same paint-pipeline
/// class of bug as M5.9.5 (listview internal layout doesn't pick
/// up the new geometry without a 1-pixel jiggle). Delaying past the
/// collapse animation avoids fighting comctl's own paint.
const TIMER_GROUP_COLLAPSE_REPAINT: usize = 9004;
const GROUP_COLLAPSE_REPAINT_MS: u32 = 100;

/// `LVN_GROUPINFO` — sent by a list-view control when a group's
/// state has changed (collapsed, expanded, …). Not exposed as a
/// public constant in windows-rs 0.54, so we hardcode it: the value
/// is `LVN_FIRST - 88` per comctl headers, where `LVN_FIRST` is
/// `(0u32 - 100u32) = 4294967196`. Verified live: this is the only
/// notification that fires on chevron clicks.
const LVN_GROUPINFO: u32 = 0xFFFFFF44;

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
                eprintln!("amwall: WM_CREATE failed: {e}");
                LRESULT(-1)
            }
        },
        WM_SIZE => {
            on_size(hwnd);
            // (Re-)arm the resize-cleanup timer. Each new WM_SIZE
            // pushes the deadline back; once size events stop the
            // timer fires once (100 ms later) and we run the
            // listview-jiggle repaint to land in a clean paint
            // state. This handles every resize path — drag,
            // double-click maximize, Aero Snap, programmatic
            // SetWindowPos — without depending on WM_EXITSIZEMOVE.
            unsafe {
                SetTimer(hwnd, TIMER_RESIZE_CLEANUP, RESIZE_CLEANUP_MS, None);
            }
            LRESULT(0)
        }
        WM_SHOWWINDOW => {
            // wparam=TRUE means we're becoming visible. The
            // listviews were ShowWindow(SW_SHOW)'d during WM_CREATE
            // (via on_tab_change) but their first WM_PAINT was
            // dropped because the parent was still hidden — so
            // re-trigger the active-listview reveal now that the
            // parent is up. Idempotent: subsequent visibility
            // changes (minimize/restore) just re-show the same lv.
            if wparam.0 != 0 {
                on_tab_change(hwnd);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_ENTERSIZEMOVE => {
            // Mark resize-in-progress so on_size can skip the
            // listview paint flag (bRepaint=FALSE) for the
            // duration of the live drag. WM_SIZE fires many times
            // per second during a drag and paint coalescing
            // leaves the listview half-painted otherwise.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                state.resizing.set(true);
            }
            LRESULT(0)
        }
        WM_EXITSIZEMOVE => {
            // Drag finished. Clear the resize flag, then re-fire
            // the clean repaint path: on_size with paint enabled
            // (one final layout at the settled size), then
            // on_tab_change which jiggles the active listview to
            // wake its header subwindow up.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                state.resizing.set(false);
            }
            on_size(hwnd);
            on_tab_change(hwnd);
            LRESULT(0)
        }
        WM_NOTIFY => {
            let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
            // TCN_SELCHANGE: user clicked a different tab — show
            // the matching listview, hide the others.
            if nmhdr.idFrom == IDC_TAB as usize && nmhdr.code == TCN_SELCHANGE {
                on_tab_change(hwnd);
            }
            // RBN_HEIGHTCHANGE: the rebar's overall height grew
            // or shrank — typically because the toolbar's
            // TBSTYLE_WRAPABLE wrapped buttons to a new row. Re-
            // run on_size so the tab control + listview shift
            // down (or up) to match the new rebar height. Without
            // this the wrapped second row of buttons paints over
            // whatever sits below the rebar.
            if nmhdr.code == windows::Win32::UI::Controls::RBN_HEIGHTCHANGE {
                on_size(hwnd);
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
            // NM_RCLICK on any of the Apps tabs (Profile / Service /
            // UWP) shows the right-click context menu (M5.4c).
            if nmhdr.code == NM_RCLICK
                && (nmhdr.idFrom == IDC_APPS_PROFILE as usize
                    || nmhdr.idFrom == IDC_APPS_SERVICE as usize
                    || nmhdr.idFrom == IDC_APPS_UWP as usize)
            {
                let activate = unsafe { &*(lparam.0 as *const NMITEMACTIVATE) };
                on_apps_context_menu(hwnd, nmhdr.idFrom as i32, activate);
            }
            // LVN_GROUPINFO fires whenever a group's state changes —
            // most importantly when the user clicks a collapse
            // chevron. comctl32 doesn't expose any other notification
            // for that gesture, so this is the canonical hook.
            // Schedule the same paint-jiggle the resize cleanup uses
            // so collapsed/expanded items render cleanly.
            if nmhdr.code == LVN_GROUPINFO
                && (nmhdr.idFrom == IDC_APPS_PROFILE as usize
                    || nmhdr.idFrom == IDC_APPS_SERVICE as usize
                    || nmhdr.idFrom == IDC_APPS_UWP as usize
                    || nmhdr.idFrom == IDC_RULES_BLOCKLIST as usize
                    || nmhdr.idFrom == IDC_RULES_SYSTEM as usize
                    || nmhdr.idFrom == IDC_RULES_CUSTOM as usize)
            {
                unsafe {
                    SetTimer(
                        hwnd,
                        TIMER_GROUP_COLLAPSE_REPAINT,
                        GROUP_COLLAPSE_REPAINT_MS,
                        None,
                    );
                }
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
            let id = (wparam.0 as u32) & 0xFFFF;
            let notif = ((wparam.0 as u32) >> 16) & 0xFFFF;
            on_command(hwnd, id, notif);
            LRESULT(0)
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, wparam, lparam);
            LRESULT(0)
        }
        m if m == super::notification::WM_USER_TOAST_MOVED => {
            on_toast_moved(hwnd, wparam, lparam);
            LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_CONNECTIONS_REFRESH {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    populate_connections_tab(state);
                }
            } else if wparam.0 == TIMER_EVENT_DRAIN {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    drain_events(hwnd, state);
                }
            } else if wparam.0 == TIMER_GROUP_COLLAPSE_REPAINT {
                // One-shot — disarm before any further work so a
                // re-arm during repaint doesn't recurse.
                unsafe {
                    let _ = KillTimer(hwnd, TIMER_GROUP_COLLAPSE_REPAINT);
                }
                // The active listview is whichever tab is selected;
                // running on_tab_change does the SW_SHOW + force-
                // repaint jiggle that fixes paint glitches without
                // re-inserting items (so the user's just-collapsed
                // state survives).
                on_tab_change(hwnd);
            } else if wparam.0 == TIMER_RESIZE_CLEANUP {
                // One-shot. Disarm immediately so we don't keep
                // jiggling on every tick after a single resize.
                unsafe {
                    let _ = KillTimer(hwnd, TIMER_RESIZE_CLEANUP);
                }
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    let tab = state.tab.get();
                    if tab.0 != 0 {
                        let sel = unsafe {
                            SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0))
                        }
                        .0 as isize;
                        let slot = if sel < 0 { 0 } else { sel as usize };
                        // Repopulate clears + re-inserts items
                        // and forces the listview to rebuild its
                        // view, which is invariant to whatever
                        // half-painted state comctl32 is in
                        // post-resize. Followed by on_tab_change
                        // for the jiggle that wakes the header
                        // subwindow up.
                        repopulate_tab(state, slot);
                    }
                }
                on_tab_change(hwnd);
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
                    let state = Box::from_raw(raw);
                    let f = state.font.get();
                    if !f.is_invalid() {
                        let _ = DeleteObject(f);
                    }
                    drop(state);
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
    let Toolbar { toolbar, search } = toolbar::create(hwnd, state.dpi.get())?;
    state.toolbar.set(toolbar);
    state.search.set(search);

    // Tab control — listviews are siblings, not children.
    let tab = create_tab_control(hwnd)?;
    state.tab.set(tab);
    insert_tabs(tab)?;

    // Per-tab listviews. Created in TAB_LISTVIEW_IDS order, all
    // hidden initially; the `on_tab_change` call at the end shows
    // the one matching the selected tab.
    //
    // Each listview is MoveWindow'd to a non-zero rect *before*
    // configure_listview adds columns. Inserting columns into a
    // 0×0 listview leaves the internal header control with bogus
    // geometry that subsequent resizes don't recover — observed as
    // headers/rows that stay invisible until hot-tracked column-
    // by-column on hover. on_size below sizes the listview to its
    // real rect; the 800×600 here is just placeholder geometry so
    // the header has somewhere to lay itself out.
    for (slot, &id) in TAB_LISTVIEW_IDS.iter().enumerate() {
        let lv = create_tab_listview(hwnd, id)?;
        unsafe {
            let _ = MoveWindow(lv, 0, 0, 800, 600, false);
        }
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
    // Services / UWP come from a Win32 SCM walk + a registry walk
    // of the UWP repository hive — both cached on `state` so tab-
    // switch + search-filter repaints don't re-enumerate.
    refresh_system_app_caches(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    populate_user_rules(state);
    populate_internal_rules(state, IDC_RULES_SYSTEM);
    populate_internal_rules(state, IDC_RULES_BLOCKLIST);

    // Apply persisted UI settings: menu checks + always-on-top +
    // search-bar visibility. After this the window mirrors what
    // the user left set last time.
    apply_initial_settings(hwnd, state);

    // Bind the system message font (Segoe UI 9pt + ClearType on
    // Windows 10/11) to every child created so far — toolbar
    // buttons, tab labels, listview items, status-bar text. Modal
    // dialogs handle this via DS_SHELLFONT in their templates;
    // raw CreateWindowEx-built controls need WM_SETFONT.
    let font = super::font::load_message_font();
    state.font.set(font);
    super::font::apply_recursive(hwnd, font);

    // Triggers on_size (which lays out children) and on_tab_change.
    on_size(hwnd);
    on_tab_change(hwnd);

    // Best-effort subscribe to WFP net events so the Packets log
    // tab can fill in. Failures (most commonly: not running as
    // admin) are logged and swallowed — the rest of the GUI works
    // fine without an event feed.
    try_subscribe_events(state);
    unsafe {
        SetTimer(hwnd, TIMER_EVENT_DRAIN, EVENT_DRAIN_INTERVAL_MS, None);
    }

    // First-run wizard (M9.4): if the user has never seen it
    // and simplewall has a config to import, ask. Runs once per
    // install (gated on `Settings.first_run_done`) so we don't
    // pester returning users.
    maybe_run_first_run_wizard(hwnd, state);

    Ok(())
}

/// Helper for `on_wm_create` end — gates on `first_run_done` and
/// dispatches to the wizard. On Imported, replaces the in-memory
/// profile + repaints the apps tab. Always sets `first_run_done`
/// when a real choice was made (Import / StartFresh / NotApplicable),
/// leaves it false for `Skipped` so a TaskDialog failure retries.
fn maybe_run_first_run_wizard(hwnd: HWND, state: &WndState) {
    if state.app.settings.borrow().first_run_done {
        return;
    }
    let profile_path = state.app.profile_path.borrow().clone();
    let choice = super::first_run_wizard::maybe_run(hwnd, &profile_path);
    use super::first_run_wizard::Choice;
    match choice {
        Choice::Imported => {
            // Re-read the file we just wrote so the in-memory
            // profile reflects it. parse failure is unlikely (we
            // just wrote a valid file by copying simplewall's) but
            // log + fall through to the existing empty profile if
            // it happens.
            match std::fs::read_to_string(&profile_path)
                .map_err(|e| e.to_string())
                .and_then(|xml| crate::profile::parse_str(&xml).map_err(|e| e.to_string()))
            {
                Ok(p) => {
                    state.app.profile.replace(p);
                    populate_apps_tab(state);
                    populate_user_rules(state);
                    on_tab_change(hwnd);
                    set_status_text(
                        state.status.get(),
                        0,
                        "Imported simplewall profile.",
                    );
                }
                Err(e) => eprintln!(
                    "amwall: imported profile parse failed: {e}"
                ),
            }
        }
        Choice::StartFresh | Choice::NotApplicable => {}
        Choice::Skipped => return, // don't mark done — retry next launch
    }

    // Persist the user's decision so we don't show the wizard
    // again. Pattern matches `on_toggle`'s save flow.
    state.app.settings.borrow_mut().first_run_done = true;
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!(
            "amwall: settings: save first_run_done failed for {}: {e}",
            path.display()
        );
    }
}

/// Open a separate WFP engine handle and subscribe to net events.
/// Stores the handles on `state`; on failure logs to stderr and
/// leaves the state's event fields as `None`.
fn try_subscribe_events(state: &WndState) {
    let engine = match crate::wfp::WfpEngine::open() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("amwall: WFP engine open failed for events: {e:?}");
            return;
        }
    };
    match crate::wfp::events::subscribe(&engine) {
        Ok((sub, rx)) => {
            // Snapshot the current set of amwall filters before
            // moving the engine into state — used by drain_events
            // to gate toast notifications to drops from our own
            // filters.
            refresh_amwall_filter_ids_with(&engine, state);
            *state.event_subscription.borrow_mut() = Some(sub);
            *state.event_rx.borrow_mut() = Some(rx);
            *state.event_engine.borrow_mut() = Some(engine);
        }
        Err(e) => {
            eprintln!(
                "amwall: net-event subscribe failed (admin may be required): {e}"
            );
            // Drop the engine — no subscription means no point
            // holding it open.
        }
    }
}

/// Repopulate the `amwall_filter_ids` cache + toolbar
/// "Enable filters" ↔ "Disable filters" appearance. Called at
/// startup (with the event-subscription engine) and after every
/// successful install/uninstall (with the engine that did the
/// mutation) so the cache always reflects live kernel state.
/// Repopulate the toast-gating filter-id cache. Does NOT touch
/// `filters_active` — that's driven by the install/uninstall
/// outcome, not by the filter count, so an empty profile still
/// flips the toggle button when the user enables the engine.
fn refresh_amwall_filter_ids_with(engine: &crate::wfp::WfpEngine, state: &WndState) {
    match engine.enumerate_filter_ids_for_provider(&crate::install::PROVIDER_KEY) {
        Ok(ids) => {
            *state.amwall_filter_ids.borrow_mut() = ids.into_iter().collect();
        }
        Err(e) => {
            eprintln!("amwall: failed to enumerate amwall filter ids: {e:?}");
        }
    }
}

/// Swap the toolbar's "Enable filters" button between its enabled
/// and disabled appearance: green tick-shield + "Enable filters"
/// when no amwall filters are installed, red cross-shield +
/// "Disable filters" when they are. Same `IDM_TRAY_START` command
/// id either way — the click handler branches on
/// `state.filters_active`.
fn update_enable_filters_button(state: &WndState, active: bool) {
    use windows::Win32::UI::Controls::{TBBUTTONINFOW, TBIF_IMAGE, TBIF_TEXT, TB_SETBUTTONINFOW};
    let toolbar = state.toolbar.get();
    if toolbar.0 == 0 {
        return;
    }
    let dpi = state.dpi.get();
    let icons = super::icons::build(dpi);
    let lookup_id = if active {
        super::icons::FILTER_DISABLE_MARKER
    } else {
        IDM_TRAY_START
    };
    let img_idx = super::icons::index_for(&icons, lookup_id);

    let label = if active { "Disable filters" } else { "Enable filters" };
    let mut wlabel = wide(label);
    let mut info = TBBUTTONINFOW {
        cbSize: std::mem::size_of::<TBBUTTONINFOW>() as u32,
        dwMask: TBIF_IMAGE | TBIF_TEXT,
        iImage: img_idx,
        pszText: PWSTR(wlabel.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            toolbar,
            TB_SETBUTTONINFOW,
            WPARAM(IDM_TRAY_START as usize),
            LPARAM(&mut info as *mut _ as isize),
        );
    }
}

/// Handler for `notification::WM_USER_TOAST_MOVED`. Posted by the
/// toast wndproc when the user finishes dragging — wparam carries
/// the new top-left x, lparam carries y, both as i32 round-tripped
/// through usize/isize. Cast back symmetrically and persist to
/// settings so the position survives across runs.
fn on_toast_moved(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let x = wparam.0 as isize as i32;
    let y = lparam.0 as i32;

    {
        let mut s = state.app.settings.borrow_mut();
        s.notification_x = x;
        s.notification_y = y;
    }

    // Same per-toggle persistence pattern used by on_toggle —
    // disk write failures stay in-memory-correct, just don't
    // survive a restart, and we log to stderr.
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!(
            "amwall: settings: save failed for {}: {e}",
            path.display()
        );
    }
}

/// Drain any pending events from the channel into the log buffer,
/// trimming the front to keep the buffer at most `EVENT_LOG_CAP`
/// entries. If the Log tab is currently visible, repopulate the
/// listview so the new rows show up live.
fn drain_events(hwnd: HWND, state: &WndState) {
    let settings = state.app.settings.borrow();
    let notify = settings.enable_notifications;
    let mut log = state.event_log.borrow_mut();
    let mut writer = state.event_log_writer.borrow_mut();
    let mut new_arrivals = false;
    let mut last_drop: Option<crate::wfp::events::NetEvent> = None;
    if let Some(rx) = state.event_rx.borrow().as_ref() {
        while let Ok(event) = rx.try_recv() {
            // Persist to the on-disk log first. Settings gate
            // (enable_log, exclude_classify_allow, rotation cap)
            // are applied inside the writer.
            writer.append(&event, &settings);

            // Toast the most recent drop in this batch and only
            // when the drop came from one of OUR filters — bare
            // FwpmNetEventSubscribe0 sees every drop in the
            // kernel (Windows Firewall, other WFP providers, …),
            // so notifying on all of them spams the user with
            // events that have nothing to do with amwall. Multi-
            // drop batches collapse to a single toast.
            if notify
                && let crate::wfp::events::NetEvent::Drop(d) = &event
                && let Some(filter_id) = d.filter_id
                && state.amwall_filter_ids.borrow().contains(&filter_id)
            {
                last_drop = Some(event.clone());
            }
            if log.len() >= EVENT_LOG_CAP {
                log.pop_front();
            }
            log.push_back(event);
            new_arrivals = true;
        }
    }
    drop(writer);
    drop(log);
    let settings_snapshot = settings.clone();
    drop(settings);
    if let Some(ev) = last_drop {
        super::notification::show_drop_notification(&ev, &settings_snapshot, hwnd);
    }

    if !new_arrivals {
        return;
    }
    // Repopulate only if Log tab is the active one — otherwise
    // we'd be doing UI work nobody sees. Switching to Log will
    // populate from the buffer regardless.
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel =
        unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    if sel == 7 {
        populate_log_tab(state);
        // Update the count segment on the status bar too.
        on_tab_change(hwnd);
    }
}

/// Apply the persisted Settings to the live window: menu check
/// marks, always-on-top, search-bar visibility, autosize-columns,
/// and a repopulate of the Apps tab so `show_filenames_only` /
/// path-display preferences kick in.
///
/// Called at startup (from on_create) and after Settings-dialog
/// Save so toggles take effect without a restart.
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
    apply_always_on_top(hwnd, s.always_on_top);
    apply_search_bar_visibility(hwnd, s.show_search_bar);
    super::font::set_dark_mode(hwnd, s.use_dark_theme);
    let autosize = s.autosize_columns;
    drop(s);

    refresh_blocklist_menu_checks(hwnd, state);
    localize_top_menu(hwnd, state);

    // Apps tab basename-vs-fullpath rendering depends on
    // `show_filenames_only`, so refresh it on every settings
    // apply. Other tabs aren't affected.
    populate_apps_tab(state);

    if autosize {
        autosize_active_listview_columns(state);
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

    // Layout: toolbar at the very top with full client width;
    // search edit below it; tab control below that.
    //
    //   1. Tell the toolbar its width via SetWindowPos. Its
    //      WM_SIZE handler runs TBSTYLE_WRAPABLE wrap if needed.
    //   2. Query TB_GETMAXSIZE for the wrapped height.
    //   3. MoveWindow the toolbar to (0, 0, total_w, tb_h).
    //   4. Position the search edit just below.
    //   5. Tab control sits below the search edit.
    let toolbar_hwnd = state.toolbar.get();
    let search_hwnd = state.search.get();
    const SEARCH_H: i32 = 24;
    let mut tb_h = 0;
    let mut header_h = 0;
    if toolbar_hwnd.0 != 0 {
        // 1. MoveWindow at the new width — the WRAPABLE toolbar
        //    auto-grows itself to its preferred height (rows ×
        //    row_h + comctl32 trailing padding). We can't shrink
        //    it back: a second MoveWindow gets reverted on the
        //    next WM_SIZE.
        // 2. Read the actual content extent (max bottom across
        //    all buttons + separators) — that's where the visible
        //    content ends.
        // 3. SetWindowRgn clips the toolbar's painted area to that
        //    extent. The window's logical rect stays at the
        //    toolbar's preferred size (so its layout state is
        //    untouched), but the gap between content_h and
        //    preferred_h becomes transparent — no visible blank
        //    band before the next control.
        unsafe {
            let _ = MoveWindow(toolbar_hwnd, 0, 0, total_w, 1, true);
        }
        tb_h = toolbar::toolbar_layout_height(toolbar_hwnd);
        toolbar::clip_to_content(toolbar_hwnd, total_w, tb_h);
        header_h += tb_h;
    }
    let _ = tb_h; // header_h is what downstream layout uses
    if search_hwnd.0 != 0 {
        let visible = state.app.settings.borrow().show_search_bar;
        if visible {
            unsafe {
                let _ = MoveWindow(search_hwnd, 0, header_h, total_w, SEARCH_H, true);
            }
            header_h += SEARCH_H;
        }
    }
    let rebar_h = header_h;
    let _ = tb_h; // kept for future per-row tinting if we want it

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

    // Compute the tab's content rect (the area inside the tab
    // strip) so we can size listviews to fill it.
    let mut content = RECT {
        left: 0,
        top: tab_y,
        right: total_w,
        bottom: tab_y + tab_h,
    };
    unsafe {
        let _ = SendMessageW(
            tab,
            TCM_ADJUSTRECT,
            WPARAM(0),
            LPARAM(&mut content as *mut _ as isize),
        );
    }
    let cw = content.right - content.left;
    let ch = content.bottom - content.top;

    // Mirror upstream simplewall (controls.c:_app_window_resize):
    // batch ONLY rebar + tab in DeferWindowPos, then MoveWindow
    // each listview INDIVIDUALLY outside the batch with
    // bRepaint=TRUE. Earlier versions batched all 9 (tab + 8
    // listviews) which reliably caused the listviews' inner
    // header + body to skip their first WM_PAINT after a resize
    // until hover hot-tracked them column-by-column.
    use windows::Win32::UI::WindowsAndMessaging::{
        BeginDeferWindowPos, DeferWindowPos, EndDeferWindowPos, SWP_NOACTIVATE, SWP_NOZORDER,
    };
    unsafe {
        // Only the tab control needs DeferWindowPos here — the
        // toolbar + search edit were positioned above. (The
        // batch-of-1 still provides atomic invalidation.)
        if let Ok(mut hdwp) = BeginDeferWindowPos(1) {
            if let Ok(h) = DeferWindowPos(
                hdwp,
                tab,
                HWND::default(),
                0,
                tab_y,
                total_w,
                tab_h,
                SWP_NOZORDER | SWP_NOACTIVATE,
            ) {
                hdwp = h;
            }
            let _ = EndDeferWindowPos(hdwp);
        }

        // bRepaint=FALSE while the user is actively dragging the
        // resize edge (resizing flag set by WM_ENTERSIZEMOVE).
        // MoveWindow still updates the window rect and fires
        // WM_SIZE on the listview so its internal layout updates,
        // but suppresses the per-pixel paint flood that would
        // otherwise produce visible flashing. The cleanup timer
        // armed by WM_SIZE fires once 100 ms after the last size
        // event and runs repopulate_tab + on_tab_change to land
        // the listview in a clean visible state.
        let repaint = !state.resizing.get();
        for slot in 0..TAB_LISTVIEW_IDS.len() {
            let lv = state.listviews[slot].get();
            if lv.0 == 0 {
                continue;
            }
            let _ = MoveWindow(lv, content.left, content.top, cw, ch, repaint);
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

/// Position a listview at `(x, y, w, h)` and force its internal
/// header subwindow to repaint. A single `MoveWindow` leaves the
/// header ghosted (visible-but-blank) until hover hot-tracking
/// forces per-element invalidation — the standard
/// `RedrawWindow(RDW_ALLCHILDREN)` doesn't reliably reach it
/// under comctl6. The reliable workaround is to make `MoveWindow`
/// fire `WM_SIZE` *twice*: once with a 1-pixel-larger rect (which
/// is a real size change so the listview re-lays out its
/// internals), then once with the correct rect (which trips the
/// re-layout a second time and lands on the right size). Used by
/// `on_tab_change` to wake the active listview's header up after
/// `SW_SHOW`.
fn force_listview_repaint(lv: HWND, x: i32, y: i32, w: i32, h: i32) {
    unsafe {
        let _ = MoveWindow(lv, x, y, w + 1, h + 1, true);
        let _ = MoveWindow(lv, x, y, w, h, true);
    }
}

/// Get a listview's current rect in its parent's client
/// coordinates, suitable for handing back to `force_listview_repaint`.
/// Returns `None` if the Win32 calls fail (shouldn't happen for
/// live windows).
fn current_lv_rect_in_parent(lv: HWND, parent: HWND) -> Option<(i32, i32, i32, i32)> {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::Graphics::Gdi::ScreenToClient;
    use windows::Win32::UI::WindowsAndMessaging::GetWindowRect;
    let mut wr = RECT::default();
    if unsafe { GetWindowRect(lv, &mut wr) }.is_err() {
        return None;
    }
    let mut tl = POINT {
        x: wr.left,
        y: wr.top,
    };
    if unsafe { ScreenToClient(parent, &mut tl) }.0 == 0 {
        return None;
    }
    Some((tl.x, tl.y, wr.right - wr.left, wr.bottom - wr.top))
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

    // ShowWindow(SW_SHOW) on a previously-hidden child window adds
    // its area to the parent's update region but doesn't always
    // queue a WM_PAINT for the child's own client rect — so the
    // listview can become visible without ever drawing its headers
    // or rows until something else (mouse hover hot-tracking)
    // pokes it. Force a full repaint on the just-shown listview.
    for (slot, lv_cell) in state.listviews.iter().enumerate() {
        let lv = lv_cell.get();
        if lv.0 == 0 {
            continue;
        }
        unsafe {
            if slot == sel_slot {
                let _ = ShowWindow(lv, SW_SHOW);
                if let Some((x, y, w, h)) = current_lv_rect_in_parent(lv, hwnd) {
                    force_listview_repaint(lv, x, y, w, h);
                }
            } else {
                let _ = ShowWindow(lv, SW_HIDE);
            }
        }
    }

    // Slot 7 is IDC_LOG (Packets log) — populate from the
    // accumulated event_log buffer when user lands on the tab. The
    // drain timer keeps it live while the tab stays visible.
    if sel_slot == 7 {
        populate_log_tab(state);
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

/// `WM_COMMAND` dispatch. `id` is LOWORD(wParam) — the menu /
/// control identifier. `notif` is HIWORD(wParam) — for control
/// notifications (EN_CHANGE, etc.); 0 for menu / accelerator
/// messages.
fn on_command(hwnd: HWND, id: u32, notif: u32) {
    // Search edit notification: refilter active tab as the user
    // types. EN_CHANGE = 0x0300.
    const EN_CHANGE: u32 = 0x0300;
    if (id as i32) == IDC_SEARCH && notif == EN_CHANGE {
        on_search_changed(hwnd);
        return;
    }
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
        IDM_SETTINGS => on_open_settings(hwnd),
        IDM_ADD_FILE => on_add_app(hwnd),

        // Apps tab right-click menu (M5.4c). All of these consume
        // `state.context_target` populated at NM_RCLICK time.
        IDM_ALLOW => on_context_set_enabled(hwnd, true),
        IDM_BLOCK => on_context_set_enabled(hwnd, false),
        IDM_REMOVE_FROM_PROFILE => on_context_remove(hwnd),
        IDM_EXPLORE => on_context_explore(hwnd),
        IDM_COPY => on_context_copy(hwnd),
        IDM_PROPERTIES => on_context_properties(hwnd),

        // Blocklist top-menu mode toggles (M7). Each pair updates
        // `Settings.blocklist_*` and re-renders the radio check
        // marks across the three sub-menus. The new mode takes
        // effect on the next "Enable filters" install.
        IDM_BLOCKLIST_SPY_DISABLE
        | IDM_BLOCKLIST_SPY_ALLOW
        | IDM_BLOCKLIST_SPY_BLOCK
        | IDM_BLOCKLIST_UPDATE_DISABLE
        | IDM_BLOCKLIST_UPDATE_ALLOW
        | IDM_BLOCKLIST_UPDATE_BLOCK
        | IDM_BLOCKLIST_EXTRA_DISABLE
        | IDM_BLOCKLIST_EXTRA_ALLOW
        | IDM_BLOCKLIST_EXTRA_BLOCK => on_blocklist_mode_pick(hwnd, id),

        other => eprintln!("amwall: menu id {other} not yet wired up"),
    }
}

/// Handle a click on one of the Blocklist top-menu items. Updates
/// `Settings.blocklist_*` to the chosen mode, persists to disk, and
/// refreshes the radio check marks.
fn on_blocklist_mode_pick(hwnd: HWND, id: u16) {
    use super::settings::BlocklistMode;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };

    {
        let mut s = state.app.settings.borrow_mut();
        match id {
            IDM_BLOCKLIST_SPY_DISABLE => s.blocklist_spy = BlocklistMode::Disable,
            IDM_BLOCKLIST_SPY_ALLOW => s.blocklist_spy = BlocklistMode::Allow,
            IDM_BLOCKLIST_SPY_BLOCK => s.blocklist_spy = BlocklistMode::Block,
            IDM_BLOCKLIST_UPDATE_DISABLE => s.blocklist_update = BlocklistMode::Disable,
            IDM_BLOCKLIST_UPDATE_ALLOW => s.blocklist_update = BlocklistMode::Allow,
            IDM_BLOCKLIST_UPDATE_BLOCK => s.blocklist_update = BlocklistMode::Block,
            IDM_BLOCKLIST_EXTRA_DISABLE => s.blocklist_extra = BlocklistMode::Disable,
            IDM_BLOCKLIST_EXTRA_ALLOW => s.blocklist_extra = BlocklistMode::Allow,
            IDM_BLOCKLIST_EXTRA_BLOCK => s.blocklist_extra = BlocklistMode::Block,
            _ => return,
        }
    }

    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!(
            "amwall: settings: save failed for {}: {e}",
            path.display()
        );
    }

    refresh_blocklist_menu_checks(hwnd, state);
}

/// Build + show the apps context menu, then route the chosen
/// command through `on_command`. Stores the right-clicked target on
/// `state.context_target` for the IDM_* handlers to read.
fn on_apps_context_menu(hwnd: HWND, listview_id: i32, activate: &NMITEMACTIVATE) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    // Map the clicked listview row back to its source-vec index
    // via the `lParam` the populator stamped at insert time. The
    // listview row index alone is stale once filters skip rows.
    let source_idx = {
        let lv_listview = match listview_id {
            id if id == IDC_APPS_PROFILE => state.listviews[0].get(),
            id if id == IDC_APPS_SERVICE => state.listviews[1].get(),
            id if id == IDC_APPS_UWP => state.listviews[2].get(),
            _ => return,
        };
        if lv_listview.0 == 0 {
            return;
        }
        match listview_item_param(lv_listview, activate.iItem) {
            Some(p) => p as usize,
            None => return,
        }
    };
    let target = {
        let profile = state.app.profile.borrow();
        let services = state.services.borrow();
        let uwp = state.uwp_packages.borrow();
        super::apps_context_menu::target_from_source(
            listview_id,
            activate.iItem,
            source_idx,
            &profile,
            &services,
            &uwp,
        )
    };
    let target = match target {
        Some(t) => t,
        // Right-click on empty area / out-of-range row — nothing
        // to act on. Could show a different "create new" menu but
        // that's M5.4 polish.
        None => return,
    };
    *state.context_target.borrow_mut() = Some(target.clone());

    let cmd = super::apps_context_menu::show(hwnd, &target);
    if let Some(id) = cmd {
        // TPM_RETURNCMD bypasses the WM_COMMAND queue, so dispatch
        // ourselves through the same handler.
        on_command(hwnd, id as u32, 0);
    }

    // Always clear after the menu — even if no item was picked, the
    // captured target shouldn't persist into the next interaction.
    *state.context_target.borrow_mut() = None;
}

/// Allow / Block toggle. Upserts an App entry at `target.binary_path`:
/// updates `is_enabled` if one exists, creates a new one otherwise.
/// No-op for UWP rows (binary_path is empty until M5.4d adds the
/// package-family-name model).
fn on_context_set_enabled(hwnd: HWND, enable: bool) {
    use crate::profile::App as ProfileApp;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    if target.binary_path.as_os_str().is_empty() {
        set_status_text(
            state.status.get(),
            0,
            "UWP packages not yet wired to profile (path-only model).",
        );
        return;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    {
        let mut profile = state.app.profile.borrow_mut();
        if let Some(existing) =
            profile.apps.iter_mut().find(|a| a.path == target.binary_path)
        {
            existing.is_enabled = enable;
        } else {
            profile.apps.push(ProfileApp {
                path: target.binary_path.clone(),
                is_enabled: enable,
                is_silent: false,
                is_undeletable: false,
                timestamp: now,
                timer: 0,
                hash: None,
                comment: None,
            });
        }
    }

    save_profile_to_disk(state);
    // Refresh all three apps tabs — the change can be visible on
    // any of them: the new App entry appears in Profile, the
    // matched-by-image_path service moves to Allowed/Blocked group
    // in Services, UWP isn't path-matched yet so it doesn't move
    // but the call is harmless.
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);

    let verb = if enable { "Allowed" } else { "Blocked" };
    set_status_text(
        state.status.get(),
        0,
        &format!("{verb}: {}", target.display_name),
    );
}

/// Remove the right-clicked app's entry from the profile. Only the
/// Apps Profile tab and Services tab can hit this — UWP entries
/// can't be in_profile yet, so the menu item is hidden for them.
fn on_context_remove(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    {
        let mut profile = state.app.profile.borrow_mut();
        profile.apps.retain(|a| a.path != target.binary_path);
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);
    set_status_text(
        state.status.get(),
        0,
        &format!("Removed: {}", target.display_name),
    );
}

/// Open the binary's containing folder in Explorer with the file
/// pre-selected. Uses `ShellExecuteW("open", "explorer.exe",
/// "/select, <path>")` — the canonical idiom that handles paths
/// with spaces, NT-style native paths, and missing folders gracefully
/// (Explorer just opens at the closest existing parent).
fn on_context_explore(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    if target.binary_path.as_os_str().is_empty() {
        return;
    }
    let path_str = target.binary_path.display().to_string();
    let args = format!("/select,\"{path_str}\"");
    let mut wargs = wide(&args);
    let mut wexe = wide("explorer.exe");
    let mut wverb = wide("open");
    unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(
            hwnd,
            windows::core::PCWSTR(wverb.as_mut_ptr()),
            windows::core::PCWSTR(wexe.as_mut_ptr()),
            windows::core::PCWSTR(wargs.as_mut_ptr()),
            windows::core::PCWSTR::null(),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );
    }
}

/// Copy the right-clicked row's display name to the clipboard.
fn on_context_copy(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let text = match state.context_target.borrow().clone() {
        Some(t) => t.display_name,
        None => return,
    };
    set_clipboard_text(hwnd, &text);
}

/// Properties: open the App properties modal for the right-clicked
/// row's profile entry. Grayed out in the menu for UWP and not-yet-
/// added rows, so when this fires we know `target.in_profile` is
/// true and `target.binary_path` matches an `App` in the profile.
/// On Save, replace the matched entry, persist, repopulate.
fn on_context_properties(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    if !target.in_profile || target.binary_path.as_os_str().is_empty() {
        return;
    }

    let initial = {
        let profile = state.app.profile.borrow();
        match profile.apps.iter().find(|a| a.path == target.binary_path) {
            Some(a) => a.clone(),
            None => return,
        }
    };

    let updated = match super::app_properties::open(hwnd, &initial) {
        Some(u) => u,
        None => return, // Close / no edits.
    };

    {
        let mut profile = state.app.profile.borrow_mut();
        if let Some(slot) = profile.apps.iter_mut().find(|a| a.path == target.binary_path) {
            *slot = updated;
        }
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);
    set_status_text(
        state.status.get(),
        0,
        &format!("Saved: {}", target.display_name),
    );
}

/// Push UTF-16 text to the clipboard. Standard Win32 idiom:
/// `OpenClipboard` → `EmptyClipboard` → `GlobalAlloc(GMEM_MOVEABLE)`
/// → `GlobalLock` + memcpy → `GlobalUnlock` → `SetClipboardData`
/// (which takes ownership of the HGLOBAL on success). On failure the
/// HGLOBAL is freed locally so we don't leak.
fn set_clipboard_text(hwnd: HWND, text: &str) {
    use windows::Win32::Foundation::{GlobalFree, HANDLE};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    let mut wide_text: Vec<u16> = text.encode_utf16().collect();
    wide_text.push(0);
    let bytes = std::mem::size_of_val(wide_text.as_slice());

    let hmem = match unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) } {
        Ok(h) => h,
        Err(_) => return,
    };
    let dst = unsafe { GlobalLock(hmem) } as *mut u16;
    if dst.is_null() {
        unsafe {
            let _ = GlobalFree(hmem);
        }
        return;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide_text.as_ptr(), dst, wide_text.len());
        let _ = GlobalUnlock(hmem);
    }

    if unsafe { OpenClipboard(hwnd) }.is_err() {
        unsafe {
            let _ = GlobalFree(hmem);
        }
        return;
    }
    unsafe {
        let _ = EmptyClipboard();
        // Clipboard takes ownership of the HGLOBAL on success;
        // free it ourselves on failure to avoid leaking.
        let handle = HANDLE(hmem.0 as isize);
        if SetClipboardData(CF_UNICODETEXT.0 as u32, handle).is_err() {
            let _ = GlobalFree(hmem);
        }
        let _ = CloseClipboard();
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
            "amwall: settings: save failed for {}: {e}",
            path.display()
        );
    }

    // Visual side effects.
    match id {
        IDM_ALWAYSONTOP_CHK => apply_always_on_top(hwnd, new_value),
        IDM_SHOWSEARCHBAR_CHK => apply_search_bar_visibility(hwnd, new_value),
        IDM_USEDARKTHEME_CHK => super::font::set_dark_mode(hwnd, new_value),
        IDM_SHOWFILENAMESONLY_CHK => {
            // Filename / full-path display affects Apps tab rendering.
            populate_apps_tab(state);
        }
        IDM_AUTOSIZECOLUMNS_CHK => {
            if new_value {
                autosize_active_listview_columns(state);
            }
        }
        // The remaining toggles are persisted but have no visible
        // effect yet — load_on_startup wires into the registry
        // when M9 lands, etc.
        _ => {}
    }
}

/// File → Toolbar Enable filters: install the current profile via
/// the same `install_profile` path the CLI uses. Requires admin;
/// if not elevated we surface a friendly error instead of crashing
/// when WFP refuses the call.
/// Map the GUI-side `BlocklistMode` (enum used by Settings →
/// Blocklist tri-state radios) to the install-time `BlocklistAction`.
/// Same shape — kept as separate types so `crate::install` doesn't
/// need to depend on GUI code.
fn blocklist_mode_to_action(
    m: super::settings::BlocklistMode,
) -> crate::install::BlocklistAction {
    match m {
        super::settings::BlocklistMode::Disable => crate::install::BlocklistAction::Disable,
        super::settings::BlocklistMode::Allow => crate::install::BlocklistAction::Allow,
        super::settings::BlocklistMode::Block => crate::install::BlocklistAction::Block,
    }
}

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
             Close amwall and re-launch from an elevated shell\n\
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
            eprintln!("amwall: WfpEngine::open failed: {e}");
            set_status_text(state.status.get(), 0, "Failed to open WFP engine.");
            return;
        }
    };

    let new_active;
    if state.filters_active.get() {
        // ---- Disable path ----
        match crate::install::uninstall(&engine) {
            Ok(report) => {
                set_status_text(state.status.get(), 0, "Filters are disabled.");
                set_status_text(
                    state.status.get(),
                    1,
                    &format!(
                        "{} filter(s) removed, {} sublayer(s) cleared.",
                        report.filters_deleted, report.sublayers_deleted
                    ),
                );
                new_active = false;
            }
            Err(e) => {
                eprintln!("amwall: uninstall failed: {e:?}");
                set_status_text(state.status.get(), 0, "Filter uninstall failed.");
                return;
            }
        }
    } else {
        // ---- Enable path ----
        let blocklist = {
            let s = state.app.settings.borrow();
            crate::install::BlocklistConfig {
                spy: blocklist_mode_to_action(s.blocklist_spy),
                update: blocklist_mode_to_action(s.blocklist_update),
                extra: blocklist_mode_to_action(s.blocklist_extra),
            }
        };
        let report = match crate::install::install_with_internal(
            &engine,
            &state.app.profile.borrow(),
            Some(&state.app.internal_profile),
            &blocklist,
            true, // persistent: reboots keep the filters
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("amwall: install failed: {e}");
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
        new_active = true;
    }

    // Drive the toolbar toggle from the install/uninstall outcome
    // directly — even if the profile is empty (0 filters), the
    // provider+sublayer registration that install_profile does is
    // enough to consider us "active" and we want the button to
    // flip to red. The cache refresh is a separate, toast-only
    // concern.
    state.filters_active.set(new_active);
    update_enable_filters_button(state, new_active);
    refresh_amwall_filter_ids_with(&engine, state);
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

/// Replace the six top-level menu labels with localized strings
/// (M8). Each lookup falls back to the English baseline so an
/// empty / partial locale leaves the unaffected entries in
/// English. `SetMenuItemInfoW(MIIM_STRING, MF_BYPOSITION)` updates
/// just the label without touching the popup handle hanging off
/// the position. `DrawMenuBar` forces the title strip to repaint
/// at the new widths.
fn localize_top_menu(hwnd: HWND, state: &WndState) {
    use crate::locale::ids::{
        IDS_EDIT, IDS_FILE, IDS_HELP, IDS_SETTINGS, IDS_TRAY_BLOCKLIST_RULES, IDS_VIEW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        DrawMenuBar, MENUITEMINFOW, MIIM_STRING, SetMenuItemInfoW,
    };

    let menu = unsafe { GetMenu(hwnd) };
    if menu.0 == 0 {
        return;
    }
    let locale = &state.app.locale;

    let entries: [(u32, u32, &str); 6] = [
        (0, IDS_FILE, "&File"),
        (1, IDS_EDIT, "&Edit"),
        (2, IDS_VIEW, "&View"),
        (3, IDS_SETTINGS, "&Settings"),
        (4, IDS_TRAY_BLOCKLIST_RULES, "&Blocklist"),
        (5, IDS_HELP, "&Help"),
    ];

    for (pos, ids, fallback) in entries {
        let text = locale.lookup(ids).unwrap_or(fallback);
        let mut wbuf = wide(text);
        let info = MENUITEMINFOW {
            cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
            fMask: MIIM_STRING,
            dwTypeData: PWSTR(wbuf.as_mut_ptr()),
            ..Default::default()
        };
        unsafe {
            let _ = SetMenuItemInfoW(menu, pos, true, &info);
        }
    }
    unsafe {
        let _ = DrawMenuBar(hwnd);
    }
}

/// Apply CheckMenuRadioItem-style filled-bullet marks to the
/// Blocklist top-menu's three Spy/Update/Extra mode groups so the
/// user can tell at a glance which mode is active. Called at
/// startup (from `apply_initial_settings`) and every time a mode
/// toggle fires.
fn refresh_blocklist_menu_checks(hwnd: HWND, state: &WndState) {
    use super::settings::BlocklistMode;
    use windows::Win32::UI::WindowsAndMessaging::{CheckMenuRadioItem, MF_BYCOMMAND};
    let menu = unsafe { GetMenu(hwnd) };
    if menu.0 == 0 {
        return;
    }
    let s = state.app.settings.borrow();

    let pick = |mode: BlocklistMode, dis: u16, allow: u16, block: u16| -> u16 {
        match mode {
            BlocklistMode::Disable => dis,
            BlocklistMode::Allow => allow,
            BlocklistMode::Block => block,
        }
    };

    let trios = [
        (
            s.blocklist_spy,
            IDM_BLOCKLIST_SPY_DISABLE,
            IDM_BLOCKLIST_SPY_ALLOW,
            IDM_BLOCKLIST_SPY_BLOCK,
        ),
        (
            s.blocklist_update,
            IDM_BLOCKLIST_UPDATE_DISABLE,
            IDM_BLOCKLIST_UPDATE_ALLOW,
            IDM_BLOCKLIST_UPDATE_BLOCK,
        ),
        (
            s.blocklist_extra,
            IDM_BLOCKLIST_EXTRA_DISABLE,
            IDM_BLOCKLIST_EXTRA_ALLOW,
            IDM_BLOCKLIST_EXTRA_BLOCK,
        ),
    ];
    for (mode, dis, allow, block) in trios {
        let chosen = pick(mode, dis, allow, block);
        unsafe {
            let _ = CheckMenuRadioItem(
                menu,
                dis as u32,
                block as u32,
                chosen as u32,
                MF_BYCOMMAND.0,
            );
        }
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
    // Search edit is now a direct child of the main window,
    // cached in WndState — no GetDlgItem hop.
    let search = state.search.get();
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

/// File → Add app: pick an .exe path, append it to
/// `profile.apps` (if not already present), persist + repopulate.
fn on_add_app(hwnd: HWND) {
    use crate::profile::App as ProfileApp;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let path = match super::dialogs::open_executable(hwnd) {
        Some(p) => p,
        None => return,
    };

    // Skip if the rule already references this exact path.
    {
        let profile = state.app.profile.borrow();
        if profile.apps.iter().any(|a| a.path == path) {
            set_status_text(state.status.get(), 0, "App already in profile.");
            return;
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let new_app = ProfileApp {
        path,
        is_enabled: true,
        is_silent: false,
        is_undeletable: false,
        timestamp: now,
        timer: 0,
        hash: None,
        comment: None,
    };
    state.app.profile.borrow_mut().apps.push(new_app);
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    set_status_text(state.status.get(), 0, "App added.");
}

/// File → Settings / toolbar Settings: open the multi-tab modal
/// Settings dialog. On Save, replace the in-memory Settings,
/// persist to disk, and re-apply window-level effects (always-
/// on-top, search-bar visibility, menu check marks).
fn on_open_settings(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let snapshot = state.app.settings.borrow().clone();
    let updated = match super::settings_dialog::open(hwnd, &snapshot) {
        Some(s) => s,
        None => return, // Close
    };
    state.app.settings.replace(updated.clone());
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = updated.save(&path) {
        eprintln!(
            "amwall: settings: save failed for {}: {e}",
            path.display()
        );
    }
    // Re-apply effects whose window state we manage directly.
    apply_initial_settings(hwnd, state);
}

/// Toolbar "Create rule" / Edit menu equivalent: open the rule
/// editor on a fresh blank rule. On OK, append to
/// `profile.custom_rules`, persist, repopulate the User rules tab.
fn on_create_rule(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let apps_snapshot = state.app.profile.borrow().apps.clone();
    let new_rule = match super::rule_editor::open(hwnd, None, &apps_snapshot) {
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

    let apps_snapshot = state.app.profile.borrow().apps.clone();
    let updated = match super::rule_editor::open(hwnd, Some(&existing), &apps_snapshot) {
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
            "amwall: profile auto-save failed for {}: {e}",
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
                "amwall: import: read failed for {}: {e}",
                path.display()
            );
            set_status_text(state.status.get(), 0, "Import failed: read error.");
            return;
        }
    };
    let new_profile = match crate::profile::parse_str(&xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("amwall: import: parse failed: {e}");
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
            "amwall: export: write failed for {}: {e}",
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
                "amwall: refresh: read failed for {}: {e}",
                path.display(),
            );
            set_status_text(state.status.get(), 0, "Refresh failed: read error.");
            return;
        }
    };
    let new_profile = match crate::profile::parse_str(&xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("amwall: refresh: parse failed: {e}");
            set_status_text(state.status.get(), 0, "Refresh failed: parse error.");
            return;
        }
    };
    state.app.profile.replace(new_profile);
    // F5 also re-walks SCM + the UWP repository so the user picks
    // up newly-installed services / packages without restarting.
    refresh_system_app_caches(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
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
    shell_open_url(hwnd, w!("https://github.com/amrust/amwall"));
}

/// Help → About: modern TaskDialog with version, copyright, GPL
/// notice, and a clickable repo link. ENABLE_HYPERLINKS routes
/// link clicks to our callback which fires ShellExecuteW.
fn on_about(hwnd: HWND) {
    use windows::Win32::UI::Controls::{
        TASKDIALOG_FLAGS, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOGCONFIG_1,
        TDCBF_OK_BUTTON, TDF_ENABLE_HYPERLINKS, TaskDialogIndirect,
    };

    let title = wide("About amwall");
    let main_instr = wide("amwall");
    let version = env!("CARGO_PKG_VERSION");
    let content_str = format!(
        concat!(
            "Version {version}\n",
            "\n",
            "A Rust port of simplewall, a Windows Filtering Platform (WFP) firewall.\n",
            "\n",
            "Copyright \u{00A9} 2026 amwall contributors.\n",
            "Licensed under the GNU General Public License v3.0 or later.\n",
            "\n",
            "Original simplewall \u{00A9} 2016\u{2013}2026 Henry++.\n",
            "\n",
            "<a href=\"https://github.com/amrust/amwall\">",
            "github.com/amrust/amwall</a>",
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

/// Open https://github.com/amrust/amwall/releases in
/// the system's default browser. Replaces upstream's PayPal donate
/// flow — same toolbar slot, friendlier action.
fn open_releases_page(hwnd: HWND) {
    shell_open_url(
        hwnd,
        w!("https://github.com/amrust/amwall/releases"),
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
        eprintln!("amwall: ShellExecuteW failed: code {}", result.0);
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

    // Group view (M5.4d): Apps tabs get the upstream 5-bucket
    // Allowed/Timer/Special/Blocked/Blocked-silent layout; Rules
    // tabs get a 2-bucket Enabled/Disabled split. Group titles are
    // placeholders here ("Allowed", "Blocked", ...) — the populators
    // re-render them with `(group_count/total_count)` suffixes after
    // each populate. Network and Log don't use groups; they're
    // chronological transient lists.
    match id {
        IDC_APPS_PROFILE | IDC_APPS_SERVICE | IDC_APPS_UWP => {
            super::listview_groups::enable(lv);
            insert_apps_groups(lv);
        }
        IDC_RULES_BLOCKLIST | IDC_RULES_SYSTEM | IDC_RULES_CUSTOM => {
            super::listview_groups::enable(lv);
            insert_rules_groups(lv);
        }
        _ => {}
    }

    Ok(())
}

fn insert_apps_groups(lv: HWND) {
    use super::listview_groups::{
        GROUP_APP_ALLOWED, GROUP_APP_BLOCKED, GROUP_APP_BLOCKED_SILENT, GROUP_APP_SPECIAL,
        GROUP_APP_TIMER, insert,
    };
    // Insert order is cosmetic — Win32 sorts groups by iGroupId
    // for display. Listed in display order here for readability:
    // Blocked first, then Allowed last.
    for (gid, title) in [
        (GROUP_APP_BLOCKED, "Blocked"),
        (GROUP_APP_BLOCKED_SILENT, "Blocked (silent)"),
        (GROUP_APP_TIMER, "Timer"),
        (GROUP_APP_SPECIAL, "Special apps"),
        (GROUP_APP_ALLOWED, "Allowed"),
    ] {
        let mut wtitle = wide(title);
        insert(lv, gid, &mut wtitle);
    }
}

fn insert_rules_groups(lv: HWND) {
    use super::listview_groups::{GROUP_RULE_DISABLED, GROUP_RULE_ENABLED, insert};
    for (gid, title) in [
        (GROUP_RULE_ENABLED, "Enabled"),
        (GROUP_RULE_DISABLED, "Disabled"),
    ] {
        let mut wtitle = wide(title);
        insert(lv, gid, &mut wtitle);
    }
}

/// Re-render the apps-tab group headers with `(count/total)`
/// suffixes after a populate. Walks `iGroupId` per item — cheap
/// since the listview is in-memory and small (≤500 rows even on
/// large machines after refresh).
fn refresh_apps_group_headers(lv: HWND) {
    use super::listview_groups::{
        GROUP_APP_ALLOWED, GROUP_APP_BLOCKED, GROUP_APP_BLOCKED_SILENT, GROUP_APP_SPECIAL,
        GROUP_APP_TIMER, set_header,
    };
    let total = unsafe {
        SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0))
    }
    .0 as i32;
    let mut counts: [i32; 5] = [0; 5];
    for row in 0..total {
        if let Some(gid) = listview_item_group(lv, row) {
            if (0..5).contains(&gid) {
                counts[gid as usize] += 1;
            }
        }
    }
    let labels = [
        (GROUP_APP_BLOCKED, "Blocked"),
        (GROUP_APP_BLOCKED_SILENT, "Blocked (silent)"),
        (GROUP_APP_TIMER, "Timer"),
        (GROUP_APP_SPECIAL, "Special apps"),
        (GROUP_APP_ALLOWED, "Allowed"),
    ];
    for (gid, base) in labels {
        let n = counts[gid as usize];
        let mut wtitle = wide(&format!("{base} ({n}/{total})"));
        set_header(lv, gid, &mut wtitle);
    }
}

/// Same idea as `refresh_apps_group_headers` for rules tabs.
fn refresh_rules_group_headers(lv: HWND) {
    use super::listview_groups::{GROUP_RULE_DISABLED, GROUP_RULE_ENABLED, set_header};
    let total = unsafe {
        SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0))
    }
    .0 as i32;
    let mut enabled = 0i32;
    let mut disabled = 0i32;
    for row in 0..total {
        match listview_item_group(lv, row) {
            Some(g) if g == GROUP_RULE_ENABLED => enabled += 1,
            Some(g) if g == GROUP_RULE_DISABLED => disabled += 1,
            _ => {}
        }
    }
    let mut w_enabled = wide(&format!("Enabled ({enabled}/{total})"));
    let mut w_disabled = wide(&format!("Disabled ({disabled}/{total})"));
    set_header(lv, GROUP_RULE_ENABLED, &mut w_enabled);
    set_header(lv, GROUP_RULE_DISABLED, &mut w_disabled);
}

/// Read the `iGroupId` of the row at `idx`. Wraps the LVM_GETITEM
/// dance — LVITEMW.iGroupId is only filled when LVIF_GROUPID is in
/// the request mask.
fn listview_item_group(lv: HWND, idx: i32) -> Option<i32> {
    let mut item = LVITEMW {
        mask: LVIF_GROUPID,
        iItem: idx,
        ..Default::default()
    };
    let res = unsafe {
        SendMessageW(
            lv,
            LVM_GETITEM,
            WPARAM(0),
            LPARAM(&mut item as *mut _ as isize),
        )
    };
    if res.0 == 0 { None } else { Some(item.iGroupId) }
}

/// Read the `lParam` (source-vec index) the populator stamped on
/// the row at `idx`. Returns `None` if the LVM_GETITEM call fails
/// (out-of-range row, or a row that wasn't populated by us).
/// Used by NM_RCLICK to round-trip from a clicked listview row to
/// the underlying `profile.apps` / `state.services` /
/// `state.uwp_packages` slot.
fn listview_item_param(lv: HWND, idx: i32) -> Option<isize> {
    let mut item = LVITEMW {
        mask: LVIF_PARAM,
        iItem: idx,
        ..Default::default()
    };
    let res = unsafe {
        SendMessageW(
            lv,
            LVM_GETITEM,
            WPARAM(0),
            LPARAM(&mut item as *mut _ as isize),
        )
    };
    if res.0 == 0 { None } else { Some(item.lParam.0) }
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
    let filter = state.search_text.borrow().clone();
    let mut row = 0i32;
    for rule in profile.custom_rules.iter() {
        if !search_match(&rule.name, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
        let mut name_buf = wide(&rule.name);
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_GROUPID,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            iGroupId: super::listview_groups::rule_group_id(rule),
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
    drop(profile);
    refresh_rules_group_headers(lv);
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
    let filenames_only = state.app.settings.borrow().show_filenames_only;
    let filter = state.search_text.borrow().clone();
    let mut row = 0i32;
    for (orig_idx, app) in profile.apps.iter().enumerate() {
        // Only File-kind entries show on this tab. Service and
        // UWP entries (path-less SCM short names like "Dnscache"
        // and S-1-15-2-... package family SIDs) belong on the
        // Services / UWP apps sub-tabs respectively. Without
        // this filter, importing a simplewall profile dumps all
        // three kinds onto Apps where most users only expect
        // .exe paths — caught during M9.4 live testing.
        if app.kind() != crate::profile::AppKind::File {
            continue;
        }

        // View → Show filenames only chooses between basename and
        // full path. Default-on matches upstream behaviour.
        let display_name = if filenames_only {
            app.path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| app.path.display().to_string())
        } else {
            app.path.display().to_string()
        };
        if !search_match(&display_name, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
        let mut name_buf = wide(&display_name);

        // INDEXTOSTATEIMAGEMASK(2) = checked, (1) = unchecked.
        // The state image bits live in the high nibble of `state`
        // (mask LVIS_STATEIMAGEMASK). LVIF_STATE in `mask` plus the
        // matching `stateMask` is the documented way to set this
        // alongside the row insert.
        let state_image_index = if app.is_enabled { 2u32 } else { 1u32 };
        // `lParam` carries the original index in `profile.apps`.
        // The listview row index isn't a 1:1 map any more (the
        // AppKind filter and the search filter both skip rows),
        // so the right-click handler needs `lParam` to round-
        // trip to the same App that was rendered. Using the
        // listview row directly read the wrong App's
        // `is_enabled` and showed inverted Allow/Block check
        // marks on imported profiles — caught during M9.4
        // testing.
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image_index << 12),
            iGroupId: super::listview_groups::app_group_id(app),
            lParam: LPARAM(orig_idx as isize),
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
    drop(profile);
    refresh_apps_group_headers(lv);
}

/// Populate the Apps → Services tab from the cached SCM enumeration
/// (`state.services`). Walks every Win32 service the SCM knows
/// about, regardless of running state — the user may want to author
/// a rule for a service that's currently stopped. Display name
/// shown in column 0, "Added" column 1 left blank since these
/// haven't been imported into the profile yet.
fn populate_services_tab(state: &WndState) {
    let lv = state.listviews[1].get();
    if lv.0 == 0 {
        return;
    }
    unsafe {
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }

    let services = state.services.borrow();
    let profile = state.app.profile.borrow();
    let filter = state.search_text.borrow().clone();
    let mut row = 0i32;
    for (orig_idx, svc) in services.iter().enumerate() {
        // Match the search filter against display name first, then
        // service name as a fallback — users may know either.
        let name_for_display = if svc.display_name.is_empty() {
            svc.service_name.as_str()
        } else {
            svc.display_name.as_str()
        };
        if !search_match(name_for_display, &filter)
            && !search_match(&svc.service_name, &filter)
        {
            continue;
        }
        let i = row;
        row += 1;
        let mut name_buf = wide(name_for_display);

        // Group + checkbox state both come from any matching profile
        // App. Unmanaged services (no profile entry) are checkbox-
        // off and group as Blocked (amwall's default-deny baseline).
        let matched_app = profile.apps.iter().find(|a| a.path == svc.image_path);
        let (group_id, state_image) = match matched_app {
            Some(a) => (
                super::listview_groups::app_group_id(a),
                if a.is_enabled { 2u32 } else { 1u32 },
            ),
            None => (super::listview_groups::GROUP_APP_BLOCKED, 1u32),
        };

        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM,
            iItem: i,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            iGroupId: group_id,
            // Original index in `state.services` — see the
            // populate_apps_tab comment for why the listview row
            // can't be used as a direct index when the search
            // filter skips entries.
            lParam: LPARAM(orig_idx as isize),
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
        // "Added" column stays empty for system-discovered services.
    }
    drop(profile);
    drop(services);
    refresh_apps_group_headers(lv);
}

/// Populate the Apps → UWP tab from the cached registry walk
/// (`state.uwp_packages`). One row per installed packaged app.
fn populate_uwp_tab(state: &WndState) {
    let lv = state.listviews[2].get();
    if lv.0 == 0 {
        return;
    }
    unsafe {
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }

    let packages = state.uwp_packages.borrow();
    let filter = state.search_text.borrow().clone();
    let mut row = 0i32;
    for (orig_idx, pkg) in packages.iter().enumerate() {
        // Search matches display name OR package full name (the
        // latter is what advanced users key off of).
        if !search_match(&pkg.display_name, &filter)
            && !search_match(&pkg.package_full_name, &filter)
        {
            continue;
        }
        let i = row;
        row += 1;
        let mut name_buf = wide(&pkg.display_name);
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM,
            iItem: i,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(1u32 << 12),
            // UWP packages have no path-based App match yet, so
            // they uniformly land in Blocked (default-deny).
            iGroupId: super::listview_groups::GROUP_APP_BLOCKED,
            // Original index in `state.uwp_packages` — same
            // rationale as the apps / services populators.
            lParam: LPARAM(orig_idx as isize),
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
    }
    drop(packages);
    refresh_apps_group_headers(lv);
}

/// Re-walk SCM and the UWP repository, replacing the cached
/// enumerations on `WndState`. Called once from `WM_CREATE` after
/// the listviews exist, and again from `IDM_REFRESH` (F5) so the
/// user can pick up newly-installed services / packages without
/// restarting amwall.
fn refresh_system_app_caches(state: &WndState) {
    *state.services.borrow_mut() = super::services_enum::enumerate();
    *state.uwp_packages.borrow_mut() = super::uwp_enum::enumerate();
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
    let filter = state.search_text.borrow().clone();
    let mut row = 0i32;
    for c in conns.iter() {
        if !search_match(&c.process, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
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

/// Populate the Packets log tab (`IDC_LOG`, slot 7) from the
/// in-memory event ring. Called when the user switches to the tab
/// and on every drain-timer tick that accepted new arrivals while
/// the tab was visible. Search text filters by app basename.
///
/// Columns set up in `configure_listview` for IDC_LOG:
///   # | Name | Date | Address(Source) | Host(Source) | Port(Source) |
///   Address(Destination) | Host(Destination) | Port(Destination) |
///   Protocol | Direction | Filter
fn populate_log_tab(state: &WndState) {
    // Slot 7 in TAB_LISTVIEW_IDS is IDC_LOG.
    let lv = state.listviews[7].get();
    if lv.0 == 0 {
        return;
    }
    unsafe {
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }
    let log = state.event_log.borrow();
    let filter = state.search_text.borrow().clone();

    let mut row = 0i32;
    for (event_idx, event) in log.iter().enumerate() {
        let details = match event {
            crate::wfp::events::NetEvent::Drop(d)
            | crate::wfp::events::NetEvent::Allow(d) => d,
            // Other event types (IKE / IPsec / capability) don't
            // carry the per-packet info the Log tab columns expect
            // — skip rather than render rows full of blanks.
            crate::wfp::events::NetEvent::Other(_) => continue,
        };
        let app_path = details.app_path.as_deref().unwrap_or("");
        let app_name = log_basename(app_path);
        if !search_match(app_name, &filter) {
            continue;
        }
        let i = row;
        row += 1;
        let mut idx_buf = wide(&format!("{}", event_idx + 1));
        let item = LVITEMW {
            mask: LVIF_TEXT,
            iItem: i,
            iSubItem: 0,
            pszText: PWSTR(idx_buf.as_mut_ptr()),
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
        set_subitem(lv, i, 1, app_name);
        set_subitem(lv, i, 2, &format_event_time(details.timestamp));
        set_subitem(
            lv,
            i,
            3,
            &details
                .local_addr
                .map(|a| a.to_string())
                .unwrap_or_default(),
        );
        // col 4 (Host source) intentionally empty — DNS would block
        // the UI thread.
        set_subitem(
            lv,
            i,
            5,
            &details
                .local_port
                .map(|p| p.to_string())
                .unwrap_or_default(),
        );
        set_subitem(
            lv,
            i,
            6,
            &details
                .remote_addr
                .map(|a| a.to_string())
                .unwrap_or_default(),
        );
        // col 7 (Host destination) intentionally empty — same reason
        // as col 4.
        set_subitem(
            lv,
            i,
            8,
            &details
                .remote_port
                .map(|p| p.to_string())
                .unwrap_or_default(),
        );
        set_subitem(lv, i, 9, &log_protocol_label(details.protocol));
        set_subitem(lv, i, 10, log_direction_label(details.direction));
        set_subitem(
            lv,
            i,
            11,
            &details
                .filter_id
                .map(|f| f.to_string())
                .unwrap_or_default(),
        );
    }
}

/// Last component of an NT-form path
/// (`\device\harddiskvolume3\…\chrome.exe` → `chrome.exe`). Returns
/// the full input if there's no `\`.
fn log_basename(path: &str) -> &str {
    path.rsplit_once('\\')
        .map(|(_, tail)| tail)
        .unwrap_or(path)
}

/// IP-protocol number → display label. Numbers we don't recognise
/// render as their decimal form (`"47"` for GRE etc.).
fn log_protocol_label(p: Option<u8>) -> String {
    match p {
        Some(1) => "ICMPv4".to_string(),
        Some(6) => "TCP".to_string(),
        Some(17) => "UDP".to_string(),
        Some(58) => "ICMPv6".to_string(),
        Some(n) => n.to_string(),
        None => String::new(),
    }
}

fn log_direction_label(d: Option<crate::wfp::events::NetDirection>) -> &'static str {
    match d {
        Some(crate::wfp::events::NetDirection::Inbound) => "Inbound",
        Some(crate::wfp::events::NetDirection::Outbound) => "Outbound",
        None => "",
    }
}

/// SystemTime → "HH:MM:SS" in the user's local timezone. Round-trip
/// via FILETIME → SYSTEMTIME (UTC) → SystemTimeToTzSpecificLocalTime
/// is the standard Win32 idiom; falling back to UTC if the local
/// conversion fails (which it shouldn't for any sane time).
fn format_event_time(t: std::time::SystemTime) -> String {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::Time::{
        FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime,
    };

    let dur = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // FILETIME = 100-ns intervals since 1601-01-01. Add the
    // 1601→1970 offset (11_644_473_600 s) to get from a UNIX-epoch
    // duration to a FILETIME value.
    let intervals: u64 = (dur.as_secs() + 11_644_473_600) * 10_000_000
        + (dur.subsec_nanos() as u64) / 100;
    let ft = FILETIME {
        dwLowDateTime: (intervals & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (intervals >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    if unsafe { FileTimeToSystemTime(&ft, &mut utc) }.is_err() {
        return String::new();
    }
    let mut local = SYSTEMTIME::default();
    if unsafe { SystemTimeToTzSpecificLocalTime(None, &utc, &mut local) }.is_err() {
        return format!("{:02}:{:02}:{:02}", utc.wHour, utc.wMinute, utc.wSecond);
    }
    format!("{:02}:{:02}:{:02}", local.wHour, local.wMinute, local.wSecond)
}

/// EN_CHANGE on the rebar's search edit. Reads the new text,
/// stores it on the WndState, repopulates whichever tab is
/// currently visible — that's the cheapest option that handles
/// every tab uniformly without a separate "filter visible rows"
/// codepath per listview.
fn on_search_changed(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let edit = state.search.get();
    if edit.0 == 0 {
        return;
    }
    let mut buf = [0u16; 256];
    let n = unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetWindowTextW(edit, &mut buf)
    } as usize;
    let new_text = String::from_utf16_lossy(&buf[..n]);
    *state.search_text.borrow_mut() = new_text;

    // Repopulate just the active tab — switching tabs runs its
    // own populate path which also reads search_text.
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel =
        unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let slot = if sel < 0 { 0 } else { sel as usize };
    repopulate_tab(state, slot);
    on_tab_change(hwnd); // refreshes the count in the status bar
}

/// Re-run whichever populator covers the given tab slot.
fn repopulate_tab(state: &WndState, slot: usize) {
    match slot {
        0 => populate_apps_tab(state),
        1 => populate_services_tab(state),
        2 => populate_uwp_tab(state),
        3 => populate_internal_rules(state, IDC_RULES_BLOCKLIST),
        4 => populate_internal_rules(state, IDC_RULES_SYSTEM),
        5 => populate_user_rules(state),
        6 => populate_connections_tab(state),
        7 => populate_log_tab(state),
        _ => {}
    }
}

/// Case-insensitive substring match used by every populator.
/// Empty filter = pass-through.
fn search_match(haystack: &str, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    haystack.to_lowercase().contains(&filter.to_lowercase())
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

    let filter = state.search_text.borrow().clone();
    let mut row = 0i32;
    for rule in rules.iter() {
        if !search_match(&rule.name, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
        let mut name_buf = wide(&rule.name);
        let state_image = if rule.is_enabled { 2u32 } else { 1u32 };
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE | LVIF_GROUPID,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            iGroupId: super::listview_groups::rule_group_id(rule),
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
    refresh_rules_group_headers(lv);
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
/// path: `amwall — <path>`. Em-dash (U+2014) for the
/// separator, matching upstream's title-bar style. The path goes
/// through `Path::display()` so non-UTF-8 path components (rare on
/// Windows but possible) round-trip lossily without panicking.
fn format_window_title(path: &std::path::Path) -> String {
    format!("amwall \u{2014} {}", path.display())
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

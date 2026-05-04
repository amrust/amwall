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
    HIMAGELIST,
    InitCommonControlsEx, LIST_VIEW_ITEM_STATE_FLAGS, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT,
    LVCFMT_RIGHT, LVCOLUMNW, LVIF_GROUPID, LVIF_IMAGE, LVIF_PARAM, LVIF_STATE, LVIF_TEXT,
    LVIS_STATEIMAGEMASK, LVITEMW,
    LVM_DELETEALLITEMS, LVM_ENSUREVISIBLE, LVM_GETCOUNTPERPAGE, LVM_GETITEM, LVM_GETITEMCOUNT,
    LVM_GETNEXTITEM, LVM_GETTOPINDEX, LVM_INSERTCOLUMNW,
    LVM_INSERTITEMW, LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETIMAGELIST,
    LVM_SETITEMSTATE, LVM_SETITEMTEXTW, LVN_COLUMNCLICK, LVN_KEYDOWN, LVSIL_SMALL,
    LVIS_SELECTED, LVNI_SELECTED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT,
    LVS_REPORT, LVS_SHAREIMAGELISTS,
    CDDS_ITEMPREPAINT, CDDS_PREPAINT, CDRF_DODEFAULT, CDRF_NEWFONT, CDRF_NOTIFYITEMDRAW,
    LVS_SHOWSELALWAYS, NM_CUSTOMDRAW, NM_DBLCLK, NM_RCLICK, NMHDR, NMITEMACTIVATE,
    NMLVCUSTOMDRAW, NMLVKEYDOWN,
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
    ShowWindow, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY,
    WM_DPICHANGED, WM_ENTERSIZEMOVE, WM_EXITSIZEMOVE, WM_NCCREATE, WM_NCDESTROY, WM_NOTIFY,
    WM_SETREDRAW, WM_SHOWWINDOW, WM_SIZE, WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CHILD,
    WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR, w};

use super::app::App;
use super::ids::{
    IDC_APPS_PROFILE, IDC_APPS_SERVICE, IDC_APPS_UWP, IDC_LOG, IDC_NETWORK,
    IDC_RULES_BLOCKLIST, IDC_RULES_CUSTOM, IDC_RULES_SYSTEM, IDC_SEARCH, IDC_STATUSBAR, IDC_TAB,
    IDM_ABOUT, IDM_ADD_FILE, IDM_ALWAYSONTOP_CHK, IDM_AUTOSIZECOLUMNS_CHK, IDM_EMERGENCY_RESET,
    IDM_BLOCKLIST_EXTRA_ALLOW, IDM_BLOCKLIST_EXTRA_BLOCK, IDM_BLOCKLIST_EXTRA_DISABLE,
    IDM_BLOCKLIST_SPY_ALLOW, IDM_BLOCKLIST_SPY_BLOCK, IDM_BLOCKLIST_SPY_DISABLE,
    IDM_ALLOW, IDM_BLOCK, IDM_BLOCKLIST_UPDATE_ALLOW, IDM_BLOCKLIST_UPDATE_BLOCK,
    IDM_BLOCKLIST_UPDATE_DISABLE, IDM_CHECKUPDATES, IDM_CHECKUPDATES_CHK, IDM_COPY, IDM_EXIT,
    IDM_EXPLORE, IDM_EXPORT, IDM_FONT, IDM_IMPORT,
    IDM_LOADONSTARTUP_CHK, IDM_LOGCLEAR, IDM_OPENRULESEDITOR, IDM_PROPERTIES, IDM_PURGE_TIMERS,
    IDM_REMOVE_FROM_PROFILE,
    IDM_PURGE_UNUSED, IDM_REFRESH, IDM_RELEASES, IDM_RULE_ALLOW6TO4, IDM_RULE_ALLOWLOOPBACK,
    IDM_RULE_ALLOWWINDOWSUPDATE, IDM_RULE_BLOCKINBOUND, IDM_RULE_BLOCKOUTBOUND, IDM_SETTINGS,
    IDM_SHOWFILENAMESONLY_CHK, IDM_SHOWSEARCHBAR_CHK, IDM_SIZE_EXTRALARGE, IDM_SIZE_LARGE,
    IDM_SIZE_SMALL, IDM_SKIPUACWARNING_CHK, IDM_STARTMINIMIZED_CHK, IDM_TRAY_ENABLELOG_CHK,
    IDM_TRAY_ENABLENOTIFICATIONS_CHK, IDM_TRAY_ENABLEUILOG_CHK, IDM_TRAY_LOGCLEAR,
    IDM_TRAY_LOGSHOW, IDM_TRAY_SHOW, IDM_TRAY_START, IDM_USEDARKTHEME_CHK, IDM_VIEW_DETAILS,
    IDM_VIEW_ICON, IDM_VIEW_TILE, IDM_WEBSITE, TAB_LISTVIEW_IDS,
};
use super::dialogs;
use super::toolbar::{self, Toolbar};
use super::{post_quit, wide};

/// Window class name. Win32 uses this string to look up our class
/// registration.
const CLASS_NAME: PCWSTR = w!("AmwallMainWindow");

/// Sort state for the Apps Profile listview. Click a column
/// header → toggle sort direction (or switch column). Drives
/// `populate_apps_tab`'s iteration order.
#[derive(Debug, Clone, Copy)]
struct AppsSortState {
    /// 0 = Name, 1 = Added timestamp. Other columns ignored.
    column: i32,
    /// `true` = small → large; `false` = large → small. Default
    /// is descending on Added so the most recent activity shows
    /// at the top of each group.
    ascending: bool,
}

impl Default for AppsSortState {
    fn default() -> Self {
        Self {
            column: 1,
            ascending: false,
        }
    }
}

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
const APPS_COL_WIDTHS: &[i32] = &[280, 150, 460]; // Name, Added (date+time), Path
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
    /// Same filter ids partitioned by which install path created
    /// them. Drives the `Settings.exclude_blocklist` /
    /// `exclude_custom` / `exclude_stealth` gates in
    /// `auto_catalog_drops`. Populated only by fresh installs
    /// (the startup-detection path can't recover categories from
    /// a previous session, so this stays empty until the user
    /// next clicks Enable filters).
    categorized_filter_ids:
        std::cell::RefCell<crate::install::CategorizedFilterIds>,
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
    /// Sort state for the Apps Profile tab, toggled by clicking
    /// a column header (LVN_COLUMNCLICK). Default: most-recent
    /// Added first, so the user sees fresh activity at the top
    /// of each group (especially "Blocked" once auto-cataloging
    /// of new drops lands in the next commit).
    apps_sort: Cell<AppsSortState>,
    /// Set of full image paths currently owning at least one
    /// active TCP / UDP connection. Refreshed periodically by
    /// the connections-tab timer; consumed by the apps-tab row
    /// colorizer to highlight "this app is talking right now"
    /// in pink.
    connected_paths: std::cell::RefCell<std::collections::HashSet<std::path::PathBuf>>,
    /// Cache of `WinVerifyTrust` results per binary path. Filled
    /// asynchronously by a background worker thread (see
    /// `signed_tx`). The colorizer takes a brief lock per row to
    /// read; missing entries paint as "not signed" until the
    /// worker fills them in. `Arc<Mutex<...>>` instead of
    /// `RefCell` because the worker writes from another thread.
    signed_cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, bool>>,
    >,
    /// Sends file paths to the background WinVerifyTrust worker.
    /// `None` until the worker spawns at WM_CREATE; populator
    /// code enqueues every File-kind app path once.
    signed_tx: std::cell::RefCell<
        Option<std::sync::mpsc::Sender<std::path::PathBuf>>,
    >,
    /// Most recently right-clicked listview row, set on NM_RCLICK
    /// before the popup menu shows and consumed by the IDM_*
    /// handlers. None after the menu dismisses (or never opened).
    context_target: std::cell::RefCell<Option<super::apps_context_menu::ContextTarget>>,
    /// Cached per-path icon indices into the system small-icon
    /// imagelist (same global imagelist Explorer uses). Filled
    /// lazily on first row-render and reused across repaints,
    /// so the populator pays the SHGetFileInfo cost once per
    /// distinct path per session.
    app_icon_cache: super::app_icons::IconCache,
    /// `true` once Shell_NotifyIcon(NIM_ADD) has accepted our
    /// tray icon. Gates NIM_MODIFY / NIM_DELETE so we don't
    /// double-add (which silently fails) or remove an icon we
    /// never registered.
    tray_added: Cell<bool>,
    /// Runtime ID of the registered "TaskbarCreated" broadcast.
    /// Cached at WM_CREATE so the wndproc can compare incoming
    /// messages against it cheaply (it's a per-process constant
    /// once registered).
    taskbar_created_msg: Cell<u32>,
    /// Reverse-DNS cache shared with the
    /// [`dns_resolve`](super::dns_resolve) worker thread.
    /// `Some(host)` = PTR record resolved; `None` = queried but
    /// no record / lookup failed (so the populator doesn't
    /// re-enqueue dead IPs every refresh). Only consulted when
    /// `Settings.use_network_resolution` is on; the worker
    /// itself runs unconditionally and is cheap while idle.
    dns_cache: std::sync::Arc<
        std::sync::Mutex<super::dns_resolve::DnsCacheMap>,
    >,
    /// Sends new IPs to the DNS worker. `None` until the worker
    /// spawns at WM_CREATE.
    dns_tx: std::cell::RefCell<Option<std::sync::mpsc::Sender<std::net::IpAddr>>>,
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
            categorized_filter_ids: std::cell::RefCell::new(
                crate::install::CategorizedFilterIds::default(),
            ),
            filters_active: Cell::new(false),
            services: std::cell::RefCell::new(Vec::new()),
            uwp_packages: std::cell::RefCell::new(Vec::new()),
            context_target: std::cell::RefCell::new(None),
            apps_sort: Cell::new(AppsSortState::default()),
            connected_paths: std::cell::RefCell::new(std::collections::HashSet::new()),
            signed_cache: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            signed_tx: std::cell::RefCell::new(None),
            tray_added: Cell::new(false),
            taskbar_created_msg: Cell::new(0),
            app_icon_cache: super::app_icons::IconCache::new(),
            dns_cache: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            dns_tx: std::cell::RefCell::new(None),
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

/// Periodic pump that scans `profile.apps` for entries whose
/// `timer` field has elapsed and rolls them back to `is_enabled
/// = false`. Mirrors upstream's "timed Allow" feature where the
/// user grants an app an N-minute window. 60-second tick is
/// coarse enough that idle CPU stays unmeasurable; finer
/// granularity isn't useful since timers are usually set in
/// minutes.
const TIMER_APP_EXPIRY: usize = 9005;
const APP_EXPIRY_INTERVAL_MS: u32 = 60_000;

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

        // Pull `start_minimized` before consuming `app` so we can
        // skip the SW_SHOW below and let the tray icon be the
        // sole entry point on first paint.
        let start_minimized = app.settings.borrow().start_minimized;

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

        // Tray icon is added during WM_CREATE so it's already
        // registered by the time we either show or hide the
        // window — keeps "Start minimized" honest (the user
        // sees the tray icon as soon as the process is up).
        if start_minimized {
            // Don't paint the main window — the tray icon is
            // the only entry point until the user clicks it.
            // No SW_SHOW means the window never lands on the
            // taskbar in the first place.
            let _ = UpdateWindow(hwnd);
        } else {
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = UpdateWindow(hwnd);
        }
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
        append_string(view, IDM_VIEW_DETAILS, "Layout: &Details");
        append_string(view, IDM_VIEW_ICON, "Layout: &Icons");
        append_string(view, IDM_VIEW_TILE, "Layout: &Tiles");
        append_separator(view);
        append_string(view, IDM_SIZE_SMALL, "Icon size: S&mall");
        append_string(view, IDM_SIZE_LARGE, "Icon size: &Large");
        append_string(view, IDM_SIZE_EXTRALARGE, "Icon size: &Extra-large");
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
        append_separator(help);
        append_string(help, IDM_EMERGENCY_RESET, "&Emergency WFP reset...");
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
            // NM_CUSTOMDRAW on the Apps tabs — pick a row
            // background color per upstream simplewall's
            // highlighting scheme (Invalid / System / Signed
            // / etc.). Only Invalid + System wired here; the
            // others need extra checks (signed = WinVerifyTrust,
            // pico = process-type detection) that aren't in
            // scope yet.
            if nmhdr.code == NM_CUSTOMDRAW
                && (nmhdr.idFrom == IDC_APPS_PROFILE as usize
                    || nmhdr.idFrom == IDC_APPS_SERVICE as usize
                    || nmhdr.idFrom == IDC_APPS_UWP as usize)
            {
                return on_apps_custom_draw(hwnd, lparam, nmhdr.idFrom as i32);
            }
            // LVN_COLUMNCLICK on the Apps Profile listview
            // toggles sort. iSubItem on NMLISTVIEW carries the
            // column index. Repeating click on the same column
            // flips ascending/descending; clicking a different
            // column resets to descending (so most-recent-first
            // is the default for Added).
            if nmhdr.code == LVN_COLUMNCLICK
                && nmhdr.idFrom == IDC_APPS_PROFILE as usize
            {
                let nmlv = unsafe {
                    &*(lparam.0 as *const windows::Win32::UI::Controls::NMLISTVIEW)
                };
                on_apps_column_click(hwnd, nmlv.iSubItem);
            }
            // Apps tab keyboard shortcuts (Ctrl+A select all,
            // Del bulk delete from profile).
            if nmhdr.code == LVN_KEYDOWN
                && (nmhdr.idFrom == IDC_APPS_PROFILE as usize
                    || nmhdr.idFrom == IDC_APPS_SERVICE as usize
                    || nmhdr.idFrom == IDC_APPS_UWP as usize)
            {
                let kd = unsafe { &*(lparam.0 as *const NMLVKEYDOWN) };
                let id = nmhdr.idFrom as i32;
                if kd.wVKey == VK_DELETE.0 {
                    on_apps_delete_selected(hwnd, id);
                } else if kd.wVKey == ('A' as u16) && ctrl_is_down() {
                    on_apps_select_all(hwnd, id);
                }
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
        m if m == super::connect_dialog::WM_USER_CONNECT_ALLOW => {
            on_connect_allow(hwnd, wparam);
            LRESULT(0)
        }
        m if m == super::connect_dialog::WM_USER_CONNECT_BLOCK => {
            on_connect_block(hwnd, wparam);
            LRESULT(0)
        }
        m if m == super::tray::WM_USER_TRAYICON => {
            on_tray_message(hwnd, lparam);
            LRESULT(0)
        }
        m if m == WM_USER_SIGNED_REFRESH => {
            // Worker filled new cache entries — repaint the
            // active apps listview so freshly-verified rows
            // show their green/no-green colour.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let tab = state.tab.get();
                if tab.0 != 0 {
                    let sel = unsafe {
                        SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0))
                    }
                    .0 as isize;
                    if (0..=2).contains(&sel) {
                        let lv = state.listviews[sel as usize].get();
                        if lv.0 != 0 {
                            unsafe {
                                let _ = windows::Win32::Graphics::Gdi::InvalidateRect(
                                    lv,
                                    None,
                                    false,
                                );
                            }
                        }
                    }
                }
            }
            LRESULT(0)
        }
        m if m == super::dns_resolve::WM_USER_DNS_REFRESH => {
            // DNS worker resolved a batch of hostnames; if the
            // Connections tab is visible re-populate so the new
            // names appear in the Host columns. Tab indices 6 +
            // 7 are Connections + Log; both consume hostnames.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let tab = state.tab.get();
                if tab.0 != 0 {
                    let sel = unsafe {
                        SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0))
                    }
                    .0 as isize;
                    if sel == 6 {
                        populate_connections_tab(state);
                    } else if sel == 7 {
                        populate_log_tab(state);
                    }
                }
            }
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
            } else if wparam.0 == TIMER_APP_EXPIRY {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    expire_timed_apps(hwnd, state);
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
        WM_CLOSE => {
            // X / Alt+F4 hides to the tray instead of exiting,
            // matching simplewall's behavior. The user keeps
            // IDM_EXIT (File → Exit, Ctrl+Q, tray "Exit amwall")
            // as the real quit path. If NIM_ADD failed at
            // startup we fall through to DefWindowProc so the
            // user isn't trapped with no way to close the
            // window.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                if state.tray_added.get() {
                    unsafe {
                        let _ = ShowWindow(hwnd, SW_HIDE);
                    }
                    return LRESULT(0);
                }
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_DESTROY => {
            // Tear down the tray icon before quitting so the
            // notification area doesn't keep a stale slot for
            // the dead HWND until the user hovers over it.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                if state.tray_added.get() {
                    super::tray::remove(hwnd);
                    state.tray_added.set(false);
                }
            }
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
        _ => {
            // explorer.exe restart broadcast — re-register the
            // tray icon since the previous notification area is
            // gone. Cached registered-message id lives on
            // `state.taskbar_created_msg`.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                let tcm = state.taskbar_created_msg.get();
                if tcm != 0 && msg == tcm {
                    state.tray_added.set(false);
                    let active = state.filters_active.get();
                    if super::tray::add(hwnd, active) {
                        state.tray_added.set(true);
                    }
                    return LRESULT(0);
                }
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

/// Handle a tray-icon callback message. lparam's LOWORD carries
/// the underlying mouse / keyboard event the shell observed.
/// `tray_single_click` decides which gesture toggles the window:
///  - true: single-click toggles, double-click is a no-op (the
///    second click of a double-click also dispatches WM_LBUTTONUP,
///    so the toggle just bounces back to the previous state — the
///    user effectively sees nothing happen).
///  - false (default, matches upstream): single-click only
///    foregrounds the window (when visible); double-click toggles.
///
/// Right-click always pops the context menu.
fn on_tray_message(hwnd: HWND, lparam: LPARAM) {
    use windows::Win32::UI::WindowsAndMessaging::{
        IsWindowVisible, SetForegroundWindow, WM_CONTEXTMENU, WM_LBUTTONDBLCLK, WM_LBUTTONUP,
        WM_RBUTTONUP,
    };
    let event = (lparam.0 as u32) & 0xFFFF;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let single_click = state.app.settings.borrow().tray_single_click;
    match event {
        WM_LBUTTONUP => {
            if single_click {
                super::tray::toggle_main_window(hwnd);
            } else if unsafe { IsWindowVisible(hwnd).as_bool() } {
                unsafe {
                    let _ = SetForegroundWindow(hwnd);
                }
            }
        }
        WM_LBUTTONDBLCLK if !single_click => {
            super::tray::toggle_main_window(hwnd);
        }
        WM_RBUTTONUP | WM_CONTEXTMENU => {
            super::tray::show_context_menu(hwnd, state.filters_active.get());
        }
        _ => {}
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
    // Persisted user choice (View → Font…) wins over the system
    // message font. Falls back when the saved face is empty
    // (default install) or load_named_font returns None (face
    // uninstalled since last save).
    let font = {
        let s = state.app.settings.borrow();
        super::font::load_named_font(&s.font_face, s.font_height)
            .unwrap_or_else(super::font::load_message_font)
    };
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
        SetTimer(hwnd, TIMER_APP_EXPIRY, APP_EXPIRY_INTERVAL_MS, None);
    }

    // Filters installed on a previous run survive process exit
    // (we ask BFE to persist them across reboots, which also
    // means they outlive amwall itself). On startup we check
    // whether our provider has any filters in the engine and
    // flip `filters_active` to match — otherwise the toolbar /
    // title-bar would say "off" while the kernel is still
    // dropping packets.
    detect_initial_filter_state(hwnd, state);

    // Register the always-visible tray icon and the
    // "TaskbarCreated" broadcast id (so we can re-register on
    // explorer.exe restart). Done after detect_initial_filter_state
    // so the icon paints with the correct color/mono variant.
    state
        .taskbar_created_msg
        .set(super::tray::taskbar_created_message());
    let active = state.filters_active.get();
    if super::tray::add(hwnd, active) {
        state.tray_added.set(true);
    } else {
        eprintln!("amwall: Shell_NotifyIcon(NIM_ADD) failed; tray icon unavailable.");
    }

    // Spawn the WinVerifyTrust background worker so the apps-
    // tab signed-row colorizer can fill its cache without
    // blocking the GUI thread. Stores the sender on `state` so
    // populator code can enqueue paths.
    let tx = spawn_signed_worker(hwnd, state.signed_cache.clone());
    *state.signed_tx.borrow_mut() = Some(tx);

    // Reverse-DNS worker: fills `dns_cache` on a background
    // thread and pings the GUI back via WM_USER_DNS_REFRESH after
    // each batch. Only consulted when
    // `Settings.use_network_resolution` is on, but always alive
    // so toggling the setting from off→on doesn't need a respawn.
    let dns_tx = super::dns_resolve::spawn_worker(hwnd, state.dns_cache.clone());
    *state.dns_tx.borrow_mut() = Some(dns_tx);

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

/// Reconcile `state.filters_active` with the kernel's actual
/// filter state at startup. `try_subscribe_events` has already
/// populated `amwall_filter_ids` from a fresh enumeration; if
/// that set is non-empty, our provider has live filters and we
/// were "active" when the user last closed the program — flip
/// the toolbar, title-bar icon, and status line to match.
fn detect_initial_filter_state(hwnd: HWND, state: &WndState) {
    let active = !state.amwall_filter_ids.borrow().is_empty();
    if !active {
        return;
    }
    state.filters_active.set(true);
    update_enable_filters_button(state, true);
    update_titlebar_icon(hwnd, true);
    set_status_text(state.status.get(), 0, "Filters are enabled.");
}

/// Swap the toolbar's "Enable filters" button between its enabled
/// and disabled appearance: green tick-shield + "Enable filters"
/// when no amwall filters are installed, red cross-shield +
/// "Disable filters" when they are. Same `IDM_TRAY_START` command
/// id either way — the click handler branches on
/// `state.filters_active`.
/// Swap the window's title-bar icon between the active (color)
/// and inactive (monochrome) forms whenever filter state
/// changes. Mirrors upstream simplewall's "fire icon goes gray
/// when filters are off" cue. Both icons are embedded in the
/// .rc as resources `1` and `2`; we LoadIcon at swap time
/// rather than caching since this fires at most once per user
/// click.
fn update_titlebar_icon(hwnd: HWND, active: bool) {
    use windows::Win32::UI::WindowsAndMessaging::{ICON_BIG, ICON_SMALL, LoadIconW, WM_SETICON};
    let hi = match unsafe {
        windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
    } {
        Ok(h) => h,
        Err(_) => return,
    };
    let res_id = if active { 1usize } else { 2usize };
    let icon = match unsafe { LoadIconW(hi, PCWSTR(res_id as *const u16)) } {
        Ok(i) => i,
        Err(_) => return,
    };
    unsafe {
        SendMessageW(
            hwnd,
            WM_SETICON,
            WPARAM(ICON_SMALL as usize),
            LPARAM(icon.0),
        );
        SendMessageW(
            hwnd,
            WM_SETICON,
            WPARAM(ICON_BIG as usize),
            LPARAM(icon.0),
        );
    }

    // Keep the tray icon's color/mono variant in sync with the
    // title bar so both surfaces tell the same story.
    if let Some(state) = unsafe { state_ref(hwnd) } {
        if state.tray_added.get() {
            super::tray::update(hwnd, active);
        }
    }
}

/// Push `TBSTATE_CHECKED` on/off on a toolbar button identified by
/// its command id. Used for the Notifications toggle so the button
/// visibly reflects whether the connect-prompt mode is on.
fn set_toolbar_button_checked(state: &WndState, id: u16, checked: bool) {
    use windows::Win32::UI::Controls::{
        TBSTATE_CHECKED, TBSTATE_ENABLED, TB_SETSTATE,
    };
    let toolbar = state.toolbar.get();
    if toolbar.0 == 0 {
        return;
    }
    let st = if checked {
        TBSTATE_ENABLED | TBSTATE_CHECKED
    } else {
        TBSTATE_ENABLED
    };
    unsafe {
        SendMessageW(
            toolbar,
            TB_SETSTATE,
            WPARAM(id as usize),
            LPARAM(st as isize),
        );
    }
}

/// Toolbar / menu Notifications click handler: flip
/// `Settings.enable_notifications`, persist, and reflect the new
/// state on the toolbar button via TBSTATE_CHECKED.
fn on_toggle_notifications(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let new_value = {
        let mut s = state.app.settings.borrow_mut();
        s.enable_notifications = !s.enable_notifications;
        s.enable_notifications
    };
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!(
            "amwall: settings: save failed for {}: {e}",
            path.display()
        );
    }
    set_toolbar_button_checked(state, IDM_TRAY_ENABLENOTIFICATIONS_CHK, new_value);
    set_status_text(
        state.status.get(),
        0,
        if new_value {
            "Notifications: on (Allow/Block prompt on first connect)."
        } else {
            "Notifications: off."
        },
    );
}

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

/// Convert a kernel-reported NT path (e.g.
/// `\device\harddiskvolume3\windows\system32\svchost.exe`) into
/// the Win32 drive-letter form (`C:\Windows\System32\svchost.exe`)
/// that `profile.apps[].path` and `FwpmGetAppIdFromFileName0`
/// both work with. Walks every assigned DOS drive letter, asks
/// the kernel for its NT root via `QueryDosDeviceW`, picks the
/// matching prefix.
///
/// Returns `None` for paths that don't resolve to any current
/// drive — could happen when a now-unmounted volume produced the
/// drop, or for non-disk app ids. Caller skips the catalog in
/// that case.
fn nt_path_to_win32(nt_path: &str) -> Option<String> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    let nt_lc = nt_path.to_lowercase();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let drive_w: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let n = unsafe { QueryDosDeviceW(PCWSTR(drive_w.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            continue;
        }
        // QueryDosDeviceW returns a double-NUL-terminated list of
        // NT names; the first entry is the canonical mapping. Find
        // the first NUL to slice it.
        let first_end = buf[..n as usize].iter().position(|&c| c == 0).unwrap_or(n as usize);
        let nt_root = String::from_utf16_lossy(&buf[..first_end]);
        let nt_root_lc = nt_root.to_lowercase();
        if nt_root_lc.is_empty() {
            continue;
        }
        if nt_lc.starts_with(&nt_root_lc) {
            let suffix = &nt_path[nt_root.len()..];
            return Some(format!("{drive}{suffix}"));
        }
    }
    None
}

/// Custom WM message posted by the WinVerifyTrust worker after
/// it determines a batch of paths' signed status. Triggers an
/// apps-tab repaint so freshly-verified rows pick up the green
/// "signed" highlight.
const WM_USER_SIGNED_REFRESH: u32 =
    windows::Win32::UI::WindowsAndMessaging::WM_USER + 0x103;

/// Worker-thread entry. Drains `rx` for paths to verify,
/// updates `cache` with each result, and posts
/// `WM_USER_SIGNED_REFRESH` to the main HWND so the apps tab
/// repaints. Coalesces refresh notifications: only posts one
/// every ~10 paths or after `rx` returns Empty for >50 ms,
/// which keeps the GUI responsive without spamming repaints.
fn spawn_signed_worker(
    main_hwnd: HWND,
    cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, bool>>,
    >,
) -> std::sync::mpsc::Sender<std::path::PathBuf> {
    use std::sync::mpsc::{Receiver, Sender, channel};
    let (tx, rx): (Sender<std::path::PathBuf>, Receiver<std::path::PathBuf>) = channel();
    // Snapshot the HWND as a usize since HWND isn't Send. We
    // re-wrap it on the worker side; PostMessage is thread-safe
    // by Win32 contract.
    let hwnd_raw = main_hwnd.0 as usize;
    std::thread::spawn(move || {
        const BATCH_FOR_REFRESH: u32 = 10;
        let mut since_last_post = 0u32;
        // Channel-closed (app shutting down) breaks the loop.
        while let Ok(path) = rx.recv() {
            // Skip if already cached.
            if let Ok(g) = cache.lock() {
                if g.contains_key(&path) {
                    continue;
                }
            }
            let signed = win_verify_trust(&path);
            if let Ok(mut g) = cache.lock() {
                g.insert(path, signed);
            }
            since_last_post += 1;
            if since_last_post >= BATCH_FOR_REFRESH {
                since_last_post = 0;
                post_signed_refresh(hwnd_raw);
            }
        }
        // Final flush so the last partial batch repaints too.
        if since_last_post > 0 {
            post_signed_refresh(hwnd_raw);
        }
    });
    tx
}

fn post_signed_refresh(hwnd_raw: usize) {
    use windows::Win32::UI::WindowsAndMessaging::PostMessageW;
    let h = HWND(hwnd_raw as isize);
    unsafe {
        let _ = PostMessageW(h, WM_USER_SIGNED_REFRESH, WPARAM(0), LPARAM(0));
    }
}

/// Re-walk the IP Helper tables and replace `connected_paths`
/// with the current set. Cheap (one syscall per protocol +
/// process-handle opens for each unique PID), but synchronous —
/// only invoked from populator entry points so it runs at most
/// once per tab repaint, not once per row.
fn refresh_connected_paths(state: &WndState) {
    *state.connected_paths.borrow_mut() = super::connections::enumerate_active_paths();
}

/// Run the M5.9.5 paint-jiggle on the currently-active apps
/// listview. Used after `auto_catalog_drops` adds rows so they
/// show up in the same paint cycle without waiting for a
/// resize / scroll / click. The 1-pixel MoveWindow forces
/// listview internal layout to recompute, which is the only
/// reliable way to wake comctl up for fresh rows.
fn force_active_apps_listview_jiggle(hwnd: HWND, state: &WndState) {
    use windows::Win32::Graphics::Gdi::{
        InvalidateRect, RDW_ALLCHILDREN, RDW_ERASE, RDW_INVALIDATE, RDW_UPDATENOW, RedrawWindow,
    };
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel = unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let slot: usize = if (0..=2).contains(&sel) { sel as usize } else { 0 };
    let lv = state.listviews[slot].get();
    if lv.0 == 0 {
        return;
    }

    // Synchronous pass — handles the simple cases (auto-catalog
    // during a fully-painted listview).
    //  1. MoveWindow jiggle — wakes the header subwindow so
    //     column titles + sort arrows render after a resize.
    //  2. InvalidateRect on the client — marks the rows dirty.
    //  3. RedrawWindow with RDW_UPDATENOW — flushes the paint
    //     synchronously instead of waiting for the next idle.
    if let Some((x, y, w, h)) = current_lv_rect_in_parent(lv, hwnd) {
        force_listview_repaint(lv, x, y, w, h);
    }
    unsafe {
        let _ = InvalidateRect(lv, None, true);
        let _ = RedrawWindow(
            lv,
            None,
            None,
            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW,
        );
    }

    // Deferred pass — same trick the resize-end cleanup uses.
    // After delete + populate, comctl32's internal paint state
    // can be sticky enough that even a synchronous redraw doesn't
    // land cleanly on the first try. Arming TIMER_RESIZE_CLEANUP
    // re-fires repopulate_tab + on_tab_change ~100 ms later, by
    // which point comctl32 has settled and the second redraw
    // takes. This is the same path WM_SIZE already uses, so the
    // user gets identical post-resize-end visual behavior after
    // any delete / auto-catalog batch.
    unsafe {
        SetTimer(hwnd, TIMER_RESIZE_CLEANUP, RESIZE_CLEANUP_MS, None);
    }
}

/// Walk this drain tick's batch and return one `(path, remote)`
/// pair per *newly seen* app — i.e., an app whose drop fires
/// from amwall's filters AND whose path isn't yet in
/// `profile.apps`. Auto-catalog adds each as a disabled (blocked)
/// entry as a side-effect so the Apps Profile tab fills with
/// "everything that's tried to connect since filters went on";
/// the returned `(path, remote)` list is what the caller hands
/// to the connect-prompt dialog (one prompt per app, ever — apps
/// already in the profile suppress further prompts naturally).
///
/// Dedup runs against `profile.apps` AND within the batch
/// itself (a single app dropping 100 packets in one 500 ms
/// tick only produces one entry).
///
/// Returning `(path, remote)` lets the caller show "brave.exe
/// → 142.250.65.74:443" in the dialog without re-walking the
/// drop event.
/// Sweep `profile.apps` for entries whose `timer` field has
/// elapsed (Unix timestamp <= now). Each expired entry rolls
/// back to `is_enabled = false` and clears its timer, then a
/// single reinstall pushes the new posture to the kernel. No-op
/// when nothing has expired so the 60-second tick stays cheap.
/// Mirrors upstream's "timed Allow" feature.
fn expire_timed_apps(hwnd: HWND, state: &WndState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut expired = 0usize;
    {
        let mut profile = state.app.profile.borrow_mut();
        for app in profile.apps.iter_mut() {
            if app.timer > 0 && app.timer <= now && app.is_enabled {
                app.is_enabled = false;
                app.timer = 0;
                expired += 1;
            }
        }
    }
    if expired == 0 {
        return;
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    force_active_apps_listview_jiggle(hwnd, state);
    reinstall_filters_if_active(state);
    set_status_text(
        state.status.get(),
        0,
        &format!(
            "{expired} app timer(s) expired \u{2014} rolled back to Block."
        ),
    );
}

fn auto_catalog_drops(
    state: &WndState,
    events: &[crate::wfp::events::NetEvent],
) -> Vec<(std::path::PathBuf, String)> {
    use crate::wfp::events::NetEvent;
    let mut new_apps: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut seen: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();

    {
        let profile = state.app.profile.borrow();
        for event in events {
            let details = match event {
                NetEvent::Drop(d) => d,
                _ => continue,
            };
            // Only auto-catalog drops from amwall's own filters.
            // Without this gate, every Windows Defender / third-
            // party WFP-provider drop would dump exes into our
            // profile.
            let filter_id = match details.filter_id {
                Some(f) => f,
                None => continue,
            };
            if !state.amwall_filter_ids.borrow().contains(&filter_id) {
                continue;
            }
            // Settings -> Exclude gates. Drop the prompt for
            // events whose source filter category the user has
            // told us to ignore. The categorized sets are filled
            // at install time; before the first install (this
            // session) they're empty and these checks no-op.
            {
                let s = state.app.settings.borrow();
                let cats = state.categorized_filter_ids.borrow();
                if s.exclude_blocklist && cats.blocklist.contains(&filter_id) {
                    continue;
                }
                if s.exclude_custom && cats.user_rules.contains(&filter_id) {
                    continue;
                }
                if s.exclude_stealth && cats.stealth.contains(&filter_id) {
                    continue;
                }
            }
            let nt = match details.app_path.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };
            let win32 = match nt_path_to_win32(nt) {
                Some(p) => p,
                None => continue,
            };
            let path = std::path::PathBuf::from(&win32);
            if !seen.insert(path.clone()) {
                continue;
            }
            if profile.apps.iter().any(|a| a.path == path) {
                continue;
            }
            // ASCII arrow — Segoe UI in dialog mode renders the
            // Unicode "→" (U+2192) as a placeholder box on some
            // systems; "->" round-trips cleanly.
            let remote = match (details.remote_addr, details.remote_port) {
                (Some(addr), Some(port)) => format!("-> {addr}:{port}"),
                (Some(addr), None) => format!("-> {addr}"),
                _ => String::new(),
            };
            new_apps.push((path, remote));
        }
    }

    if new_apps.is_empty() {
        return new_apps;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut profile = state.app.profile.borrow_mut();
    for (path, _) in &new_apps {
        profile.apps.push(crate::profile::App {
            path: path.clone(),
            is_enabled: false,
            is_silent: false,
            is_undeletable: false,
            timestamp: now,
            timer: 0,
            hash: None,
            comment: None,
        });
    }
    new_apps
}

/// Show the centered Allow/Block dialog once per app in
/// `new_apps`. The list comes from `auto_catalog_drops` and
/// only contains paths that were *just added* to the profile in
/// this drain tick — so this is necessarily the app's first
/// drop since filters went on. One dialog per entry, ever:
/// already-in-profile apps never reach this list.
///
/// Skips entries whose `profile.apps` row is `is_silent=true`.
/// Auto-catalog creates new entries with `is_silent=false`, so
/// in the current code path this gate never fires — but it's
/// the parity-correct check (upstream's `_app_logthread` reads
/// `INFO_IS_SILENT` before calling `_app_notify_addobject`,
/// `log.c:1391-1395`), and any future code path that re-feeds
/// already-cataloged apps into this function will respect the
/// user's "stop bothering me" preference.
///
/// Modeless / non-focus-stealing — `show_async` returns
/// immediately. The user's Allow click flows back via
/// `WM_USER_CONNECT_ALLOW`, which flips `is_enabled`. Block
/// flows back via `WM_USER_CONNECT_BLOCK`, which sets
/// `is_silent`. X / dismiss leaves both fields untouched.
fn process_connect_prompts(
    hwnd: HWND,
    state: &WndState,
    new_apps: &[(std::path::PathBuf, String)],
) {
    let profile = state.app.profile.borrow();
    for (path, remote) in new_apps {
        let silenced = profile
            .apps
            .iter()
            .find(|a| a.path == *path)
            .map(|a| a.is_silent)
            .unwrap_or(false);
        if silenced {
            continue;
        }
        super::connect_dialog::show_async(hwnd, path, remote);
    }
}

/// True when the foreground application is in a fullscreen state
/// the shell tells us we shouldn't disturb — D3D-fullscreen games,
/// PowerPoint presentations, etc. Used by `drain_events` to gate
/// the connect-prompt dialog when `notification_fullscreen_silent`
/// is on. Falls back to "not fullscreen" on any API failure so a
/// missing shell32 entry point doesn't suppress all prompts.
fn is_user_in_fullscreen() -> bool {
    use windows::Win32::UI::Shell::{
        QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN,
        SHQueryUserNotificationState,
    };
    let state = match unsafe { SHQueryUserNotificationState() } {
        Ok(s) => s,
        Err(_) => return false,
    };
    matches!(
        state,
        QUNS_RUNNING_D3D_FULL_SCREEN | QUNS_PRESENTATION_MODE | QUNS_BUSY
    )
}

/// Handler for `WM_USER_CONNECT_BLOCK` — user clicked Block on
/// the connect prompt. Sets `is_silent = true` on the matching
/// `profile.apps` entry so future drops for the same exe don't
/// re-prompt. `is_enabled` stays `false` (already set by auto-
/// catalog). No filter reinstall: the per-app permit set is
/// driven by `is_enabled`, which is unchanged.
///
/// Mirrors upstream simplewall's `notifications.c:87`:
/// `ptr_app->is_silent = (button_id == IDC_BLOCK_BTN);`.
fn on_connect_block(hwnd: HWND, wparam: WPARAM) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let path_raw = wparam.0 as *mut std::path::PathBuf;
    if path_raw.is_null() {
        return;
    }
    let path_box = unsafe { Box::from_raw(path_raw) };
    let path: std::path::PathBuf = *path_box;

    {
        let mut profile = state.app.profile.borrow_mut();
        if let Some(app) = profile.apps.iter_mut().find(|a| a.path == path) {
            app.is_silent = true;
        } else {
            return;
        }
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    set_status_text(
        state.status.get(),
        0,
        &format!(
            "Silenced: {}",
            path.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string())
        ),
    );
}

/// Handler for `WM_USER_CONNECT_ALLOW` posted by the connect-
/// prompt dialog when the user clicks Allow. Reclaims the
/// `Box<PathBuf>` the dialog stuffed into wparam, finds the
/// matching App, flips `is_enabled = true`, persists, and
/// re-pushes filters to the kernel so the per-app permit lands.
fn on_connect_allow(hwnd: HWND, wparam: WPARAM) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let path_raw = wparam.0 as *mut std::path::PathBuf;
    if path_raw.is_null() {
        return;
    }
    let path_box = unsafe { Box::from_raw(path_raw) };
    let path: std::path::PathBuf = *path_box;

    {
        let mut profile = state.app.profile.borrow_mut();
        if let Some(app) = profile.apps.iter_mut().find(|a| a.path == path) {
            app.is_enabled = true;
        } else {
            // Edge case: user removed the app from profile while
            // the dialog was up. Nothing to do.
            return;
        }
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    reinstall_filters_if_active(state);
    set_status_text(
        state.status.get(),
        0,
        &format!(
            "Allowed: {}",
            path.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string())
        ),
    );
}

/// Drain any pending events from the channel into the log buffer,
/// trimming the front to keep the buffer at most `EVENT_LOG_CAP`
/// entries. If the Log tab is currently visible, repopulate the
/// listview so the new rows show up live.
fn drain_events(hwnd: HWND, state: &WndState) {
    let settings = state.app.settings.borrow();
    let notify = settings.enable_notifications;
    let filters_active = state.filters_active.get();
    let mut log = state.event_log.borrow_mut();
    let mut writer = state.event_log_writer.borrow_mut();
    let mut new_arrivals = false;
    // Collect this tick's events for downstream batch processing
    // (auto-catalog deduplicates within the batch).
    let mut batch: Vec<crate::wfp::events::NetEvent> = Vec::new();
    if let Some(rx) = state.event_rx.borrow().as_ref() {
        while let Ok(event) = rx.try_recv() {
            // Persist to the on-disk log first. Settings gate
            // (enable_log, exclude_classify_allow, rotation cap)
            // are applied inside the writer.
            writer.append(&event, &settings);

            // The in-memory ring (and therefore the Packets log
            // tab) only fills when the user has explicitly turned
            // Log UI on — matches upstream's "Log UI is off by
            // default; flipping it on starts capturing events".
            // Auto-catalog still gets the event because it works
            // off `batch`, not `event_log`.
            if settings.enable_ui_log {
                if log.len() >= EVENT_LOG_CAP {
                    log.pop_front();
                }
                log.push_back(event.clone());
                new_arrivals = true;
            }
            batch.push(event);
        }
    }
    drop(writer);
    drop(log);
    drop(settings);

    // Auto-catalog drops as Blocked entries when filters are on.
    // Returns the list of newly-added apps (with their first
    // drop's remote endpoint) so the connect-prompt dialog can
    // show context. An app already in `profile.apps` never
    // appears here regardless of how many packets it drops —
    // that's how we guarantee "one Allow/Block window per exe,
    // ever".
    let mut profile_changed = false;
    let new_apps = if filters_active && !batch.is_empty() {
        auto_catalog_drops(state, &batch)
    } else {
        Vec::new()
    };
    if !new_apps.is_empty() {
        profile_changed = true;
    }

    // Connect-prompt dialogs (centered Allow/Block, modeless) —
    // only when notifications are enabled. One dialog per
    // newly-cataloged app. show_async returns immediately; the
    // user's Allow choice flows back via WM_USER_CONNECT_ALLOW
    // and is handled by `on_connect_allow` in the wndproc.
    //
    // notification_fullscreen_silent: skip the popup entirely
    // when the user is in a fullscreen game / presentation. The
    // app is still cataloged + persisted (so once the user exits
    // fullscreen they'll see the new Blocked entry on the Apps
    // tab) — only the modal-style interruption is suppressed.
    let suppress_centered = state.app.settings.borrow().notification_fullscreen_silent
        && is_user_in_fullscreen();
    if filters_active && notify && !new_apps.is_empty() && !suppress_centered {
        process_connect_prompts(hwnd, state, &new_apps);
    }

    // notification_on_tray: pop a tray-icon balloon for each new
    // app the centered prompt would have / did show. Routes
    // through Shell_NotifyIcon NIM_MODIFY + NIIF_INFO so the
    // user sees blocks accumulate in the action center without
    // a focus-stealing dialog. Independent of suppress_centered:
    // the user can have both, just centered, or just balloon.
    if filters_active
        && notify
        && !new_apps.is_empty()
        && state.app.settings.borrow().notification_on_tray
    {
        for (path, remote) in &new_apps {
            let title = format!(
                "amwall - blocked: {}",
                path.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string())
            );
            let body = format!("Connecting to {remote}");
            super::tray::show_balloon(hwnd, &title, &body);
        }
    }

    if profile_changed {
        save_profile_to_disk(state);
        populate_apps_tab(state);
        on_tab_change(hwnd);
        // Force the listview's internal layout to pick up the
        // freshly-inserted rows in the same paint cycle. Without
        // this, the new entries don't appear until the user
        // resizes / scrolls / clicks — the same paint-pipeline
        // class of bug as M5.9.5 / M5.4d, so reuse the same
        // 1-pixel jiggle the resize cleanup uses.
        force_active_apps_listview_jiggle(hwnd, state);
    }

    // Drop-toast removed: the connect-prompt dialog (when
    // `enable_notifications` is on) is the user-facing
    // first-connect signal now. The toast was redundant and the
    // user explicitly asked it off — packet-level visibility
    // belongs to the Packets log tab / the on-disk log, not to
    // the notifications path.

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
        (IDM_RULE_BLOCKOUTBOUND, s.rule_block_outbound),
        (IDM_RULE_BLOCKINBOUND, s.rule_block_inbound),
        (IDM_RULE_ALLOWLOOPBACK, s.rule_allow_loopback),
        (IDM_RULE_ALLOW6TO4, s.rule_allow_6to4),
        (IDM_RULE_ALLOWWINDOWSUPDATE, s.rule_allow_windows_update),
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
    // Reflect Notifications mode on the toolbar button so the
    // user can tell at a glance whether the Allow/Block prompt
    // will fire on first-connect drops. Default is on.
    let notify = state.app.settings.borrow().enable_notifications;
    set_toolbar_button_checked(state, IDM_TRAY_ENABLENOTIFICATIONS_CHK, notify);
    // Title-bar icon reflects current filter state (color when
    // active, monochrome when off).
    update_titlebar_icon(hwnd, state.filters_active.get());

    // Apps tab basename-vs-fullpath rendering depends on
    // `show_filenames_only`, so refresh it on every settings
    // apply. Other tabs aren't affected.
    populate_apps_tab(state);

    // View → Layout / Size persistence. Sends LVM_SETVIEW +
    // LVM_SETIMAGELIST(LVSIL_NORMAL) to the Apps tab listviews,
    // and toggles the radio checks on the View menu.
    apply_view_settings(hwnd, state);

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
        IDM_EXIT => on_exit(hwnd),
        IDM_RELEASES => open_releases_page(hwnd),
        IDM_REFRESH => on_refresh(hwnd),
        IDM_IMPORT => on_import(hwnd),
        IDM_EXPORT => on_export(hwnd),
        IDM_ABOUT => on_about(hwnd),
        IDM_EMERGENCY_RESET => on_emergency_reset(hwnd),
        IDM_WEBSITE => open_website(hwnd),
        IDM_CHECKUPDATES => open_releases_page(hwnd),
        IDM_PURGE_UNUSED => on_purge_unused(hwnd),
        IDM_PURGE_TIMERS => on_purge_timers(hwnd),
        IDM_LOGCLEAR | IDM_TRAY_LOGCLEAR => on_log_clear(hwnd),
        IDM_TRAY_LOGSHOW => on_log_show(hwnd),

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
        | IDM_CHECKUPDATES_CHK
        | IDM_RULE_BLOCKOUTBOUND
        | IDM_RULE_BLOCKINBOUND
        | IDM_RULE_ALLOWLOOPBACK
        | IDM_RULE_ALLOW6TO4
        | IDM_RULE_ALLOWWINDOWSUPDATE => on_toggle(hwnd, id),

        IDM_TRAY_START => on_enable_filters(hwnd),
        IDM_TRAY_SHOW => super::tray::toggle_main_window(hwnd),
        IDM_FONT => on_pick_font(hwnd),
        IDM_VIEW_DETAILS | IDM_VIEW_ICON | IDM_VIEW_TILE => on_pick_view_type(hwnd, id),
        IDM_SIZE_SMALL | IDM_SIZE_LARGE | IDM_SIZE_EXTRALARGE => on_pick_icon_size(hwnd, id),
        IDM_OPENRULESEDITOR => on_create_rule(hwnd),
        IDM_SETTINGS => on_open_settings(hwnd),
        IDM_ADD_FILE => on_add_app(hwnd),
        IDM_TRAY_ENABLENOTIFICATIONS_CHK => on_toggle_notifications(hwnd),

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

/// NM_CUSTOMDRAW handler for the Apps Profile / Services / UWP
/// listviews. Picks a row background color following upstream
/// simplewall's highlighting scheme (subset for now: Invalid +
/// System). The two-phase dance — return CDRF_NOTIFYITEMDRAW on
/// the prepaint stage so the listview asks us again per-item,
/// then set clrTextBk + return CDRF_NEWFONT — is the standard
/// Win32 idiom for per-row colors.
fn on_apps_custom_draw(_hwnd: HWND, lparam: LPARAM, listview_id: i32) -> LRESULT {
    let nmlv = unsafe { &mut *(lparam.0 as *mut NMLVCUSTOMDRAW) };
    match nmlv.nmcd.dwDrawStage {
        x if x == CDDS_PREPAINT => LRESULT(CDRF_NOTIFYITEMDRAW as isize),
        x if x == CDDS_ITEMPREPAINT => {
            // Recover the source-vec index via the lParam stamp
            // the populator wrote at insert time. `nmcd.dwItemSpec`
            // is the listview row.
            let row = nmlv.nmcd.dwItemSpec as i32;
            if let Some((state, path)) = path_for_row_with_state(listview_id, row) {
                if let Some(c) = pick_app_row_color(&path, state) {
                    nmlv.clrTextBk = c;
                    return LRESULT(CDRF_NEWFONT as isize);
                }
            }
            LRESULT(CDRF_DODEFAULT as isize)
        }
        _ => LRESULT(CDRF_DODEFAULT as isize),
    }
}

/// Like `path_for_row` but also returns the resolved `&WndState`
/// so the colorizer can read `connected_paths` / `signed_cache`
/// without re-walking the EnumWindows lookup. Same lookup,
/// different return shape.
fn path_for_row_with_state(
    listview_id: i32,
    row: i32,
) -> Option<(&'static WndState, std::path::PathBuf)> {
    use windows::Win32::UI::WindowsAndMessaging::GetParent;
    let lv = match listview_id {
        x if x == IDC_APPS_PROFILE => find_listview(0)?,
        x if x == IDC_APPS_SERVICE => find_listview(1)?,
        x if x == IDC_APPS_UWP => find_listview(2)?,
        _ => return None,
    };
    if lv.0 == 0 {
        return None;
    }
    let parent = unsafe { GetParent(lv) };
    if parent.0 == 0 {
        return None;
    }
    let state = unsafe { state_ref(parent) }?;
    let source_idx = listview_item_param(lv, row)? as usize;
    let path = match listview_id {
        x if x == IDC_APPS_PROFILE => {
            state.app.profile.borrow().apps.get(source_idx).map(|a| a.path.clone())?
        }
        x if x == IDC_APPS_SERVICE => {
            state.services.borrow().get(source_idx).and_then(|s| {
                if s.image_path.as_os_str().is_empty() {
                    None
                } else {
                    Some(s.image_path.clone())
                }
            })?
        }
        _ => return None,
    };
    Some((state, path))
}

/// Resolve `(listview_id, row)` to the underlying File-shaped
/// path via the same source-vec lookup the right-click handler
/// uses. Returns `None` for rows that don't have a matching
/// path (UWP, services without an image_path, etc.).
#[allow(dead_code)]
fn path_for_row(listview_id: i32, row: i32) -> Option<std::path::PathBuf> {
    // Re-grab `state` here — we don't have hwnd in this helper's
    // closure scope; the wndproc-thread guarantee plus
    // `state_ref(hwnd)` reassures the borrow checker via the
    // unsafe cast convention used throughout.
    //
    // Actually we DO have hwnd via `current focus`. Cleaner is
    // to grab state via the listview's GetParent — but the
    // active-tab listview's parent is always the main hwnd, so
    // we walk that.
    use windows::Win32::UI::WindowsAndMessaging::GetParent;
    let lv = match listview_id {
        x if x == IDC_APPS_PROFILE => find_listview(0)?,
        x if x == IDC_APPS_SERVICE => find_listview(1)?,
        x if x == IDC_APPS_UWP => find_listview(2)?,
        _ => return None,
    };
    if lv.0 == 0 {
        return None;
    }
    let parent = unsafe { GetParent(lv) };
    if parent.0 == 0 {
        return None;
    }
    let state = unsafe { state_ref(parent) }?;
    let source_idx = listview_item_param(lv, row)? as usize;
    match listview_id {
        x if x == IDC_APPS_PROFILE => {
            state.app.profile.borrow().apps.get(source_idx).map(|a| a.path.clone())
        }
        x if x == IDC_APPS_SERVICE => {
            state.services.borrow().get(source_idx).and_then(|s| {
                if s.image_path.as_os_str().is_empty() {
                    None
                } else {
                    Some(s.image_path.clone())
                }
            })
        }
        _ => None,
    }
}

/// Find the Nth listview by walking enumerated child windows
/// for the class name `SysListView32`. We can't get to
/// `WndState` here without hwnd, but each tab's listview is the
/// Nth-of-its-class child of the main window. Used only by
/// `path_for_row` which doesn't carry an hwnd through.
///
/// Implementation cheat: walk every visible top-level window
/// looking for the amwall main class — there's only ever one.
fn find_listview(slot: usize) -> Option<HWND> {
    use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetClassNameW};
    use std::cell::Cell;

    thread_local! {
        static FOUND: Cell<HWND> = const { Cell::new(HWND(0)) };
    }
    FOUND.with(|f| f.set(HWND(0)));
    unsafe extern "system" fn cb(hwnd: HWND, _lp: LPARAM) -> windows::Win32::Foundation::BOOL {
        let mut buf = [0u16; 64];
        let n = unsafe { GetClassNameW(hwnd, &mut buf) } as usize;
        let s = String::from_utf16_lossy(&buf[..n]);
        if s == "AmwallMainWindow" {
            FOUND.with(|f| f.set(hwnd));
            return windows::Win32::Foundation::FALSE;
        }
        windows::Win32::Foundation::TRUE
    }
    unsafe {
        let _ = EnumWindows(Some(cb), LPARAM(0));
    }
    let main = FOUND.with(|f| f.get());
    if main.0 == 0 {
        return None;
    }
    let state = unsafe { state_ref(main) }?;
    Some(state.listviews[slot].get())
}

/// Pick a row color following upstream's `_app_getappcolor` priority:
///   - Invalid: file doesn't exist on disk → pinkish red.
///     Imported simplewall profiles often carry references to
///     apps the user has uninstalled.
///   - Connection: an active TCP / UDP endpoint right now → pink.
///     Surfaces "what's chatting at this moment".
///   - Signed: passes `WinVerifyTrust` → pale green. Marks
///     properly-signed binaries — hint that they're more
///     trustworthy than unsigned third-party ones.
///   - Pico: WSL / Linux subsystem process → blue. Detection
///     would need per-process inspection (path-only
///     classification doesn't work — every Pico process is
///     spawned from `wsl.exe` / `wslhost.exe`), so the
///     code path's there but always returns `false`. Reserved
///     so the priority order matches upstream.
///   - System: path under `C:\Windows\` → pastel blue. OS-bundled
///     binaries vs user-installed apps.
///
/// First match wins; default returns `None` for the listview's
/// default background.
fn pick_app_row_color(
    path: &std::path::Path,
    state: &WndState,
) -> Option<windows::Win32::Foundation::COLORREF> {
    use windows::Win32::Foundation::COLORREF;
    // 1. Invalid (path doesn't exist on disk).
    if !path.as_os_str().is_empty() && !path.is_file() {
        return Some(COLORREF(rgb_packed(255, 125, 148)));
    }
    // 2. Active connection — refreshed by populate_apps_tab.
    if state.connected_paths.borrow().contains(path) {
        return Some(COLORREF(rgb_packed(255, 168, 242)));
    }
    // 3. Signed (cached — first paint slow, subsequent fast).
    if path_is_signed_cached(state, path) {
        return Some(COLORREF(rgb_packed(175, 228, 163)));
    }
    // 4. Pico — reserved; detection isn't path-driven so it
    //    always returns false today.
    if is_pico(path) {
        return Some(COLORREF(rgb_packed(51, 153, 255)));
    }
    // 5. System (Windows-bundled binaries).
    if let Some(s) = path.to_str() {
        let lower = s.to_lowercase();
        if lower.starts_with(r"c:\windows\") {
            return Some(COLORREF(rgb_packed(220, 232, 250)));
        }
    }
    None
}

/// Returns the cached `WinVerifyTrust` result for `path`, or
/// `false` if the worker hasn't gotten to it yet. The colorizer
/// uses this — paint stays fast, and the apps tab repaints
/// once the worker fills the cache. Verification itself happens
/// on a background thread fed by `signed_tx` (queued from
/// `populate_apps_tab`).
fn path_is_signed_cached(state: &WndState, path: &std::path::Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    match state.signed_cache.lock() {
        Ok(g) => g.get(path).copied().unwrap_or(false),
        Err(_) => false,
    }
}

/// `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` returning
/// `0` means the binary's signature chain is valid. Anything else
/// (TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, etc.) means we
/// treat it as unsigned. We pass `WTD_REVOKE_NONE` to skip the
/// revocation network check — keeps each call latency-bounded
/// and avoids hangs on offline machines.
fn win_verify_trust(path: &std::path::Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    };
    use windows::core::{GUID, PCWSTR};

    let wpath: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..unsafe { std::mem::zeroed() }
    };
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.Anonymous = WINTRUST_DATA_0 {
        pFile: &mut file_info,
    };

    // GUID for WINTRUST_ACTION_GENERIC_VERIFY_V2 — the standard
    // file-signature action.
    let action = GUID::from_u128(0x00aac56b_cd44_11d0_8cc2_00c04fc295ee);

    let result = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &action as *const _ as *mut _,
            &mut data as *mut _ as *mut std::ffi::c_void,
        )
    };

    // Always close the trust state to release the cached
    // signature data WinVerifyTrust holds onto.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &action as *const _ as *mut _,
            &mut data as *mut _ as *mut std::ffi::c_void,
        );
    }

    result == 0
}

/// WSL "Pico" process detection. Path-only classification can't
/// distinguish Pico from regular processes (every Pico instance
/// hangs off `wsl.exe` / `wslhost.exe` and the actual Linux
/// binary lives in the per-distro filesystem). Detecting at row-
/// paint time would need a process snapshot + per-PID query of
/// `ProcessSubsystemInformation` via `NtQueryInformationProcess`,
/// which is heavier than the row-color decision warrants.
/// Returning `false` here reserves the color slot in the
/// priority chain so the structure stays parallel to upstream
/// without surfacing the (always-empty) blue.
fn is_pico(_path: &std::path::Path) -> bool {
    false
}

/// Pack RGB to a Win32 COLORREF (0x00BBGGRR). Standard helper —
/// inlined here to avoid pulling another module.
fn rgb_packed(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

/// User clicked a column header on the Apps Profile listview.
/// Toggle sort direction if it's the same column, otherwise
/// switch to that column with a descending default (so a fresh
/// click on Added shows latest-first).
fn on_apps_column_click(hwnd: HWND, column: i32) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let mut sort = state.apps_sort.get();
    if sort.column == column {
        sort.ascending = !sort.ascending;
    } else {
        sort.column = column;
        sort.ascending = false;
    }
    state.apps_sort.set(sort);
    populate_apps_tab(state);
}

/// `true` if either Ctrl key is currently pressed. Used to
/// disambiguate plain-A from Ctrl-A in LVN_KEYDOWN handlers
/// (NMLVKEYDOWN doesn't carry modifier state).
fn ctrl_is_down() -> bool {
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, VK_CONTROL};
    let s = unsafe { GetKeyState(VK_CONTROL.0 as i32) };
    (s as u16 & 0x8000) != 0
}

/// Select every row in the active apps-tab listview. Wired to
/// Ctrl+A on the apps tabs so users can quickly clear an
/// imported profile via Ctrl+A → Del.
fn on_apps_select_all(hwnd: HWND, listview_id: i32) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = match listview_id {
        x if x == IDC_APPS_PROFILE => state.listviews[0].get(),
        x if x == IDC_APPS_SERVICE => state.listviews[1].get(),
        x if x == IDC_APPS_UWP => state.listviews[2].get(),
        _ => return,
    };
    if lv.0 == 0 {
        return;
    }
    let item = LVITEMW {
        state: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        ..Default::default()
    };
    // iItem = -1 (cast to usize::MAX in WPARAM) tells comctl
    // "apply this state to every row".
    unsafe {
        SendMessageW(
            lv,
            LVM_SETITEMSTATE,
            WPARAM(usize::MAX),
            LPARAM(&item as *const _ as isize),
        );
    }
}

/// Walk the active apps-tab listview's selected rows, recover
/// each row's source-vec index via the lParam stamp, and remove
/// the corresponding profile entries. Reinstalls filters
/// afterwards if filters are active.
///
/// Per-tab semantics:
///   - Apps Profile: drops the matching `profile.apps[]` slots.
///   - Services: removes any `profile.apps[]` whose `path`
///     matches the selected services' SCM short name — does NOT
///     touch the SCM service itself.
///   - UWP: removes any `profile.apps[]` whose `path` matches
///     the selected packages' SID. SID-less rows (registry hive
///     incomplete) silently no-op.
fn on_apps_delete_selected(hwnd: HWND, listview_id: i32) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = match listview_id {
        x if x == IDC_APPS_PROFILE => state.listviews[0].get(),
        x if x == IDC_APPS_SERVICE => state.listviews[1].get(),
        x if x == IDC_APPS_UWP => state.listviews[2].get(),
        _ => return,
    };
    if lv.0 == 0 {
        return;
    }

    // Walk LVM_GETNEXTITEM(LVNI_SELECTED) until we run out of
    // selected rows, collecting source indices via lParam.
    let mut source_indices: Vec<usize> = Vec::new();
    let mut next: i32 = -1;
    loop {
        next = unsafe {
            SendMessageW(
                lv,
                LVM_GETNEXTITEM,
                WPARAM(next as isize as usize),
                LPARAM(LVNI_SELECTED as isize),
            )
        }
        .0 as i32;
        if next < 0 {
            break;
        }
        if let Some(p) = listview_item_param(lv, next) {
            source_indices.push(p as usize);
        }
    }
    if source_indices.is_empty() {
        return;
    }

    // Confirm only on bulk deletes (>1 row) to keep single-row
    // delete responsive — same key (Del) the user already uses
    // for individual removal via the right-click menu.
    if source_indices.len() > 1 && !confirm_bulk_delete(hwnd, source_indices.len()) {
        return;
    }

    let mut removed = 0usize;
    match listview_id {
        x if x == IDC_APPS_PROFILE => {
            // Sort indices descending so removals don't shift
            // later indices we still need to read.
            source_indices.sort_unstable_by(|a, b| b.cmp(a));
            let mut profile = state.app.profile.borrow_mut();
            for idx in source_indices {
                if idx < profile.apps.len() {
                    profile.apps.remove(idx);
                    removed += 1;
                }
            }
        }
        x if x == IDC_APPS_SERVICE => {
            // Collect the matched service short-names first, then
            // retain-by-not-in-set on profile.apps. Avoids the
            // index-shift issue and cleanly handles services
            // whose name doesn't have a profile entry (no-op for
            // those rows).
            let services = state.services.borrow();
            let paths: Vec<std::path::PathBuf> = source_indices
                .into_iter()
                .filter_map(|i| {
                    services
                        .get(i)
                        .map(|s| std::path::PathBuf::from(&s.service_name))
                })
                .collect();
            let mut profile = state.app.profile.borrow_mut();
            let before = profile.apps.len();
            profile.apps.retain(|a| !paths.contains(&a.path));
            removed = before - profile.apps.len();
        }
        x if x == IDC_APPS_UWP => {
            // Match by package SID — same identifier the right-
            // click and install paths use.
            let uwp = state.uwp_packages.borrow();
            let sids: Vec<std::path::PathBuf> = source_indices
                .into_iter()
                .filter_map(|i| {
                    uwp.get(i)
                        .and_then(|p| p.package_sid.as_deref())
                        .map(std::path::PathBuf::from)
                })
                .collect();
            if !sids.is_empty() {
                let mut profile = state.app.profile.borrow_mut();
                let before = profile.apps.len();
                profile.apps.retain(|a| !sids.contains(&a.path));
                removed = before - profile.apps.len();
            }
        }
        _ => return,
    }

    if removed == 0 {
        set_status_text(state.status.get(), 0, "Nothing to remove from profile.");
        return;
    }

    save_profile_to_disk(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);
    // Same paint-pipeline jiggle the auto-catalog flow uses —
    // populate + tab-change alone leave comctl32 in a half-
    // painted state where deleted rows linger until the user
    // scrolls or resizes. Forcing an InvalidateRect on the
    // listview's parent rect re-runs the paint pipeline cleanly.
    force_active_apps_listview_jiggle(hwnd, state);
    reinstall_filters_if_active(state);
    set_status_text(
        state.status.get(),
        0,
        &format!("Removed {removed} entrie(s) from profile."),
    );
}

/// MessageBox confirm for bulk-delete. Yes/No, default No so a
/// stray Enter doesn't wipe the list.
fn confirm_bulk_delete(hwnd: HWND, count: usize) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO,
    };
    let msg = wide(&format!(
        "Remove {count} entries from the profile?\n\nThis can't be undone.",
    ));
    let title = wide("Confirm bulk delete");
    let r = unsafe {
        MessageBoxW(
            hwnd,
            PCWSTR(msg.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        )
    };
    r == IDYES
}

/// Allow / Block toggle. Upserts an App entry at `target.binary_path`:
/// updates `is_enabled` if one exists, creates a new one otherwise.
/// `binary_path` carries an exe path for File rows, an image path
/// for Service rows, and a `S-1-15-2-…` SID string for UWP rows
/// (`App::kind_for` reclassifies based on the prefix). The empty-
/// path bail only fires now if the registry hive is partially
/// corrupt and a UWP row had no PackageSid value to read.
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
            "Cannot add: missing identifier (UWP package SID unavailable).",
        );
        return;
    }

    // Collect every selected row's binary path. Falls back to the
    // single right-clicked target if nothing is highlighted —
    // matches the user's expectation that Ctrl+A → right-click →
    // Allow processes the whole selection in one shot, while a
    // bare right-click on a row still works on just that row.
    let paths = collect_selection_paths(state, target.listview_id, &target);
    if paths.is_empty() {
        return;
    }

    // confirm_allow: warn before flipping a previously-blocked app
    // to Allow, since allowing malware is the asymmetric mistake
    // (block-by-mistake is recoverable; allow-by-mistake leaks
    // traffic the user just decided to ban).
    if enable && state.app.settings.borrow().confirm_allow {
        let was_blocked = {
            let profile = state.app.profile.borrow();
            paths
                .iter()
                .any(|p| profile.apps.iter().any(|a| &a.path == p && !a.is_enabled))
        };
        if was_blocked && !confirm_allow_traffic(hwnd, &paths) {
            return;
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut affected = 0usize;
    {
        let mut profile = state.app.profile.borrow_mut();
        for path in &paths {
            if let Some(existing) =
                profile.apps.iter_mut().find(|a| &a.path == path)
            {
                existing.is_enabled = enable;
            } else {
                profile.apps.push(ProfileApp {
                    path: path.clone(),
                    is_enabled: enable,
                    is_silent: false,
                    is_undeletable: false,
                    timestamp: now,
                    timer: 0,
                    hash: None,
                    comment: None,
                });
            }
            affected += 1;
        }
    }

    save_profile_to_disk(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);
    // One reinstall covers every path's permit / removal in a
    // single cleanup_provider + install pass — much cheaper than
    // re-pushing per app.
    reinstall_filters_if_active(state);

    let verb = if enable { "Allowed" } else { "Blocked" };
    let msg = if affected == 1 {
        format!("{verb}: {}", target.display_name)
    } else {
        format!("{verb} {affected} app(s).")
    };
    set_status_text(state.status.get(), 0, &msg);
}

/// Walk the listview's selected rows and return the corresponding
/// binary paths via the source-vec lookup the populator stamped
/// into LVITEMW.lParam. Empty selection falls back to the single
/// right-clicked target so a bare right-click still works on
/// just that row.
fn collect_selection_paths(
    state: &WndState,
    listview_id: i32,
    fallback_target: &super::apps_context_menu::ContextTarget,
) -> Vec<std::path::PathBuf> {
    let lv = match listview_id {
        x if x == IDC_APPS_PROFILE => state.listviews[0].get(),
        x if x == IDC_APPS_SERVICE => state.listviews[1].get(),
        x if x == IDC_APPS_UWP => state.listviews[2].get(),
        _ => return Vec::new(),
    };
    if lv.0 == 0 {
        return vec![fallback_target.binary_path.clone()];
    }

    let mut source_indices: Vec<usize> = Vec::new();
    let mut next: i32 = -1;
    loop {
        next = unsafe {
            SendMessageW(
                lv,
                LVM_GETNEXTITEM,
                WPARAM(next as isize as usize),
                LPARAM(LVNI_SELECTED as isize),
            )
        }
        .0 as i32;
        if next < 0 {
            break;
        }
        if let Some(p) = listview_item_param(lv, next) {
            source_indices.push(p as usize);
        }
    }

    if source_indices.is_empty() {
        return vec![fallback_target.binary_path.clone()];
    }

    let mut out: Vec<std::path::PathBuf> = Vec::new();
    match listview_id {
        x if x == IDC_APPS_PROFILE => {
            let profile = state.app.profile.borrow();
            for idx in source_indices {
                if let Some(app) = profile.apps.get(idx) {
                    if !app.path.as_os_str().is_empty() {
                        out.push(app.path.clone());
                    }
                }
            }
        }
        x if x == IDC_APPS_SERVICE => {
            let services = state.services.borrow();
            for idx in source_indices {
                if let Some(svc) = services.get(idx) {
                    if !svc.image_path.as_os_str().is_empty() {
                        out.push(svc.image_path.clone());
                    }
                }
            }
        }
        x if x == IDC_APPS_UWP => {
            // No path-based mapping yet — fall back to single
            // target which will be rejected upstream by the
            // empty-path check.
            out.push(fallback_target.binary_path.clone());
        }
        _ => {}
    }
    out
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
    force_active_apps_listview_jiggle(hwnd, state);
    reinstall_filters_if_active(state);
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
    reinstall_filters_if_active(state);
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
            // Settings → Rules — global behavior switches that
            // shape the install-time filter set. on_toggle just
            // flips + persists; the install path reads each one
            // when "Enable filters" runs (or right-click reinstall
            // re-pushes the new posture).
            IDM_RULE_BLOCKOUTBOUND => &mut s.rule_block_outbound,
            IDM_RULE_BLOCKINBOUND => &mut s.rule_block_inbound,
            IDM_RULE_ALLOWLOOPBACK => &mut s.rule_allow_loopback,
            IDM_RULE_ALLOW6TO4 => &mut s.rule_allow_6to4,
            IDM_RULE_ALLOWWINDOWSUPDATE => &mut s.rule_allow_windows_update,
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
        IDM_AUTOSIZECOLUMNS_CHK if new_value => {
            autosize_active_listview_columns(state);
        }
        IDM_LOADONSTARTUP_CHK => {
            // Write or remove the HKCU\...\Run\amwall registry
            // value so Explorer launches us at user logon. Same
            // hive upstream uses (`StartUpExtensionLoad` doesn't
            // exist — the canonical mechanism is the Run key).
            if let Err(e) = super::startup::set_load_on_startup(new_value) {
                eprintln!("amwall: load_on_startup registry write failed: {e}");
            }
        }
        IDM_RULE_BLOCKOUTBOUND
        | IDM_RULE_BLOCKINBOUND
        | IDM_RULE_ALLOWLOOPBACK
        | IDM_RULE_ALLOW6TO4
        | IDM_RULE_ALLOWWINDOWSUPDATE => {
            // Each of these reshapes the install-time filter set.
            // If filters are already on, push the new posture
            // through immediately so the toggle is visible without
            // making the user click "Disable filters" then "Enable
            // filters" by hand.
            reinstall_filters_if_active(state);
        }
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
        let (blocklist, global_rules, persistent) = {
            let s = state.app.settings.borrow();
            (
                crate::install::BlocklistConfig {
                    spy: blocklist_mode_to_action(s.blocklist_spy),
                    update: blocklist_mode_to_action(s.blocklist_update),
                    extra: blocklist_mode_to_action(s.blocklist_extra),
                },
                crate::install::GlobalRulesConfig {
                    block_outbound: s.rule_block_outbound,
                    block_inbound: s.rule_block_inbound,
                    allow_loopback: s.rule_allow_loopback,
                    allow_6to4: s.rule_allow_6to4,
                    allow_windows_update: s.rule_allow_windows_update,
                    use_stealth_mode: s.use_stealth_mode,
                },
                s.install_boottime_filters,
            )
        };
        let report = match crate::install::install_with_internal(
            &engine,
            &state.app.profile.borrow(),
            Some(&state.app.internal_profile),
            &blocklist,
            &global_rules,
            persistent,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("amwall: install failed: {e}");
                set_status_text(state.status.get(), 0, "Filter install failed.");
                return;
            }
        };
        // Stash categorized ids on state so drain_events can
        // honor exclude_blocklist / exclude_custom /
        // exclude_stealth without re-categorizing each event.
        *state.categorized_filter_ids.borrow_mut() = report.filter_ids.clone();
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
    update_titlebar_icon(hwnd, new_active);
    refresh_amwall_filter_ids_with(&engine, state);
}

/// Re-push the user's current profile + settings into the kernel
/// when filters are already active. No-op when filters are off
/// (toggling Allow/Block on a row in that case is purely a
/// profile edit; the next Enable filters click will install the
/// fresh state). Closes the gap where the right-click context
/// menu's Allow / Block / Remove updated `profile.apps[].is_enabled`
/// and redrew the row but didn't push the new permit or remove
/// the old one — the user reported a Block toggle on brave.exe
/// having no effect on its actual traffic from exactly this gap.
///
/// Implementation: full `cleanup_provider` then re-install. A
/// surgical "delete just this app's filters" path would be
/// faster but needs reading FWPM_FILTER0.filterCondition to
/// match by AppPath, which is several hundred lines of matching
/// machinery. cleanup_provider runs in O(filter count) syscalls
/// and even on a 200-app profile (~1000 filters) finishes in
/// well under a second.
fn reinstall_filters_if_active(state: &WndState) {
    if !state.filters_active.get() {
        return;
    }
    let engine = match crate::wfp::WfpEngine::open() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("amwall: reinstall: WFP engine open failed: {e:?}");
            return;
        }
    };
    if let Err(e) = engine.cleanup_provider(&crate::install::PROVIDER_KEY) {
        eprintln!("amwall: reinstall: cleanup_provider failed: {e:?}");
        return;
    }

    let (blocklist, global_rules, persistent) = {
        let s = state.app.settings.borrow();
        (
            crate::install::BlocklistConfig {
                spy: blocklist_mode_to_action(s.blocklist_spy),
                update: blocklist_mode_to_action(s.blocklist_update),
                extra: blocklist_mode_to_action(s.blocklist_extra),
            },
            crate::install::GlobalRulesConfig {
                block_outbound: s.rule_block_outbound,
                block_inbound: s.rule_block_inbound,
                allow_loopback: s.rule_allow_loopback,
                allow_6to4: s.rule_allow_6to4,
                allow_windows_update: s.rule_allow_windows_update,
                use_stealth_mode: s.use_stealth_mode,
            },
            s.install_boottime_filters,
        )
    };
    let report = match crate::install::install_with_internal(
        &engine,
        &state.app.profile.borrow(),
        Some(&state.app.internal_profile),
        &blocklist,
        &global_rules,
        persistent,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("amwall: reinstall: install failed: {e}");
            // We tore down successfully but the reinstall failed
            // — flip filters_active so the toolbar reflects the
            // actual state and the user can investigate.
            state.filters_active.set(false);
            update_enable_filters_button(state, false);
            // No hwnd here — the toolbar update reaches the
            // window via `state.toolbar`, but the title-bar
            // icon swap needs the main hwnd. Caller-paths
            // (right-click handlers) all run on the GUI thread
            // and will refresh on the next apply_initial pass
            // if needed.
            return;
        }
    };
    refresh_amwall_filter_ids_with(&engine, state);
    *state.categorized_filter_ids.borrow_mut() = report.filter_ids.clone();
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
    // M12.2: when use_hashes is on, compute SHA-256 for File-
    // kind apps that don't yet have a stored hash AND check for
    // drift on apps that do. Mirrors upstream simplewall's
    // `_app_getfilehashinfo` -> `<item hash="..."/>` flow at
    // db.c:1027 + helper.c:1882. Cheap on a typical exe (a few
    // ms each); we run it inline on save rather than spawning a
    // worker since the user expects "save" to mean "everything
    // is on disk now", not "queued".
    update_hashes_if_enabled(state);

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

/// M12.2 use_hashes worker: walk File-kind apps in the profile,
/// compute current SHA-256, compare against stored. Three cases:
///
/// - `app.hash` empty + file readable: store the computed hash.
/// - `app.hash` non-empty + file readable + matches: no-op.
/// - `app.hash` non-empty + file readable + differs: log a
///   warning to stderr (caught by swaplog) and surface in the
///   status bar. The stored hash is NOT overwritten — drift
///   detection is a one-shot signal; the user clears it by
///   editing or removing the App entry.
///
/// No-op when `use_hashes` is off or the app isn't File-shaped.
fn update_hashes_if_enabled(state: &WndState) {
    use crate::profile::AppKind;

    if !state.app.settings.borrow().use_hashes {
        return;
    }
    let mut profile = state.app.profile.borrow_mut();
    let mut drifted: Vec<String> = Vec::new();
    for app in profile.apps.iter_mut() {
        if app.kind() != AppKind::File {
            continue;
        }
        let Some(current) = crate::hash::sha256_file(&app.path) else {
            // Unreadable file — skip, leave any existing hash
            // alone. Don't surface as drift (the file might
            // simply have been uninstalled).
            continue;
        };
        match &app.hash {
            None => {
                app.hash = Some(current);
            }
            Some(stored) if stored.eq_ignore_ascii_case(&current) => {
                // Match — nothing to do.
            }
            Some(_) => {
                let name = app
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| app.path.display().to_string());
                eprintln!(
                    "amwall: hash drift detected for {} ({}): \
                     stored hash differs from current binary",
                    name,
                    app.path.display()
                );
                drifted.push(name);
            }
        }
    }
    drop(profile);
    if !drifted.is_empty() {
        let msg = if drifted.len() == 1 {
            format!("Hash drift: {}", drifted[0])
        } else {
            format!("Hash drift on {} apps (see log)", drifted.len())
        };
        set_status_text(state.status.get(), 0, &msg);
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
/// Help → Emergency WFP reset. Confirms via MessageBox, then
/// (a) tears down amwall's WFP provider + every filter under it,
/// (b) clears `profile.apps` and `profile.custom_rules` to their
/// empty form, (c) saves the empty profile to disk so the wipe
/// survives restart, (d) flips `filters_active` and updates the
/// toolbar so the user sees the change. Use this when amwall has
/// installed filters that are blocking something the user can't
/// File → Exit. Honors `confirm_exit`: if filters are active and
/// the setting is on, prompts before destroying the window. Other
/// exit paths (tray "Exit amwall", Ctrl+Q accelerator) all funnel
/// through this same handler.
fn on_exit(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_YESNO,
    };
    if let Some(state) = unsafe { state_ref(hwnd) } {
        let s = state.app.settings.borrow();
        if s.confirm_exit && state.filters_active.get() {
            drop(s);
            let body = wide(
                "Filters are currently enabled. Quitting amwall \
                 will leave them in place (they survive process \
                 exit). Continue?",
            );
            let title = wide("Exit amwall?");
            let answer = unsafe {
                MessageBoxW(
                    hwnd,
                    PCWSTR(body.as_ptr()),
                    PCWSTR(title.as_ptr()),
                    MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
                )
            };
            if answer != IDYES {
                return;
            }
        }
    }
    unsafe {
        let _ = DestroyWindow(hwnd);
    }
}

/// Edit → Purge unused apps. Walks `profile.apps` and removes
/// every entry whose binary no longer exists on disk (i.e. the
/// "Invalid" rows the listview colorizer paints pink-red).
/// Disabled rows are kept — they're an explicit user decision —
/// only the broken-path rows are pruned. Re-installs filters if
/// active so the kernel forgets the deleted apps' permits.
fn on_purge_unused(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let removed = {
        let mut profile = state.app.profile.borrow_mut();
        let before = profile.apps.len();
        profile.apps.retain(|a| a.path.exists());
        before - profile.apps.len()
    };
    if removed == 0 {
        set_status_text(state.status.get(), 0, "No unused apps to purge.");
        return;
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    force_active_apps_listview_jiggle(hwnd, state);
    reinstall_filters_if_active(state);
    set_status_text(
        state.status.get(),
        0,
        &format!("Purged {removed} unused app(s)."),
    );
}

/// Edit → Purge timers. Clears every app's expiration timer
/// (the "this rule expires at <timestamp>" field on `App.timer`).
/// Mirrors upstream's IDM_PURGE_TIMERS, which surfaces in the
/// menu but never as a feature anyone reaches for unless they've
/// been using timed Allow rules. Profile saved + filters
/// re-installed so the kernel matches.
fn on_purge_timers(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let cleared = {
        let mut profile = state.app.profile.borrow_mut();
        let mut count = 0usize;
        for a in profile.apps.iter_mut() {
            if a.timer != 0 {
                a.timer = 0;
                count += 1;
            }
        }
        count
    };
    if cleared == 0 {
        set_status_text(state.status.get(), 0, "No active timers.");
        return;
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    force_active_apps_listview_jiggle(hwnd, state);
    reinstall_filters_if_active(state);
    set_status_text(
        state.status.get(),
        0,
        &format!("Cleared {cleared} app timer(s)."),
    );
}

/// Edit → Clear log (also reachable via the toolbar's "Clear
/// log" button). Wipes the in-memory event ring and truncates
/// the on-disk log file. Honors `confirm_log_clear`.
fn on_log_clear(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_YESNO,
    };
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    if state.app.settings.borrow().confirm_log_clear {
        let body = wide(
            "Clear the packets log? This empties the in-memory log \
             tab and truncates the on-disk log file. The action \
             can't be undone.",
        );
        let title = wide("Clear log");
        let answer = unsafe {
            MessageBoxW(
                hwnd,
                PCWSTR(body.as_ptr()),
                PCWSTR(title.as_ptr()),
                MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
            )
        };
        if answer != IDYES {
            return;
        }
    }
    state.event_log.borrow_mut().clear();
    state.event_log_writer.borrow_mut().truncate();
    populate_log_tab(state);
    on_tab_change(hwnd);
    set_status_text(state.status.get(), 0, "Log cleared.");
}

/// Toolbar "Show log" button. Opens the log file in the
/// configured external viewer (`Settings.log_viewer`); falls back
/// to the OS default handler when the viewer field is empty.
/// Reports a status-bar message if the log path doesn't resolve
/// (most commonly: `enable_log` is off and nothing has been
/// written yet).
fn on_log_show(hwnd: HWND) {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let (log_path, viewer) = {
        let s = state.app.settings.borrow();
        (s.log_path.clone(), s.log_viewer.clone())
    };
    let resolved = if log_path.is_empty() {
        super::event_log::default_log_path()
    } else {
        std::path::PathBuf::from(log_path)
    };
    if !resolved.is_file() {
        set_status_text(
            state.status.get(),
            0,
            "Log file not found — turn on packets logging first.",
        );
        return;
    }

    let path_w = wide(&resolved.display().to_string());
    let result = if viewer.is_empty() {
        // No configured viewer → ShellExecute "open" the file
        // through whatever handler is registered for .log /
        // text files (notepad on a default install).
        unsafe {
            ShellExecuteW(
                hwnd,
                w!("open"),
                PCWSTR(path_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        }
    } else {
        // User picked a viewer (e.g. baretail.exe / mtputty) —
        // pass the log path as that exe's command-line argument.
        let viewer_w = wide(&viewer);
        let arg_w = wide(&format!("\"{}\"", resolved.display()));
        unsafe {
            ShellExecuteW(
                hwnd,
                w!("open"),
                PCWSTR(viewer_w.as_ptr()),
                PCWSTR(arg_w.as_ptr()),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        }
    };
    // ShellExecute returns an HINSTANCE encoding the result —
    // > 32 means success, <= 32 is a SE_ERR_* code.
    if (result.0 as isize) <= 32 {
        set_status_text(
            state.status.get(),
            0,
            "Failed to launch log viewer (check Settings → Logging).",
        );
    }
}

/// View → Font…. Shows the system Choose Font dialog seeded
/// with the currently-applied font, and on OK builds a fresh
/// HFONT, swaps it onto every child of the main window via
/// `font::apply_recursive`, deletes the old HFONT, and persists
/// the user's choice into `Settings.font_face` /
/// `Settings.font_height` so it survives restart.
/// View → Layout radio-pick handler. Updates `Settings.view_type`,
/// persists, and reapplies to all three apps-tab listviews via
/// `LVM_SETVIEW`. Mirrors upstream simplewall's `IDM_VIEW_*` arm
/// at `main.c:3337-3363`.
fn on_pick_view_type(hwnd: HWND, id: u16) {
    use crate::gui::settings::ViewType;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let new_view = match id {
        IDM_VIEW_ICON => ViewType::Icon,
        IDM_VIEW_TILE => ViewType::Tile,
        _ => ViewType::Details,
    };
    {
        let mut s = state.app.settings.borrow_mut();
        if s.view_type == new_view {
            return;
        }
        s.view_type = new_view;
    }
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!("amwall: settings: save view_type failed: {e}");
    }
    apply_view_settings(hwnd, state);
}

/// View → Size radio-pick handler. Updates `Settings.icon_size`,
/// persists, and reapplies. Mirrors upstream's `IDM_SIZE_*` arm
/// at `main.c:3365`.
fn on_pick_icon_size(hwnd: HWND, id: u16) {
    use crate::gui::settings::IconSize;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let new_size = match id {
        IDM_SIZE_LARGE => IconSize::Large,
        IDM_SIZE_EXTRALARGE => IconSize::ExtraLarge,
        _ => IconSize::Small,
    };
    {
        let mut s = state.app.settings.borrow_mut();
        if s.icon_size == new_size {
            return;
        }
        s.icon_size = new_size;
    }
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!("amwall: settings: save icon_size failed: {e}");
    }
    apply_view_settings(hwnd, state);
}

/// Push the current `view_type` + `icon_size` settings to the
/// three Apps tab listviews via `LVM_SETVIEW` and `LVM_SETIMAGELIST`.
/// Also sets the radio check marks on the View menu.
///
/// Listviews other than Apps (Rules / Connections / Log) stay
/// in `LV_VIEW_DETAILS` always — those are pure tabular data,
/// the icon/tile modes don't make sense there.
fn apply_view_settings(hwnd: HWND, state: &WndState) {
    use crate::gui::settings::{IconSize, ViewType};
    use windows::Win32::UI::Controls::{
        LV_VIEW_DETAILS, LV_VIEW_ICON, LV_VIEW_TILE, LVSIL_NORMAL,
    };
    use windows::Win32::UI::WindowsAndMessaging::CheckMenuRadioItem;

    const LVM_SETVIEW: u32 = 0x108E; // see CommCtrl.h: LVM_FIRST + 142

    let s = state.app.settings.borrow();
    let view_value: u32 = match s.view_type {
        ViewType::Details => LV_VIEW_DETAILS,
        ViewType::Icon => LV_VIEW_ICON,
        ViewType::Tile => LV_VIEW_TILE,
    };
    let large_il = match s.icon_size {
        IconSize::Small => super::app_icons::system_small_imagelist(),
        IconSize::Large => super::app_icons::system_large_imagelist(),
        IconSize::ExtraLarge => super::app_icons::system_extralarge_imagelist(),
    };
    drop(s);

    // Apply view + LVSIL_NORMAL on Apps Profile / Services / UWP.
    for slot in 0..=2 {
        let lv = state.listviews[slot].get();
        if lv.0 == 0 {
            continue;
        }
        unsafe {
            SendMessageW(lv, LVM_SETVIEW, WPARAM(view_value as usize), LPARAM(0));
            if large_il != HIMAGELIST::default() {
                SendMessageW(
                    lv,
                    LVM_SETIMAGELIST,
                    WPARAM(LVSIL_NORMAL as usize),
                    LPARAM(large_il.0),
                );
            }
        }
    }

    // Radio-check the menu items so the user sees the current
    // pick. CheckMenuRadioItem operates on a contiguous range of
    // IDs; we have two ranges (3 view types, 3 icon sizes).
    let s = state.app.settings.borrow();
    let view_id = match s.view_type {
        ViewType::Details => IDM_VIEW_DETAILS,
        ViewType::Icon => IDM_VIEW_ICON,
        ViewType::Tile => IDM_VIEW_TILE,
    };
    let size_id = match s.icon_size {
        IconSize::Small => IDM_SIZE_SMALL,
        IconSize::Large => IDM_SIZE_LARGE,
        IconSize::ExtraLarge => IDM_SIZE_EXTRALARGE,
    };
    drop(s);
    let menu = unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetMenu(hwnd)
    };
    if !menu.is_invalid() {
        unsafe {
            let _ = CheckMenuRadioItem(
                menu,
                IDM_VIEW_DETAILS as u32,
                IDM_VIEW_TILE as u32,
                view_id as u32,
                windows::Win32::UI::WindowsAndMessaging::MF_BYCOMMAND.0,
            );
            let _ = CheckMenuRadioItem(
                menu,
                IDM_SIZE_SMALL as u32,
                IDM_SIZE_EXTRALARGE as u32,
                size_id as u32,
                windows::Win32::UI::WindowsAndMessaging::MF_BYCOMMAND.0,
            );
        }
    }
}

fn on_pick_font(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let (face, height) = {
        let s = state.app.settings.borrow();
        (s.font_face.clone(), s.font_height)
    };
    let (new_face, new_height) = match super::font::pick_font(hwnd, &face, height) {
        Some(pair) => pair,
        None => return, // user cancelled
    };

    let new_font = match super::font::load_named_font(&new_face, new_height) {
        Some(f) => f,
        None => {
            set_status_text(state.status.get(), 0, "Font load failed; reverted.");
            return;
        }
    };

    // Swap onto the live tree, then delete the old handle so we
    // don't leak GDI objects across font changes.
    let old = state.font.get();
    state.font.set(new_font);
    super::font::apply_recursive(hwnd, new_font);
    if !old.is_invalid() {
        unsafe {
            let _ = DeleteObject(old);
        }
    }

    {
        let mut s = state.app.settings.borrow_mut();
        s.font_face = new_face;
        s.font_height = new_height;
    }
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!("amwall: settings: save font choice failed: {e}");
    }
    set_status_text(state.status.get(), 0, "Font updated.");
}

/// Modal yes/no for the right-click Allow path when the target
/// app was previously blocked. Returns true if the user
/// confirmed the change. Used by `on_context_set_enabled`.
fn confirm_allow_traffic(hwnd: HWND, paths: &[std::path::PathBuf]) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_YESNO,
    };
    let body_str = if paths.len() == 1 {
        let name = paths[0]
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| paths[0].display().to_string());
        format!(
            "{} is currently blocked. Allowing it will let it \
             reach the network the next time it tries.\n\n\
             Continue?",
            name
        )
    } else {
        format!(
            "{} previously-blocked apps will be set to Allow. \
             They will reach the network the next time they try.\n\n\
             Continue?",
            paths.len()
        )
    };
    let body = wide(&body_str);
    let title = wide("Allow previously-blocked traffic?");
    let answer = unsafe {
        MessageBoxW(
            hwnd,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
        )
    };
    answer == IDYES
}

/// figure out how to unblock — restores the system to its
/// pre-amwall networking behaviour without uninstalling the app.
fn on_emergency_reset(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO,
    };
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };

    let body = wide(
        "Emergency reset will:\n\
         \n\
         \u{2022} Remove every WFP filter amwall has installed\n\
         \u{2022} Empty the Apps Profile and User rules lists\n\
         \u{2022} Turn off Enable filters\n\
         \n\
         Use this if amwall is blocking something you can't \
         identify and you need to restore the OS-default \
         networking behaviour. The change is immediate. Continue?",
    );
    let title = wide("Emergency WFP reset");
    let answer = unsafe {
        MessageBoxW(
            hwnd,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        )
    };
    if answer != IDYES {
        return;
    }

    // 1. Tear down every filter, sublayer, and the provider
    //    itself. cleanup_provider is best-effort: it succeeds
    //    even if the provider was already gone (e.g. the user
    //    already disabled filters).
    if let Ok(engine) = crate::wfp::WfpEngine::open() {
        if let Err(e) = engine.cleanup_provider(&crate::install::PROVIDER_KEY) {
            eprintln!("amwall: emergency reset: cleanup_provider failed: {e:?}");
        }
    } else {
        eprintln!("amwall: emergency reset: WFP engine open failed (skipping cleanup)");
    }

    // 2. Empty the in-memory profile + persist.
    {
        let mut profile = state.app.profile.borrow_mut();
        profile.apps.clear();
        profile.custom_rules.clear();
        profile.rule_configs.clear();
    }
    save_profile_to_disk(state);

    // 3. Reflect the disabled state on the toolbar + caches.
    state.filters_active.set(false);
    update_enable_filters_button(state, false);
    update_titlebar_icon(hwnd, false);
    state.amwall_filter_ids.borrow_mut().clear();
    *state.categorized_filter_ids.borrow_mut() =
        crate::install::CategorizedFilterIds::default();

    // 4. Repaint the affected tabs.
    populate_apps_tab(state);
    populate_user_rules(state);
    on_tab_change(hwnd);

    set_status_text(state.status.get(), 0, "Emergency reset complete.");
    set_status_text(state.status.get(), 1, "");
}

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
        // LVS_SHAREIMAGELISTS so the listview doesn't ImageList_Destroy
        // the shell's global system imagelist when it goes away —
        // we attach that imagelist for per-row exe icons and we
        // don't own it.
        let style = WS_CHILD
            | WS_BORDER
            | WINDOW_STYLE(LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS);
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
            add_column(lv, 2, "Path", scale_dpi(APPS_COL_WIDTHS[2], dpi), false)?;

            // Attach the system small-icon imagelist so per-row
            // LVITEMW.iImage indices resolve to whatever icon the
            // shell would draw for that exe in Explorer. Free —
            // we never own the imagelist, so no destroy needed.
            let il = super::app_icons::system_small_imagelist();
            if il != HIMAGELIST::default() {
                unsafe {
                    SendMessageW(
                        lv,
                        LVM_SETIMAGELIST,
                        WPARAM(LVSIL_SMALL as usize),
                        LPARAM(il.0),
                    );
                }
            } else {
                eprintln!(
                    "amwall: system small-icon imagelist unavailable; \
                     listview id {id} won't show per-row icons"
                );
            }
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

/// Snapshot of a listview's scroll position. Captured before a
/// delete-all/refill cycle so [`end_listview_refill`] can put the
/// user back where they were.
#[derive(Debug, Clone, Copy)]
struct SavedScroll {
    top: i32,
    count_per_page: i32,
}

/// Pair with [`end_listview_refill`]. Snapshots the current
/// scroll position, freezes paints (`WM_SETREDRAW(0)`), and
/// wipes the listview. Used by every populator that does a
/// bulk delete-all / re-insert — without the pair, the auto-
/// refresh timers (Connections every 1.5 s, Log every drain
/// tick) yank the user back to row 0 and they can't read past
/// the first page.
fn begin_listview_refill(lv: HWND) -> SavedScroll {
    let top = unsafe {
        SendMessageW(lv, LVM_GETTOPINDEX, WPARAM(0), LPARAM(0))
    }
    .0 as i32;
    let count_per_page = unsafe {
        SendMessageW(lv, LVM_GETCOUNTPERPAGE, WPARAM(0), LPARAM(0))
    }
    .0 as i32;
    unsafe {
        let _ = SendMessageW(lv, WM_SETREDRAW, WPARAM(0), LPARAM(0));
        let _ = SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }
    SavedScroll { top, count_per_page }
}

/// Pair with [`begin_listview_refill`]. Restores the saved
/// scroll position, re-enables paints, and forces a single
/// invalidate so the deferred redraw fires once. `new_count` is
/// how many rows the populator actually inserted — needed to
/// clamp `saved.top` if the list shrank (e.g. a connection
/// closed) so we don't try to scroll past the new end. The
/// two-step ENSUREVISIBLE (last-visible-of-old-view first, then
/// `saved.top`) is the canonical comctl idiom for "put `top`
/// back at the top of the visible area."
fn end_listview_refill(lv: HWND, saved: SavedScroll, new_count: i32) {
    if saved.top > 0 && new_count > 0 {
        let bottom = (saved.top + saved.count_per_page - 1).min(new_count - 1);
        unsafe {
            let _ = SendMessageW(lv, LVM_ENSUREVISIBLE, WPARAM(bottom as usize), LPARAM(1));
            let _ = SendMessageW(lv, LVM_ENSUREVISIBLE, WPARAM(saved.top as usize), LPARAM(1));
        }
    }
    unsafe {
        let _ = SendMessageW(lv, WM_SETREDRAW, WPARAM(1), LPARAM(0));
        let _ = windows::Win32::Graphics::Gdi::InvalidateRect(lv, None, false);
    }
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

    let saved = begin_listview_refill(lv);

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
    end_listview_refill(lv, saved, row);
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

    // Refresh the active-connections cache so the row colorizer
    // can paint pink for "talking right now" without an
    // O(rows) IP Helper walk per paint.
    refresh_connected_paths(state);

    // Enqueue every File-kind app path for background
    // WinVerifyTrust verification. The worker dedups against
    // the shared cache, so re-enqueueing is cheap. Paths land
    // green-if-signed on the next repaint after the worker
    // posts WM_USER_SIGNED_REFRESH.
    if let Some(tx) = state.signed_tx.borrow().as_ref() {
        let profile = state.app.profile.borrow();
        for app in profile.apps.iter() {
            if app.kind() == crate::profile::AppKind::File {
                let _ = tx.send(app.path.clone());
            }
        }
    }

    let saved = begin_listview_refill(lv);

    let profile = state.app.profile.borrow();
    let filenames_only = state.app.settings.borrow().show_filenames_only;
    let filter = state.search_text.borrow().clone();

    // Sort the iteration order per the user's last column-click
    // (default: Added desc, so most recent activity surfaces at
    // the top of each group). The `iGroupId` we stamp per item
    // still drives Win32 group bucketing — the sort just picks
    // ordering within each group.
    let sort = state.apps_sort.get();
    let mut indexed: Vec<(usize, &crate::profile::App)> =
        profile.apps.iter().enumerate().collect();
    indexed.sort_by(|a, b| {
        let cmp = match sort.column {
            0 => a.1.path.cmp(&b.1.path),
            // 1 (and any other column) sorts by timestamp.
            _ => a.1.timestamp.cmp(&b.1.timestamp),
        };
        if sort.ascending { cmp } else { cmp.reverse() }
    });

    let mut row = 0i32;
    for (orig_idx, app) in indexed {
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
        // Per-row iImage index into the system small-icon
        // imagelist that configure_listview attached. `-1` =
        // shell couldn't resolve the path; we drop LVIF_IMAGE
        // from the mask in that case so comctl32 doesn't fire
        // LVN_GETDISPINFO callbacks asking us to fill it in.
        let icon_idx = state.app_icon_cache.index_for(&app.path);
        let mut item_mask = LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM;
        if icon_idx >= 0 {
            item_mask |= LVIF_IMAGE;
        }
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
            mask: item_mask,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image_index << 12),
            iGroupId: super::listview_groups::app_group_id(app),
            iImage: icon_idx.max(0),
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
        // Column 2: full path (independent of `show_filenames_only`,
        // which only controls the Name column).
        set_subitem(lv, idx as i32, 2, &app.path.display().to_string());
    }
    drop(profile);
    refresh_apps_group_headers(lv);
    end_listview_refill(lv, saved, row);
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
    refresh_connected_paths(state);
    let saved = begin_listview_refill(lv);

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

        // Look up the icon for the service's resolved binary
        // path; -1 (no icon) is common here for driver-only
        // services where image_path is empty.
        let icon_idx = if svc.image_path.as_os_str().is_empty() {
            -1
        } else {
            state.app_icon_cache.index_for(&svc.image_path)
        };
        let mut item_mask = LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM;
        if icon_idx >= 0 {
            item_mask |= LVIF_IMAGE;
        }
        let item = LVITEMW {
            mask: item_mask,
            iItem: i,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            iGroupId: group_id,
            iImage: icon_idx.max(0),
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
        // Path column shows the resolved binary path (svchost.exe
        // host or the standalone exe), or empty when QueryServiceConfig
        // couldn't resolve one (e.g. driver-only services).
        let path_str = svc.image_path.display().to_string();
        if !path_str.is_empty() {
            set_subitem(lv, i, 2, &path_str);
        }
    }
    drop(profile);
    drop(services);
    refresh_apps_group_headers(lv);
    end_listview_refill(lv, saved, row);
}

/// Populate the Apps → UWP tab from the cached registry walk
/// (`state.uwp_packages`). One row per installed packaged app.
fn populate_uwp_tab(state: &WndState) {
    let lv = state.listviews[2].get();
    if lv.0 == 0 {
        return;
    }
    let saved = begin_listview_refill(lv);

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
        // Pull the icon off the package's install directory.
        // Most UWP packages ship a square logo .png; the shell
        // resolves that into a small icon for us.
        let icon_idx = if pkg.install_path.as_os_str().is_empty() {
            -1
        } else {
            state.app_icon_cache.index_for(&pkg.install_path)
        };
        let mut item_mask = LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM;
        if icon_idx >= 0 {
            item_mask |= LVIF_IMAGE;
        }
        let item = LVITEMW {
            mask: item_mask,
            iItem: i,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(1u32 << 12),
            // UWP packages have no path-based App match yet, so
            // they uniformly land in Blocked (default-deny).
            iGroupId: super::listview_groups::GROUP_APP_BLOCKED,
            iImage: icon_idx.max(0),
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
        // Path column for UWP shows the package install location
        // (`C:\Program Files\WindowsApps\<package>...`).
        let path_str = pkg.install_path.display().to_string();
        if !path_str.is_empty() {
            set_subitem(lv, i, 2, &path_str);
        }
    }
    drop(packages);
    refresh_apps_group_headers(lv);
    end_listview_refill(lv, saved, row);
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

    let saved = begin_listview_refill(lv);
    let filter = state.search_text.borrow().clone();
    let resolve = state.app.settings.borrow().use_network_resolution;
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
        // Host(Source) — only filled when reverse DNS is on and
        // the cache already has a hit. Misses enqueue a lookup.
        let local_host = lookup_or_enqueue(state, c.local.ip, resolve);
        set_subitem(lv, idx as i32, 2, &local_host);
        set_subitem(lv, idx as i32, 3, &c.local.port.to_string());
        let remote_addr = if c.remote.ip.is_unspecified() {
            String::new()
        } else {
            c.remote.ip.to_string()
        };
        set_subitem(lv, idx as i32, 4, &remote_addr);
        let remote_host = if c.remote.ip.is_unspecified() {
            String::new()
        } else {
            lookup_or_enqueue(state, c.remote.ip, resolve)
        };
        set_subitem(lv, idx as i32, 5, &remote_host);
        let remote_port = if c.remote.port == 0 {
            String::new()
        } else {
            c.remote.port.to_string()
        };
        set_subitem(lv, idx as i32, 6, &remote_port);
        set_subitem(lv, idx as i32, 7, c.protocol.label());
        set_subitem(lv, idx as i32, 8, c.state);
    }
    end_listview_refill(lv, saved, row);
}

/// Hostname-or-empty for one IP. When `resolve` is false we don't
/// even consult the cache (so the Host columns stay blank just
/// like they did pre-Phase-G). On hit, returns the cached
/// hostname or empty for "queried, no PTR record". On miss,
/// enqueues the IP for the worker and returns empty so the row
/// renders immediately; a WM_USER_DNS_REFRESH will repopulate
/// once resolution lands.
///
/// Skips loopback / unspecified / multicast IPs — looking those
/// up just wastes worker cycles since they have no meaningful
/// PTR record to surface.
fn lookup_or_enqueue(
    state: &WndState,
    ip: std::net::IpAddr,
    resolve: bool,
) -> String {
    if !resolve {
        return String::new();
    }
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return String::new();
    }
    if let Ok(g) = state.dns_cache.lock() {
        if let Some(entry) = g.get(&ip) {
            return entry.clone().unwrap_or_default();
        }
    }
    if let Some(tx) = state.dns_tx.borrow().as_ref() {
        let _ = tx.send(ip);
    }
    String::new()
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
    let saved = begin_listview_refill(lv);
    let log = state.event_log.borrow();
    let filter = state.search_text.borrow().clone();
    let resolve = state.app.settings.borrow().use_network_resolution;

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
        // Host source: DNS cache hit → render hostname; miss
        // enqueues an async lookup and a later WM_USER_DNS_REFRESH
        // re-runs this populator.
        let local_host = details
            .local_addr
            .map(|a| lookup_or_enqueue(state, a, resolve))
            .unwrap_or_default();
        set_subitem(lv, i, 4, &local_host);
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
        let remote_host = details
            .remote_addr
            .map(|a| lookup_or_enqueue(state, a, resolve))
            .unwrap_or_default();
        set_subitem(lv, i, 7, &remote_host);
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
    end_listview_refill(lv, saved, row);
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

    let saved = begin_listview_refill(lv);

    let rules: &[Rule] = match id {
        IDC_RULES_BLOCKLIST => &state.app.internal_profile.blocklist_rules,
        IDC_RULES_SYSTEM => &state.app.internal_profile.system_rules,
        _ => {
            end_listview_refill(lv, saved, 0);
            return;
        }
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
    end_listview_refill(lv, saved, row);
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

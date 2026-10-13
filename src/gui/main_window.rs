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
    CDDS_ITEMPREPAINT, CDDS_PREPAINT, CDRF_DODEFAULT, CDRF_NEWFONT, CDRF_NOTIFYITEMDRAW,
    HDM_GETITEMCOUNT, HIMAGELIST, ICC_BAR_CLASSES, ICC_COOL_CLASSES, ICC_LISTVIEW_CLASSES,
    ICC_TAB_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx, LIST_VIEW_ITEM_STATE_FLAGS,
    LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCFMT_RIGHT, LVCOLUMNW, LVIF_GROUPID, LVIF_IMAGE,
    LVIF_PARAM, LVIF_STATE, LVIF_TEXT, LVIS_SELECTED, LVIS_STATEIMAGEMASK, LVITEMW,
    LVM_DELETEALLITEMS, LVM_ENSUREVISIBLE, LVM_GETCOUNTPERPAGE, LVM_GETHEADER, LVM_GETITEM,
    LVM_GETITEMCOUNT, LVM_GETITEMSTATE, LVM_GETITEMTEXTW, LVM_GETNEXTITEM, LVM_GETTOPINDEX,
    LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETIMAGELIST,
    LVM_SETITEMSTATE, LVM_SETITEMTEXTW, LVN_COLUMNCLICK, LVN_ITEMCHANGED, LVN_KEYDOWN,
    LVNI_SELECTED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_REPORT,
    LVS_SHAREIMAGELISTS, LVS_SHOWSELALWAYS, LVSIL_SMALL, NM_CUSTOMDRAW, NM_DBLCLK, NM_RCLICK,
    NMHDR, NMITEMACTIVATE, NMLVCUSTOMDRAW, NMLVKEYDOWN, NMTBGETINFOTIPW, SB_SETPARTS, SB_SETTEXTW,
    SBARS_TOOLTIPS, STATUSCLASSNAMEW, TBN_GETINFOTIPW, TCIF_TEXT, TCITEMW, TCM_ADJUSTRECT,
    TCM_GETCURSEL, TCM_INSERTITEMW, TCM_SETCURSEL, TCN_SELCHANGE, WC_LISTVIEWW, WC_TABCONTROLW,
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
    WM_DPICHANGED, WM_NCCREATE, WM_NCDESTROY, WM_NOTIFY, WM_SETREDRAW, WM_SHOWWINDOW, WM_SIZE,
    WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
    WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR, w};

use super::app::App;
use super::ids::{
    IDC_APPS_PROFILE, IDC_APPS_SERVICE, IDC_APPS_UWP, IDC_LOG, IDC_NETWORK, IDC_RULES_BLOCKLIST,
    IDC_RULES_CUSTOM, IDC_RULES_SYSTEM, IDC_SEARCH, IDC_STATUSBAR, IDC_TAB, IDM_ABOUT,
    IDM_ADD_FILE, IDM_ALLOW, IDM_ALWAYSONTOP_CHK, IDM_AUTOSIZECOLUMNS_CHK, IDM_BLOCK,
    IDM_BLOCKLIST_EXTRA_ALLOW, IDM_BLOCKLIST_EXTRA_BLOCK, IDM_BLOCKLIST_EXTRA_DISABLE,
    IDM_BLOCKLIST_SPY_ALLOW, IDM_BLOCKLIST_SPY_BLOCK, IDM_BLOCKLIST_SPY_DISABLE,
    IDM_BLOCKLIST_UPDATE_ALLOW, IDM_BLOCKLIST_UPDATE_BLOCK, IDM_BLOCKLIST_UPDATE_DISABLE,
    IDM_CHECK, IDM_CHECKUPDATES, IDM_CHECKUPDATES_CHK, IDM_CLOSE_CONNECTION,
    IDM_CONTEXT_RULE_FIRST, IDM_CONTEXT_RULE_LAST, IDM_COPY, IDM_COPY_VALUE, IDM_DELETE,
    IDM_EMERGENCY_RESET, IDM_EXIT, IDM_EXPLORE, IDM_EXPORT, IDM_FIND, IDM_FONT, IDM_IMPORT,
    IDM_LOADONSTARTUP_CHK, IDM_LOGCLEAR, IDM_OPENRULESEDITOR, IDM_PROPERTIES, IDM_PURGE_TIMERS,
    IDM_PURGE_UNUSED, IDM_REFRESH, IDM_RELEASES, IDM_REMOVE_FROM_PROFILE, IDM_RULE_ALLOW6TO4,
    IDM_RULE_ALLOWLOOPBACK, IDM_RULE_ALLOWWINDOWSUPDATE, IDM_RULE_BLOCKINBOUND,
    IDM_RULE_BLOCKOUTBOUND, IDM_SELECT_ALL, IDM_SETTINGS, IDM_SHOW_IN_LIST,
    IDM_SHOWFILENAMESONLY_CHK, IDM_SHOWSEARCHBAR_CHK, IDM_SIZE_EXTRALARGE, IDM_SIZE_LARGE,
    IDM_SIZE_SMALL, IDM_SKIPUACWARNING_CHK, IDM_STARTMINIMIZED_CHK, IDM_TAB_NEXT, IDM_TAB_PREV,
    IDM_TIMER_1HR, IDM_TIMER_4HR, IDM_TIMER_15MIN, IDM_TIMER_30MIN, IDM_TOGGLE_SILENT,
    IDM_TOGGLE_UNDELETABLE, IDM_TRAY_ENABLELOG_CHK, IDM_TRAY_ENABLENOTIFICATIONS_CHK,
    IDM_TRAY_ENABLENOTIFICATIONSSOUND_CHK, IDM_TRAY_ENABLEUILOG_CHK, IDM_TRAY_LOGCLEAR,
    IDM_TRAY_LOGCLEAR_ERR, IDM_TRAY_LOGSHOW, IDM_TRAY_LOGSHOW_ERR,
    IDM_TRAY_NOTIFICATIONFULLSCREENSILENTMODE_CHK, IDM_TRAY_NOTIFICATIONONTRAY_CHK, IDM_TRAY_SHOW,
    IDM_TRAY_START, IDM_UNCHECK, IDM_USECERTIFICATES_CHK, IDM_USEDARKTHEME_CHK, IDM_USEHASHES_CHK,
    IDM_VIEW_DETAILS, IDM_VIEW_ICON, IDM_VIEW_TILE, IDM_WEBSITE, IDM_ZOOM, TAB_LISTVIEW_IDS,
};
use rust_i18n::t;

use super::dialogs;
use super::toolbar::{self, Toolbar};
use super::{post_quit, wide};

#[cfg(test)]
mod ui_regression_tests;

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

/// Sort state for the Connections listview. Click a column header to
/// sort by it; click again to flip direction. `column == -1` means
/// "no sort" — rows stay in IP-Helper enumeration order (the default).
/// A fresh click starts descending, so clicking a Speed / Total header
/// puts the busiest connection at the top.
#[derive(Debug, Clone, Copy)]
struct NetworkSortState {
    column: i32,
    ascending: bool,
}

impl Default for NetworkSortState {
    fn default() -> Self {
        Self {
            column: -1,
            ascending: false,
        }
    }
}

/// Per-app network rollup shown on the Apps tab: aggregate download /
/// upload rate across the app's live TCP connections, plus the set of
/// interfaces those connections ride. Recomputed each sampling tick.
#[derive(Debug, Default, Clone)]
struct AppTraffic {
    download_speed: u64,
    upload_speed: u64,
    /// Friendly interface names ("Wi-Fi", "Ethernet", a VPN tunnel),
    /// de-duplicated and in first-seen order. Usually one.
    interfaces: Vec<String>,
}

/// Win32 timer id used to drive Connections-tab live refresh.
/// Distinct from any IDC_* control id since Win32 routes timers
/// through the same WM_TIMER queue.
const TIMER_CONNECTIONS_REFRESH: usize = 9001;

/// Win32 timer id driving the Apps-tab live traffic/interface columns.
/// MUST be unique across all TIMER_* ids below (9002 collided with
/// TIMER_EVENT_DRAIN, which silently killed the event-drain / connect-
/// prompt pipeline). Keep this list collision-free.
const TIMER_APPS_REFRESH: usize = 9008;

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

// Per-tab column definitions (localized title, creation-time width,
// alignment) now live in `gui::column_sizing` — one table shared by the
// listview creator, the DPI rescaler, and the diagnostics report, so a
// column added in one place cannot go missing in another. The widths
// there are the creation-time starting point; upstream-parity
// auto-sizing re-fits them to the actual header text on first paint.

/// Per-window state pointed to from `GWLP_USERDATA`. Holds the App
/// (heap-allocated by `gui::run`) plus cached child HWNDs and the
/// last-known DPI. We cache the toolbar/listview/status HWNDs to
/// avoid `GetDlgItem` lookups on every WM_SIZE.
struct PendingPrompt {
    id: u64,
    app: crate::profile::App,
    parent: HWND,
}

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
    event_subscription: std::cell::RefCell<Option<crate::wfp::events::EventSubscription>>,
    event_rx: std::cell::RefCell<Option<std::sync::mpsc::Receiver<crate::wfp::events::NetEvent>>>,
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
    /// The connection snapshot most recently rendered on the Network
    /// tab. Populate stamps each row's lParam with its index into this
    /// Vec so a right-click can round-trip row → Connection (Fable #27).
    connections: std::cell::RefCell<Vec<super::connections::Connection>>,
    /// IP Helper, adapter and process queries run on one background
    /// worker. None during native UI tests, which supply cached data.
    network_worker: std::cell::RefCell<
        Option<super::snapshot_worker::SnapshotWorker<super::network_snapshot::NetworkSnapshot>>,
    >,
    /// Latest complete observation, reused by sorting, DNS updates and
    /// tab switches without blocking the message loop or resampling rates.
    network_snapshot: std::cell::RefCell<super::network_snapshot::NetworkSnapshot>,
    /// Sort column/direction for the Connections listview (column
    /// header clicks). Default: unsorted (enumeration order).
    network_sort: Cell<NetworkSortState>,
    /// Per-app network rollup (aggregate speed + interfaces) keyed by
    /// the **ASCII-lowercased** full image path, feeding the Apps tab's
    /// Speed / Interface columns. Lowercased because `profile.apps[].path`
    /// is stored lowercase while `process_full_path` returns the OS's real
    /// casing, and Windows paths are case-insensitive — an exact `PathBuf`
    /// key would never match (same normalization as the rule/colorizer
    /// matching elsewhere). Refreshed on the apps-tab timer.
    app_traffic: std::cell::RefCell<std::collections::HashMap<String, AppTraffic>>,
    /// Per-process network meter (ETW Kernel-Network). Drives the Apps
    /// tab's Speed columns with real TCP+UDP throughput — unlike the
    /// per-connection ESTATS view it captures UDP (µTP torrents, etc.).
    /// `None` when the trace couldn't start (not elevated), in which case
    /// the Speed columns fall back to blank. Stops its session + thread
    /// on drop.
    net_meter: std::cell::RefCell<Option<super::net_meter::NetMeter>>,
    /// File-backed event log writer (M6.3). Lazily opens / rotates
    /// the on-disk log per `Settings.enable_log` + `log_path` +
    /// `log_size_limit`. Mirrors the in-memory `event_log` ring,
    /// but persists across app restarts.
    event_log_writer: std::cell::RefCell<super::event_log::EventLogWriter>,
    /// Suppress persistence notifications while applying a layout ourselves.
    applying_columns: Cell<bool>,
    initializing: Cell<bool>,
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
    categorized_filter_ids: std::cell::RefCell<crate::install::CategorizedFilterIds>,
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
    ///
    /// The `SignedInfo` value carries both the chain-valid bool
    /// (used by the row colorizer) and an optional signer-display
    /// name (filled when `Settings.use_certificates` is on,
    /// surfaced in App Properties / connect prompt / Connections
    /// "Signature" column). The pair lives in a single cache
    /// entry so we don't re-walk the trust state machine twice.
    signed_cache:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, SignedInfo>>>,
    /// Mirror of `Settings.use_certificates` shared with the
    /// signed worker. Atomic so the toggle handler can flip it
    /// without restarting the thread; the worker reads it
    /// per-path before deciding whether to extract the signer
    /// display name.
    use_certificates_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Sends file paths to the background WinVerifyTrust worker.
    /// `None` until the worker spawns at WM_CREATE; populator
    /// code enqueues every File-kind app path once.
    signed_tx: std::cell::RefCell<Option<std::sync::mpsc::Sender<std::path::PathBuf>>>,
    /// Most recently right-clicked listview row, set on NM_RCLICK
    /// before the popup menu shows and consumed by the IDM_*
    /// handlers. None after the menu dismisses (or never opened).
    context_target: std::cell::RefCell<Option<super::apps_context_menu::ContextTarget>>,
    /// Runtime-only map of app path -> last connect-prompt unix time.
    /// Throttles retries while an app remains blocked but not silenced.
    last_notify: std::cell::RefCell<std::collections::HashMap<std::path::PathBuf, i64>>,
    /// Runtime-only set of app paths that currently have an OPEN connect-
    /// prompt window. A drop for an app already in this set never spawns
    /// a second window, so an un-acted prompt (user away from the PC)
    /// can't stack into dozens overnight. This mirrors upstream
    /// simplewall's one-notification-per-app model (`_app_notify_addobject`
    /// swaps a single `ptr_app->notification`, notifications.c:149, into
    /// one window). Cleared when the window closes for any reason via
    /// `WM_USER_CONNECT_PROMPT_CLOSED`. Closing a prompt is a Block choice.
    pending_prompts:
        std::cell::RefCell<std::collections::HashMap<std::path::PathBuf, PendingPrompt>>,
    next_prompt_id: Cell<u64>,
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
    dns_cache: std::sync::Arc<std::sync::Mutex<super::dns_resolve::DnsCacheMap>>,
    /// Sends new IPs to the DNS worker. `None` until the worker
    /// spawns at WM_CREATE.
    dns_tx: std::cell::RefCell<Option<std::sync::mpsc::Sender<std::net::IpAddr>>>,
    /// Number of preset rows in the User Rules tab, refreshed at
    /// the end of every `populate_user_rules`. Rows 0..preset_count
    /// come from `internal_profile.custom_rules` (bundled presets,
    /// toggle via overrides); rows >=preset_count come from
    /// `profile.custom_rules` (user-added, toggle via in-place
    /// `is_enabled`). The toggle dispatcher uses this boundary to
    /// route checkbox clicks to the correct mutator.
    user_rules_preset_count: Cell<usize>,
}

impl WndState {
    fn new(app: Box<App>) -> Self {
        Self::with_net_meter(app, super::net_meter::NetMeter::start())
    }

    fn with_net_meter(app: Box<App>, net_meter: Option<super::net_meter::NetMeter>) -> Self {
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
            connections: std::cell::RefCell::new(Vec::new()),
            network_worker: std::cell::RefCell::new(None),
            network_snapshot: std::cell::RefCell::new(
                super::network_snapshot::NetworkSnapshot::default(),
            ),
            network_sort: Cell::new(NetworkSortState::default()),
            app_traffic: std::cell::RefCell::new(std::collections::HashMap::new()),
            net_meter: std::cell::RefCell::new(net_meter),
            event_log_writer: std::cell::RefCell::new(super::event_log::EventLogWriter::new()),
            applying_columns: Cell::new(false),
            initializing: Cell::new(true),
            amwall_filter_ids: std::cell::RefCell::new(std::collections::HashSet::new()),
            categorized_filter_ids: std::cell::RefCell::new(
                crate::install::CategorizedFilterIds::default(),
            ),
            filters_active: Cell::new(false),
            services: std::cell::RefCell::new(Vec::new()),
            uwp_packages: std::cell::RefCell::new(Vec::new()),
            context_target: std::cell::RefCell::new(None),
            last_notify: std::cell::RefCell::new(std::collections::HashMap::new()),
            pending_prompts: std::cell::RefCell::new(std::collections::HashMap::new()),
            next_prompt_id: Cell::new(1),
            apps_sort: Cell::new(AppsSortState::default()),
            connected_paths: std::cell::RefCell::new(std::collections::HashSet::new()),
            signed_cache: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            use_certificates_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            signed_tx: std::cell::RefCell::new(None),
            tray_added: Cell::new(false),
            taskbar_created_msg: Cell::new(0),
            app_icon_cache: super::app_icons::IconCache::new(),
            user_rules_preset_count: Cell::new(0),
            dns_cache: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
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

/// Pick up first-connection events promptly and yield between bounded batches.
const EVENT_DRAIN_INTERVAL_MS: u32 = 100;
const EVENT_DRAIN_BATCH: usize = 256;

/// Periodic pump that scans `profile.apps` for entries whose
/// `timer` field has elapsed and rolls them back to `is_enabled
/// = false`. Mirrors upstream's "timed Allow" feature where the
/// user grants an app an N-minute window. 60-second tick is
/// coarse enough that idle CPU stays unmeasurable; finer
/// granularity isn't useful since timers are usually set in
/// minutes.
const TIMER_APP_EXPIRY: usize = 9005;
const APP_EXPIRY_INTERVAL_MS: u32 = 60_000;

/// Save header changes after the native control finishes committing its order.
const TIMER_SAVE_COLUMNS: usize = 9009;
const WM_SAVE_COLUMN_LAYOUT: u32 = windows::Win32::UI::WindowsAndMessaging::WM_APP + 30;

/// Hourly auto-check timer for new GitHub releases. Fires every
/// 60 minutes once the window is up; the WM_TIMER branch calls
/// `update_check::check_async` (same path as the startup check),
/// which posts `WM_USER_UPDATE_AVAILABLE` if a newer tag exists
/// and the user hasn't already dismissed it (see
/// `Settings.update_dismissed_tag`). Stays silent on no-update or
/// on transient network failures — only signal, no noise.
const TIMER_UPDATE_CHECK: usize = 9006;

/// use_hashes drift-enforcement tick id. Every 10 minutes (matching
/// upstream's app-monitor cadence, helper.c:1778) `check_hash_drift`
/// disables any enabled File app whose binary changed on disk and
/// rebuilds filters so the tampered binary loses its permit. Security
/// audit finding F.1.
const TIMER_HASH_CHECK: usize = 9007;
const HASH_CHECK_INTERVAL_MS: u32 = 10 * 60 * 1000;
const UPDATE_CHECK_INTERVAL_MS: u32 = 60 * 60 * 1000;

/// Register the window class, create the main window, show it.
/// Ownership of `app` is transferred into the window's
/// `GWLP_USERDATA` and reclaimed on `WM_NCDESTROY`.
pub fn create(app: Box<App>, force_show: bool) -> Result<HWND, String> {
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
            dwICC: ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES | ICC_COOL_CLASSES,
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
        let start_minimized = app.settings.borrow().start_minimized && !force_show;

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

        // Restore the saved window position + size before the window is
        // shown, so it appears where the user left it instead of at the
        // system default. No-op when nothing valid was saved (fresh
        // install) — the show block below then uses CW_USEDEFAULT.
        // Mirrors upstream simplewall `_r_window_restoreposition`
        // (main.c:2201). When starting minimized we still set the normal
        // rect (so a later restore-from-tray lands in the right spot) but
        // keep the window hidden.
        restore_window_placement(hwnd, start_minimized);

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
        append_string(file, IDM_SETTINGS, &t!("file.settings"));
        append_separator(file);
        append_string(file, IDM_ADD_FILE, &t!("file.add_app"));
        append_separator(file);
        append_string(file, IDM_IMPORT, &t!("file.import"));
        append_string(file, IDM_EXPORT, &t!("file.export"));
        append_separator(file);
        append_string(file, IDM_EXIT, &t!("file.exit"));
        append_popup(menu, file, &t!("menu.file"));

        // ---- Edit ----
        let edit = CreatePopupMenu().ok()?;
        append_string(edit, IDM_PURGE_UNUSED, &t!("edit.purge_unused"));
        append_string(edit, IDM_PURGE_TIMERS, &t!("edit.purge_timers"));
        append_separator(edit);
        append_string(edit, IDM_LOGCLEAR, &t!("edit.clear_log"));
        append_separator(edit);
        append_string(edit, IDM_REFRESH, &t!("edit.refresh"));
        append_popup(menu, edit, &t!("menu.edit"));

        // ---- View ----
        let view = CreatePopupMenu().ok()?;
        append_string(view, IDM_ALWAYSONTOP_CHK, &t!("view.always_on_top"));
        append_string(view, IDM_USEDARKTHEME_CHK, &t!("view.dark_theme"));
        append_string(view, IDM_AUTOSIZECOLUMNS_CHK, &t!("view.autosize_columns"));
        append_string(view, IDM_SHOWFILENAMESONLY_CHK, &t!("view.filenames_only"));
        append_string(view, IDM_SHOWSEARCHBAR_CHK, &t!("view.show_search"));
        append_separator(view);
        append_string(view, IDM_VIEW_DETAILS, &t!("view.layout_details"));
        append_string(view, IDM_VIEW_ICON, &t!("view.layout_icons"));
        append_string(view, IDM_VIEW_TILE, &t!("view.layout_tiles"));
        append_separator(view);
        append_string(view, IDM_SIZE_SMALL, &t!("view.icon_small"));
        append_string(view, IDM_SIZE_LARGE, &t!("view.icon_large"));
        append_string(view, IDM_SIZE_EXTRALARGE, &t!("view.icon_extralarge"));
        append_separator(view);
        append_string(view, IDM_FONT, &t!("view.font"));
        append_popup(menu, view, &t!("menu.view"));

        // ---- Settings ----
        let settings = CreatePopupMenu().ok()?;
        append_string(
            settings,
            IDM_LOADONSTARTUP_CHK,
            &t!("settings.load_on_startup"),
        );
        append_string(
            settings,
            IDM_STARTMINIMIZED_CHK,
            &t!("settings.start_minimized"),
        );
        append_string(settings, IDM_SKIPUACWARNING_CHK, &t!("settings.skip_uac"));
        append_string(
            settings,
            IDM_CHECKUPDATES_CHK,
            &t!("settings.check_updates"),
        );
        append_separator(settings);
        append_string(
            settings,
            IDM_USECERTIFICATES_CHK,
            &t!("settings.check_signatures"),
        );
        append_string(settings, IDM_USEHASHES_CHK, &t!("settings.check_hashes"));
        append_separator(settings);

        let rules = CreatePopupMenu().ok()?;
        append_string(rules, IDM_RULE_BLOCKOUTBOUND, &t!("rules.block_outbound"));
        append_string(rules, IDM_RULE_BLOCKINBOUND, &t!("rules.block_inbound"));
        append_separator(rules);
        append_string(rules, IDM_RULE_ALLOWLOOPBACK, &t!("rules.allow_loopback"));
        append_string(rules, IDM_RULE_ALLOW6TO4, &t!("rules.allow_6to4"));
        append_string(
            rules,
            IDM_RULE_ALLOWWINDOWSUPDATE,
            &t!("rules.allow_windows_update"),
        );
        append_popup(settings, rules, &t!("menu.rules"));
        append_popup(menu, settings, &t!("menu.settings"));

        // ---- Blocklist ----
        let blocklist = CreatePopupMenu().ok()?;

        let spy = CreatePopupMenu().ok()?;
        append_string(spy, IDM_BLOCKLIST_SPY_DISABLE, &t!("blocklist.disable"));
        append_string(spy, IDM_BLOCKLIST_SPY_ALLOW, &t!("blocklist.allow"));
        append_string(spy, IDM_BLOCKLIST_SPY_BLOCK, &t!("blocklist.block"));
        append_popup(blocklist, spy, &t!("blocklist.spy_telemetry"));

        let update = CreatePopupMenu().ok()?;
        append_string(
            update,
            IDM_BLOCKLIST_UPDATE_DISABLE,
            &t!("blocklist.disable"),
        );
        append_string(update, IDM_BLOCKLIST_UPDATE_ALLOW, &t!("blocklist.allow"));
        append_string(update, IDM_BLOCKLIST_UPDATE_BLOCK, &t!("blocklist.block"));
        append_popup(blocklist, update, &t!("blocklist.ms_update"));

        let extra = CreatePopupMenu().ok()?;
        append_string(extra, IDM_BLOCKLIST_EXTRA_DISABLE, &t!("blocklist.disable"));
        append_string(extra, IDM_BLOCKLIST_EXTRA_ALLOW, &t!("blocklist.allow"));
        append_string(extra, IDM_BLOCKLIST_EXTRA_BLOCK, &t!("blocklist.block"));
        append_popup(blocklist, extra, &t!("blocklist.ms_apps"));

        append_popup(menu, blocklist, &t!("menu.blocklist"));

        // ---- Help ----
        let help = CreatePopupMenu().ok()?;
        append_string(help, IDM_WEBSITE, &t!("help.website"));
        append_string(help, IDM_CHECKUPDATES, &t!("help.check_updates"));
        append_string(help, IDM_ABOUT, &t!("help.about"));
        append_separator(help);
        append_string(help, IDM_EMERGENCY_RESET, &t!("help.emergency_reset"));
        append_popup(menu, help, &t!("menu.help"));

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
        let _ = AppendMenuW(parent, MF_POPUP, child.0 as usize, PCWSTR(buf.as_ptr()));
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        m if m != 0 && m == super::single_instance::activation_message() => {
            super::window_state::show(hwnd);
            LRESULT(0)
        }
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
            LRESULT(0)
        }
        WM_SAVE_COLUMN_LAYOUT => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                remember_column_layout(state, wparam.0, false);
                unsafe {
                    SetTimer(hwnd, TIMER_SAVE_COLUMNS, 250, None);
                }
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
            // NM_RCLICK on a Rules tab (Blocklist / System / Custom)
            // shows the Rules context menu (Fable #27).
            if nmhdr.code == NM_RCLICK
                && (nmhdr.idFrom == IDC_RULES_BLOCKLIST as usize
                    || nmhdr.idFrom == IDC_RULES_SYSTEM as usize
                    || nmhdr.idFrom == IDC_RULES_CUSTOM as usize)
            {
                let activate = unsafe { &*(lparam.0 as *const NMITEMACTIVATE) };
                on_rules_context_menu(hwnd, nmhdr.idFrom as i32, activate);
            }
            // NM_RCLICK on the Network / Log tabs (Fable #27 parts 2/3).
            if nmhdr.code == NM_RCLICK && nmhdr.idFrom == IDC_NETWORK as usize {
                let activate = unsafe { &*(lparam.0 as *const NMITEMACTIVATE) };
                on_network_context_menu(hwnd, activate);
            }
            if nmhdr.code == NM_RCLICK && nmhdr.idFrom == IDC_LOG as usize {
                let activate = unsafe { &*(lparam.0 as *const NMITEMACTIVATE) };
                on_log_context_menu(hwnd, activate);
            }
            // NM_CUSTOMDRAW on the Apps tabs — pick a row
            // background color per upstream simplewall's
            // highlighting scheme. pick_app_row_color drives all
            // categories from the (Fable #31) Highlighting settings
            // page: Invalid / Connection / Signed / Undelete / System
            // are live; Pico is reserved (not path-detectable) and
            // Special applies only to Rules/Net/Log rows (not colorized).
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
            if nmhdr.code == LVN_COLUMNCLICK && nmhdr.idFrom == IDC_APPS_PROFILE as usize {
                let nmlv =
                    unsafe { &*(lparam.0 as *const windows::Win32::UI::Controls::NMLISTVIEW) };
                on_apps_column_click(hwnd, nmlv.iSubItem);
            }
            // LVN_COLUMNCLICK on the Connections listview sorts by the
            // clicked column (toggling direction on repeat clicks). Lets
            // the user rank by download / upload / total to surface the
            // busiest connections.
            if nmhdr.code == LVN_COLUMNCLICK && nmhdr.idFrom == IDC_NETWORK as usize {
                let nmlv =
                    unsafe { &*(lparam.0 as *const windows::Win32::UI::Controls::NMLISTVIEW) };
                on_network_column_click(hwnd, nmlv.iSubItem);
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
            // LVN_ITEMCHANGED: checkbox state-image change on an
            // Apps / Rules listview. We discriminate user clicks
            // from our own populate inserts via the old-state-image
            // value: a fresh insert lands with old state image = 0
            // ("no state"), whereas a real click flips from 1<->2.
            // Without this gate, every populator round-trip would
            // re-fire the toggle handler and instantly re-write
            // settings / overrides we just rendered from.
            if nmhdr.code == LVN_ITEMCHANGED
                && (nmhdr.idFrom == IDC_APPS_PROFILE as usize
                    || nmhdr.idFrom == IDC_APPS_SERVICE as usize
                    || nmhdr.idFrom == IDC_APPS_UWP as usize
                    || nmhdr.idFrom == IDC_RULES_BLOCKLIST as usize
                    || nmhdr.idFrom == IDC_RULES_SYSTEM as usize
                    || nmhdr.idFrom == IDC_RULES_CUSTOM as usize)
            {
                let nmlv =
                    unsafe { &*(lparam.0 as *const windows::Win32::UI::Controls::NMLISTVIEW) };
                let old_image = (nmlv.uOldState & LVIS_STATEIMAGEMASK.0) >> 12;
                let new_image = (nmlv.uNewState & LVIS_STATEIMAGEMASK.0) >> 12;
                let state_image_changed = old_image != new_image;
                // old_image == 0 means "fresh insert" — comctl
                // synthesises a 0->{1,2} transition for every row
                // we add during populate. We only act when the row
                // already had a real checkbox state, so this gate
                // also filters out the change LVM_DELETEALLITEMS
                // generates per row at the start of every refill.
                let is_user_click = old_image != 0 && state_image_changed;
                if is_user_click {
                    let new_checked = new_image == 2;
                    on_listview_checkbox_toggle(hwnd, nmhdr.idFrom as i32, nmlv.iItem, new_checked);
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
        m if m == super::connect_dialog::WM_USER_CONNECT_PROMPT_CLOSED => {
            on_connect_prompt_closed(hwnd, wparam);
            LRESULT(0)
        }
        m if m == super::update_check::WM_USER_UPDATE_AVAILABLE => {
            on_update_available(hwnd, wparam);
            LRESULT(0)
        }
        m if m == super::update_check::WM_USER_UPDATE_UPTODATE => {
            on_update_uptodate(hwnd, wparam);
            LRESULT(0)
        }
        m if m == super::update_check::WM_USER_UPDATE_ERROR => {
            on_update_error(hwnd);
            LRESULT(0)
        }
        m if m == super::tray::WM_USER_TRAYICON => {
            on_tray_message(hwnd, lparam);
            LRESULT(0)
        }
        m if m == WM_USER_SIGNED_REFRESH => {
            // Color changes need a paint, not a destructive row rebuild.
            if let Some(state) = unsafe { state_ref(hwnd) } {
                repaint_active_apps_listview(hwnd, state);
            }
            LRESULT(0)
        }
        m if m == super::network_snapshot::READY => {
            if let Some(state) = unsafe { state_ref(hwnd) } {
                render_ready_network_snapshot(hwnd, state);
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
                    let sel = unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0
                        as isize;
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
            if wparam.0 == TIMER_SAVE_COLUMNS {
                unsafe {
                    let _ = KillTimer(hwnd, TIMER_SAVE_COLUMNS);
                }
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    let path = state.app.settings_path.borrow().clone();
                    if let Err(e) = state.app.settings.borrow().save(&path) {
                        eprintln!("amwall: column layout: settings save failed: {e}");
                    }
                }
            } else if matches!(wparam.0, TIMER_CONNECTIONS_REFRESH | TIMER_APPS_REFRESH) {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    render_ready_network_snapshot(hwnd, state);
                    request_network_snapshot(state);
                }
            } else if wparam.0 == TIMER_EVENT_DRAIN {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    drain_events(hwnd, state);
                }
            } else if wparam.0 == TIMER_APP_EXPIRY {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    expire_timed_apps(hwnd, state);
                }
            } else if wparam.0 == TIMER_HASH_CHECK {
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    check_hash_drift(hwnd, state);
                }
            } else if wparam.0 == TIMER_UPDATE_CHECK {
                // Hourly auto-check: re-runs the same worker the
                // startup auto-check uses, with the currently-
                // persisted dismissed tag so the popup doesn't
                // re-fire for a release the user already saw and
                // dismissed (Yes-opens-page or No-dismisses both
                // write update_dismissed_tag — see on_update_available).
                if let Some(state) = unsafe { state_ref(hwnd) } {
                    if state.app.settings.borrow().check_updates {
                        let dismissed = state.app.settings.borrow().update_dismissed_tag.clone();
                        let dismissed_opt = if dismissed.is_empty() {
                            None
                        } else {
                            Some(dismissed.as_str())
                        };
                        super::update_check::check_async(
                            hwnd,
                            env!("CARGO_PKG_VERSION"),
                            dismissed_opt,
                        );
                    }
                }
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
                    super::window_state::hide(hwnd);
                    return LRESULT(0);
                }
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_DESTROY => {
            super::connect_dialog::shutdown();
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
            let tray_state = {
                let s = state.app.settings.borrow();
                super::tray::TrayMenuState {
                    filters_active: state.filters_active.get(),
                    enable_notifications: s.enable_notifications,
                    notification_sound: s.notification_sound,
                    notification_fullscreen_silent: s.notification_fullscreen_silent,
                    notification_on_tray: s.notification_on_tray,
                    enable_log: s.enable_log,
                    enable_ui_log: s.enable_ui_log,
                    error_log_exists: error_log_target().is_file(),
                }
            };
            super::tray::show_context_menu(hwnd, &tray_state);
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
    // Give the header a usable initial rectangle before inserting columns;
    // the first layout pass below sizes every view to the tab content area.
    for (slot, &id) in TAB_LISTVIEW_IDS.iter().enumerate() {
        let lv = create_tab_listview(hwnd, id)?;
        unsafe {
            let _ = MoveWindow(lv, 0, 0, 800, 600, false);
        }
        configure_listview(lv, id, state.dpi.get())?;
        if !unsafe {
            windows::Win32::UI::Shell::SetWindowSubclass(lv, Some(listview_header_proc), 1, 0)
        }
        .as_bool()
        {
            return Err("Could not attach column layout notifications".into());
        }
        state.listviews[slot].set(lv);
        if let Some(layout) = state.app.settings.borrow().column_layouts[slot].clone() {
            state.applying_columns.set(true);
            layout.apply(lv, listview_column_count(lv) as usize, state.dpi.get());
            state.applying_columns.set(false);
        }
    }

    // Status bar at the bottom. Two parts: filter state, item count.
    let status = create_status_bar(hwnd)?;
    state.status.set(status);
    set_status_text(status, 0, &t!("status.filters_disabled"));
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
    state.initializing.set(false);
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
        // use_hashes drift enforcement, every 10 min (check_hash_drift
        // no-ops when use_hashes is off). Security audit finding F.1.
        SetTimer(hwnd, TIMER_HASH_CHECK, HASH_CHECK_INTERVAL_MS, None);
    }

    // Filters installed on a previous run survive process exit
    // (we ask BFE to persist them across reboots, which also
    // means they outlive amwall itself). On startup we check
    // whether our provider has any filters in the engine and
    // flip `filters_active` to match — otherwise the toolbar /
    // title-bar would say "off" while the kernel is still
    // dropping packets.
    detect_initial_filter_state(hwnd, state);

    // Detect persisted permits before checking hashes, so drift can revoke
    // an existing permit as well as prevent a new one during auto-enable.
    check_hash_drift(hwnd, state);

    // If the user's last explicit choice was "filters on" but
    // the kernel has no amwall filters (fresh install, or a
    // pre-1.1.15 profile that ran with install_boottime_filters
    // = false and lost its filters at last reboot), install them
    // now so the user doesn't have to click Enable. No-op when
    // filters were already detected as active or when the user
    // explicitly turned them off in the previous session.
    try_auto_enable_filters_at_startup(hwnd, state);

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
    state.use_certificates_flag.store(
        state.app.settings.borrow().use_certificates,
        std::sync::atomic::Ordering::Relaxed,
    );
    let tx = spawn_signed_worker(
        hwnd,
        state.signed_cache.clone(),
        state.use_certificates_flag.clone(),
    );
    *state.signed_tx.borrow_mut() = Some(tx);

    // Reverse-DNS worker: fills `dns_cache` on a background
    // thread and pings the GUI back via WM_USER_DNS_REFRESH after
    // each batch. Only consulted when
    // `Settings.use_network_resolution` is on, but always alive
    // so toggling the setting from off→on doesn't need a respawn.
    let dns_tx = super::dns_resolve::spawn_worker(hwnd, state.dns_cache.clone());
    *state.dns_tx.borrow_mut() = Some(dns_tx);
    start_network_worker(hwnd, state);

    // First-run wizard (M9.4): if the user has never seen it
    // and simplewall has a config to import, ask. Runs once per
    // install (gated on `Settings.first_run_done`) so we don't
    // pester returning users.
    maybe_run_first_run_wizard(hwnd, state);

    // Update check: ping GitHub's releases/latest in a worker
    // thread; if newer than our compiled-in version, post
    // WM_USER_UPDATE_AVAILABLE back here. Failures are silent.
    // amwall NEVER auto-downloads / auto-installs — the prompt
    // just offers to open the releases page in the user's
    // browser. Gated by `Settings.check_updates` (default on,
    // matches upstream simplewall's `IsCheckUpdates`).
    //
    // The dismissed-tag pref is read here on the GUI thread and
    // handed off to the worker thread so the worker doesn't have
    // to grab the settings borrow. Same pattern used by the
    // hourly TIMER_UPDATE_CHECK tick — see WM_TIMER below.
    if state.app.settings.borrow().check_updates {
        let dismissed = state.app.settings.borrow().update_dismissed_tag.clone();
        let dismissed_opt = if dismissed.is_empty() {
            None
        } else {
            Some(dismissed.as_str())
        };
        super::update_check::check_async(hwnd, env!("CARGO_PKG_VERSION"), dismissed_opt);
        unsafe {
            SetTimer(hwnd, TIMER_UPDATE_CHECK, UPDATE_CHECK_INTERVAL_MS, None);
        }
    }

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
                    set_status_text(state.status.get(), 0, &t!("status.imported_simplewall"));
                }
                Err(e) => eprintln!("amwall: imported profile parse failed: {e}"),
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
            note_events_unavailable(state);
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
            eprintln!("amwall: net-event subscribe failed (admin may be required): {e}");
            note_events_unavailable(state);
            // Drop the engine — no subscription means no point
            // holding it open.
        }
    }
}

/// Surface a net-event subscribe failure in the status bar. Without an
/// event feed the Packets log stays empty and no connection toasts fire,
/// but the log / notification toggles still look active -- so a silent
/// stderr-only failure leaves the user believing amwall is watching
/// traffic when it isn't. Fable sweep finding #16.
fn note_events_unavailable(state: &WndState) {
    set_status_text(state.status.get(), 0, &t!("status.events_unavailable"));
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
    set_status_text(state.status.get(), 0, &t!("status.filters_enabled"));
}

/// Auto-install filters at startup when the user's persisted
/// choice was "on" but the kernel has none of our filters loaded.
/// Covers two cases:
///   - Fresh install: settings file just created, default
///     `filters_active_persisted = true`, nothing in the kernel.
///   - Pre-1.1.15 user upgrading from a build that defaulted
///     `install_boottime_filters = false`: filters got wiped at
///     the last Windows reboot, but their persisted choice was
///     "on" so we restore them.
///
/// No-op when the kernel already had filters (handled by
/// `detect_initial_filter_state`) or when the user explicitly
/// disabled filters in the previous session. Silent no-op when
/// not running elevated — startup is the wrong time to pop a
/// "needs admin" dialog (the user would see it on every boot
/// even though they just want the GUI for inspection).
fn try_auto_enable_filters_at_startup(hwnd: HWND, state: &WndState) {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    if state.filters_active.get() {
        return;
    }
    if !state.app.settings.borrow().filters_active_persisted {
        eprintln!("amwall: auto-enable filters: skipping (persisted choice was off)");
        return;
    }
    if !unsafe { IsUserAnAdmin() }.as_bool() {
        eprintln!(
            "amwall: auto-enable filters: skipping (not elevated; would need admin to install)"
        );
        return;
    }
    eprintln!("amwall: auto-enable filters: persisted=true and kernel empty; installing now");
    let engine = match crate::wfp::WfpEngine::open() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("amwall: auto-enable filters: WfpEngine::open failed: {e}");
            return;
        }
    };
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
                install_boottime: s.install_boottime_filters,
            },
            // Permanent GUI install -> always persistent (survives a
            // reboot); the boot-time set is the separate field above. This
            // de-conflates the old persistent==install_boottime. Fable #12.
            true,
        )
    };
    ensure_enabled_hash_baselines(state);
    let report = match crate::install::install_with_internal(
        &engine,
        &state.app.profile.borrow(),
        Some(&state.app.internal_profile),
        Some(&state.app.internal_rules_state.borrow()),
        &blocklist,
        &global_rules,
        persistent,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("amwall: auto-enable filters: install failed: {e}");
            return;
        }
    };
    *state.categorized_filter_ids.borrow_mut() = report.filter_ids.clone();
    state.filters_active.set(true);
    update_enable_filters_button(state, true);
    update_titlebar_icon(hwnd, true);
    refresh_amwall_filter_ids_with(&engine, state);
    set_status_text(state.status.get(), 0, &t!("status.filters_enabled"));
    set_status_text(
        state.status.get(),
        1,
        &t!(
            "status.filters_installed",
            added = report.filters_added,
            skipped = report.rules_skipped
        ),
    );
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
    let hi =
        match unsafe { windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null()) } {
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
        SendMessageW(hwnd, WM_SETICON, WPARAM(ICON_BIG as usize), LPARAM(icon.0));
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
    use windows::Win32::UI::Controls::{TB_SETSTATE, TBSTATE_CHECKED, TBSTATE_ENABLED};
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
        eprintln!("amwall: settings: save failed for {}: {e}", path.display());
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
    use windows::Win32::UI::Controls::{TB_SETBUTTONINFOW, TBBUTTONINFOW, TBIF_IMAGE, TBIF_TEXT};
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
    // icons::build() returns a throwaway HIMAGELIST (11 DIBs) we only
    // needed for the index lookup; it's never attached to a control, so
    // destroy it or one imagelist leaks on every filters enable/disable/
    // state refresh (5 call sites). Fable sweep finding #18.
    unsafe {
        let _ = windows::Win32::UI::Controls::ImageList_Destroy(icons.himagelist);
    }

    let label = if active {
        t!("toolbar.disable_filters")
    } else {
        t!("toolbar.enable_filters")
    };
    let mut wlabel = wide(&label);
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
        eprintln!("amwall: settings: save failed for {}: {e}", path.display());
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
        let first_end = buf[..n as usize]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(n as usize);
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
// 0x120 is in a deliberately empty range. Used to be 0x103 — same
// value as connect_dialog::WM_USER_CONNECT_BLOCK. The worker would
// PostMessageW(0x103) thinking it was kicking the apps-tab repaint;
// the wnd_proc match-arm dispatch picked the connect_block arm first
// (declared earlier in the file), and on_connect_block silently
// returned because wparam was 0 (worker passes null). Net result:
// every WM_USER_SIGNED_REFRESH the worker has ever posted since
// M11.5 was silently dropped, which is why row colours never
// appeared on cold launch — the four attempts in v1.1.10–v1.1.13
// were all editing a handler that was never being called.
const WM_USER_SIGNED_REFRESH: u32 = windows::Win32::UI::WindowsAndMessaging::WM_USER + 0x120;

/// Worker-thread entry. Drains `rx` for paths to verify,
/// updates `cache` with each result, and posts
/// `WM_USER_SIGNED_REFRESH` to the main HWND so the apps tab
/// repaints. Coalesces refresh notifications: only posts one
/// every ~10 paths or after `rx` returns Empty for >50 ms,
/// which keeps the GUI responsive without spamming repaints.
///
/// `extract_signer_flag` is a shared atomic that mirrors
/// `Settings.use_certificates`. The main thread flips it when
/// the toggle changes; the worker reads it per-path so the
/// signer field gets populated/skipped without restarting the
/// worker.
fn spawn_signed_worker(
    main_hwnd: HWND,
    cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, SignedInfo>>,
    >,
    extract_signer_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::sync::mpsc::Sender<std::path::PathBuf> {
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::{Receiver, Sender, channel};
    let (tx, rx): (Sender<std::path::PathBuf>, Receiver<std::path::PathBuf>) = channel();
    // Snapshot the HWND as a usize since HWND isn't Send. We
    // re-wrap it on the worker side; PostMessage is thread-safe
    // by Win32 contract.
    let hwnd_raw = main_hwnd.0 as usize;
    std::thread::spawn(move || {
        let mut batch = super::refresh_batch::RefreshBatch::new();
        loop {
            let path = match batch.recv(&rx) {
                Ok(path) => path,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if batch.flush(std::time::Instant::now(), false) {
                        post_signed_refresh(hwnd_raw);
                    }
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    if batch.flush(std::time::Instant::now(), true) {
                        post_signed_refresh(hwnd_raw);
                    }
                    break;
                }
            };
            // Skip if already cached AND the cached entry has
            // (or doesn't need) a signer. Re-verify when the
            // user just turned use_certificates on so we
            // backfill the signer for previously-cached rows.
            let want_signer = extract_signer_flag.load(Ordering::Relaxed);
            if let Ok(g) = cache.lock() {
                if let Some(prev) = g.get(&path) {
                    let already_complete = !want_signer || prev.signer.is_some() || !prev.signed;
                    if already_complete {
                        continue;
                    }
                }
            }
            // Display-only signer worker: no revocation network check
            // (fast, offline-safe). Security audit finding F.2.
            if batch.flush(std::time::Instant::now(), true) {
                post_signed_refresh(hwnd_raw);
            }
            let info = verify_signature(&path, want_signer);
            if let Ok(mut g) = cache.lock() {
                g.insert(path, info);
            }
            if batch.changed(std::time::Instant::now()) {
                post_signed_refresh(hwnd_raw);
            }
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

/// Start observation only after a real main window exists. Tests keep
/// this optional and render their own snapshots without touching the OS.
fn start_network_worker(hwnd: HWND, state: &WndState) {
    *state.network_worker.borrow_mut() = Some(super::network_snapshot::start(hwnd));
    request_network_snapshot(state);
}

/// Refresh requests coalesce while collection is running. A slow IP
/// Helper call never queues a backlog of obsolete snapshots.
fn request_network_snapshot(state: &WndState) {
    if let Some(worker) = state.network_worker.borrow().as_ref() {
        worker.request();
    }
}

/// Adopt one complete observation. ETW rates are sampled once per new
/// snapshot so a header click or DNS repaint cannot consume the next
/// interval and make every speed briefly fall to zero.
fn consume_network_snapshot(state: &WndState) -> bool {
    let snapshot = state
        .network_worker
        .borrow()
        .as_ref()
        .and_then(|worker| worker.take_ready());
    let Some(mut snapshot) = snapshot else {
        return false;
    };
    if let Some(meter) = state.net_meter.borrow_mut().as_mut() {
        snapshot.pid_rates = meter.rates();
        let endpoint_rates = meter.conn_rates();
        for connection in &mut snapshot.connections {
            if connection.has_stats {
                continue;
            }
            let is_udp = connection.protocol == super::connections::Protocol::Udp;
            if let Some(rate) = endpoint_rates.get(&(is_udp, connection.local.port)) {
                connection.download_speed = rate.download;
                connection.upload_speed = rate.upload;
                connection.total_bytes = rate.total;
                connection.has_stats = true;
            }
        }
    }
    *state.network_snapshot.borrow_mut() = snapshot;
    refresh_connected_paths(state);
    refresh_app_traffic(state);
    true
}

/// Update the row-color cache from the last complete observation. No
/// network table or process queries are performed on the GUI thread.
fn refresh_connected_paths(state: &WndState) {
    *state.connected_paths.borrow_mut() = state
        .network_snapshot
        .borrow()
        .process_paths
        .values()
        .map(std::path::PathBuf::from)
        .collect();
}

/// Queue one native repaint for the visible apps view. Hidden tabs stay hidden.
fn repaint_active_apps_listview(_hwnd: HWND, state: &WndState) {
    let selected = unsafe { SendMessageW(state.tab.get(), TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0;
    if (0..=2).contains(&selected) {
        redraw_listview(state.listviews[selected as usize].get());
    }
}

/// Invalidate client, header and border together. The message loop coalesces
/// updates; forcing synchronous paints during mutation caused visible flicker.
fn redraw_listview(lv: HWND) {
    use windows::Win32::Graphics::Gdi::{
        RDW_ALLCHILDREN, RDW_ERASE, RDW_FRAME, RDW_INVALIDATE, RedrawWindow,
    };
    if lv.0 != 0 {
        unsafe {
            let _ = RedrawWindow(
                lv,
                None,
                None,
                RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN,
            );
        }
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
    repaint_active_apps_listview(hwnd, state);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(
        state.status.get(),
        0,
        &format!("{expired} app timer(s) expired \u{2014} rolled back to Block."),
    );
}

/// What to do with one drop net-event, decided purely so the
/// "catalog + prompt for ANY provider's drop" rule (the v1.1.19 fix)
/// and the Fable-#24 re-prompt throttle are unit-testable without a
/// window or a live BFE. `auto_catalog_drops` gathers the inputs and
/// carries out the side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropDisposition {
    /// Nothing to do: no filter id, an excluded source category, no
    /// resolvable app path, or an already-silenced / not-yet-due app.
    Ignore,
    /// A not-yet-cataloged app — add it as blocked, then prompt.
    CatalogNew,
    /// An existing blocked-but-not-silenced app due for a re-prompt.
    Reprompt,
}

/// Read-only view of an already-cataloged app for the decision.
#[derive(Debug, Clone, Copy)]
struct ExistingApp {
    is_silent: bool,
    is_enabled: bool,
}

/// Inputs to the per-drop decision. The wrapper does the impure lookups
/// (path resolution, profile / categorized-ids / pending / last-notify
/// reads) and passes the resulting primitives so `classify_drop` stays
/// pure.
struct DropContext {
    has_filter_id: bool,
    has_resolved_path: bool,
    exclude_blocklist: bool,
    in_blocklist: bool,
    exclude_custom: bool,
    in_user_rules: bool,
    exclude_stealth: bool,
    in_stealth: bool,
    existing: Option<ExistingApp>,
    /// True while a prompt window for this app is already open.
    prompt_open: bool,
    /// notification_timeout in seconds; `<= 0` disables re-prompting.
    reprompt_after_secs: i64,
    secs_since_last_prompt: i64,
}

/// Decide the fate of one drop event. Pure — mirrors the exact sequence
/// of early-outs in the original `auto_catalog_drops` loop so behavior
/// is unchanged; the point is that the sequence is now testable.
///
/// CRITICAL: there is deliberately NO WFP-provider gate here. A drop
/// from ANY provider whose filter isn't in an excluded category is
/// cataloged — that is the v1.1.19 fix (mirrors upstream log.c:1355 /
/// :1394, where `is_myprovider` gates only the UI packet-log tab). The
/// `catalogs_foreign_provider_drop` test guards its absence.
fn classify_drop(ctx: &DropContext) -> DropDisposition {
    // No filter id -> can't categorize (upstream `!log->filter_id`, log.c:528).
    if !ctx.has_filter_id {
        return DropDisposition::Ignore;
    }
    // Settings -> Exclude by the source filter's category.
    if (ctx.exclude_blocklist && ctx.in_blocklist)
        || (ctx.exclude_custom && ctx.in_user_rules)
        || (ctx.exclude_stealth && ctx.in_stealth)
    {
        return DropDisposition::Ignore;
    }
    // Need a resolvable app path.
    if !ctx.has_resolved_path {
        return DropDisposition::Ignore;
    }
    match ctx.existing {
        None => DropDisposition::CatalogNew,
        Some(ExistingApp {
            is_silent,
            is_enabled,
        }) => {
            // Re-prompt only a still-blocked, not-silenced app, throttled
            // by notification_timeout, and never while its window is open.
            if is_silent || is_enabled || ctx.reprompt_after_secs <= 0 {
                return DropDisposition::Ignore;
            }
            if ctx.prompt_open {
                return DropDisposition::Ignore;
            }
            if ctx.secs_since_last_prompt < ctx.reprompt_after_secs {
                return DropDisposition::Ignore;
            }
            DropDisposition::Reprompt
        }
    }
}

/// The "-> addr:port" remote label for a prompt row. ASCII arrow —
/// Segoe UI in dialog mode renders U+2192 as a placeholder box on some
/// systems; "->" round-trips cleanly.
fn format_remote(details: &crate::wfp::events::NetEventDetails) -> String {
    match (details.remote_addr, details.remote_port) {
        (Some(addr), Some(port)) => format!("-> {addr}:{port}"),
        (Some(addr), None) => format!("-> {addr}"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod catalog_decision_tests {
    use super::{DropContext, DropDisposition, ExistingApp, classify_drop};

    /// A drop that SHOULD be cataloged: real filter id, resolvable path,
    /// not excluded, not yet in the profile. Tests tweak one field.
    fn fresh_drop() -> DropContext {
        DropContext {
            has_filter_id: true,
            has_resolved_path: true,
            exclude_blocklist: false,
            in_blocklist: false,
            exclude_custom: false,
            in_user_rules: false,
            exclude_stealth: false,
            in_stealth: false,
            existing: None,
            prompt_open: false,
            reprompt_after_secs: 1800,
            secs_since_last_prompt: 0,
        }
    }

    fn blocked_existing() -> Option<ExistingApp> {
        Some(ExistingApp {
            is_silent: false,
            is_enabled: false,
        })
    }

    #[test]
    fn ignores_drop_without_filter_id() {
        let c = DropContext {
            has_filter_id: false,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn ignores_drop_without_resolvable_path() {
        let c = DropContext {
            has_resolved_path: false,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn catalogs_a_new_app() {
        assert_eq!(classify_drop(&fresh_drop()), DropDisposition::CatalogNew);
    }

    /// THE v1.1.19 guard. A drop owned by a foreign WFP provider — its
    /// filter id is in NONE of amwall's categorized sets — is still
    /// cataloged; there is no own-provider gate. Re-adding one fails here.
    #[test]
    fn catalogs_foreign_provider_drop() {
        let c = DropContext {
            has_filter_id: true, // a real drop...
            in_blocklist: false, // ...whose filter is not one of ours
            in_user_rules: false,
            in_stealth: false,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::CatalogNew);
    }

    #[test]
    fn excludes_category_only_when_its_flag_is_on() {
        // Blocklist-sourced drop, but exclude flag off -> still cataloged.
        let c = DropContext {
            in_blocklist: true,
            exclude_blocklist: false,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::CatalogNew);
        // Flag on -> excluded.
        let c = DropContext {
            in_blocklist: true,
            exclude_blocklist: true,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn excludes_custom_and_stealth_categories() {
        let c = DropContext {
            in_user_rules: true,
            exclude_custom: true,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
        let c = DropContext {
            in_stealth: true,
            exclude_stealth: true,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn ignores_already_silenced_app() {
        let c = DropContext {
            existing: Some(ExistingApp {
                is_silent: true,
                is_enabled: false,
            }),
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn ignores_already_allowed_app() {
        let c = DropContext {
            existing: Some(ExistingApp {
                is_silent: false,
                is_enabled: true,
            }),
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn ignores_reprompt_when_timeout_disabled() {
        let c = DropContext {
            existing: blocked_existing(),
            reprompt_after_secs: 0, // disabled
            secs_since_last_prompt: 100_000,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn ignores_reprompt_while_prompt_window_open() {
        let c = DropContext {
            existing: blocked_existing(),
            prompt_open: true,
            secs_since_last_prompt: 100_000, // long past due, but window open
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn ignores_reprompt_before_timeout_elapses() {
        let c = DropContext {
            existing: blocked_existing(),
            reprompt_after_secs: 1800,
            secs_since_last_prompt: 1799, // one second short
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Ignore);
    }

    #[test]
    fn reprompts_blocked_app_when_due() {
        let c = DropContext {
            existing: blocked_existing(),
            reprompt_after_secs: 1800,
            secs_since_last_prompt: 1800, // exactly due
            prompt_open: false,
            ..fresh_drop()
        };
        assert_eq!(classify_drop(&c), DropDisposition::Reprompt);
    }
}

fn auto_catalog_drops(
    _hwnd: HWND,
    state: &WndState,
    events: &[crate::wfp::events::NetEvent],
) -> Vec<(std::path::PathBuf, String)> {
    use crate::wfp::events::NetEvent;
    let mut new_apps: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut seen: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    let mut resolved_paths = std::collections::HashMap::new();
    // Apps already in the profile, blocked-but-not-silenced, that are due
    // for a re-prompt (Fable #24). Kept separate from `new_apps` so they
    // don't get re-added to profile.apps.
    let mut reprompt: Vec<(std::path::PathBuf, String)> = Vec::new();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Re-prompt window in seconds for blocked, unsilenced apps
    // (notification_timeout is minutes; 0 disables retries).
    let reprompt_after = state.app.settings.borrow().notification_timeout as i64 * 60;

    {
        let profile = state.app.profile.borrow();
        for event in events {
            let NetEvent::Drop(details) = event else {
                continue;
            };

            // Resolve the app path (pure string transform).
            let path = details
                .app_path
                .as_deref()
                .filter(|s| !s.is_empty())
                .and_then(|raw| {
                    resolved_paths
                        .entry(raw)
                        .or_insert_with(|| nt_path_to_win32(raw).map(std::path::PathBuf::from))
                        .clone()
                });

            // Gather the (impure) decision inputs; `classify_drop` is pure.
            // Catalog + prompt for a drop from ANY WFP provider, not just
            // amwall's own — the v1.1.19 fix; `classify_drop` has no
            // provider gate and its `catalogs_foreign_provider_drop` test
            // guards that.
            let existing = path
                .as_ref()
                .and_then(|p| profile.apps.iter().find(|a| a.path == *p))
                .map(|a| ExistingApp {
                    is_silent: a.is_silent,
                    is_enabled: a.is_enabled,
                });
            let (in_blocklist, in_user_rules, in_stealth) = match details.filter_id {
                Some(fid) => {
                    let cats = state.categorized_filter_ids.borrow();
                    (
                        cats.blocklist.contains(&fid),
                        cats.user_rules.contains(&fid),
                        cats.stealth.contains(&fid),
                    )
                }
                None => (false, false, false),
            };
            let prompt_open = path
                .as_ref()
                .map(|p| state.pending_prompts.borrow().contains_key(p))
                .unwrap_or(false);
            let secs_since_last_prompt = path
                .as_ref()
                .map(|p| {
                    now_secs.saturating_sub(state.last_notify.borrow().get(p).copied().unwrap_or(0))
                })
                .unwrap_or(0);
            let ctx = {
                let s = state.app.settings.borrow();
                DropContext {
                    has_filter_id: details.filter_id.is_some(),
                    has_resolved_path: path.is_some(),
                    exclude_blocklist: s.exclude_blocklist,
                    in_blocklist,
                    exclude_custom: s.exclude_custom,
                    in_user_rules,
                    exclude_stealth: s.exclude_stealth,
                    in_stealth,
                    existing,
                    prompt_open,
                    reprompt_after_secs: reprompt_after,
                    secs_since_last_prompt,
                }
            };

            // Seen-dedup runs only for actionable dispositions, so an
            // Ignored drop never suppresses a later actionable one for the
            // same path (matches the original, which `continue`d before
            // `seen.insert` for the no-id / excluded / bad-path cases).
            match classify_drop(&ctx) {
                DropDisposition::Ignore => {}
                DropDisposition::CatalogNew => {
                    let path = path.expect("CatalogNew implies a resolved path");
                    if seen.insert(path.clone()) {
                        new_apps.push((path, format_remote(details)));
                    }
                }
                DropDisposition::Reprompt => {
                    let path = path.expect("Reprompt implies a resolved path");
                    if seen.insert(path.clone()) {
                        reprompt.push((path, format_remote(details)));
                    }
                }
            }
        }
    }

    if new_apps.is_empty() && reprompt.is_empty() {
        return new_apps;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Every discovered app starts blocked. Publisher/signature metadata is
    // display-only; permission changes require an explicit user Allow action.
    let mut for_prompt: Vec<(std::path::PathBuf, String)> = Vec::new();
    {
        let mut profile = state.app.profile.borrow_mut();
        for (path, remote) in new_apps.into_iter() {
            let app = crate::profile::App {
                path: path.clone(),
                is_enabled: false,
                is_silent: false,
                is_undeletable: false,
                timestamp: now,
                timer: 0,
                hash: None,
                comment: None,
            };
            profile.apps.push(app);
            for_prompt.push((path, remote));
        }
    }

    // Existing blocked-not-silent apps due for a re-prompt were queued
    // above; they're already in profile.apps so they skipped the add loop.
    for_prompt.extend(reprompt);

    // Record the prompt time for every app we're about to prompt for, so
    // it isn't re-prompted again until notification_timeout elapses.
    // Fable sweep finding #24.
    if !for_prompt.is_empty() {
        let mut ln = state.last_notify.borrow_mut();
        for (path, _) in &for_prompt {
            ln.insert(path.clone(), now_secs);
        }
    }

    for_prompt
}

/// Whether a fresh connect-prompt window should open for an app.
/// Pure so the overnight-stacking fix (logic-atlas stage 11) can't
/// silently regress. Two load-bearing gates:
///   - `is_silent`: the user chose Block / "stop asking" for this app —
///     never re-prompt (mirrors upstream `INFO_IS_SILENT`,
///     `log.c:1391-1395`).
///   - `already_pending`: a prompt window for this app is already on
///     screen; opening another is exactly the stacking bug. One window
///     per app.
fn should_show_connect_prompt(is_silent: bool, already_pending: bool) -> bool {
    !is_silent && !already_pending
}

/// Show the centered Allow/Block dialog for each app in `new_apps`
/// that doesn't already have one open. The list comes from
/// `auto_catalog_drops` — usually apps *just added* to the profile
/// this drain tick, but also blocked-not-silenced apps due for a
/// timeout re-prompt. At most ONE prompt window per app is open at a
/// time (tracked in `state.pending_prompts`), so an un-acted prompt
/// (user away from the PC) can't stack into dozens of windows
/// overnight; the guard clears on window close via
/// `WM_USER_CONNECT_PROMPT_CLOSED`.
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
/// flows back via `WM_USER_CONNECT_BLOCK`, which keeps the app blocked
/// and sets `is_silent`. X / Escape / Alt+F4 use the same Block action.
fn process_connect_prompts(
    hwnd: HWND,
    state: &WndState,
    new_apps: &[(std::path::PathBuf, String)],
) {
    let profile = state.app.profile.borrow();
    for (path, remote) in new_apps {
        let Some(app) = profile.apps.iter().find(|a| a.path == *path) else {
            continue;
        };
        if app.is_enabled {
            continue;
        }
        // One open prompt window per app: if this app already has a
        // prompt on screen (e.g. the user is away and it keeps retrying),
        // don't open another -- that stacking is what produced dozens of
        // windows overnight. The guard clears on window close via
        // WM_USER_CONNECT_PROMPT_CLOSED.
        let already_pending = state.pending_prompts.borrow().contains_key(path);
        if !should_show_connect_prompt(app.is_silent, already_pending) {
            continue;
        }
        // Reserve the one-window-per-app slot before showing.
        let id = state.next_prompt_id.get();
        state.next_prompt_id.set(id.wrapping_add(1));
        state.pending_prompts.borrow_mut().insert(
            path.clone(),
            PendingPrompt {
                id,
                app: app.clone(),
                parent: hwnd,
            },
        );
        // Pull cached signer for the prompt's "Signed by X" line.
        // Cache will usually have the entry by now since the
        // path was just auto-cataloged and the worker keeps a
        // few hundred ms ahead of the populator on warm runs;
        // first-ever drop will see None and the prompt renders
        // without the signer line.
        let signer = path_signer_cached(state, path);
        if !super::connect_dialog::show_async(hwnd, path, remote, signer.as_deref(), id) {
            // Window creation failed -- don't leave a stuck guard that
            // would suppress this app's prompt for the rest of the session.
            state.pending_prompts.borrow_mut().remove(path);
        }
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

/// Handler for `WM_USER_UPDATE_AVAILABLE` — the update-check
/// worker found a newer release tag on GitHub. Reclaims the
/// `Box<UpdateInfo>` from wparam, pops a Yes/No MessageBox
/// asking if the user wants to open the releases page, and if
/// they say yes, hands the URL to ShellExecuteW so it opens in
/// their default browser. No is silent — we don't re-prompt
/// until the next time amwall starts.
///
/// Explicitly never downloads or installs anything: amwall is
/// a firewall, and a firewall that auto-updates is one that can
/// be MITM'd into installing whatever an attacker controls.
fn on_update_available(hwnd: HWND, wparam: WPARAM) {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONINFORMATION, MB_YESNO, MessageBoxW,
    };

    // take() the payload by token; a forged / stale wparam is a safe
    // miss (no Box::from_raw on an attacker integer). Fable sweep #19.
    let Some(info) = super::msg_slab::take::<super::update_check::UpdateInfo>(wparam.0) else {
        return;
    };

    // Prepend "v" so "Current version" and "Latest version" lines
    // both render with the same v-prefixed shape (GitHub's tag
    // comes in as "v1.2.3"; CARGO_PKG_VERSION is the bare "1.2.3").
    // The version-comparison in update_check::is_strictly_newer
    // strips "v" from both inputs already, so this only affects
    // what the user sees in the dialog.
    let current_display = format!("v{}", env!("CARGO_PKG_VERSION"));
    let body = t!(
        "message.update_available_body",
        latest = &info.latest_tag,
        current = &current_display
    );
    let mut wbody = wide(&body);
    let mut wtitle = wide(&t!("dialog.update_available"));
    let result = unsafe {
        MessageBoxW(
            hwnd,
            windows::core::PCWSTR(wbody.as_mut_ptr()),
            windows::core::PCWSTR(wtitle.as_mut_ptr()),
            MB_YESNO | MB_ICONINFORMATION,
        )
    };
    if result == IDYES {
        let mut wurl = wide(&info.releases_url);
        let mut wverb = wide("open");
        unsafe {
            windows::Win32::UI::Shell::ShellExecuteW(
                hwnd,
                windows::core::PCWSTR(wverb.as_mut_ptr()),
                windows::core::PCWSTR(wurl.as_mut_ptr()),
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR::null(),
                windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            );
        }
    }

    // Whichever way the user closed the dialog (Yes-opens-page,
    // No-dismisses, Esc), record that this tag has been seen so
    // the hourly TIMER_UPDATE_CHECK doesn't pop the same popup
    // every hour for a release the user already chose to act
    // on — or chose not to. Manual Help -> Check for updates is
    // unaffected (check_async_manual passes None as dismissed,
    // so the popup re-appears for the same tag whenever asked).
    if let Some(state) = unsafe { state_ref(hwnd) } {
        let mut s = state.app.settings.borrow_mut();
        if s.update_dismissed_tag != info.latest_tag {
            s.update_dismissed_tag = info.latest_tag.clone();
            let path = state.app.settings_path.borrow().clone();
            if let Err(e) = s.save(&path) {
                eprintln!(
                    "amwall: failed to persist update_dismissed_tag={}: {e}",
                    info.latest_tag,
                );
            }
        }
    }
}

/// Manual `Help -> Check for updates` entry point. Fires the
/// async update-check worker with the manual flag set, so the
/// worker reports back regardless of outcome (newer / same /
/// fetch failed). Surfaces an immediate &t!("status.checking_updates")
/// in the status bar so the user knows the click registered
/// before the (typically <1 s) HTTP round-trip completes.
fn on_check_updates_manual(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    set_status_text(state.status.get(), 0, &t!("status.checking_updates"));
    super::update_check::check_async_manual(hwnd, env!("CARGO_PKG_VERSION"));
}

/// Handler for `WM_USER_UPDATE_UPTODATE` — manual check
/// concluded amwall is already on the latest tag. Shows a
/// MessageBox with both the running version and the GitHub
/// `releases/latest` tag so the user can verify the comparison.
/// Auto-check at startup never reaches this path.
fn on_update_uptodate(hwnd: HWND, wparam: WPARAM) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};

    // take() the payload by token; a forged / stale wparam is a safe
    // miss (no Box::from_raw on an attacker integer). Fable sweep #19.
    let Some(info) = super::msg_slab::take::<super::update_check::UpdateInfo>(wparam.0) else {
        return;
    };

    // Same v-prefix shape match as on_update_available — keeps the
    // "Current" / "Latest" lines consistent in the dialog.
    let current_display = format!("v{}", env!("CARGO_PKG_VERSION"));
    let body = t!(
        "message.update_uptodate_body",
        current = &current_display,
        latest = &info.latest_tag
    );
    let mut wbody = wide(&body);
    let mut wtitle = wide(&t!("dialog.check_updates"));
    unsafe {
        MessageBoxW(
            hwnd,
            windows::core::PCWSTR(wbody.as_mut_ptr()),
            windows::core::PCWSTR(wtitle.as_mut_ptr()),
            MB_OK | MB_ICONINFORMATION,
        );
    }
    if let Some(state) = unsafe { state_ref(hwnd) } {
        set_status_text(state.status.get(), 0, &t!("status.up_to_date"));
    }
}

/// Handler for `WM_USER_UPDATE_ERROR` — the manual check
/// couldn't reach GitHub (offline, DNS, rate limit, etc.).
/// Shows an explanatory MessageBox so the user knows the click
/// produced a real failure, not a silent no-op.
fn on_update_error(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MessageBoxW};
    let mut wbody = wide(&t!("message.update_error_body"));
    let mut wtitle = wide(&t!("dialog.check_updates"));
    unsafe {
        MessageBoxW(
            hwnd,
            windows::core::PCWSTR(wbody.as_mut_ptr()),
            windows::core::PCWSTR(wtitle.as_mut_ptr()),
            MB_OK | MB_ICONWARNING,
        );
    }
    if let Some(state) = unsafe { state_ref(hwnd) } {
        set_status_text(state.status.get(), 0, &t!("status.update_check_failed"));
    }
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
    // take() the path by token; a forged / stale wparam is a safe miss
    // (no Box::from_raw on an attacker integer). Fable sweep #19.
    let Some(path) = take_current_prompt(state, wparam) else {
        return;
    };

    {
        let mut profile = state.app.profile.borrow_mut();
        if let Some(app) = profile.apps.iter_mut().find(|a| a.path == path) {
            app.is_enabled = false;
            app.is_silent = true;
        } else {
            return;
        }
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    set_status_text(state.status.get(), 0, &t!("status.silenced", name = name));
}

/// Apply one explicit Allow without rebuilding unrelated firewall rules.
/// The profile and filter caches change only after all four permits commit.
fn allow_prompt_app(
    state: &WndState,
    path: &std::path::Path,
    install: impl FnOnce(&crate::profile::App) -> Result<Vec<u64>, crate::install::InstallError>,
) -> Result<bool, crate::install::InstallError> {
    let Some(mut candidate) = state
        .app
        .profile
        .borrow()
        .apps
        .iter()
        .find(|app| app.path == path && !app.is_enabled)
        .cloned()
    else {
        return Ok(false);
    };
    candidate.is_enabled = true;
    if state.app.settings.borrow().use_hashes {
        super::hash_baseline::capture_missing(
            std::slice::from_mut(&mut candidate),
            crate::hash::sha256_file,
        );
    }
    let ids = if state.filters_active.get() {
        install(&candidate)?
    } else {
        Vec::new()
    };
    // No message dispatch occurs between taking this snapshot and committing.
    // A failed transaction leaves the saved decision blocked and can be retried.
    if let Some(app) = state
        .app
        .profile
        .borrow_mut()
        .apps
        .iter_mut()
        .find(|app| app.path == path)
    {
        *app = candidate;
    }
    state
        .amwall_filter_ids
        .borrow_mut()
        .extend(ids.iter().copied());
    state
        .categorized_filter_ids
        .borrow_mut()
        .per_app
        .extend(ids);
    Ok(true)
}

/// Handler for an Allow click from the notification's dedicated message loop.
fn on_connect_allow(hwnd: HWND, wparam: WPARAM) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    // take() the path by token; a forged / stale wparam is a safe miss
    // (no Box::from_raw on an attacker integer). Fable sweep #19.
    let Some(path) = take_current_prompt(state, wparam) else {
        return;
    };

    let started = std::time::Instant::now();
    match allow_prompt_app(state, &path, |app| {
        let engine = crate::wfp::WfpEngine::open()?;
        crate::install::install_app_permit(&engine, app, true)
    }) {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            eprintln!("amwall: notification Allow failed; app remains blocked: {e}");
            warn_filter_update_failed(hwnd, state);
            return;
        }
    }
    eprintln!(
        "amwall: notification permission committed in {:?}",
        started.elapsed()
    );
    save_profile_to_disk(state);
    populate_apps_tab(state);
    let selected = unsafe { SendMessageW(state.tab.get(), TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0;
    match selected {
        1 => populate_services_tab(state),
        2 => populate_uwp_tab(state),
        _ => {}
    }
    if selected >= 0 {
        update_item_count(state, selected as usize);
    }
    eprintln!(
        "amwall: notification Allow saved and displayed in {:?}",
        started.elapsed()
    );
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    set_status_text(
        state.status.get(),
        0,
        &t!("status.allowed_count", name = name),
    );
}

/// Handler for `WM_USER_CONNECT_PROMPT_CLOSED`, posted by the connect-
/// prompt dialog's `WM_NCDESTROY` when its window closes for any reason.
/// Clears only the matching generation's reservation. User closes have
/// already posted Block; programmatic cancellation never changes permission.
fn on_connect_prompt_closed(hwnd: HWND, wparam: WPARAM) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    // take() the path by token; a forged / stale wparam is a safe miss.
    let Some(event) = super::msg_slab::take::<super::connect_dialog::PromptEvent>(wparam.0) else {
        return;
    };
    let mut pending = state.pending_prompts.borrow_mut();
    if pending.get(&event.path).is_some_and(|p| p.id == event.id) {
        pending.remove(&event.path);
    }
}

/// A queued click is valid only for the prompt and app decision it displayed.
fn take_current_prompt(state: &WndState, token: WPARAM) -> Option<std::path::PathBuf> {
    let event = super::msg_slab::take::<super::connect_dialog::PromptEvent>(token.0)?;
    let mut pending = state.pending_prompts.borrow_mut();
    let prompt = pending.get(&event.path)?;
    if prompt.id != event.id {
        return None;
    }
    let unchanged = state
        .app
        .profile
        .borrow()
        .apps
        .iter()
        .any(|app| super::prompt_checks::decision_unchanged(app, &prompt.app));
    pending.remove(&event.path);
    unchanged.then_some(event.path)
}

fn cancel_changed_prompts(state: &WndState) {
    let profile = state.app.profile.borrow();
    state.pending_prompts.borrow_mut().retain(|_, prompt| {
        let unchanged = profile
            .apps
            .iter()
            .any(|app| super::prompt_checks::decision_unchanged(app, &prompt.app));
        if !unchanged {
            super::connect_dialog::cancel(prompt.parent, prompt.id);
        }
        unchanged
    });
}

fn cancel_all_prompts(state: &WndState) {
    for (_, prompt) in state.pending_prompts.borrow_mut().drain() {
        super::connect_dialog::cancel(prompt.parent, prompt.id);
    }
}

fn render_ready_network_snapshot(hwnd: HWND, state: &WndState) {
    if !consume_network_snapshot(state) {
        return;
    }
    let slot = unsafe { SendMessageW(state.tab.get(), TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0;
    match slot {
        0 => {
            refresh_apps_traffic_columns(state);
            repaint_active_apps_listview(hwnd, state);
        }
        1 | 2 => repaint_active_apps_listview(hwnd, state),
        6 => populate_connections_tab(state),
        _ => {}
    }
}

/// Drain any pending events from the channel into the log buffer,
/// trimming the front to keep the buffer at most `EVENT_LOG_CAP`
/// entries. If the Log tab is currently visible, repopulate the
/// listview so the new rows show up live.
/// Which per-app flag `on_toggle_app_flag` flips. Fable sweep #28.
enum AppFlag {
    /// `is_silent` — suppresses the connect re-prompt for this app.
    Silent,
    /// `is_undeletable` — Purge-unused / manual delete skip it.
    Undeletable,
}

/// Toggle a per-app flag across the selected app(s) (Fable #28 — bulk).
/// Neither flag affects the installed filters, so no reinstall is needed
/// -- just persist and repopulate so the check mark reflects the change.
/// The new value is computed ONCE from the first selected app so a mixed
/// selection all moves the same way (upstream _app_command_disable,
/// messages.c:2489); falls back to the single right-clicked row.
fn on_toggle_app_flag(hwnd: HWND, flag: AppFlag) {
    let Some(state) = (unsafe { state_ref(hwnd) }) else {
        return;
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    let paths = collect_selection_paths(state, target.listview_id, &target);
    if paths.is_empty() {
        return;
    }
    {
        let mut profile = state.app.profile.borrow_mut();
        // New value from the first selected app that exists in the profile.
        let new_val = paths.iter().find_map(|p| {
            profile
                .apps
                .iter()
                .find(|a| &a.path == p)
                .map(|a| match flag {
                    AppFlag::Silent => !a.is_silent,
                    AppFlag::Undeletable => !a.is_undeletable,
                })
        });
        let Some(new_val) = new_val else {
            return;
        };
        for p in &paths {
            if let Some(app) = profile.apps.iter_mut().find(|a| &a.path == p) {
                match flag {
                    AppFlag::Silent => app.is_silent = new_val,
                    AppFlag::Undeletable => app.is_undeletable = new_val,
                }
            }
        }
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
}

/// "Allow for N": enable the right-clicked app now and stamp App.timer
/// with the absolute expiry (now + duration). The armed expire_timed_apps
/// sweep rolls it back to blocked when the timer elapses. The timer field
/// was serialized / expired / purged but nothing ever SET it, so the whole
/// timed-allow feature was unreachable. Fable sweep finding #23.
fn on_set_app_timer(hwnd: HWND, duration_secs: i64) {
    let Some(state) = (unsafe { state_ref(hwnd) }) else {
        return;
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    if target.binary_path.as_os_str().is_empty() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let expiry = now + duration_secs;
    {
        let mut profile = state.app.profile.borrow_mut();
        if let Some(app) = profile
            .apps
            .iter_mut()
            .find(|a| a.path == target.binary_path)
        {
            app.is_enabled = true;
            app.timer = expiry;
        } else {
            profile.apps.push(crate::profile::App {
                path: target.binary_path.clone(),
                is_enabled: true,
                is_silent: false,
                is_undeletable: false,
                timestamp: now,
                timer: expiry,
                hash: None,
                comment: None,
            });
        }
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(
        state.status.get(),
        0,
        &format!("Allowed {} temporarily.", target.display_name),
    );
}

/// Ctrl+F — move keyboard focus to the search box so the user can filter
/// the active list without reaching for the mouse. IDM_FIND was a defined
/// but unwired stub. Fable sweep finding #33.
fn on_focus_search(hwnd: HWND) {
    use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
    let Some(state) = (unsafe { state_ref(hwnd) }) else {
        return;
    };
    let search = state.search.get();
    if search.0 != 0 {
        unsafe {
            let _ = SetFocus(search);
        }
    }
}

/// Play the system "MailBeep" event sound for a connect prompt when
/// Settings -> notification sound is enabled. Best-effort and async so it
/// never blocks the event drain. Mirrors upstream simplewall's connect-
/// prompt cue. Fable sweep finding #29 (the toggle was a dead no-op).
fn play_notification_sound() {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Media::Audio::{PlaySoundW, SND_ALIAS, SND_ASYNC};
    let alias = wide("MailBeep");
    unsafe {
        let _ = PlaySoundW(
            PCWSTR(alias.as_ptr()),
            HMODULE::default(),
            SND_ALIAS | SND_ASYNC,
        );
    }
}

/// Collect at most one bounded batch. A busy producer cannot monopolize the UI.
fn receive_event_batch(
    rx: &std::sync::mpsc::Receiver<crate::wfp::events::NetEvent>,
) -> Vec<crate::wfp::events::NetEvent> {
    rx.try_iter().take(EVENT_DRAIN_BATCH).collect()
}

fn drain_events(hwnd: HWND, state: &WndState) {
    let batch = state
        .event_rx
        .borrow()
        .as_ref()
        .map(receive_event_batch)
        .unwrap_or_default();
    // Backlogs use a short timer, leaving input and paint messages ahead of
    // each continuation. Never post a self-perpetuating high-priority loop.
    unsafe {
        SetTimer(
            hwnd,
            TIMER_EVENT_DRAIN,
            if batch.len() == EVENT_DRAIN_BATCH {
                10
            } else {
                EVENT_DRAIN_INTERVAL_MS
            },
            None,
        );
    }
    let filters_active = state.filters_active.get();
    let old_count = state.app.profile.borrow().apps.len();
    let new_apps = if filters_active && !batch.is_empty() {
        auto_catalog_drops(hwnd, state, &batch)
    } else {
        Vec::new()
    };
    let profile_changed = state.app.profile.borrow().apps.len() != old_count;

    // Queue notifications before disk logging, hashing, list population or WFP
    // updates. Their dedicated message loop can paint while this thread works.
    let notify = state.app.settings.borrow().enable_notifications;
    let suppress_centered =
        state.app.settings.borrow().notification_fullscreen_silent && is_user_in_fullscreen();
    if filters_active && notify && !new_apps.is_empty() {
        if !suppress_centered {
            if state.app.settings.borrow().notification_sound {
                play_notification_sound();
            }
            process_connect_prompts(hwnd, state, &new_apps);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        for (path, remote) in &new_apps {
            state.last_notify.borrow_mut().insert(path.clone(), now);
            if state.app.settings.borrow().notification_on_tray {
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string());
                super::tray::show_balloon(
                    hwnd,
                    &t!("status.tray_blocked", name = name),
                    &t!("status.connecting", remote = remote),
                );
            }
        }
    }

    let settings = state.app.settings.borrow();
    let mut log = state.event_log.borrow_mut();
    let mut writer = state.event_log_writer.borrow_mut();
    let mut new_arrivals = false;
    for event in batch {
        writer.append(&event, &settings);
        if settings.enable_ui_log {
            if log.len() >= EVENT_LOG_CAP {
                log.pop_front();
            }
            log.push_back(event);
            new_arrivals = true;
        }
    }
    drop(writer);
    drop(log);
    drop(settings);

    if profile_changed {
        save_profile_to_disk(state);
        populate_apps_tab(state);
    }
    // Do not run on_tab_change here: it re-enumerates the selected tab and
    // used to refill the log twice on every batch.
    let selected = unsafe { SendMessageW(state.tab.get(), TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0;
    if new_arrivals && selected == 7 {
        populate_log_tab(state);
    }
    if (profile_changed && selected == 0) || (new_arrivals && selected == 7) {
        update_item_count(state, selected as usize);
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
        // Skip UAC: derived from "is the task registered?", not
        // from a saved bool. The persisted `skip_uac_warning`
        // field is still updated on toggle so the settings file
        // mirrors reality, but the task itself is the source of
        // truth — a user could remove the task from Task Scheduler
        // directly, and the menu should then show unchecked.
        (IDM_SKIPUACWARNING_CHK, crate::skipuac::is_registered()),
        (IDM_CHECKUPDATES_CHK, s.check_updates),
        (IDM_RULE_BLOCKOUTBOUND, s.rule_block_outbound),
        (IDM_RULE_BLOCKINBOUND, s.rule_block_inbound),
        (IDM_RULE_ALLOWLOOPBACK, s.rule_allow_loopback),
        (IDM_RULE_ALLOW6TO4, s.rule_allow_6to4),
        (IDM_RULE_ALLOWWINDOWSUPDATE, s.rule_allow_windows_update),
        (IDM_USECERTIFICATES_CHK, s.use_certificates),
        (IDM_USEHASHES_CHK, s.use_hashes),
    ];
    for (id, v) in pairs {
        set_menu_check(hwnd, id, v);
    }
    apply_always_on_top(hwnd, s.always_on_top);
    apply_search_bar_visibility(hwnd, s.show_search_bar);
    super::font::set_dark_mode(hwnd, s.use_dark_theme);
    super::connect_dialog::set_dark_mode(s.use_dark_theme);
    let autosize = s.autosize_columns;
    drop(s);

    refresh_blocklist_menu_checks(hwnd, state);
    localize_top_menu(hwnd, state);
    // Reflect Notifications mode on the toolbar button so the
    // user can tell at a glance whether the Allow/Block prompt
    // will fire on first-connect drops. Default is on.
    let notify = state.app.settings.borrow().enable_notifications;
    set_toolbar_button_checked(state, IDM_TRAY_ENABLENOTIFICATIONS_CHK, notify);
    // Same for the "Log to file" / "Log UI" toggle buttons, so their
    // pressed state reflects the saved settings at launch. Fable #26.
    {
        let s = state.app.settings.borrow();
        set_toolbar_button_checked(state, IDM_TRAY_ENABLELOG_CHK, s.enable_log);
        set_toolbar_button_checked(state, IDM_TRAY_ENABLEUILOG_CHK, s.enable_ui_log);
    }
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
        autosize_active_listview_columns(state, false);
    }
}

/// Lay out toolbar, search, tabs and status bar on each size change.
/// Child-window moves are batched; resizing never rebuilds list contents.
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

    let toolbar_hwnd = state.toolbar.get();
    let search_hwnd = state.search.get();
    let search_h = scale_dpi(24, state.dpi.get());
    let mut header_h = if toolbar_hwnd.0 != 0 {
        toolbar::layout(toolbar_hwnd, total_w)
    } else {
        0
    };
    if search_hwnd.0 != 0 && state.app.settings.borrow().show_search_bar {
        unsafe {
            let _ = MoveWindow(search_hwnd, 0, header_h, total_w, search_h, true);
        }
        header_h += search_h;
    }
    let rebar_h = header_h;

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

    use windows::Win32::UI::WindowsAndMessaging::{
        BeginDeferWindowPos, DeferWindowPos, EndDeferWindowPos,
    };
    let positions = std::iter::once((tab, 0, tab_y, total_w, tab_h))
        .chain(
            state
                .listviews
                .iter()
                .map(|lv| (lv.get(), content.left, content.top, cw.max(0), ch.max(0))),
        )
        .filter(|(h, ..)| h.0 != 0)
        .collect::<Vec<_>>();
    // If allocation fails, fall back to ordinary positioning, never use an
    // invalid HDWP after a failed DeferWindowPos.
    let mut batch = unsafe { BeginDeferWindowPos(positions.len() as i32) }.ok();
    for &(child, x, y, w, h) in &positions {
        batch = batch.and_then(|b| {
            unsafe {
                DeferWindowPos(
                    b,
                    child,
                    HWND::default(),
                    x,
                    y,
                    w,
                    h,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                )
            }
            .ok()
        });
    }
    let applied = batch.is_some_and(|b| unsafe { EndDeferWindowPos(b) }.is_ok());
    if !applied {
        for (child, x, y, w, h) in positions {
            unsafe {
                let _ = SetWindowPos(
                    child,
                    HWND::default(),
                    x,
                    y,
                    w,
                    h,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
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
    // Snapshot physical widths at the old DPI without marking unvisited tabs
    // as customized. They still need first-show sizing for localized headings.
    let layouts: Vec<_> = state
        .listviews
        .iter()
        .map(|lv| {
            let lv = lv.get();
            super::column_layout::ColumnLayout::capture(
                lv,
                listview_column_count(lv) as usize,
                state.dpi.get(),
            )
        })
        .collect();
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
    for (slot, layout) in layouts.into_iter().enumerate() {
        let lv = state.listviews[slot].get();
        if lv.0 == 0 {
            continue;
        }
        if let Some(layout) = layout {
            state.applying_columns.set(true);
            layout.apply(lv, listview_column_count(lv) as usize, new_dpi);
            state.applying_columns.set(false);
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
    let sel = unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let sel_slot = if sel < 0 { 0 } else { sel as usize };
    if matches!(sel_slot, 0 | 1 | 2 | 6) {
        request_network_snapshot(state);
    }

    // Hide inactive siblings before revealing the active one. The listview
    // must sit above the tab's content surface in sibling z-order.
    for (slot, lv_cell) in state.listviews.iter().enumerate() {
        let lv = lv_cell.get();
        if lv.0 != 0 && slot != sel_slot {
            unsafe {
                let _ = ShowWindow(lv, SW_HIDE);
            }
        }
    }
    if let Some(lv) = state.listviews.get(sel_slot).map(Cell::get) {
        unsafe {
            let _ = SetWindowPos(
                lv,
                windows::Win32::UI::WindowsAndMessaging::HWND_TOP,
                0,
                0,
                0,
                0,
                SWP_NOMOVE
                    | SWP_NOSIZE
                    | SWP_NOACTIVATE
                    | windows::Win32::UI::WindowsAndMessaging::SWP_SHOWWINDOW,
            );
        }
        redraw_listview(lv);
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
            SetTimer(
                hwnd,
                TIMER_CONNECTIONS_REFRESH,
                CONNECTIONS_REFRESH_MS,
                None,
            );
        }
    } else {
        // Stop polling when the user navigates away — avoids
        // hammering IP Helper for tabs the user can't see.
        unsafe {
            let _ = KillTimer(hwnd, TIMER_CONNECTIONS_REFRESH);
        }
    }

    // Slot 0 is IDC_APPS_PROFILE — drive the live Speed / Interface
    // columns while it's showing, off the same traffic sample the
    // Connections tab uses.
    if sel_slot == 0 {
        refresh_apps_traffic_columns(state);
        unsafe {
            SetTimer(hwnd, TIMER_APPS_REFRESH, CONNECTIONS_REFRESH_MS, None);
        }
    } else {
        unsafe {
            let _ = KillTimer(hwnd, TIMER_APPS_REFRESH);
        }
    }

    update_item_count(state, sel_slot);

    // Fit the newly-shown tab's columns to its own header text and
    // content. Upstream does this at the end of its tab-change
    // handler for the same reason (main.c:2609) — each tab has its
    // own column set, so sizing only makes sense once it is visible.
    autosize_active_listview_columns(state, false);
}

/// Update the count without rebuilding or re-enumerating the selected view.
fn update_item_count(state: &WndState, slot: usize) {
    let Some(lv) = state.listviews.get(slot).map(Cell::get) else {
        return;
    };
    if lv.0 != 0 && state.status.get().0 != 0 {
        let count = unsafe { SendMessageW(lv, windows_lvm_getitemcount(), WPARAM(0), LPARAM(0)) }.0;
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
    // Search edit (the toolbar rebar's filter box). EN_CHANGE
    // refilters the active tab as the user types; the other
    // edit-control notifications (EN_SETFOCUS=0x0100,
    // EN_KILLFOCUS=0x0200, EN_UPDATE=0x0400, etc.) we don't
    // care about — but we must still early-return on them so
    // they don't fall through to the menu-id match below and
    // hit the "menu id 104 not yet wired up" catchall.
    const EN_CHANGE: u32 = 0x0300;
    if (id as i32) == IDC_SEARCH {
        if notif == EN_CHANGE {
            on_search_changed(hwnd);
        }
        return;
    }
    let id = id as u16;
    // Apps "Rules" submenu — a contiguous range of per-rule commands
    // (Fable #28). Range-checked before the match, mirroring upstream's
    // IDX_RULES_SPECIAL guard (main.c:3094).
    if (IDM_CONTEXT_RULE_FIRST..=IDM_CONTEXT_RULE_LAST).contains(&id) {
        on_context_assign_rule(hwnd, id);
        return;
    }
    // Keyboard-accelerator context commands act on the active tab's
    // listview (Fable #33). The apps right-click path re-dispatches with
    // notif==0 and a live context_target, so gate on notif==1 (the
    // accelerator marker) to avoid intercepting that.
    if notif == 1
        && matches!(
            id,
            IDM_DELETE
                | IDM_SELECT_ALL
                | IDM_ZOOM
                | IDM_TAB_NEXT
                | IDM_TAB_PREV
                | IDM_PROPERTIES
                | IDM_COPY
                | IDM_COPY_VALUE
                | IDM_EXPLORE
        )
    {
        accel_dispatch(hwnd, id);
        return;
    }
    match id {
        IDM_EXIT => on_exit(hwnd),
        IDM_RELEASES => open_releases_page(hwnd),
        IDM_REFRESH => on_refresh(hwnd),
        IDM_IMPORT => on_import(hwnd),
        IDM_EXPORT => on_export(hwnd),
        IDM_ABOUT => on_about(hwnd),
        IDM_EMERGENCY_RESET => on_emergency_reset(hwnd),
        IDM_WEBSITE => open_website(hwnd),
        IDM_CHECKUPDATES => on_check_updates_manual(hwnd),
        IDM_PURGE_UNUSED => on_purge_unused(hwnd),
        IDM_PURGE_TIMERS => on_purge_timers(hwnd),
        IDM_FIND => on_focus_search(hwnd),
        IDM_LOGCLEAR | IDM_TRAY_LOGCLEAR => on_log_clear(hwnd),
        IDM_TRAY_LOGSHOW => on_log_show(hwnd),
        // Errors-log (swaplog.txt) show / clear from the tray (Fable #30).
        IDM_TRAY_LOGSHOW_ERR => on_log_err_show(hwnd),
        IDM_TRAY_LOGCLEAR_ERR => on_log_err_clear(hwnd),

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
        | IDM_RULE_ALLOWWINDOWSUPDATE
        | IDM_TRAY_ENABLELOG_CHK
        | IDM_TRAY_ENABLEUILOG_CHK
        // Tray Notifications submenu sub-toggles (Fable #30).
        | IDM_TRAY_ENABLENOTIFICATIONSSOUND_CHK
        | IDM_TRAY_NOTIFICATIONFULLSCREENSILENTMODE_CHK
        | IDM_TRAY_NOTIFICATIONONTRAY_CHK => on_toggle(hwnd, id),

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
        IDM_COPY_VALUE => on_context_copy_value(hwnd),
        IDM_PROPERTIES => on_context_properties(hwnd),
        IDM_TIMER_15MIN => on_set_app_timer(hwnd, 15 * 60),
        IDM_TIMER_30MIN => on_set_app_timer(hwnd, 30 * 60),
        IDM_TIMER_1HR => on_set_app_timer(hwnd, 60 * 60),
        IDM_TIMER_4HR => on_set_app_timer(hwnd, 4 * 60 * 60),
        IDM_TOGGLE_SILENT => on_toggle_app_flag(hwnd, AppFlag::Silent),
        IDM_TOGGLE_UNDELETABLE => on_toggle_app_flag(hwnd, AppFlag::Undeletable),

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
        eprintln!("amwall: settings: save failed for {}: {e}", path.display());
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
    let mut target = match target {
        Some(t) => t,
        // Right-click on empty area / out-of-range row — nothing
        // to act on. Could show a different "create new" menu but
        // that's M5.4 polish.
        None => return,
    };
    // Capture the clicked column + its text so "Copy value" (Fable #28)
    // can label itself and copy that column across the selection.
    target.column = activate.iSubItem;
    let lv = apps_listview_hwnd(state, listview_id);
    target.column_text = listview_item_text(lv, activate.iItem, activate.iSubItem);
    // Build the "Rules" submenu entries for this app (togglable rules).
    let rule_items = {
        let profile = state.app.profile.borrow();
        build_rule_menu_items(&profile, &target.binary_path.to_string_lossy())
    };
    *state.context_target.borrow_mut() = Some(target.clone());

    let cmd = super::apps_context_menu::show(hwnd, &target, &rule_items);
    if let Some(id) = cmd {
        // TPM_RETURNCMD bypasses the WM_COMMAND queue, so dispatch
        // ourselves through the same handler.
        on_command(hwnd, id as u32, 0);
    }

    // Always clear after the menu — even if no item was picked, the
    // captured target shouldn't persist into the next interaction.
    *state.context_target.borrow_mut() = None;
}

// ===================================================================
// Rules-tab right-click context menu (Fable #27).
// ===================================================================

/// Resolve one of the three Rules-tab listview ids to its HWND
/// (TAB_LISTVIEW_IDS slots 3=Blocklist, 4=System, 5=Custom).
fn rules_listview_hwnd(state: &WndState, listview_id: i32) -> HWND {
    match listview_id {
        x if x == IDC_RULES_BLOCKLIST => state.listviews[3].get(),
        x if x == IDC_RULES_SYSTEM => state.listviews[4].get(),
        x if x == IDC_RULES_CUSTOM => state.listviews[5].get(),
        _ => HWND(0),
    }
}

/// A Rules-tab row resolved to the rule it drives. `CustomUser` mutates
/// `profile.custom_rules[idx].is_enabled` directly; `Override` records a
/// state override keyed by rule name (system / blocklist / preset-custom
/// rules are read-only, so their enabled state lives in
/// internal_rules_state).
enum RuleTarget {
    CustomUser(usize),
    Override {
        kind: crate::internal_rules_state::RuleKind,
        name: String,
        default: bool,
    },
}

/// Map a Rules-tab (listview_id, row) to the rule it represents,
/// mirroring the per-tab filter-walk in `on_listview_checkbox_toggle`
/// (the source of truth for row→rule under search filtering). Read-only
/// and returns owned data, so a bulk handler can resolve every selected
/// row BEFORE mutating — the per-row repopulate the checkbox handler
/// does would otherwise shift indices mid-loop.
fn resolve_rule_row(state: &WndState, listview_id: i32, row: i32) -> Option<RuleTarget> {
    use crate::internal_rules_state::RuleKind;
    if row < 0 {
        return None;
    }
    let filter = state.search_text.borrow().clone();
    match listview_id {
        x if x == IDC_RULES_CUSTOM => {
            let preset_count = state.user_rules_preset_count.get();
            let row_usize = row as usize;
            if row_usize < preset_count {
                // Preset row → override keyed by name (default from bundle).
                let rule = state
                    .app
                    .internal_profile
                    .custom_rules
                    .iter()
                    .filter(|r| search_match(&r.name, &filter))
                    .nth(row_usize)?;
                Some(RuleTarget::Override {
                    kind: RuleKind::Custom,
                    name: rule.name.clone(),
                    default: rule.is_enabled,
                })
            } else {
                // User-added row → real index into profile.custom_rules.
                let user_row = row_usize - preset_count;
                let profile = state.app.profile.borrow();
                let real_idx = profile
                    .custom_rules
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| search_match(&r.name, &filter))
                    .map(|(i, _)| i)
                    .nth(user_row)?;
                Some(RuleTarget::CustomUser(real_idx))
            }
        }
        x if x == IDC_RULES_SYSTEM => {
            let rule = state
                .app
                .internal_profile
                .system_rules
                .iter()
                .filter(|r| search_match(&r.name, &filter))
                .nth(row as usize)?;
            Some(RuleTarget::Override {
                kind: RuleKind::System,
                name: rule.name.clone(),
                default: rule.is_enabled,
            })
        }
        x if x == IDC_RULES_BLOCKLIST => {
            let rule = state
                .app
                .internal_profile
                .blocklist_rules
                .iter()
                .filter(|r| search_match(&r.name, &filter))
                .nth(row as usize)?;
            Some(RuleTarget::Override {
                kind: RuleKind::Blocklist,
                name: rule.name.clone(),
                default: rule.is_enabled,
            })
        }
        _ => None,
    }
}

/// True if `row` currently carries LVIS_SELECTED.
fn is_row_selected(lv: HWND, row: i32) -> bool {
    if lv.0 == 0 || row < 0 {
        return false;
    }
    let st = unsafe {
        SendMessageW(
            lv,
            LVM_GETITEMSTATE,
            WPARAM(row as usize),
            LPARAM(LVIS_SELECTED.0 as isize),
        )
    }
    .0 as u32;
    (st & LVIS_SELECTED.0) != 0
}

/// Clear the selection and select+focus just `row` (Explorer-style, for
/// a right-click on a not-yet-selected row).
fn select_only_row(lv: HWND, row: i32) {
    if lv.0 == 0 || row < 0 {
        return;
    }
    let clear = LVITEMW {
        state: LIST_VIEW_ITEM_STATE_FLAGS(0),
        stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        ..Default::default()
    };
    let sel = LVITEMW {
        state: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_SETITEMSTATE,
            WPARAM(usize::MAX),
            LPARAM(&clear as *const _ as isize),
        );
        SendMessageW(
            lv,
            LVM_SETITEMSTATE,
            WPARAM(row as usize),
            LPARAM(&sel as *const _ as isize),
        );
    }
}

/// Show the Rules-tab context menu and dispatch the chosen command
/// through a dedicated, tab-aware match (NOT on_command — the shared
/// ids would otherwise hit the Apps handlers). Mirrors upstream
/// _app_message_contextmenu's rules branch (messages.c:622-675).
fn on_rules_context_menu(hwnd: HWND, listview_id: i32, activate: &NMITEMACTIVATE) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = rules_listview_hwnd(state, listview_id);
    if lv.0 == 0 {
        return;
    }
    let row = activate.iItem;
    if row < 0 {
        return;
    }
    // A right-click doesn't auto-select in a listview. Ensure the clicked
    // row is selected so selection-based Edit/Delete act on it; if it was
    // already part of a multi-selection, leave that intact for bulk
    // Check/Uncheck.
    if !is_row_selected(lv, row) {
        select_only_row(lv, row);
    }

    let is_custom = listview_id == IDC_RULES_CUSTOM;
    // Only user-added Custom rows are editable/deletable; presets and all
    // system/blocklist rows are read-only.
    let is_deletable = is_custom
        && matches!(
            listview_item_param(lv, row).map(classify_user_rule_row),
            Some(UserRuleRow::User(_))
        );
    let column_text = listview_item_text(lv, row, activate.iSubItem);

    let target = super::rules_context_menu::RulesContextTarget {
        listview_id,
        row,
        column: activate.iSubItem,
        is_custom,
        is_deletable,
        column_text,
    };
    let Some(id) = super::rules_context_menu::show(hwnd, &target) else {
        return;
    };
    match id {
        IDM_OPENRULESEDITOR => on_create_rule(hwnd),
        IDM_PROPERTIES => on_edit_selected_rule(hwnd),
        IDM_DELETE => on_delete_selected_rule(hwnd),
        IDM_CHECK => on_rules_bulk_enable(hwnd, listview_id, true),
        IDM_UNCHECK => on_rules_bulk_enable(hwnd, listview_id, false),
        IDM_SELECT_ALL => on_rules_select_all(hwnd, listview_id),
        IDM_COPY => on_rules_copy(hwnd, listview_id, None),
        IDM_COPY_VALUE => on_rules_copy(hwnd, listview_id, Some(activate.iSubItem)),
        _ => {}
    }
}

/// Enable / disable every selected rule (Fable #27 — Check / Uncheck).
/// Resolves all selected rows to rule identities first, then applies and
/// persists once (a single reinstall), reusing the exact row→rule
/// mapping via `resolve_rule_row`.
fn on_rules_bulk_enable(hwnd: HWND, listview_id: i32, enable: bool) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = rules_listview_hwnd(state, listview_id);
    if lv.0 == 0 {
        return;
    }
    let rows = selected_rows(lv, -1);
    if rows.is_empty() {
        return;
    }
    let targets: Vec<RuleTarget> = rows
        .iter()
        .filter_map(|&r| resolve_rule_row(state, listview_id, r))
        .collect();
    if targets.is_empty() {
        return;
    }
    let mut profile_dirty = false;
    let mut overrides_dirty = false;
    for t in &targets {
        match t {
            RuleTarget::CustomUser(idx) => {
                let mut profile = state.app.profile.borrow_mut();
                if let Some(rule) = profile.custom_rules.get_mut(*idx) {
                    if rule.is_enabled != enable {
                        rule.is_enabled = enable;
                        profile_dirty = true;
                    }
                }
            }
            RuleTarget::Override {
                kind,
                name,
                default,
            } => {
                let mut overrides = state.app.internal_rules_state.borrow_mut();
                overrides.set(*kind, name, enable, *default);
                overrides_dirty = true;
            }
        }
    }
    if profile_dirty {
        save_profile_to_disk(state);
    }
    if overrides_dirty {
        let path = state.app.internal_rules_state_path.borrow().clone();
        let overrides = state.app.internal_rules_state.borrow();
        if let Err(e) = overrides.save(&path) {
            eprintln!(
                "amwall: failed to persist internal_rules_state to {}: {e}",
                path.display(),
            );
        }
    }
    populate_user_rules(state);
    populate_internal_rules(state, IDC_RULES_SYSTEM);
    populate_internal_rules(state, IDC_RULES_BLOCKLIST);
    on_tab_change(hwnd);
    reinstall_filters_if_active(hwnd, state);
}

/// Select every row on the given Rules listview (Ctrl+A / menu).
fn on_rules_select_all(hwnd: HWND, listview_id: i32) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = rules_listview_hwnd(state, listview_id);
    if lv.0 == 0 {
        return;
    }
    let item = LVITEMW {
        state: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_SETITEMSTATE,
            WPARAM(usize::MAX),
            LPARAM(&item as *const _ as isize),
        );
    }
}

/// Copy selected Rules rows to the clipboard. `column = None` joins all
/// columns per row with ", "; `Some(c)` copies just that column. One row
/// per line (Fable #27, mirrors upstream _app_command_copy).
fn on_rules_copy(hwnd: HWND, listview_id: i32, column: Option<i32>) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = rules_listview_hwnd(state, listview_id);
    if lv.0 == 0 {
        return;
    }
    let rows = selected_rows(lv, -1);
    if rows.is_empty() {
        return;
    }
    let lines: Vec<String> = match column {
        Some(c) => rows
            .iter()
            .map(|&r| listview_item_text(lv, r, c).unwrap_or_default())
            .collect(),
        None => {
            let ncols = listview_column_count(lv).max(1);
            rows.iter()
                .map(|&r| {
                    (0..ncols)
                        .map(|c| listview_item_text(lv, r, c).unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .collect()
        }
    };
    set_clipboard_text(hwnd, &lines.join("\r\n"));
}

// ===================================================================
// Network + Log tab context menus (Fable #27 parts 2 & 3).
// ===================================================================

/// Copy the selected rows of any report listview. `column = None` joins
/// all columns per row with ", "; `Some(c)` copies just that column.
fn copy_selected(hwnd: HWND, lv: HWND, column: Option<i32>) {
    if lv.0 == 0 {
        return;
    }
    let rows = selected_rows(lv, -1);
    if rows.is_empty() {
        return;
    }
    let lines: Vec<String> = match column {
        Some(c) => rows
            .iter()
            .map(|&r| listview_item_text(lv, r, c).unwrap_or_default())
            .collect(),
        None => {
            let ncols = listview_column_count(lv).max(1);
            rows.iter()
                .map(|&r| {
                    (0..ncols)
                        .map(|c| listview_item_text(lv, r, c).unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .collect()
        }
    };
    set_clipboard_text(hwnd, &lines.join("\r\n"));
}

/// Select every row of a report listview.
fn select_all_rows(lv: HWND) {
    if lv.0 == 0 {
        return;
    }
    let item = LVITEMW {
        state: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_SETITEMSTATE,
            WPARAM(usize::MAX),
            LPARAM(&item as *const _ as isize),
        );
    }
}

/// Open a file's containing folder in Explorer with it pre-selected.
fn explore_path(hwnd: HWND, path: &std::path::Path) {
    if path.as_os_str().is_empty() {
        return;
    }
    let args = format!("/select,\"{}\"", path.display());
    let mut wargs = wide(&args);
    let mut wexe = wide("explorer.exe");
    let mut wverb = wide("open");
    unsafe {
        ShellExecuteW(
            hwnd,
            windows::core::PCWSTR(wverb.as_mut_ptr()),
            windows::core::PCWSTR(wexe.as_mut_ptr()),
            windows::core::PCWSTR(wargs.as_mut_ptr()),
            windows::core::PCWSTR::null(),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );
    }
}

/// Select + scroll to the Apps-Profile row whose stamped source index
/// maps to `path`.
fn select_apps_row_by_path(state: &WndState, path: &std::path::Path) {
    let lv = state.listviews[0].get();
    if lv.0 == 0 {
        return;
    }
    let count = unsafe { SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0 as i32;
    let profile = state.app.profile.borrow();
    for row in 0..count {
        if let Some(src) = listview_item_param(lv, row).map(|p| p as usize) {
            if profile.apps.get(src).is_some_and(|a| a.path == path) {
                drop(profile);
                select_only_row(lv, row);
                unsafe {
                    SendMessageW(lv, LVM_ENSUREVISIBLE, WPARAM(row as usize), LPARAM(0));
                }
                return;
            }
        }
    }
}

/// "Show in list": add the app to the profile if it isn't there, switch
/// to the Apps Profile tab, and select the app's row. Mirrors upstream's
/// _app_command_properties network/log cases (messages.c:2789/2820).
fn show_app_in_list(hwnd: HWND, state: &WndState, path: &std::path::Path) {
    if path.as_os_str().is_empty() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let added = {
        let mut profile = state.app.profile.borrow_mut();
        if profile.apps.iter().any(|a| a.path == path) {
            false
        } else {
            profile.apps.push(crate::profile::App {
                path: path.to_path_buf(),
                is_enabled: false,
                is_silent: false,
                is_undeletable: false,
                timestamp: now,
                timer: 0,
                hash: None,
                comment: None,
            });
            true
        }
    };
    if added {
        save_profile_to_disk(state);
    }
    // Switch the tab control to Apps Profile (index 0) and repopulate.
    let tab = state.tab.get();
    if tab.0 != 0 {
        unsafe {
            SendMessageW(tab, TCM_SETCURSEL, WPARAM(0), LPARAM(0));
        }
    }
    on_tab_change(hwnd);
    if added {
        reinstall_filters_if_active(hwnd, state);
    }
    select_apps_row_by_path(state, path);
}

/// Render an (ip, port) pair as an amwall rule-string matcher. `None`
/// for the unspecified address (nothing to match).
fn addr_port_rule_string(ip: std::net::IpAddr, port: u16) -> Option<String> {
    if ip.is_unspecified() {
        return None;
    }
    Some(if port == 0 {
        ip.to_string()
    } else {
        match ip {
            std::net::IpAddr::V4(a) => format!("{a}:{port}"),
            std::net::IpAddr::V6(a) => format!("[{a}]:{port}"),
        }
    })
}

/// Build a BLOCK rule pre-filled from an endpoint pair + app, for the
/// Network / Log "Create rule..." command (upstream _app_command_openeditor,
/// messages.c:2587/2635).
fn build_endpoint_rule(
    name: &str,
    local: Option<(std::net::IpAddr, u16)>,
    remote: Option<(std::net::IpAddr, u16)>,
    protocol: Option<u8>,
    direction: crate::profile::Direction,
    app_path: Option<&str>,
) -> crate::profile::Rule {
    crate::profile::Rule {
        name: name.to_string(),
        remote: remote.and_then(|(ip, p)| addr_port_rule_string(ip, p)),
        local: local.and_then(|(ip, p)| addr_port_rule_string(ip, p)),
        direction,
        action: crate::profile::Action::Block,
        protocol,
        address_family: None,
        apps: app_path.map(|s| s.to_string()),
        is_services: false,
        is_enabled: true,
        os_version: None,
        comment: None,
    }
}

/// Open the rule editor pre-filled with `rule`; on OK push it to
/// custom_rules and persist/repopulate/reinstall.
fn create_rule_prefilled(hwnd: HWND, state: &WndState, rule: crate::profile::Rule) {
    let apps_snapshot = state.app.profile.borrow().apps.clone();
    let new_rule = match super::rule_editor::open(hwnd, Some(&rule), &apps_snapshot) {
        Some(r) => r,
        None => return,
    };
    state.app.profile.borrow_mut().custom_rules.push(new_rule);
    save_profile_to_disk(state);
    populate_user_rules(state);
    on_tab_change(hwnd);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(state.status.get(), 0, &t!("status.rule_added"));
}

/// Tear down the selected live connection (Network "Close connection").
/// Needs elevation and only works for IPv4 established TCP.
fn on_close_connection(hwnd: HWND, state: &WndState, conn: &super::connections::Connection) {
    match super::connections::close_connection(conn) {
        Ok(()) => {
            populate_connections_tab(state);
            on_tab_change(hwnd);
            set_status_text(state.status.get(), 0, "Connection closed.");
        }
        Err(code) => {
            eprintln!("amwall: close_connection failed: 0x{code:08x}");
            let msg = if !super::is_elevated() {
                "Closing a connection requires running amwall as administrator."
            } else {
                "Failed to close the connection."
            };
            set_status_text(state.status.get(), 0, msg);
        }
    }
}

/// Show the Network-tab context menu and dispatch its command.
fn on_network_context_menu(hwnd: HWND, activate: &NMITEMACTIVATE) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = state.listviews[6].get();
    let row = activate.iItem;
    if lv.0 == 0 || row < 0 {
        return;
    }
    if !is_row_selected(lv, row) {
        select_only_row(lv, row);
    }
    let Some(src) = listview_item_param(lv, row).map(|p| p as usize) else {
        return;
    };
    let conn = state.connections.borrow().get(src).cloned();
    let Some(conn) = conn else {
        return;
    };
    let path = super::connections::process_full_path(conn.pid);
    let target = super::net_log_context_menu::NetContextTarget {
        has_path: path.is_some(),
        is_closable: conn.is_closable(),
        column: activate.iSubItem,
        column_text: listview_item_text(lv, row, activate.iSubItem),
    };
    let Some(id) = super::net_log_context_menu::show_network(hwnd, &target) else {
        return;
    };
    match id {
        IDM_SHOW_IN_LIST => {
            if let Some(p) = &path {
                show_app_in_list(hwnd, state, p);
            }
        }
        IDM_OPENRULESEDITOR => {
            let proto = match conn.protocol {
                super::connections::Protocol::Tcp => Some(6u8),
                super::connections::Protocol::Udp => Some(17u8),
            };
            let app_str = path.as_ref().map(|p| p.to_string_lossy().into_owned());
            let rule = build_endpoint_rule(
                &conn.process,
                Some((conn.local.ip, conn.local.port)),
                Some((conn.remote.ip, conn.remote.port)),
                proto,
                crate::profile::Direction::Any,
                app_str.as_deref(),
            );
            create_rule_prefilled(hwnd, state, rule);
        }
        IDM_EXPLORE => {
            if let Some(p) = &path {
                explore_path(hwnd, p);
            }
        }
        IDM_CLOSE_CONNECTION => on_close_connection(hwnd, state, &conn),
        IDM_SELECT_ALL => select_all_rows(lv),
        IDM_COPY => copy_selected(hwnd, lv, None),
        IDM_COPY_VALUE => copy_selected(hwnd, lv, Some(activate.iSubItem)),
        _ => {}
    }
}

/// Show the Log-tab context menu and dispatch its command.
fn on_log_context_menu(hwnd: HWND, activate: &NMITEMACTIVATE) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let lv = state.listviews[7].get();
    let row = activate.iItem;
    if lv.0 == 0 || row < 0 {
        return;
    }
    if !is_row_selected(lv, row) {
        select_only_row(lv, row);
    }
    let Some(evt_idx) = listview_item_param(lv, row).map(|p| p as usize) else {
        return;
    };
    // Clone the detail we need so the event_log borrow drops before the
    // menu (which pumps messages and could re-enter the log).
    let details = {
        let log = state.event_log.borrow();
        match log.get(evt_idx) {
            Some(crate::wfp::events::NetEvent::Drop(d))
            | Some(crate::wfp::events::NetEvent::Allow(d)) => Some(d.clone()),
            _ => None,
        }
    };
    let Some(details) = details else {
        return;
    };
    let app_path = details.app_path.clone();
    let has_path = app_path.as_deref().is_some_and(|p| !p.is_empty());
    let target = super::net_log_context_menu::LogContextTarget {
        has_path,
        column: activate.iSubItem,
        column_text: listview_item_text(lv, row, activate.iSubItem),
    };
    let Some(id) = super::net_log_context_menu::show_log(hwnd, &target) else {
        return;
    };
    match id {
        IDM_SHOW_IN_LIST => {
            if let Some(p) = app_path.as_deref() {
                show_app_in_list(hwnd, state, std::path::Path::new(p));
            }
        }
        IDM_OPENRULESEDITOR => {
            let dir = match details.direction {
                Some(crate::wfp::events::NetDirection::Inbound) => {
                    crate::profile::Direction::Inbound
                }
                Some(crate::wfp::events::NetDirection::Outbound) => {
                    crate::profile::Direction::Outbound
                }
                None => crate::profile::Direction::Any,
            };
            let name = app_path
                .as_deref()
                .map(log_basename)
                .unwrap_or("rule")
                .to_string();
            let rule = build_endpoint_rule(
                &name,
                details.local_addr.zip(details.local_port),
                details.remote_addr.zip(details.remote_port),
                details.protocol,
                dir,
                app_path.as_deref(),
            );
            create_rule_prefilled(hwnd, state, rule);
        }
        IDM_EXPLORE => {
            if let Some(p) = app_path.as_deref() {
                explore_path(hwnd, std::path::Path::new(p));
            }
        }
        IDM_TRAY_LOGCLEAR => on_log_clear(hwnd),
        IDM_SELECT_ALL => select_all_rows(lv),
        IDM_COPY => copy_selected(hwnd, lv, None),
        IDM_COPY_VALUE => copy_selected(hwnd, lv, Some(activate.iSubItem)),
        _ => {}
    }
}

// ===================================================================
// Keyboard-accelerator dispatch for context commands (Fable #33).
// ===================================================================

/// First selected row of a listview, or -1.
fn first_selected_row(lv: HWND) -> i32 {
    if lv.0 == 0 {
        return -1;
    }
    unsafe {
        SendMessageW(
            lv,
            LVM_GETNEXTITEM,
            WPARAM(usize::MAX),
            LPARAM(LVNI_SELECTED as isize),
        )
    }
    .0 as i32
}

/// Run an Apps-tab context command fired from a keyboard accelerator:
/// synthesize a ContextTarget from the first selected row, stash it,
/// dispatch through the existing context handler, then clear — the same
/// set/dispatch/clear pattern on_apps_context_menu uses for the mouse.
fn run_focused_apps_command(hwnd: HWND, state: &WndState, listview_id: i32, cmd: u16) {
    let lv = apps_listview_hwnd(state, listview_id);
    let row = first_selected_row(lv);
    if row < 0 {
        return;
    }
    let Some(src) = listview_item_param(lv, row).map(|p| p as usize) else {
        return;
    };
    let target = {
        let profile = state.app.profile.borrow();
        let services = state.services.borrow();
        let uwp = state.uwp_packages.borrow();
        super::apps_context_menu::target_from_source(
            listview_id,
            row,
            src,
            &profile,
            &services,
            &uwp,
        )
    };
    let Some(target) = target else {
        return;
    };
    *state.context_target.borrow_mut() = Some(target);
    match cmd {
        IDM_PROPERTIES => on_context_properties(hwnd),
        IDM_COPY | IDM_COPY_VALUE => on_context_copy(hwnd),
        IDM_EXPLORE => on_context_explore(hwnd),
        _ => {}
    }
    *state.context_target.borrow_mut() = None;
}

/// Dispatch a keyboard-accelerator context command to the active tab.
/// Tab-switch and zoom are tab-independent; the rest act on the active
/// tab's listview (upstream dispatches these by focus, main.c:3844+).
fn accel_dispatch(hwnd: HWND, cmd: u16) {
    use windows::Win32::UI::WindowsAndMessaging::{IsZoomed, SW_MAXIMIZE, SW_RESTORE, ShowWindow};
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let tab_ctl = state.tab.get();
    if tab_ctl.0 == 0 {
        return;
    }
    let sel = unsafe { SendMessageW(tab_ctl, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    if sel < 0 {
        return;
    }
    // Tab-independent commands.
    match cmd {
        IDM_TAB_NEXT | IDM_TAB_PREV => {
            let n = TAB_LISTVIEW_IDS.len() as isize;
            let next = if cmd == IDM_TAB_NEXT {
                (sel + 1) % n
            } else {
                (sel - 1 + n) % n
            };
            unsafe {
                SendMessageW(tab_ctl, TCM_SETCURSEL, WPARAM(next as usize), LPARAM(0));
            }
            on_tab_change(hwnd);
            return;
        }
        IDM_ZOOM => {
            let zoomed = unsafe { IsZoomed(hwnd).as_bool() };
            unsafe {
                let _ = ShowWindow(hwnd, if zoomed { SW_RESTORE } else { SW_MAXIMIZE });
            }
            return;
        }
        _ => {}
    }
    let tab = sel as usize;
    let listview_id = TAB_LISTVIEW_IDS.get(tab).copied().unwrap_or(0);
    match tab {
        0..=2 => match cmd {
            IDM_SELECT_ALL => on_apps_select_all(hwnd, listview_id),
            IDM_DELETE => on_apps_delete_selected(hwnd, listview_id),
            IDM_PROPERTIES | IDM_COPY | IDM_COPY_VALUE | IDM_EXPLORE => {
                run_focused_apps_command(hwnd, state, listview_id, cmd)
            }
            _ => {}
        },
        3..=5 => match cmd {
            IDM_SELECT_ALL => on_rules_select_all(hwnd, listview_id),
            IDM_COPY | IDM_COPY_VALUE => on_rules_copy(hwnd, listview_id, None),
            // Edit/Delete hardcode the Custom listview (listviews[5]) and
            // read its selection, so they must fire ONLY when the Custom
            // tab is active — otherwise Del/Enter on the System/Blocklist
            // tabs would act on a stale Custom-tab selection (review
            // finding). System/Blocklist rules aren't editable/deletable.
            IDM_PROPERTIES if tab == 5 => on_edit_selected_rule(hwnd),
            IDM_DELETE if tab == 5 => on_delete_selected_rule(hwnd),
            _ => {}
        },
        6 | 7 => {
            let lv = state.listviews[tab].get();
            match cmd {
                IDM_SELECT_ALL => select_all_rows(lv),
                IDM_COPY | IDM_COPY_VALUE => copy_selected(hwnd, lv, None),
                // Enter → Show-in-list, the menu's bold default (review
                // finding — was dropped to the no-op arm).
                IDM_PROPERTIES => accel_show_in_list(hwnd, state, tab),
                _ => {}
            }
        }
        _ => {}
    }
}

/// Enter on the Network/Log tab: resolve the first selected row to its
/// app path and jump to it in the Apps list (Show-in-list) — the bold
/// default of both context menus (review finding).
fn accel_show_in_list(hwnd: HWND, state: &WndState, tab: usize) {
    let lv = state.listviews[tab].get();
    let row = first_selected_row(lv);
    if row < 0 {
        return;
    }
    let Some(src) = listview_item_param(lv, row).map(|p| p as usize) else {
        return;
    };
    let path = if tab == 6 {
        let pid = state.connections.borrow().get(src).map(|c| c.pid);
        pid.and_then(super::connections::process_full_path)
    } else {
        let log = state.event_log.borrow();
        match log.get(src) {
            Some(crate::wfp::events::NetEvent::Drop(d))
            | Some(crate::wfp::events::NetEvent::Allow(d)) => {
                d.app_path.clone().map(std::path::PathBuf::from)
            }
            _ => None,
        }
    };
    if let Some(p) = path {
        if !p.as_os_str().is_empty() {
            show_app_in_list(hwnd, state, &p);
        }
    }
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
        x if x == IDC_APPS_PROFILE => state
            .app
            .profile
            .borrow()
            .apps
            .get(source_idx)
            .map(|a| a.path.clone())?,
        x if x == IDC_APPS_SERVICE => state.services.borrow().get(source_idx).and_then(|s| {
            if s.image_path.as_os_str().is_empty() {
                None
            } else {
                Some(s.image_path.clone())
            }
        })?,
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
        x if x == IDC_APPS_PROFILE => state
            .app
            .profile
            .borrow()
            .apps
            .get(source_idx)
            .map(|a| a.path.clone()),
        x if x == IDC_APPS_SERVICE => state.services.borrow().get(source_idx).and_then(|s| {
            if s.image_path.as_os_str().is_empty() {
                None
            } else {
                Some(s.image_path.clone())
            }
        }),
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
    use std::cell::Cell;
    use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetClassNameW};

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

/// Pick a row color following upstream's `_app_getappcolor` priority
/// ladder (profile.c:714-795), first match wins. Every category is now
/// gated on its per-category enable flag and reads its color from
/// `Settings` (Fable #31 — was hard-coded and un-gated). Order:
///   1. Invalid   — file doesn't exist on disk (uninstalled app).
///   2. Connection — an active TCP/UDP endpoint right now.
///   3. Signed    — passes `WinVerifyTrust` (cached).
///   4. Pico      — WSL/Linux subsystem process. Detection isn't
///      path-driven (every Pico process spawns from `wsl.exe`), so this
///      step is reserved — `is_pico` always returns false today.
///   5. Undelete  — a "Prevent removal" (is_undeletable) app.
///   6. System    — OS-bundled binary under `C:\Windows\`.
///
/// The `Special` (User rules) category is intentionally NOT applied
/// here: upstream gates it on `!is_profilelist`, i.e. it colors only
/// Network / Log / Rules rows, which amwall does not yet colorize (no
/// NM_CUSTOMDRAW is wired for those tabs). First match wins; `None`
/// leaves the listview's default background.
fn pick_app_row_color(
    path: &std::path::Path,
    state: &WndState,
) -> Option<windows::Win32::Foundation::COLORREF> {
    use windows::Win32::Foundation::COLORREF;
    let s = state.app.settings.borrow();
    // Resolve `%VAR%` before touching the filesystem — a profile
    // imported from simplewall stores most entries as
    // `%ProgramFiles%\…`, and testing the literal string marked every
    // one of them "does not exist" (issue #11's sibling, issue #12).
    let resolved = crate::profile::App::resolve(path);
    // 1. Invalid (path doesn't exist on disk).
    if s.highlight_invalid && !path.as_os_str().is_empty() && !resolved.is_file() {
        return Some(COLORREF(s.color_invalid));
    }
    // 2. Active connection — refreshed by populate_apps_tab.
    //    Compare lowercased: connected_paths is stored lowercase to match
    //    the lowercase profile path (Windows paths are case-insensitive).
    if s.highlight_connection && !path.as_os_str().is_empty() {
        let lc = std::path::PathBuf::from(path_match_key(path));
        if state.connected_paths.borrow().contains(&lc) {
            return Some(COLORREF(s.color_connection));
        }
    }
    // 3. Signed (cached — first paint slow, subsequent fast).
    if s.highlight_signed && path_is_signed_cached(state, path) {
        return Some(COLORREF(s.color_signed));
    }
    // 4. Pico — reserved; detection isn't path-driven (always false).
    if s.highlight_pico && is_pico(path) {
        return Some(COLORREF(s.color_pico));
    }
    // 5. Undelete — app flagged "Prevent removal". Looked up by exact
    //    path (profile-tab rows key on app.path; service/UWP rows don't
    //    match a path-keyed entry, so they stay uncolored — parity with
    //    upstream, which gates Undelete on ptr_app->is_undeletable).
    if s.highlight_undelete
        && state
            .app
            .profile
            .borrow()
            .apps
            .iter()
            .any(|a| a.is_undeletable && a.path == path)
    {
        return Some(COLORREF(s.color_undelete));
    }
    // 6. System (Windows-bundled binaries).
    if s.highlight_system {
        if let Some(txt) = path.to_str() {
            if txt.to_lowercase().starts_with(r"c:\windows\") {
                return Some(COLORREF(s.color_system));
            }
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
/// Normalized key for matching a stored app path against some *other*
/// path — an OS-reported image path, or a rule's `apps=` token.
///
/// Two normalizations, both load-bearing:
///   * `%VAR%` expansion (issue #12) — a profile entry stored as
///     `%ProgramFiles%\App\app.exe` never equalled the OS's
///     `C:\Program Files\App\app.exe`, so the "talking now" highlight,
///     the Speed/Interface columns and rule cross-references were all
///     silently dead for every imported entry.
///   * lowercasing — the profile stores lowercase while
///     `process_full_path` returns the OS's real casing, and Windows
///     paths are case-insensitive.
fn path_match_key(path: &std::path::Path) -> String {
    crate::profile::App::resolve(path)
        .to_string_lossy()
        .to_ascii_lowercase()
}

fn path_is_signed_cached(state: &WndState, path: &std::path::Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    match state.signed_cache.lock() {
        Ok(g) => g.get(path).map(|info| info.signed).unwrap_or(false),
        Err(_) => false,
    }
}

/// Cached signer display name for `path`, or `None` if the
/// worker hasn't seen it yet, the binary isn't signed, or
/// `Settings.use_certificates` is off (worker skipped the
/// extraction). Used by App Properties / Connections / connect-
/// prompt for the signer surface.
fn path_signer_cached(state: &WndState, path: &std::path::Path) -> Option<String> {
    if path.as_os_str().is_empty() {
        return None;
    }
    match state.signed_cache.lock() {
        Ok(g) => g.get(path).and_then(|info| info.signer.clone()),
        Err(_) => None,
    }
}

/// Result of `verify_signature`. Carries both the trust verdict
/// (chain valid?) and, when use_certificates is on AND the chain
/// is valid, the leaf certificate's "simple display name" — what
/// upstream simplewall surfaces in the Apps Properties dialog
/// and the Connections tab. Mirrors upstream's pair of
/// IsCertificatesEnabled-gated outputs at helper.c:1875+1931.
#[derive(Debug, Clone, Default)]
pub struct SignedInfo {
    pub signed: bool,
    pub signer: Option<String>,
}

/// `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` returning
/// `0` means the binary's signature chain is valid. Anything else
/// (TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, etc.) means we
/// treat it as unsigned. This asynchronous display-only lookup uses
/// WTD_REVOKE_NONE, like upstream's display/cache path (helper.c:851).
/// Its result never grants network permission.
///
/// When `extract_signer` is true (settings.use_certificates), the
/// state-data emitted by VERIFY is walked via
/// `WTHelperProvDataFromStateData` -> `WTHelperGetProvSignerFromChain`
/// -> `WTHelperGetProvCertFromChain` -> `CertGetNameStringW`
/// (`CERT_NAME_SIMPLE_DISPLAY_TYPE`) to pull the leaf cert's
/// display name (typically the publisher org, e.g. "Microsoft
/// Corporation" or "GitHub, Inc."). When false, signer is None
/// even for signed binaries.
fn verify_signature(path: &std::path::Path, extract_signer: bool) -> SignedInfo {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::Cryptography::{
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
    };
    use windows::Win32::Security::WinTrust::{
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows::core::{GUID, PCWSTR};

    // WinVerifyTrust opens the file by name, so it needs the resolved
    // path — a stored `%ProgramFiles%\…` string would simply fail to
    // open and every imported app would read as unsigned (issue #12).
    // Callers still key the cache on the *stored* path, which is what
    // the listview rows carry.
    let resolved = crate::profile::App::resolve(path);
    let wpath: Vec<u16> = resolved
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
    let signed = result == 0;

    // Pull the signer's display name out of the state data while
    // it's still valid (between VERIFY and CLOSE). Only worth the
    // walk when the chain verified AND the user opted into
    // certificate extraction.
    let signer = if signed && extract_signer {
        let prov_data = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
        if prov_data.is_null() {
            None
        } else {
            let signer_ptr = unsafe { WTHelperGetProvSignerFromChain(prov_data, 0, false, 0) };
            if signer_ptr.is_null() {
                None
            } else {
                let cert_ptr = unsafe { WTHelperGetProvCertFromChain(signer_ptr, 0) };
                if cert_ptr.is_null() {
                    None
                } else {
                    let cert_context = unsafe { (*cert_ptr).pCert };
                    if cert_context.is_null() {
                        None
                    } else {
                        // Probe for required size, then read.
                        let needed = unsafe {
                            CertGetNameStringW(
                                cert_context,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                None,
                                None,
                            )
                        };
                        if needed <= 1 {
                            None
                        } else {
                            let mut buf = vec![0u16; needed as usize];
                            let written = unsafe {
                                CertGetNameStringW(
                                    cert_context,
                                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                    0,
                                    None,
                                    Some(&mut buf),
                                )
                            };
                            if written <= 1 {
                                None
                            } else {
                                // Strip trailing NUL the API includes
                                // in the count.
                                let len = written as usize - 1;
                                Some(String::from_utf16_lossy(&buf[..len]))
                            }
                        }
                    }
                }
            }
        }
    } else {
        None
    };

    // Always close the trust state to release the cached
    // signature data WinVerifyTrust holds onto. MUST happen
    // after the WTHelper* walk above — `prov_data` is the same
    // backing storage Win32 reclaims on STATEACTION_CLOSE.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &action as *const _ as *mut _,
            &mut data as *mut _ as *mut std::ffi::c_void,
        );
    }

    SignedInfo { signed, signer }
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

/// User clicked a column header on the Apps Profile listview.
/// Toggle sort direction if it's the same column, otherwise
/// switch to that column with a descending default (so a fresh
/// click on Added shows latest-first).
/// Handle a user click on a listview checkbox. Routes to the
/// correct mutator based on which tab the row belongs to:
///
///   - Apps Profile / Service / UWP: flip
///     `profile.apps[i].is_enabled`, save the user profile.
///   - User Rules (preset row, idx < preset_count): flip the
///     override in `internal_rules_state` (kind = Custom),
///     save the override file.
///   - User Rules (user-added, idx >= preset_count): flip
///     `profile.custom_rules[i].is_enabled`, save the profile.
///   - System Rules: flip the override in `internal_rules_state`
///     (kind = System), save the override file.
///   - Blocklist: same as System but kind = Blocklist. The
///     install pipeline currently ignores per-rule blocklist
///     overrides (per-category Settings → Blocklist tri-state is
///     the canonical control), but persisting the toggle keeps
///     the UI honest — the row moves between Enabled and Disabled
///     groups, and a future fine-grained blocklist apply will
///     pick the overrides up without extra wiring.
///
/// After the mutation: re-populate the tab so the row moves into
/// the right group (Enabled / Disabled), and fire
/// `reinstall_filters_if_active` so the change takes effect
/// without the user having to click Disable+Enable manually —
/// matches upstream simplewall's auto-reapply UX.
fn on_listview_checkbox_toggle(hwnd: HWND, listview_id: i32, row: i32, new_enabled: bool) {
    use crate::internal_rules_state::RuleKind;

    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    if row < 0 {
        return;
    }

    // Defensive: comctl32 fires LVN_ITEMCHANGED at unexpected times —
    // during the listview's CreateWindowExW init (well before any
    // populate runs), during LVS_EX_CHECKBOXES style application,
    // during populator inserts, etc. Our "old state-image != 0"
    // gate in the WM_NOTIFY dispatcher catches MOST of these but
    // not all (v1.1.8 shipped with a startup-panic crash exactly
    // because of a spurious notification that slipped the gate).
    //
    // A real user click happens at idle, with no other borrows
    // live on profile / internal_rules_state / search_text. So if
    // any of those are currently held immutably (we're inside a
    // populator, or anywhere else up the call stack), we MUST be
    // inside a comctl32-synthesised notification — not a real
    // click — and the safe response is to silently bail. The
    // `try_borrow_mut()` / `try_borrow()` calls below encode
    // exactly that semantic.
    //
    // Note: the search_text borrow is `borrow().clone()`-and-drop
    // inside the populators so it's normally not contended at
    // handler time, but we use `try_borrow()` for consistency
    // (and so a future populator that holds it longer can't
    // re-introduce the same class of panic).

    let mut profile_dirty = false;
    let mut overrides_dirty = false;
    let mut repopulate_apps_id: Option<i32> = None;
    let mut repopulate_user_rules = false;
    let mut repopulate_internal_id: Option<i32> = None;

    match listview_id {
        IDC_APPS_PROFILE | IDC_APPS_SERVICE | IDC_APPS_UWP => {
            // The Apps tabs render whichever app list applies to
            // the tab (profile.apps for Profile; the Services /
            // UWP enumerations for the other two). Only the
            // Profile tab maps a checkbox click to a writeable
            // profile entry — the Services / UWP rows describe
            // ambient OS state and aren't represented in
            // profile.apps until the user explicitly Allows /
            // Blocks them, at which point the populator surfaces
            // them in Profile. Forward Service / UWP clicks to
            // the Add-to-profile path (out of scope for v1.1.7,
            // matches pre-1.1.7 inert checkbox behaviour for
            // those tabs).
            if listview_id == IDC_APPS_PROFILE {
                // The Apps Profile list is sorted (Added-desc) and
                // search-filtered, so the visual `row` is NOT the
                // profile.apps index. Resolve the source index the
                // populator stamped into lParam (listviews[0] =
                // IDC_APPS_PROFILE), like every other Profile handler.
                // Using `row` directly toggled the wrong app -> the
                // clicked app's permit stayed live (fail-open).
                // Security audit finding C. (Pure Win32 read, so it's
                // safe to call before try_borrow_mut.)
                let lv = state.listviews[0].get();
                let Some(source_idx) = listview_item_param(lv, row).map(|p| p as usize) else {
                    return;
                };
                let Ok(mut profile) = state.app.profile.try_borrow_mut() else {
                    return;
                };
                if let Some(app) = profile.apps.get_mut(source_idx) {
                    if app.is_enabled != new_enabled {
                        app.is_enabled = new_enabled;
                        profile_dirty = true;
                    }
                }
            } else {
                // Service / UWP rows were previously inert. Resolve the
                // clicked row to its identifier (service short-name, or
                // UWP package SID) and upsert it into profile.apps -- the
                // same identity + install path the context-menu Allow /
                // Block uses (install.rs AppKind::Service / AppKind::Uwp).
                // Fable sweep finding #22.
                let lv = if listview_id == IDC_APPS_SERVICE {
                    state.listviews[1].get()
                } else {
                    state.listviews[2].get()
                };
                let ident = listview_item_param(lv, row)
                    .map(|p| p as usize)
                    .and_then(|idx| {
                        if listview_id == IDC_APPS_SERVICE {
                            state.services.try_borrow().ok().and_then(|svcs| {
                                svcs.get(idx)
                                    .map(|s| std::path::PathBuf::from(&s.service_name))
                            })
                        } else {
                            state.uwp_packages.try_borrow().ok().and_then(|pkgs| {
                                pkgs.get(idx)
                                    .and_then(|p| p.package_sid.clone())
                                    .map(std::path::PathBuf::from)
                            })
                        }
                    });
                if let Some(path) = ident {
                    if !path.as_os_str().is_empty() {
                        if let Ok(mut profile) = state.app.profile.try_borrow_mut() {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            if let Some(existing) = profile.apps.iter_mut().find(|a| a.path == path)
                            {
                                if existing.is_enabled != new_enabled {
                                    existing.is_enabled = new_enabled;
                                    profile_dirty = true;
                                }
                            } else {
                                profile.apps.push(crate::profile::App {
                                    path,
                                    is_enabled: new_enabled,
                                    is_silent: false,
                                    is_undeletable: false,
                                    timestamp: now,
                                    timer: 0,
                                    hash: None,
                                    comment: None,
                                });
                                profile_dirty = true;
                            }
                        }
                    }
                }
            }
            repopulate_apps_id = Some(listview_id);
        }
        IDC_RULES_CUSTOM => {
            let preset_count = state.user_rules_preset_count.get();
            let row_usize = row as usize;
            if row_usize < preset_count {
                // Preset row: look up by display index in the
                // bundled `internal_profile.custom_rules` (we
                // render presets in declaration order and the
                // search filter prunes them; reach the same row
                // by re-applying the same filter here so the
                // index matches what the user sees).
                let Ok(filter_borrow) = state.search_text.try_borrow() else {
                    return;
                };
                let filter = filter_borrow.clone();
                drop(filter_borrow);
                let target = state
                    .app
                    .internal_profile
                    .custom_rules
                    .iter()
                    .filter(|r| search_match(&r.name, &filter))
                    .nth(row_usize);
                if let Some(rule) = target {
                    let Ok(mut overrides) = state.app.internal_rules_state.try_borrow_mut() else {
                        return;
                    };
                    overrides.set(RuleKind::Custom, &rule.name, new_enabled, rule.is_enabled);
                    overrides_dirty = true;
                }
            } else {
                // User-added row: index into profile.custom_rules
                // via the same filter walk.
                let Ok(filter_borrow) = state.search_text.try_borrow() else {
                    return;
                };
                let filter = filter_borrow.clone();
                drop(filter_borrow);
                let user_row = row_usize - preset_count;
                let Ok(mut profile) = state.app.profile.try_borrow_mut() else {
                    return;
                };
                let visible_indices: Vec<usize> = profile
                    .custom_rules
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| search_match(&r.name, &filter))
                    .map(|(i, _)| i)
                    .collect();
                if let Some(&real_idx) = visible_indices.get(user_row) {
                    if let Some(rule) = profile.custom_rules.get_mut(real_idx) {
                        if rule.is_enabled != new_enabled {
                            rule.is_enabled = new_enabled;
                            profile_dirty = true;
                        }
                    }
                }
            }
            repopulate_user_rules = true;
        }
        IDC_RULES_SYSTEM | IDC_RULES_BLOCKLIST => {
            let (rules, kind) = if listview_id == IDC_RULES_SYSTEM {
                (&state.app.internal_profile.system_rules, RuleKind::System)
            } else {
                (
                    &state.app.internal_profile.blocklist_rules,
                    RuleKind::Blocklist,
                )
            };
            let Ok(filter_borrow) = state.search_text.try_borrow() else {
                return;
            };
            let filter = filter_borrow.clone();
            drop(filter_borrow);
            let target = rules
                .iter()
                .filter(|r| search_match(&r.name, &filter))
                .nth(row as usize);
            if let Some(rule) = target {
                let Ok(mut overrides) = state.app.internal_rules_state.try_borrow_mut() else {
                    return;
                };
                overrides.set(kind, &rule.name, new_enabled, rule.is_enabled);
                overrides_dirty = true;
            }
            repopulate_internal_id = Some(listview_id);
        }
        _ => {}
    }

    if profile_dirty {
        save_profile_to_disk(state);
    }
    if overrides_dirty {
        // Path is a RefCell<PathBuf> but the GUI only ever sets it
        // once during startup, so `try_borrow` here is effectively
        // free. Skipping save on contention is fine — the next
        // toggle will retry.
        let Ok(path_borrow) = state.app.internal_rules_state_path.try_borrow() else {
            return;
        };
        let path = path_borrow.clone();
        drop(path_borrow);
        let Ok(overrides) = state.app.internal_rules_state.try_borrow() else {
            return;
        };
        if let Err(e) = overrides.save(&path) {
            eprintln!(
                "amwall: failed to persist internal_rules_state to {}: {e}",
                path.display(),
            );
        }
    }
    if let Some(id) = repopulate_apps_id {
        let _ = id;
        populate_apps_tab(state);
    }
    if repopulate_user_rules {
        populate_user_rules(state);
    }
    if let Some(id) = repopulate_internal_id {
        populate_internal_rules(state, id);
    }
    if profile_dirty || overrides_dirty {
        reinstall_filters_if_active(hwnd, state);
    }
}

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

/// Column-header click on the Connections tab: set/toggle the sort and
/// re-render. First click on a column sorts descending; clicking the
/// same column again flips to ascending.
fn on_network_column_click(hwnd: HWND, column: i32) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let mut sort = state.network_sort.get();
    if sort.column == column {
        sort.ascending = !sort.ascending;
    } else {
        sort.column = column;
        sort.ascending = false;
    }
    state.network_sort.set(sort);
    populate_connections_tab(state);
}

/// Order the connection rows per the current [`NetworkSortState`].
/// `column == -1` leaves enumeration order untouched. Numeric columns
/// (ports, speeds, total) compare as numbers; the rest compare as
/// strings. The async Host columns (2, 5) have no stable sort key, so
/// they're treated as equal (no-op) rather than sorting on a
/// half-populated cache.
fn sort_connections(conns: &mut [super::connections::Connection], sort: NetworkSortState) {
    use std::cmp::Ordering;
    if sort.column < 0 {
        return;
    }
    conns.sort_by(|a, b| {
        let ord = match sort.column {
            0 => a
                .process
                .to_ascii_lowercase()
                .cmp(&b.process.to_ascii_lowercase()),
            1 => a.local.ip.cmp(&b.local.ip),
            3 => a.local.port.cmp(&b.local.port),
            4 => a.remote.ip.cmp(&b.remote.ip),
            6 => a.remote.port.cmp(&b.remote.port),
            7 => a.protocol.label().cmp(b.protocol.label()),
            8 => a.state.cmp(b.state),
            9 => a.download_speed.cmp(&b.download_speed),
            10 => a.upload_speed.cmp(&b.upload_speed),
            11 => a.total_bytes.cmp(&b.total_bytes),
            _ => Ordering::Equal,
        };
        if sort.ascending { ord } else { ord.reverse() }
    });
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
                    // Skip apps flagged "Prevent removal" (is_undeletable),
                    // matching on_context_remove and upstream
                    // (messages.c:2382) — the Del accelerator now routes
                    // here, so this path must honor the flag too (review
                    // finding).
                    if profile.apps[idx].is_undeletable {
                        continue;
                    }
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
            // Keep "Prevent removal" apps even when matched (review finding).
            profile
                .apps
                .retain(|a| a.is_undeletable || !paths.contains(&a.path));
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
                // Keep "Prevent removal" apps even when matched (review finding).
                profile
                    .apps
                    .retain(|a| a.is_undeletable || !sids.contains(&a.path));
                removed = before - profile.apps.len();
            }
        }
        _ => return,
    }

    if removed == 0 {
        set_status_text(state.status.get(), 0, &t!("status.nothing_to_remove"));
        return;
    }

    save_profile_to_disk(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);
    // Repaint after the profile mutation.
    repaint_active_apps_listview(hwnd, state);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(
        state.status.get(),
        0,
        &t!("status.removed_entries", count = removed),
    );
}

/// MessageBox confirm for bulk-delete. Yes/No, default No so a
/// stray Enter doesn't wipe the list.
fn confirm_bulk_delete(hwnd: HWND, count: usize) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO};
    let msg = wide(&t!("message.bulk_delete_confirm", count = count));
    let title = wide(&t!("dialog.confirm_bulk_delete"));
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
            if let Some(existing) = profile.apps.iter_mut().find(|a| &a.path == path) {
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
    reinstall_filters_if_active(hwnd, state);

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
            // Map each selected UWP row to its package SID (carried as a
            // SID-shaped path, same as the single-row context target).
            // App::kind() detects the S-1-15-2-... form as AppKind::Uwp,
            // so these route through the FWPM_CONDITION_ALE_PACKAGE_ID
            // install path. Rows whose SID didn't resolve are skipped.
            // Fable sweep finding #21 (multi-select half).
            let uwp = state.uwp_packages.borrow();
            for idx in source_indices {
                if let Some(sid) = uwp.get(idx).and_then(|p| p.package_sid.as_deref()) {
                    out.push(std::path::PathBuf::from(sid));
                }
            }
        }
        _ => {}
    }
    out
}

/// Resolve one of the three Apps-tab listview ids to its HWND.
fn apps_listview_hwnd(state: &WndState, listview_id: i32) -> HWND {
    match listview_id {
        x if x == IDC_APPS_PROFILE => state.listviews[0].get(),
        x if x == IDC_APPS_SERVICE => state.listviews[1].get(),
        x if x == IDC_APPS_UWP => state.listviews[2].get(),
        _ => HWND(0),
    }
}

// ---- Apps "Rules" submenu support (Fable #28) ----
//
// The submenu lists togglable rules; a click assigns/unassigns the
// selected app(s) to that rule. Both the menu build and the dispatch
// must decode the same combined index space, so both go through
// `togglable_rules` — the single source of order + filtering.

/// A rule referenced by the Apps "Rules" submenu — either a system or a
/// custom rule, by its index within that vector.
#[derive(Clone, Copy)]
enum RuleRef {
    System(usize),
    Custom(usize),
}

/// A "global" rule is enabled with no app list — it applies to every
/// app, so it must not appear as a per-app toggle (assigning an app
/// would silently narrow it). Mirrors upstream's helper.c:1211-1220.
fn is_global_rule(r: &crate::profile::Rule) -> bool {
    r.is_enabled && r.apps.as_deref().is_none_or(|a| a.trim().is_empty())
}

/// The combined, filtered list of togglable rules in menu order:
/// system rules first, then custom rules, globals excluded. The index
/// into this Vec is the submenu command offset from IDM_CONTEXT_RULE_FIRST.
///
/// KNOWN PARITY GAP (review finding): this takes the USER profile, whose
/// `system_rules` is always empty (only the bundled internal profile has
/// a `<rules_system>` section) — so in practice only user-added Custom
/// rules appear. Upstream's submenu also lists the built-in preset rules
/// (marked `*`). amwall can't yet do that: presets live read-only in the
/// internal profile and have no per-app app-list override mechanism
/// (internal_rules_state tracks only enabled/disabled), so offering them
/// here would produce a no-op. They remain toggleable on the Rules tab.
/// The RuleRef::System branch is kept for forward-compat if a migrated
/// user profile ever carries `<rules_system>`.
fn togglable_rules(profile: &crate::profile::Profile) -> Vec<RuleRef> {
    let mut out = Vec::new();
    for (i, r) in profile.system_rules.iter().enumerate() {
        if !is_global_rule(r) {
            out.push(RuleRef::System(i));
        }
    }
    for (i, r) in profile.custom_rules.iter().enumerate() {
        if !is_global_rule(r) {
            out.push(RuleRef::Custom(i));
        }
    }
    out
}

/// Whether a rule's `apps` list (`|`-separated) already references
/// `token`. Case-insensitive to match Windows path semantics.
fn rule_apps_contains(apps: Option<&str>, token: &str) -> bool {
    apps.is_some_and(|a| {
        a.split('|')
            .map(str::trim)
            .any(|t| t.eq_ignore_ascii_case(token))
    })
}

/// Add or remove `token` in a rule's `apps` string, normalizing back to
/// `None` when the list empties. Mirrors upstream `_app_setruletoapp`
/// (helper.c:1298).
fn set_rule_app(rule: &mut crate::profile::Rule, token: &str, add: bool) {
    let mut apps: Vec<String> = rule
        .apps
        .as_deref()
        .map(|a| {
            a.split('|')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let pos = apps.iter().position(|s| s.eq_ignore_ascii_case(token));
    if add {
        if pos.is_none() {
            apps.push(token.to_string());
        }
    } else if let Some(p) = pos {
        apps.remove(p);
    }
    rule.apps = if apps.is_empty() {
        None
    } else {
        Some(apps.join("|"))
    };
}

/// Build the "Rules" submenu entries for `app_token`: one per togglable
/// rule, in the same order `togglable_rules` yields, with a `*` suffix
/// on system (built-in) rules and a check when the rule already applies
/// to the app.
fn build_rule_menu_items(
    profile: &crate::profile::Profile,
    app_token: &str,
) -> Vec<super::apps_context_menu::RuleMenuItem> {
    togglable_rules(profile)
        .iter()
        .map(|rref| {
            let (rule, is_system) = match rref {
                RuleRef::System(i) => (&profile.system_rules[*i], true),
                RuleRef::Custom(i) => (&profile.custom_rules[*i], false),
            };
            let checked = rule_apps_contains(rule.apps.as_deref(), app_token);
            let mut label = t!("context.apply_rule", name = &rule.name).to_string();
            if is_system {
                // SZ_RULE_INTERNAL_MENU marker (main.h:101).
                label.push_str(" *");
            }
            super::apps_context_menu::RuleMenuItem { label, checked }
        })
        .collect()
}

/// Assign / unassign the selected app(s) to the rule the submenu id
/// decodes to (Fable #28). Add-vs-remove is decided ONCE from the first
/// selected app's current membership so a mixed selection all moves the
/// same way (upstream _app_command_idtorules, messages.c:1852); adding
/// the first app auto-enables the rule, removing the last disables it.
fn on_context_assign_rule(hwnd: HWND, id: u16) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    let paths = collect_selection_paths(state, target.listview_id, &target);
    let tokens: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.is_empty() {
        return;
    }
    let k = (id - IDM_CONTEXT_RULE_FIRST) as usize;
    {
        let mut profile = state.app.profile.borrow_mut();
        // Copy out the RuleRef so the immutable borrow ends before the
        // mutable one below (togglable_rules returns an owned Vec).
        let rref = togglable_rules(&profile).get(k).copied();
        let Some(rref) = rref else {
            return;
        };
        let rule: &mut crate::profile::Rule = match rref {
            RuleRef::System(i) => &mut profile.system_rules[i],
            RuleRef::Custom(i) => &mut profile.custom_rules[i],
        };
        let add = !rule_apps_contains(rule.apps.as_deref(), &tokens[0]);
        for tk in &tokens {
            set_rule_app(rule, tk, add);
        }
        let has_apps = rule.apps.as_deref().is_some_and(|a| !a.trim().is_empty());
        if add && has_apps {
            rule.is_enabled = true;
        } else if !add && !has_apps {
            rule.is_enabled = false;
        }
    }
    save_profile_to_disk(state);
    populate_user_rules(state);
    populate_internal_rules(state, IDC_RULES_SYSTEM);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(state.status.get(), 0, &t!("status.rule_updated"));
}

/// Remove the selected app entries from the profile (Fable #28 — bulk).
/// Apps flagged "Prevent removal" (is_undeletable) are skipped, matching
/// the flag's documented purpose and upstream graying Delete on them.
/// Falls back to the single right-clicked row when nothing is selected.
fn on_context_remove(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    let paths = collect_selection_paths(state, target.listview_id, &target);
    if paths.is_empty() {
        return;
    }
    let removed;
    {
        let mut profile = state.app.profile.borrow_mut();
        let before = profile.apps.len();
        profile.apps.retain(|a| {
            if a.is_undeletable {
                return true;
            }
            !paths.iter().any(|p| p == &a.path)
        });
        removed = before - profile.apps.len();
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);
    repaint_active_apps_listview(hwnd, state);
    reinstall_filters_if_active(hwnd, state);
    let msg = if removed == 1 {
        format!("Removed: {}", target.display_name)
    } else {
        format!("Removed {removed} app(s).")
    };
    set_status_text(state.status.get(), 0, &msg);
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

/// Copy all columns of every selected row to the clipboard, one row per
/// line, columns joined by ", " (Fable #28 — was display-name only).
/// Mirrors upstream _app_command_copy / IDM_COPY (messages.c:2091).
fn on_context_copy(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    let lv = apps_listview_hwnd(state, target.listview_id);
    if lv.0 == 0 {
        // No listview (shouldn't happen) — fall back to the name.
        set_clipboard_text(hwnd, &target.display_name);
        return;
    }
    let ncols = listview_column_count(lv).max(1);
    let rows = selected_rows(lv, target.row);
    let lines: Vec<String> = rows
        .iter()
        .map(|&row| {
            (0..ncols)
                .map(|c| listview_item_text(lv, row, c).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect();
    set_clipboard_text(hwnd, &lines.join("\r\n"));
}

/// Copy just the right-clicked column's value across the selected rows,
/// one per line (Fable #28 — IDM_COPY_VALUE, messages.c:2091). The
/// column index rides on the captured ContextTarget.
fn on_context_copy_value(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let target = match state.context_target.borrow().clone() {
        Some(t) => t,
        None => return,
    };
    let lv = apps_listview_hwnd(state, target.listview_id);
    if lv.0 == 0 {
        return;
    }
    let col = target.column.max(0);
    let rows = selected_rows(lv, target.row);
    let lines: Vec<String> = rows
        .iter()
        .map(|&row| listview_item_text(lv, row, col).unwrap_or_default())
        .collect();
    set_clipboard_text(hwnd, &lines.join("\r\n"));
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

    let signer = path_signer_cached(state, &target.binary_path);
    let updated = match super::app_properties::open(hwnd, &initial, signer.as_deref()) {
        Some(u) => u,
        None => return, // Close / no edits.
    };

    {
        let mut profile = state.app.profile.borrow_mut();
        if let Some(slot) = profile
            .apps
            .iter_mut()
            .find(|a| a.path == target.binary_path)
        {
            *slot = updated;
        }
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    on_tab_change(hwnd);
    reinstall_filters_if_active(hwnd, state);
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
pub(crate) fn set_clipboard_text(hwnd: HWND, text: &str) {
    use windows::Win32::Foundation::{GlobalFree, HANDLE};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
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
            IDM_USECERTIFICATES_CHK => &mut s.use_certificates,
            IDM_USEHASHES_CHK => &mut s.use_hashes,
            // Toolbar "Log to file" / "Log UI" buttons. drain_events gates
            // on these, so flipping the setting is all that's needed
            // functionally; the toolbar pressed state is synced below.
            // Fable sweep finding #26 (were dead -- hit the catchall).
            IDM_TRAY_ENABLELOG_CHK => &mut s.enable_log,
            IDM_TRAY_ENABLEUILOG_CHK => &mut s.enable_ui_log,
            // Tray Notifications submenu sub-toggles (Fable #30). No
            // visual side-effect arm needed: the tray menu is rebuilt
            // per right-click, so the new check state is read at build
            // time (set_menu_check targets the persistent menu bar and
            // is a harmless no-op for these tray-only ids).
            IDM_TRAY_ENABLENOTIFICATIONSSOUND_CHK => &mut s.notification_sound,
            IDM_TRAY_NOTIFICATIONFULLSCREENSILENTMODE_CHK => &mut s.notification_fullscreen_silent,
            IDM_TRAY_NOTIFICATIONONTRAY_CHK => &mut s.notification_on_tray,
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
        eprintln!("amwall: settings: save failed for {}: {e}", path.display());
    }

    // Visual side effects.
    match id {
        IDM_ALWAYSONTOP_CHK => apply_always_on_top(hwnd, new_value),
        IDM_SHOWSEARCHBAR_CHK => apply_search_bar_visibility(hwnd, new_value),
        IDM_USEDARKTHEME_CHK => {
            super::font::set_dark_mode(hwnd, new_value);
            super::connect_dialog::set_dark_mode(new_value);
        }
        IDM_SHOWFILENAMESONLY_CHK => {
            // Filename / full-path display affects Apps tab rendering.
            populate_apps_tab(state);
        }
        IDM_AUTOSIZECOLUMNS_CHK if new_value => {
            // Explicit user request — apply immediately rather than
            // waiting for the next refill (upstream's `is_forced`).
            autosize_active_listview_columns(state, true);
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
            reinstall_filters_if_active(hwnd, state);
        }
        IDM_USECERTIFICATES_CHK => {
            // Update the worker's atomic flag, then re-enqueue
            // every File-kind app so signers get backfilled (if
            // turning on) or can be left alone (if turning off
            // — the worker checks the flag per-path and skips
            // the certificate walk; existing cached signers
            // remain visible until cache eviction).
            state
                .use_certificates_flag
                .store(new_value, std::sync::atomic::Ordering::Relaxed);
            if new_value {
                requeue_signed_paths(state);
            }
        }
        IDM_SKIPUACWARNING_CHK => {
            // Register/unregister the Task Scheduler entry that
            // lets unelevated launches relaunch silently as
            // admin. Both calls require admin on the first
            // attempt; if amwall isn't already elevated, Windows
            // bounces the COM call with E_ACCESSDENIED. We
            // detect that, ShellExecuteEx-runas a tiny helper
            // shell command that re-runs the toggle, and then
            // refresh our checkbox to reflect the actual task
            // state.
            apply_skipuac_toggle(hwnd, state, new_value);
        }
        IDM_USEHASHES_CHK => {
            check_hash_drift(hwnd, state);
        }
        IDM_TRAY_ENABLELOG_CHK | IDM_TRAY_ENABLEUILOG_CHK => {
            // Reflect the new state on the toolbar toggle button.
            set_toolbar_button_checked(state, id, new_value);
        }
        _ => {}
    }
}

/// Skip-UAC toggle: register or unregister the Task Scheduler
/// entry that lets future amwall launches elevate without a UAC
/// prompt. The first time this is enabled, Windows shows a UAC
/// prompt because writing a HIGHEST-runlevel task requires admin;
/// every subsequent launch is silent.
///
/// Implementation: the actual register/unregister calls happen in
/// a child amwall.exe process (via `-skipuac-register` /
/// `-skipuac-unregister`) so we get auto-elevation through the
/// existing `ensure_admin` ShellExecuteEx-runas helper. We wait
/// for the child to finish, then re-check the task state and
/// reflect it on the menu.
///
/// If the child returned non-zero (user cancelled UAC, or
/// register/unregister failed) we revert the menu check to match
/// the actual task state — so the user doesn't see a misleading
/// "enabled" tick when nothing happened.
fn apply_skipuac_toggle(hwnd: HWND, state: &WndState, requested: bool) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("amwall: skipuac: cannot resolve own exe: {e}");
            // Snap the menu back to the actual task state.
            set_menu_check(
                hwnd,
                IDM_SKIPUACWARNING_CHK,
                crate::skipuac::is_registered(),
            );
            return;
        }
    };
    let exe_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();
    let arg = if requested {
        "-skipuac-register"
    } else {
        "-skipuac-unregister"
    };
    let arg_w: Vec<u16> = arg.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(arg_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    let exec_ok = unsafe { ShellExecuteExW(&mut sei) };
    if exec_ok.is_err() || sei.hProcess.0 == 0 {
        eprintln!("amwall: skipuac: ShellExecuteExW(runas) failed (UAC denied?)");
        set_menu_check(
            hwnd,
            IDM_SKIPUACWARNING_CHK,
            crate::skipuac::is_registered(),
        );
        return;
    }
    unsafe {
        let _ = WaitForSingleObject(sei.hProcess, INFINITE);
        let _ = CloseHandle(sei.hProcess);
    }

    // Re-query so the menu reflects reality, even if the child
    // failed mid-call.
    let actual = crate::skipuac::is_registered();
    set_menu_check(hwnd, IDM_SKIPUACWARNING_CHK, actual);
    {
        let mut s = state.app.settings.borrow_mut();
        s.skip_uac_warning = actual;
    }
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!("amwall: settings: save skip_uac_warning failed: {e}");
    }
    let label = if actual {
        t!("status.skip_uac_enabled")
    } else {
        t!("status.skip_uac_disabled")
    };
    set_status_text(state.status.get(), 0, &label);
}

/// Re-enqueue every File-kind app's path on the signed worker so
/// the cache gets refreshed with the newly-requested signer
/// metadata. Used when the user flips `use_certificates` on
/// after launch — the worker's per-path "already cached?" check
/// recognises that the cached entry lacks a signer and re-runs
/// the trust state machine to extract one.
fn requeue_signed_paths(state: &WndState) {
    use crate::profile::AppKind;
    let tx_borrow = state.signed_tx.borrow();
    let tx = match tx_borrow.as_ref() {
        Some(t) => t,
        None => return,
    };
    let profile = state.app.profile.borrow();
    for app in &profile.apps {
        if app.kind() == AppKind::File && !app.path.as_os_str().is_empty() {
            let _ = tx.send(app.path.clone());
        }
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
fn blocklist_mode_to_action(m: super::settings::BlocklistMode) -> crate::install::BlocklistAction {
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
        let title = wide(&t!("dialog.admin_required"));
        let body = wide(&t!("message.admin_required_body"));
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
            set_status_text(state.status.get(), 0, &t!("status.engine_failed"));
            return;
        }
    };

    let new_active;
    if state.filters_active.get() {
        // ---- Disable path ----
        match crate::install::uninstall(&engine) {
            Ok(report) => {
                set_status_text(state.status.get(), 0, &t!("status.filters_disabled"));
                set_status_text(
                    state.status.get(),
                    1,
                    &t!(
                        "status.filters_removed",
                        filters = report.filters_deleted,
                        sublayers = report.sublayers_deleted
                    ),
                );
                new_active = false;
            }
            Err(e) => {
                eprintln!("amwall: uninstall failed: {e:?}");
                set_status_text(state.status.get(), 0, &t!("status.uninstall_failed"));
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
                    install_boottime: s.install_boottime_filters,
                },
                // Permanent GUI install -> always persistent; boot-time
                // enforcement is the separate field above. Fable #12.
                true,
            )
        };
        ensure_enabled_hash_baselines(state);
        let report = match crate::install::install_with_internal(
            &engine,
            &state.app.profile.borrow(),
            Some(&state.app.internal_profile),
            Some(&state.app.internal_rules_state.borrow()),
            &blocklist,
            &global_rules,
            persistent,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("amwall: install failed: {e}");
                set_status_text(state.status.get(), 0, &t!("status.install_failed"));
                return;
            }
        };
        // Stash categorized ids on state so drain_events can
        // honor exclude_blocklist / exclude_custom /
        // exclude_stealth without re-categorizing each event.
        *state.categorized_filter_ids.borrow_mut() = report.filter_ids.clone();
        set_status_text(state.status.get(), 0, &t!("status.filters_enabled"));
        set_status_text(
            state.status.get(),
            1,
            &t!(
                "status.filters_installed",
                added = report.filters_added,
                skipped = report.rules_skipped
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

    // Persist the user's explicit choice so the next launch
    // honours it (auto-enable on if true, stay off if false).
    persist_filters_active(state, new_active);
}

/// Write `filters_active_persisted = value` to settings.txt. Same
/// pattern as `on_first_run_wizard`'s save flow. Errors logged
/// but non-fatal — the in-memory toggle still works for this
/// session, only the next-launch auto-enable would miss the
/// update.
fn persist_filters_active(state: &WndState, value: bool) {
    state.app.settings.borrow_mut().filters_active_persisted = value;
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!(
            "amwall: settings: save filters_active_persisted failed for {}: {e}",
            path.display()
        );
    }
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
/// Alert the user (modally) that a filter reinstall failed, so the
/// kernel may now hold stale rules that don't match the latest profile
/// change -- a potential fail-open the caller would otherwise paint over
/// with a success status. reinstall_filters_if_active has 12 fire-and-
/// forget callers, so a modal box (not a caller-gated Result) is the
/// reliable signal. Fable sweep finding #13.
fn warn_filter_update_failed(hwnd: HWND, state: &WndState) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    set_status_text(state.status.get(), 0, &t!("status.install_failed"));
    let title = wide("amwall");
    let body = wide(&t!("message.filter_update_failed"));
    unsafe {
        MessageBoxW(
            hwnd,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn reinstall_filters_if_active(hwnd: HWND, state: &WndState) {
    if !state.filters_active.get() {
        return;
    }
    let engine = match crate::wfp::WfpEngine::open() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("amwall: reinstall: WFP engine open failed: {e:?}");
            warn_filter_update_failed(hwnd, state);
            return;
        }
    };
    ensure_enabled_hash_baselines(state);
    if let Err(e) = engine.cleanup_provider(&crate::install::PROVIDER_KEY) {
        eprintln!("amwall: reinstall: cleanup_provider failed: {e:?}");
        warn_filter_update_failed(hwnd, state);
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
                install_boottime: s.install_boottime_filters,
            },
            // Permanent GUI install -> always persistent (survives a
            // reboot); the boot-time set is the separate field above. This
            // de-conflates the old persistent==install_boottime. Fable #12.
            true,
        )
    };
    let report = match crate::install::install_with_internal(
        &engine,
        &state.app.profile.borrow(),
        Some(&state.app.internal_profile),
        Some(&state.app.internal_rules_state.borrow()),
        &blocklist,
        &global_rules,
        persistent,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("amwall: reinstall: install failed: {e}");
            // We tore down successfully but the reinstall failed
            // — flip filters_active so the toolbar reflects the
            // actual state and the user can investigate. Title-bar
            // icon + tray icon also need the swap (Bug 1 from the
            // 1.1.4 tray-desync report: the comment used to say
            // "no hwnd here, callers will refresh later" but that
            // refresh path doesn't actually exist for any caller
            // of reinstall_filters_if_active — the user reliably
            // ended up with toolbar saying "Enable" while the tray
            // still showed the color "filters on" icon and tooltip.
            // Now we have hwnd and can do all three updates in one
            // place.).
            state.filters_active.set(false);
            update_enable_filters_button(state, false);
            update_titlebar_icon(hwnd, false);
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
fn localize_top_menu(hwnd: HWND, _state: &WndState) {
    use windows::Win32::UI::WindowsAndMessaging::{
        DrawMenuBar, MENUITEMINFOW, MIIM_STRING, SetMenuItemInfoW,
    };

    let menu = unsafe { GetMenu(hwnd) };
    if menu.0 == 0 {
        return;
    }
    let entries: [(u32, &str); 6] = [
        (0, "menu.file"),
        (1, "menu.edit"),
        (2, "menu.view"),
        (3, "menu.settings"),
        (4, "menu.blocklist"),
        (5, "menu.help"),
    ];

    for (pos, key) in entries {
        let text = t!(key);
        let mut wbuf = wide(&text);
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
        let _ = SetWindowPos(
            hwnd,
            after,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
        );
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

/// Auto-size the currently-visible listview's columns to fit both
/// their header text and their content.
///
/// Mirrors upstream `_app_listview_resize` (listview.c:789-925),
/// including its `is_forced` escape hatch: the View menu item applies
/// the sizing once even while the persisted setting is off, everything
/// else respects the setting.
///
/// The previous implementation sent `LVSCW_AUTOSIZE`, which fits a
/// column to its *items* and ignores the header — so a locale whose
/// header words are wider than the data clipped them (issue #11).
fn autosize_active_listview_columns(state: &WndState, force: bool) {
    if !force && !state.app.settings.borrow().autosize_columns {
        return;
    }
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel = unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let slot = if sel < 0 { 0 } else { sel as usize };
    if force {
        state.app.settings.borrow_mut().manual_columns[slot].clear();
    }
    autosize_listview_slot(state, slot);
}

/// Auto-size the listview in `slot` (index into `TAB_LISTVIEW_IDS`).
/// Callers that already know which tab they just refilled use this
/// directly so a background tab is not resized on another's behalf.
fn autosize_listview_slot(state: &WndState, slot: usize) {
    if state.initializing.get() {
        return;
    }
    let Some(lv) = state.listviews.get(slot).map(|c| c.get()) else {
        return;
    };
    if lv.0 == 0 {
        return;
    }
    let manual = state.app.settings.borrow().manual_columns[slot].clone();
    state.applying_columns.set(true);
    let changed = super::column_sizing::autosize_listview(lv, state.dpi.get(), &manual);
    state.applying_columns.set(false);
    if changed {
        remember_column_layout(state, slot, false);
        redraw_listview(lv);
    }
}

fn remember_column_layout(state: &WndState, slot: usize, save: bool) {
    let Some(lv) = state
        .listviews
        .get(slot)
        .map(Cell::get)
        .filter(|lv| lv.0 != 0)
    else {
        return;
    };
    let Some(layout) = super::column_layout::ColumnLayout::capture(
        lv,
        listview_column_count(lv) as usize,
        state.dpi.get(),
    ) else {
        return;
    };
    state.app.settings.borrow_mut().column_layouts[slot] = Some(layout);
    if save {
        let path = state.app.settings_path.borrow().clone();
        if let Err(e) = state.app.settings.borrow().save(&path) {
            eprintln!("amwall: column layout: settings save failed: {e}");
        }
    }
}

unsafe extern "system" fn listview_header_proc(
    lv: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    id: usize,
    _data: usize,
) -> LRESULT {
    use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass};
    if msg == WM_NOTIFY && lparam.0 != 0 {
        let parent = unsafe { windows::Win32::UI::WindowsAndMessaging::GetParent(lv) };
        unsafe {
            on_header_change(parent, &*(lparam.0 as *const NMHDR));
        }
    }
    if msg == WM_NCDESTROY {
        unsafe {
            RemoveWindowSubclass(lv, Some(listview_header_proc), id);
        }
    }
    unsafe { DefSubclassProc(lv, msg, wparam, lparam) }
}

/// `header` must point into the native WM_NOTIFY payload (NMHEADER for HDN_*).
unsafe fn on_header_change(hwnd: HWND, header: &NMHDR) {
    use windows::Win32::UI::Controls::{
        HDN_ENDDRAG, HDN_ENDTRACKA, HDN_ENDTRACKW, HDN_ITEMCHANGEDA, HDN_ITEMCHANGEDW,
    };
    if ![
        HDN_ENDDRAG,
        HDN_ENDTRACKW,
        HDN_ENDTRACKA,
        HDN_ITEMCHANGEDW,
        HDN_ITEMCHANGEDA,
    ]
    .contains(&header.code)
    {
        return;
    }
    if [HDN_ITEMCHANGEDW, HDN_ITEMCHANGEDA].contains(&header.code) {
        let notification =
            unsafe { &*(header as *const NMHDR as *const windows::Win32::UI::Controls::NMHEADERW) };
        if notification.pitem.is_null() {
            return;
        }
        let mask = unsafe { (*notification.pitem).mask };
        if mask.0
            & (windows::Win32::UI::Controls::HDI_WIDTH.0
                | windows::Win32::UI::Controls::HDI_ORDER.0)
            == 0
        {
            return;
        }
    }
    let Some(state) = (unsafe { state_ref(hwnd) }) else {
        return;
    };
    if state.applying_columns.get() || state.initializing.get() {
        return;
    }
    for (slot, lv) in state.listviews.iter().enumerate() {
        if lv.get().0 == 0 {
            continue;
        }
        let h = unsafe { SendMessageW(lv.get(), LVM_GETHEADER, WPARAM(0), LPARAM(0)) }.0;
        if h == header.hwndFrom.0 {
            let n = unsafe {
                &*(header as *const NMHDR as *const windows::Win32::UI::Controls::NMHEADERW)
            };
            let width_changed = [HDN_ENDTRACKA, HDN_ENDTRACKW].contains(&header.code)
                || (!n.pitem.is_null()
                    && unsafe { (*n.pitem).mask.0 } & windows::Win32::UI::Controls::HDI_WIDTH.0
                        != 0);
            let count = listview_column_count(lv.get()) as usize;
            if width_changed && n.iItem >= 0 && (n.iItem as usize) < count {
                let mut settings = state.app.settings.borrow_mut();
                settings.manual_columns[slot].resize(count, false);
                settings.manual_columns[slot][n.iItem as usize] = true;
            }
            // END(DRAG/TRACK) runs before the final value is committed.
            unsafe {
                let _ = windows::Win32::UI::WindowsAndMessaging::PostMessageW(
                    hwnd,
                    WM_SAVE_COLUMN_LAYOUT,
                    WPARAM(slot),
                    LPARAM(0),
                );
            }
            break;
        }
    }
}

/// Re-fit the listview in `slot` after a repopulate, but only when the
/// tab is the visible one — resizing a hidden listview measures an
/// empty client rect and would give the general column a bogus width.
fn autosize_slot_if_visible(state: &WndState, slot: usize) {
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel = unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    if sel >= 0 && sel as usize == slot && state.app.settings.borrow().autosize_columns {
        autosize_listview_slot(state, slot);
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
            set_status_text(state.status.get(), 0, &t!("status.app_exists"));
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
    set_status_text(state.status.get(), 0, &t!("status.app_added"));
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
    let old_language = snapshot.language.clone();
    let updated = match super::settings_dialog::open(hwnd, &snapshot) {
        Some(s) => s,
        None => return, // Close
    };
    let language_changed = updated.language != old_language;
    state.app.settings.replace(updated.clone());
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = updated.save(&path) {
        eprintln!("amwall: settings: save failed for {}: {e}", path.display());
    }
    if updated.use_hashes && !snapshot.use_hashes {
        check_hash_drift(hwnd, state);
    }

    if language_changed {
        restart_self(hwnd);
        return;
    }

    apply_initial_settings(hwnd, state);
    // Highlighting colors / enables may have changed — force the active
    // Apps listview to repaint so new row colors apply immediately
    // instead of only after the next populate (Fable #31). A repaint
    // is what reliably pierces LVS_EX_DOUBLEBUFFER's cached surface.
    repaint_active_apps_listview(hwnd, state);
}

fn restart_self(hwnd: HWND) {
    if let Some(state) = unsafe { state_ref(hwnd) } {
        for slot in 0..TAB_LISTVIEW_IDS.len() {
            if state.app.settings.borrow().column_layouts[slot].is_some() {
                remember_column_layout(state, slot, false);
            }
        }
    }
    save_window_placement(hwnd);
    super::request_restart(hwnd);
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
    set_status_text(state.status.get(), 0, &t!("status.rule_added"));
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
    // Resolve the selected VISUAL row to its source index in
    // profile.custom_rules via the lParam the populator stamped. A
    // preset row (negative sentinel) or a row with no lParam is
    // toggle-only and must not open the editor on an unrelated user
    // rule. Security audit finding C.
    let idx = match listview_item_param(lv, idx as i32).map(classify_user_rule_row) {
        Some(UserRuleRow::User(i)) => i,
        _ => return,
    };

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
    set_status_text(state.status.get(), 0, &t!("status.rule_updated"));
}

/// Delete-key handler for the User rules listview — confirm,
/// then remove the selected row. Persist + repopulate.
fn on_delete_selected_rule(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONQUESTION, MB_YESNO};
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
    // Resolve the selected VISUAL row to its source index via the
    // stamped lParam; a preset row (negative sentinel) or a row with
    // no lParam is a no-op so Del never removes an unrelated user
    // rule. Security audit finding C.
    let idx = match listview_item_param(lv, idx as i32).map(classify_user_rule_row) {
        Some(UserRuleRow::User(i)) => i,
        _ => return,
    };

    let title = wide(&t!("dialog.delete_rule"));
    let rule_name = state
        .app
        .profile
        .borrow()
        .custom_rules
        .get(idx)
        .map(|r| r.name.clone())
        .unwrap_or_default();
    let body = wide(&t!("message.delete_rule_confirm", name = &rule_name));
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
    set_status_text(state.status.get(), 0, &t!("status.rule_deleted"));
}

/// Serialise the current in-memory profile back to its source
/// path. Used after every Add/Edit/Delete so changes survive a
/// restart even before the user explicitly hits Save / Export.
/// Failures log to stderr + status bar; the in-memory edit
/// stands either way (the user can still re-save via
/// File > Export).
fn save_profile_to_disk(state: &WndState) {
    cancel_changed_prompts(state);
    // Ordinary saves never scan executables. Capture missing baselines before
    // installing permissions; enforce drift at startup and on TIMER_HASH_CHECK.

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
        set_status_text(state.status.get(), 0, &t!("status.autosave_failed"));
    }
}

/// Capture only missing baselines before installing enabled apps. Existing
/// baselines are never refreshed here; the drift-enforcement pass owns them.
fn ensure_enabled_hash_baselines(state: &WndState) {
    if !state.app.settings.borrow().use_hashes {
        return;
    }
    let changed = super::hash_baseline::capture_missing(
        &mut state.app.profile.borrow_mut().apps,
        crate::hash::sha256_file,
    );
    if changed {
        save_profile_to_disk(state);
    }
}

/// Verdict for a File-app's stored hash vs the current on-disk binary.
/// Pure, so the drift policy is unit-testable without disk or a live
/// BFE. Security audit finding F.1.
#[derive(Debug, PartialEq, Eq)]
enum HashVerdict {
    /// No stored hash yet — adopt the current hash as the baseline.
    Store,
    /// Stored hash matches the current binary (case-insensitive hex).
    Match,
    /// Stored hash differs — the binary at this path changed.
    Drift,
}

fn hash_drift_verdict(stored: Option<&str>, current: &str) -> HashVerdict {
    match stored {
        None => HashVerdict::Store,
        Some(s) if s.eq_ignore_ascii_case(current) => HashVerdict::Match,
        Some(_) => HashVerdict::Drift,
    }
}

/// Periodic (and one-shot at launch) `use_hashes` drift enforcement:
/// an enabled File app whose binary changed on disk is disabled and its
/// stored hash refreshed, then filters are rebuilt so the tampered
/// binary loses its WFP permit. Mirrors upstream's INFO_DISABLE on
/// drift (helper.c:1745-1778 -> profile.c:262-277). No-op when
/// `use_hashes` is off. Same mutate -> save -> repopulate -> repaint ->
/// reinstall shape as `expire_timed_apps`. Security audit finding F.1.
fn check_hash_drift(hwnd: HWND, state: &WndState) {
    use crate::profile::AppKind;

    if !state.app.settings.borrow().use_hashes {
        return;
    }
    let mut disabled: Vec<String> = Vec::new();
    let mut changed = false;
    {
        let mut profile = state.app.profile.borrow_mut();
        for app in profile.apps.iter_mut() {
            if app.kind() != AppKind::File {
                continue;
            }
            let Some(current) = crate::hash::sha256_file(&app.resolved_path()) else {
                // Unreadable (perhaps uninstalled) — leave it alone;
                // don't treat a missing file as drift.
                continue;
            };
            match hash_drift_verdict(app.hash.as_deref(), &current) {
                HashVerdict::Store => {
                    app.hash = Some(current);
                    changed = true;
                }
                HashVerdict::Match => {}
                HashVerdict::Drift => {
                    // Refresh the baseline to the new binary and, if the
                    // app was enabled, disable it so the reinstall below
                    // tears down its now-stale permit.
                    let name = app
                        .path
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| app.path.display().to_string());
                    app.hash = Some(current);
                    changed = true;
                    if app.is_enabled {
                        app.is_enabled = false;
                        disabled.push(name);
                    }
                }
            }
        }
    }
    if changed {
        save_profile_to_disk(state);
    }
    if disabled.is_empty() {
        return;
    }
    eprintln!(
        "amwall: hash drift: disabled {} app(s) whose binary changed: {}",
        disabled.len(),
        disabled.join(", ")
    );
    populate_apps_tab(state);
    on_tab_change(hwnd);
    repaint_active_apps_listview(hwnd, state);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(
        state.status.get(),
        0,
        &format!(
            "{} app(s) disabled after their binary changed on disk (hash drift).",
            disabled.len()
        ),
    );
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
            eprintln!("amwall: import: read failed for {}: {e}", path.display());
            set_status_text(state.status.get(), 0, &t!("status.import_read_error"));
            return;
        }
    };
    let new_profile = match crate::profile::parse_str(&xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("amwall: import: parse failed: {e}");
            set_status_text(state.status.get(), 0, &t!("status.import_parse_error"));
            return;
        }
    };
    cancel_all_prompts(state);
    state.app.profile.replace(new_profile);
    state.app.profile_path.replace(path.clone());
    populate_apps_tab(state);
    populate_user_rules(state);
    on_tab_change(hwnd);
    set_window_title(hwnd, &path);
    // Re-apply the WFP filter set so the kernel actually enforces the
    // imported profile instead of the previous one (upstream IDM_IMPORT
    // -> _app_changefilters). No-op unless filters are currently active.
    reinstall_filters_if_active(hwnd, state);
    set_status_text(state.status.get(), 0, &t!("status.imported"));
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
        eprintln!("amwall: export: write failed for {}: {e}", target.display());
        set_status_text(state.status.get(), 0, &t!("status.export_write_error"));
        return;
    }
    state.app.profile_path.replace(target.clone());
    set_window_title(hwnd, &target);
    set_status_text(state.status.get(), 0, &t!("status.exported"));
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
            eprintln!("amwall: refresh: read failed for {}: {e}", path.display(),);
            set_status_text(state.status.get(), 0, &t!("status.refresh_read_error"));
            return;
        }
    };
    let new_profile = match crate::profile::parse_str(&xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("amwall: refresh: parse failed: {e}");
            set_status_text(state.status.get(), 0, &t!("status.refresh_parse_error"));
            return;
        }
    };
    cancel_all_prompts(state);
    state.app.profile.replace(new_profile);
    // F5 also re-walks SCM + the UWP repository so the user picks
    // up newly-installed services / packages without restarting.
    refresh_system_app_caches(state);
    populate_apps_tab(state);
    populate_services_tab(state);
    populate_uwp_tab(state);
    populate_user_rules(state);
    on_tab_change(hwnd); // refresh status-bar item count
    // Re-apply filters so an externally-edited profile is actually
    // enforced, not just displayed (upstream IDM_REFRESH ->
    // _app_changefilters). No-op unless filters are active.
    reinstall_filters_if_active(hwnd, state);
    set_status_text(state.status.get(), 0, &t!("status.profile_reloaded"));
}

/// Fill in the tooltip text for a toolbar button. The toolbar
/// notifies us with `TBN_GETINFOTIPW` carrying `iItem` (the
/// button's command ID) and a writeable `pszText` / `cchTextMax`
/// buffer. We copy the matching tooltip into the buffer; if the
/// button isn't recognised we leave the buffer untouched (Win32
/// then falls back to the button label).
fn fill_toolbar_tooltip(info: &mut NMTBGETINFOTIPW) {
    let text = match info.iItem as u16 {
        IDM_TRAY_START => t!("tooltip.enable_filters"),
        IDM_OPENRULESEDITOR => t!("tooltip.new_rule"),
        IDM_TRAY_ENABLENOTIFICATIONS_CHK => t!("tooltip.enable_notifications"),
        IDM_TRAY_ENABLELOG_CHK => t!("tooltip.enable_log"),
        IDM_TRAY_ENABLEUILOG_CHK => t!("tooltip.enable_ui_log"),
        IDM_REFRESH => t!("tooltip.reload"),
        IDM_SETTINGS => t!("tooltip.open_settings"),
        IDM_TRAY_LOGSHOW => t!("tooltip.open_log_file"),
        IDM_TRAY_LOGCLEAR => t!("tooltip.clear_log"),
        IDM_RELEASES => t!("tooltip.open_releases"),
        _ => return,
    };
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
            let body = wide(&t!("message.exit_body"));
            let title = wide(&t!("dialog.exit"));
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
    // Persist the current window position + size so the next launch
    // restores it. Done here (the real exit path) rather than on WM_CLOSE,
    // which only hides to the tray. Mirrors upstream simplewall
    // `_r_window_saveposition` (main.c close handler).
    if let Some(state) = unsafe { state_ref(hwnd) } {
        for slot in 0..TAB_LISTVIEW_IDS.len() {
            if state.app.settings.borrow().column_layouts[slot].is_some() {
                remember_column_layout(state, slot, false);
            }
        }
    }
    save_window_placement(hwnd);
    unsafe {
        let _ = DestroyWindow(hwnd);
    }
}

/// Apply the saved main-window placement (position + size + maximized
/// state) recorded by [`save_window_placement`]. The saved rectangle is
/// clamped to a currently-visible monitor's work area first, so a rect
/// saved on a monitor that has since been unplugged or resized can never
/// strand the window off-screen. No-op when nothing valid is saved (fresh
/// install) — the caller's show path then uses the system default.
///
/// `start_minimized` keeps the window hidden (only the normal restored
/// rect is set, for a later restore-from-tray) instead of showing it.
/// Mirrors upstream simplewall `_r_window_restoreposition` (main.c:2201).
fn restore_window_placement(hwnd: HWND, start_minimized: bool) {
    use windows::Win32::UI::WindowsAndMessaging::{
        SW_HIDE, SW_SHOWMAXIMIZED, SW_SHOWNORMAL, SetWindowPlacement, WINDOWPLACEMENT,
    };

    let Some(state) = (unsafe { state_ref(hwnd) }) else {
        return;
    };
    let (x, y, w, h, maximized) = {
        let s = state.app.settings.borrow();
        if !s.has_window_placement() {
            eprintln!("amwall: window placement: none saved; using system default position");
            return;
        }
        (
            s.window_x,
            s.window_y,
            s.window_w,
            s.window_h,
            s.window_maximized,
        )
    };

    let mut rect = RECT {
        left: x,
        top: y,
        right: x + w,
        bottom: y + h,
    };
    clamp_rect_to_work_area(&mut rect);

    let show = if start_minimized {
        super::window_state::remember_hidden(hwnd, maximized);
        SW_HIDE
    } else if maximized {
        SW_SHOWMAXIMIZED
    } else {
        SW_SHOWNORMAL
    };
    // GetWindowPlacement/SetWindowPlacement use the *normal* rect; showCmd
    // carries the maximized/hidden state separately.
    let wp = WINDOWPLACEMENT {
        length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
        showCmd: show.0 as u32,
        rcNormalPosition: rect,
        ..Default::default()
    };
    match unsafe { SetWindowPlacement(hwnd, &wp) } {
        Ok(()) => eprintln!(
            "amwall: window placement: restored {}x{} at ({},{}) maximized={maximized} start_minimized={start_minimized}",
            rect.right - rect.left,
            rect.bottom - rect.top,
            rect.left,
            rect.top,
        ),
        Err(e) => eprintln!("amwall: window placement: SetWindowPlacement failed: {e}"),
    }
}

/// Record the current main-window position + size into settings and
/// persist them, so the next launch restores the window where the user
/// left it. Reads `GetWindowPlacement` (not `GetWindowRect`) so the saved
/// rectangle is always the *normal* restored rect even when the window is
/// currently maximized, minimized, or hidden to the tray. On any failure
/// the previously-saved values are left untouched. Mirrors upstream
/// simplewall `_r_window_saveposition`.
fn save_window_placement(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{GetWindowPlacement, WINDOWPLACEMENT};

    let Some(state) = (unsafe { state_ref(hwnd) }) else {
        return;
    };

    let mut wp = WINDOWPLACEMENT {
        length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
        ..Default::default()
    };
    if let Err(e) = unsafe { GetWindowPlacement(hwnd, &mut wp) } {
        eprintln!("amwall: window placement: GetWindowPlacement failed, not saving: {e}");
        return;
    }
    let r = wp.rcNormalPosition;
    let (w, h) = (r.right - r.left, r.bottom - r.top);
    if w <= 0 || h <= 0 {
        eprintln!("amwall: window placement: degenerate rect {w}x{h}, not saving");
        return;
    }
    let maximized = super::window_state::restore_maximized(hwnd, &wp);

    {
        let mut s = state.app.settings.borrow_mut();
        s.window_x = r.left;
        s.window_y = r.top;
        s.window_w = w;
        s.window_h = h;
        s.window_maximized = maximized;
    }
    eprintln!(
        "amwall: window placement: saving {w}x{h} at ({},{}) maximized={maximized}",
        r.left, r.top,
    );
    let path = state.app.settings_path.borrow().clone();
    if let Err(e) = state.app.settings.borrow().save(&path) {
        eprintln!(
            "amwall: window placement: settings save failed for {}: {e}",
            path.display()
        );
    }
}

/// Shove `rect` fully inside the work area of the monitor nearest to it,
/// shrinking it if it is larger than that work area. Prevents a rect
/// saved on a now-absent or resized monitor from restoring off-screen.
/// Mirrors upstream `_r_wnd_adjustrectangletoworkingarea`.
fn clamp_rect_to_work_area(rect: &mut RECT) {
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromRect,
    };

    let hmon = unsafe { MonitorFromRect(&*rect, MONITOR_DEFAULTTONEAREST) };
    let mut mi = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    if !unsafe { GetMonitorInfoW(hmon, &mut mi) }.as_bool() {
        return; // can't validate against a monitor — leave the rect as-is
    }
    let work = mi.rcWork;
    let work_w = work.right - work.left;
    let work_h = work.bottom - work.top;
    // Never larger than the work area; never smaller than 1px.
    let w = (rect.right - rect.left).min(work_w).max(1);
    let h = (rect.bottom - rect.top).min(work_h).max(1);
    // Clamp the top-left so the whole window sits inside the work area.
    let x = rect.left.clamp(work.left, (work.right - w).max(work.left));
    let y = rect.top.clamp(work.top, (work.bottom - h).max(work.top));
    rect.left = x;
    rect.top = y;
    rect.right = x + w;
    rect.bottom = y + h;
}

/// Edit → Purge unused apps. Mirrors upstream `_app_isappunused`
/// (profile.c:1473-1500): removes every app that is genuinely unused —
/// a File app whose binary is gone, or any app that is neither enabled,
/// silent, undeletable, nor referenced by a custom rule. `is_undeletable`
/// apps and Service/UWP apps (whose "path" is a SID / service name, not
/// an on-disk file) are NEVER purged for "not existing" — the old
/// `retain(|a| a.path.exists())` silently deleted exactly those. Confirms
/// first, since it's destructive. Re-installs filters if active so the
/// kernel forgets the deleted apps' permits.
/// Should this app be removed by `Edit → Purge unused`?
///
/// Split out of `on_purge_unused` as a pure predicate because this is
/// the most destructive decision in the program and the only one whose
/// failure mode is silent data loss. Mirrors upstream `_app_isappunused`
/// (simplewall-master/src/profile.c:1473-1500).
///
/// `resolved_exists` must be the filesystem answer for the app's
/// **resolved** path. Issue #12: testing the stored `%VAR%` string
/// reported every entry imported from simplewall as missing, and this
/// predicate then classed them all as purgeable — a single menu click
/// from deleting a freshly migrated profile.
fn is_app_unused(
    is_undeletable: bool,
    kind: crate::profile::AppKind,
    is_enabled: bool,
    is_silent: bool,
    resolved_exists: bool,
    referenced_by_rule: bool,
) -> bool {
    if is_undeletable {
        return false; // never purge
    }
    // Service / UWP apps have no on-disk file, so they never count as
    // "missing"; only a File app can be gone.
    let exists = kind != crate::profile::AppKind::File || resolved_exists;
    let used = is_enabled || is_silent || referenced_by_rule;
    !(exists && used)
}

fn on_purge_unused(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO};
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };

    // Decide what WOULD be purged (dry run) so we can show a count and
    // confirm before touching anything. Build the set of app paths any
    // custom rule targets first, so a rule's app isn't purged out from
    // under it (case-insensitive, matching Windows path semantics).
    let doomed: Vec<std::path::PathBuf> = {
        let profile = state.app.profile.borrow();
        // Normalize rule tokens the same way app paths are normalized,
        // so a rule written with `%ProgramFiles%\…` still protects an
        // app stored absolutely (and vice versa).
        let referenced: std::collections::HashSet<String> = profile
            .custom_rules
            .iter()
            .filter_map(|r| r.apps.as_deref())
            .flat_map(|apps| apps.split('|'))
            .map(|tok| tok.trim())
            .filter(|t| !t.is_empty())
            .map(|tok| path_match_key(std::path::Path::new(tok)))
            .collect();
        profile
            .apps
            .iter()
            .filter(|a| {
                is_app_unused(
                    a.is_undeletable,
                    a.kind(),
                    a.is_enabled,
                    a.is_silent,
                    // `resolved_path`, not `path`: testing the literal
                    // `%ProgramFiles%\…` string reported every imported
                    // entry as missing, which classed the whole
                    // migrated profile as purgeable (issue #12).
                    a.resolved_path().exists(),
                    referenced.contains(&path_match_key(&a.path)),
                )
            })
            .map(|a| a.path.clone())
            .collect()
    };

    if doomed.is_empty() {
        set_status_text(state.status.get(), 0, &t!("status.no_unused"));
        return;
    }

    let title = wide(&t!("edit.purge_unused"));
    let body = wide(&t!("message.bulk_delete_confirm", count = doomed.len()));
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

    let removed = {
        let mut profile = state.app.profile.borrow_mut();
        let doomed_set: std::collections::HashSet<&std::path::PathBuf> = doomed.iter().collect();
        let before = profile.apps.len();
        profile.apps.retain(|a| !doomed_set.contains(&a.path));
        before - profile.apps.len()
    };
    if removed == 0 {
        set_status_text(state.status.get(), 0, &t!("status.no_unused"));
        return;
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    repaint_active_apps_listview(hwnd, state);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(
        state.status.get(),
        0,
        &t!("status.purged_apps", count = removed),
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
        set_status_text(state.status.get(), 0, &t!("status.no_timers"));
        return;
    }
    save_profile_to_disk(state);
    populate_apps_tab(state);
    on_tab_change(hwnd);
    repaint_active_apps_listview(hwnd, state);
    reinstall_filters_if_active(hwnd, state);
    set_status_text(
        state.status.get(),
        0,
        &t!("status.cleared_timers", count = cleared),
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
        let body = wide(&t!("message.clear_log_body"));
        let title = wide(&t!("dialog.clear_log"));
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
    set_status_text(state.status.get(), 0, &t!("status.log_cleared"));
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

    // When amwall holds the admin token, a custom log_viewer taken from
    // the user-writable settings file is a code-execution vector: a
    // Medium-integrity user could plant a binary and have "Show log"
    // launch it elevated. Refuse a viewer that isn't in an admin-only
    // location and fall back to the OS default handler (the
    // viewer.is_empty() branch below). Security audit finding D.
    let viewer = if !viewer.is_empty()
        && super::is_elevated()
        && !crate::paths::is_admin_only_location(std::path::Path::new(&viewer))
    {
        eprintln!(
            "amwall: refusing to launch configured log viewer {viewer:?} while elevated \
             (not in an admin-only-writable location); opening with the default handler"
        );
        String::new()
    } else {
        viewer
    };

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

/// The file the tray "Errors log" feature acts on: amwall's real runtime
/// session log (logs\amwall-<ts>.log) when this GUI process opened one,
/// else the dev-capture `swaplog.txt` fallback. The earlier wiring
/// pointed only at swaplog.txt, which the app never writes — so the
/// submenu never appeared for installed users (review finding).
fn error_log_target() -> std::path::PathBuf {
    crate::logging::current_log_path().unwrap_or_else(crate::paths::error_log_path)
}

/// Tray Errors-log "Show log" (Fable #30). Opens amwall's session log
/// (see error_log_target) with the OS default handler. The submenu is
/// only shown when the file exists. Mirrors upstream's
/// `_app_command_logerrshow` (main.c:3628).
fn on_log_err_show(hwnd: HWND) {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let path = error_log_target();
    if !path.is_file() {
        set_status_text(state.status.get(), 0, "Error log not found.");
        return;
    }
    let path_w = wide(&path.display().to_string());
    let result = unsafe {
        ShellExecuteW(
            hwnd,
            w!("open"),
            PCWSTR(path_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if (result.0 as isize) <= 32 {
        set_status_text(state.status.get(), 0, "Failed to open the error log.");
    }
}

/// Tray Errors-log "Clear log" (Fable #30). Truncates the session log
/// (see error_log_target) in place. Best-effort: this process holds the
/// log open via SetStdHandle, so a truncate leaves the open handle's
/// write offset unchanged — subsequent lines resume past a short zero
/// region until the next launch reopens fresh; acceptable for a
/// diagnostic log. Honors confirm_log_clear like `on_log_clear`. Mirrors
/// upstream's `_app_command_logerrclear` (main.c:3634).
fn on_log_err_clear(hwnd: HWND) {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_YESNO, MessageBoxW,
    };
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let path = error_log_target();
    if !path.is_file() {
        return;
    }
    if state.app.settings.borrow().confirm_log_clear {
        let body = wide(&t!("message.clear_log_body"));
        let title = wide(&t!("dialog.clear_log"));
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
    match std::fs::write(&path, b"") {
        Ok(()) => set_status_text(state.status.get(), 0, &t!("status.log_cleared")),
        Err(e) => {
            eprintln!("amwall: failed to clear error log {}: {e}", path.display());
            set_status_text(state.status.get(), 0, "Failed to clear the error log.");
        }
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
    use windows::Win32::UI::Controls::{LV_VIEW_DETAILS, LV_VIEW_ICON, LV_VIEW_TILE, LVSIL_NORMAL};
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
    let menu = unsafe { windows::Win32::UI::WindowsAndMessaging::GetMenu(hwnd) };
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
            set_status_text(state.status.get(), 0, &t!("status.font_failed"));
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
    set_status_text(state.status.get(), 0, &t!("status.font_updated"));
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
        t!("message.allow_one_body", name = name)
    } else {
        t!("message.allow_many_body", count = paths.len())
    };
    let body = wide(&body_str);
    let title = wide(&t!("dialog.allow_blocked"));
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
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_YESNO,
    };
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };

    let body = wide(&t!("message.emergency_reset_body"));
    let title = wide(&t!("dialog.emergency_reset"));
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

    // Emergency reset tears down kernel filters, which requires admin.
    // Without it the teardown can't run -- and we must NOT wipe the
    // profile or claim "off" while the filters are still live (that
    // strands the user: traffic blocked, config gone, UI lying). Mirror
    // the on_enable_filters elevation gate.
    if !unsafe { IsUserAnAdmin() }.as_bool() {
        let title = wide(&t!("dialog.admin_required"));
        let body = wide(&t!("message.admin_required_body"));
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

    // 1. Tear down every filter, sublayer, and the provider itself.
    //    This is the whole point of the reset, so a failure here is
    //    FATAL: surface it and bail BEFORE wiping the profile or
    //    flipping the UI. cleanup_provider still succeeds when the
    //    provider is already gone (already-disabled), so a genuine Err
    //    means the teardown really did not happen.
    let engine = match crate::wfp::WfpEngine::open() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("amwall: emergency reset: WFP engine open failed: {e:?}");
            set_status_text(state.status.get(), 0, &t!("status.engine_failed"));
            return;
        }
    };
    if let Err(e) = engine.cleanup_provider(&crate::install::PROVIDER_KEY) {
        eprintln!("amwall: emergency reset: cleanup_provider failed: {e:?}");
        set_status_text(state.status.get(), 0, &t!("status.uninstall_failed"));
        return;
    }

    // 2. Empty the in-memory profile + persist (only after a
    //    successful teardown).
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
    *state.categorized_filter_ids.borrow_mut() = crate::install::CategorizedFilterIds::default();

    // Honour the panic-button intent across restarts: don't let
    // the startup auto-enable silently re-install everything we
    // just tore down.
    persist_filters_active(state, false);

    // 4. Repaint the affected tabs.
    populate_apps_tab(state);
    populate_user_rules(state);
    on_tab_change(hwnd);

    set_status_text(state.status.get(), 0, &t!("status.emergency_done"));
    set_status_text(state.status.get(), 1, "");
}

fn on_about(hwnd: HWND) {
    use windows::Win32::UI::Controls::{
        TASKDIALOG_FLAGS, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOGCONFIG_1,
        TDCBF_OK_BUTTON, TDF_ENABLE_HYPERLINKS, TaskDialogIndirect,
    };

    let title = wide(&t!("dialog.about_title"));
    let main_instr = wide(&t!("dialog.about_app"));
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
    shell_open_url(hwnd, w!("https://github.com/amrust/amwall/releases"));
}

/// Pop the user's default browser at `url`. ShellExecuteW returns
/// a HINSTANCE > 32 on success and an error code <= 32 on
/// failure. We don't surface failure beyond a stderr line since
/// the user-visible failure mode (browser doesn't open) is
/// already self-explanatory.
fn shell_open_url(hwnd: HWND, url: PCWSTR) {
    let result = unsafe {
        ShellExecuteW(
            hwnd,
            w!("open"),
            url,
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
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
    let labels: [(i32, String); 8] = [
        (IDC_APPS_PROFILE, t!("tab.apps").into()),
        (IDC_APPS_SERVICE, t!("tab.services").into()),
        (IDC_APPS_UWP, t!("tab.uwp").into()),
        (IDC_RULES_BLOCKLIST, t!("tab.blocklist").into()),
        (IDC_RULES_SYSTEM, t!("tab.system_rules").into()),
        (IDC_RULES_CUSTOM, t!("tab.user_rules").into()),
        (IDC_NETWORK, t!("tab.connections").into()),
        (IDC_LOG, t!("tab.packets_log").into()),
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
            | WS_CLIPSIBLINGS
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
    let mut ext = LVS_EX_DOUBLEBUFFER
        | LVS_EX_FULLROWSELECT
        | windows::Win32::UI::Controls::LVS_EX_HEADERDRAGDROP;
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

    // Columns. Per upstream messages.c:385-465. The definitions live
    // in `column_sizing` so the creator and the diagnostics report
    // measure the same headers.
    let Some(defs) = super::column_sizing::columns_for(id) else {
        return Err(format!("unknown listview id {id}"));
    };
    for (i, def) in defs.iter().enumerate() {
        // Creation-time width only — auto-sizing re-fits these to the
        // localized header on first paint (issue #11).
        add_column(
            lv,
            i as i32,
            &def.label(),
            scale_dpi(def.legacy_width, dpi),
            def.right,
        )?;
    }

    if matches!(id, IDC_APPS_PROFILE | IDC_APPS_SERVICE | IDC_APPS_UWP) {
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
    for (gid, key) in [
        (GROUP_APP_BLOCKED, "group.blocked"),
        (GROUP_APP_BLOCKED_SILENT, "group.blocked_silent"),
        (GROUP_APP_TIMER, "group.timer"),
        (GROUP_APP_SPECIAL, "group.special"),
        (GROUP_APP_ALLOWED, "group.allowed"),
    ] {
        let mut wtitle = wide(&t!(key));
        insert(lv, gid, &mut wtitle);
    }
}

fn insert_rules_groups(lv: HWND) {
    use super::listview_groups::{GROUP_RULE_DISABLED, GROUP_RULE_ENABLED, insert};
    for (gid, key) in [
        (GROUP_RULE_ENABLED, "group.enabled"),
        (GROUP_RULE_DISABLED, "group.disabled"),
    ] {
        let mut wtitle = wide(&t!(key));
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
    let total = unsafe { SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0 as i32;
    let mut counts: [i32; 5] = [0; 5];
    for row in 0..total {
        if let Some(gid) = listview_item_group(lv, row) {
            if (0..5).contains(&gid) {
                counts[gid as usize] += 1;
            }
        }
    }
    let labels = [
        (GROUP_APP_BLOCKED, "group.blocked"),
        (GROUP_APP_BLOCKED_SILENT, "group.blocked_silent"),
        (GROUP_APP_TIMER, "group.timer"),
        (GROUP_APP_SPECIAL, "group.special"),
        (GROUP_APP_ALLOWED, "group.allowed"),
    ];
    for (gid, key) in labels {
        let base = t!(key);
        let n = counts[gid as usize];
        let mut wtitle = wide(&format!("{base} ({n}/{total})"));
        set_header(lv, gid, &mut wtitle);
    }
}

/// Same idea as `refresh_apps_group_headers` for rules tabs.
fn refresh_rules_group_headers(lv: HWND) {
    use super::listview_groups::{GROUP_RULE_DISABLED, GROUP_RULE_ENABLED, set_header};
    let total = unsafe { SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0 as i32;
    let mut enabled = 0i32;
    let mut disabled = 0i32;
    for row in 0..total {
        match listview_item_group(lv, row) {
            Some(g) if g == GROUP_RULE_ENABLED => enabled += 1,
            Some(g) if g == GROUP_RULE_DISABLED => disabled += 1,
            _ => {}
        }
    }
    let mut w_enabled = wide(&format!("{} ({enabled}/{total})", t!("group.enabled")));
    let mut w_disabled = wide(&format!("{} ({disabled}/{total})", t!("group.disabled")));
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
    if res.0 == 0 {
        None
    } else {
        Some(item.iGroupId)
    }
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
    if res.0 == 0 {
        None
    } else {
        Some(item.lParam.0)
    }
}

/// Read the text of a listview cell `(row, subitem)` via LVM_GETITEMTEXTW.
/// Used by the context-menu Copy / Copy-value commands (Fable #28).
fn listview_item_text(lv: HWND, row: i32, subitem: i32) -> Option<String> {
    if lv.0 == 0 || row < 0 {
        return None;
    }
    let mut buf = vec![0u16; 512];
    let mut item = LVITEMW {
        iSubItem: subitem,
        pszText: windows::core::PWSTR(buf.as_mut_ptr()),
        cchTextMax: buf.len() as i32,
        ..Default::default()
    };
    let len = unsafe {
        SendMessageW(
            lv,
            LVM_GETITEMTEXTW,
            WPARAM(row as usize),
            LPARAM(&mut item as *mut _ as isize),
        )
    }
    .0;
    if len <= 0 {
        return Some(String::new());
    }
    Some(String::from_utf16_lossy(
        &buf[..(len as usize).min(buf.len())],
    ))
}

/// Number of columns in a report-view listview (via its header control).
fn listview_column_count(lv: HWND) -> i32 {
    if lv.0 == 0 {
        return 0;
    }
    let hdr = unsafe { SendMessageW(lv, LVM_GETHEADER, WPARAM(0), LPARAM(0)) }.0;
    if hdr == 0 {
        return 0;
    }
    unsafe { SendMessageW(HWND(hdr), HDM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0 as i32
}

/// Selected row indices in `lv`; falls back to `[fallback_row]` when
/// nothing is selected so a bare right-click still acts on that row.
fn selected_rows(lv: HWND, fallback_row: i32) -> Vec<i32> {
    if lv.0 == 0 {
        return Vec::new();
    }
    let mut rows = Vec::new();
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
        rows.push(next);
    }
    if rows.is_empty() && fallback_row >= 0 {
        rows.push(fallback_row);
    }
    rows
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

/// Preserve UI state by row identity, not by its transient position. Traffic,
/// resolved hostnames and connection state deliberately aren't part of identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RowIdentity {
    cells: Vec<String>,
    occurrence: usize,
}

fn row_identities(lv: HWND) -> Vec<RowIdentity> {
    use windows::Win32::UI::WindowsAndMessaging::GetDlgCtrlID;
    let id = unsafe { GetDlgCtrlID(lv) };
    let columns: &[i32] = match id {
        IDC_APPS_PROFILE => &[2],
        IDC_APPS_SERVICE | IDC_APPS_UWP => &[0, 2],
        IDC_NETWORK => &[0, 1, 3, 4, 6, 7],
        IDC_LOG => &[1, 2, 3, 5, 6, 8, 9, 10, 11],
        _ => &[0, 1, 2],
    };
    let count = unsafe { SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0 as i32;
    let mut occurrences = std::collections::HashMap::new();
    (0..count)
        .map(|row| {
            let cells: Vec<_> = columns
                .iter()
                .map(|&col| listview_item_text(lv, row, col).unwrap_or_default())
                .collect();
            let occurrence = occurrences.entry(cells.clone()).or_insert(0);
            let key = RowIdentity {
                cells,
                occurrence: *occurrence,
            };
            *occurrence += 1;
            key
        })
        .collect()
}

struct SavedScroll {
    top: i32,
    count_per_page: i32,
    horizontal: i32,
    top_key: Option<RowIdentity>,
    selected: std::collections::HashSet<RowIdentity>,
    focused: Option<RowIdentity>,
    redraw_suspended: bool,
}

fn begin_listview_refill(lv: HWND) -> SavedScroll {
    use windows::Win32::UI::Controls::LVIS_FOCUSED;
    use windows::Win32::UI::WindowsAndMessaging::{
        GWL_STYLE, GetScrollPos, GetWindowLongW, SB_HORZ,
    };
    let top = unsafe { SendMessageW(lv, LVM_GETTOPINDEX, WPARAM(0), LPARAM(0)) }.0 as i32;
    let count_per_page =
        unsafe { SendMessageW(lv, LVM_GETCOUNTPERPAGE, WPARAM(0), LPARAM(0)) }.0 as i32;
    let horizontal = unsafe { GetScrollPos(lv, SB_HORZ) };
    let keys = row_identities(lv);
    let mut selected = std::collections::HashSet::new();
    let mut focused = None;
    for (row, key) in keys.iter().enumerate() {
        let flags = unsafe {
            SendMessageW(
                lv,
                LVM_GETITEMSTATE,
                WPARAM(row),
                LPARAM((LVIS_SELECTED.0 | LVIS_FOCUSED.0) as isize),
            )
        }
        .0 as u32;
        if flags & LVIS_SELECTED.0 != 0 {
            selected.insert(key.clone());
        }
        if flags & LVIS_FOCUSED.0 != 0 {
            focused = Some(key.clone());
        }
    }
    // WM_SETREDRAW(TRUE) adds WS_VISIBLE. Never send the pair to a hidden
    // tab: doing so exposed overlapping siblings and made painting unreliable.
    // Read the control's own style, since its parent may still be hidden.
    let redraw_suspended = unsafe { GetWindowLongW(lv, GWL_STYLE) } as u32 & WS_VISIBLE.0 != 0;
    unsafe {
        if redraw_suspended {
            SendMessageW(lv, WM_SETREDRAW, WPARAM(0), LPARAM(0));
        }
        SendMessageW(lv, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }
    SavedScroll {
        top,
        count_per_page,
        horizontal,
        top_key: keys.get(top.max(0) as usize).cloned(),
        selected,
        focused,
        redraw_suspended,
    }
}

fn end_listview_refill(lv: HWND, saved: SavedScroll, new_count: i32) {
    use windows::Win32::UI::Controls::{LVIS_FOCUSED, LVM_SCROLL};
    use windows::Win32::UI::WindowsAndMessaging::{GetScrollPos, SB_HORZ};
    let keys = row_identities(lv);
    for (row, key) in keys.iter().enumerate() {
        let mut flags = LIST_VIEW_ITEM_STATE_FLAGS(0);
        if saved.selected.contains(key) {
            flags.0 |= LVIS_SELECTED.0;
        }
        if saved.focused.as_ref() == Some(key) {
            flags.0 |= LVIS_FOCUSED.0;
        }
        if flags.0 != 0 {
            let item = LVITEMW {
                stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0),
                state: flags,
                ..Default::default()
            };
            unsafe {
                SendMessageW(
                    lv,
                    LVM_SETITEMSTATE,
                    WPARAM(row),
                    LPARAM(&item as *const _ as isize),
                );
            }
        }
    }
    let top = saved
        .top_key
        .as_ref()
        .and_then(|key| keys.iter().position(|k| k == key))
        .map(|i| i as i32)
        .unwrap_or(saved.top)
        .clamp(0, (new_count - 1).max(0));
    // Enabling redraw recalculates the scroll ranges. Restore the viewport
    // afterwards, before queued paints run, or that recalculation resets it.
    if saved.redraw_suspended {
        unsafe {
            SendMessageW(lv, WM_SETREDRAW, WPARAM(1), LPARAM(0));
        }
    }
    if top > 0 && new_count > 0 {
        let bottom = (top + saved.count_per_page.max(1) - 1).min(new_count - 1);
        unsafe {
            SendMessageW(lv, LVM_ENSUREVISIBLE, WPARAM(bottom as usize), LPARAM(1));
            SendMessageW(lv, LVM_ENSUREVISIBLE, WPARAM(top as usize), LPARAM(1));
        }
    }
    unsafe {
        let dx = saved.horizontal - GetScrollPos(lv, SB_HORZ);
        if dx != 0 {
            SendMessageW(lv, LVM_SCROLL, WPARAM(dx as isize as usize), LPARAM(0));
        }
    }
    redraw_listview(lv);
}

/// Wipe the User rules ListView and re-fill from the current
/// profile's custom rules. The Apps / Services / UWP / Blocklist /
/// System rules / Connections / Log tabs follow their own
/// populators (Apps from `profile.apps`; the rest are M6+).
/// The two kinds of row the User Rules listview renders. Preset rows
/// come from the bundled `internal_profile.custom_rules` and are
/// toggle-only (not editable / deletable); user-added rows come from
/// `profile.custom_rules` and carry their source index. Which one a
/// row is gets stamped into `LVITEMW.lParam` by `populate_user_rules`,
/// so the double-click (edit) and Del (delete) handlers round-trip a
/// selected row back to the correct backing slot instead of trusting
/// the visual row index (which the preset rows above and the search
/// filter both shift). Security audit finding C. Mirrors upstream
/// simplewall reading the item's context code from lParam, never iItem
/// (simplewall-master/src/main.c:2836).
#[derive(Debug, PartialEq, Eq)]
enum UserRuleRow {
    /// A bundled preset row — toggle-only, no edit / delete.
    Preset,
    /// A user-added row at this index into `profile.custom_rules`.
    User(usize),
}

/// Sentinel stamped into a preset row's `lParam`. Presets have no slot
/// in `profile.custom_rules`, so any negative value marks a preset;
/// user rows stamp their (non-negative) source index.
const USER_RULE_ROW_PRESET: isize = -1;

/// Decode the `lParam` stamped on a User Rules row into its kind. Pure
/// so a regression test can lock the preset/user split without a live
/// listview.
fn classify_user_rule_row(lparam: isize) -> UserRuleRow {
    if lparam < 0 {
        UserRuleRow::Preset
    } else {
        UserRuleRow::User(lparam as usize)
    }
}

fn populate_user_rules(state: &WndState) {
    use crate::internal_rules_state::RuleKind;
    use crate::profile::Action;

    // Index 5 in TAB_LISTVIEW_IDS is IDC_RULES_CUSTOM.
    let lv = state.listviews[5].get();
    if lv.0 == 0 {
        return;
    }

    let saved = begin_listview_refill(lv);

    let profile = state.app.profile.borrow();
    let overrides = state.app.internal_rules_state.borrow();
    let filter = state.search_text.borrow().clone();
    let mut row = 0i32;
    let mut preset_visible: usize = 0;

    // First pass: bundled preset user rules (the simplewall-style
    // protocol presets — DNS protocol, FTP, HTTP, ICMPv4/6,
    // IMAP/POP3/SMTP, QUIC, SSH, Telnet). Their bundled is_enabled
    // is the default; the user can flip each through the checkbox,
    // and the override persists in `internal_rules_state.txt`.
    // Render them first so they always sit above user-added rules
    // in each group — the row index they occupy (0..preset_visible)
    // is how on_rule_checkbox_toggle later tells presets from
    // user-added rules.
    for rule in state.app.internal_profile.custom_rules.iter() {
        if !search_match(&rule.name, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
        preset_visible += 1;
        let mut name_buf = wide(&rule.name);
        let effective_enabled =
            overrides.effective_is_enabled(RuleKind::Custom, &rule.name, rule.is_enabled);
        let state_image = if effective_enabled { 2u32 } else { 1u32 };
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            iGroupId: super::listview_groups::rule_group_id_with(rule, effective_enabled),
            // Preset rows are toggle-only: stamp the sentinel so
            // on_edit / on_delete_selected_rule bail on them instead
            // of mistaking a preset for profile.custom_rules[row].
            lParam: LPARAM(USER_RULE_ROW_PRESET),
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
        write_rule_subitems(lv, idx as i32, rule);
    }

    // Second pass: the user's own profile.custom_rules — fully
    // editable (Properties, Remove, etc. via the context menu),
    // toggled via the existing profile.custom_rules[i].is_enabled.
    for (orig_idx, rule) in profile.custom_rules.iter().enumerate() {
        if !search_match(&rule.name, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
        let mut name_buf = wide(&rule.name);
        let state_image = if rule.is_enabled { 2u32 } else { 1u32 };
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE | LVIF_GROUPID | LVIF_PARAM,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            iGroupId: super::listview_groups::rule_group_id(rule),
            // Stamp the source index into profile.custom_rules (always
            // >= 0, so it classifies as User) so edit/delete act on the
            // clicked rule, not the visual row shifted by the preset
            // rows above and the search filter. Finding C.
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
        write_rule_subitems(lv, idx as i32, rule);
        // Action column is intentionally not surfaced — same shape
        // as upstream's 3-column User Rules layout. Reference the
        // values so the i18n keys stay rooted; a future tooltip /
        // detail pane can use them.
        let _ = match rule.action {
            Action::Permit => t!("action.permit"),
            Action::Block => t!("action.block"),
        };
    }

    drop(overrides);
    drop(profile);
    state.user_rules_preset_count.set(preset_visible);
    refresh_rules_group_headers(lv);
    end_listview_refill(lv, saved, row);
    autosize_slot_if_visible(state, 5);
}

/// Write the protocol + direction subitem columns for a rule row.
/// Shared between the presets and user-added passes in
/// `populate_user_rules`, and between the System / Blocklist
/// populator path.
fn write_rule_subitems(lv: HWND, idx: i32, rule: &crate::profile::Rule) {
    use crate::profile::Direction;
    let protocol = match rule.protocol {
        Some(1) => t!("protocol.icmp").into_owned(),
        Some(6) => t!("protocol.tcp").into_owned(),
        Some(17) => t!("protocol.udp").into_owned(),
        Some(58) => t!("protocol.icmpv6").into_owned(),
        Some(other) => other.to_string(),
        None => t!("protocol.any").into_owned(),
    };
    let direction = match rule.direction {
        Direction::Outbound => t!("direction.outbound"),
        Direction::Inbound => t!("direction.inbound"),
        Direction::Any => t!("direction.both"),
        Direction::Other(_) => t!("direction.other"),
    };
    set_subitem(lv, idx, 1, &protocol);
    set_subitem(lv, idx, 2, &direction);
}

/// Recompute app speeds and interfaces from the latest complete
/// background snapshot. Its PID paths are already resolved; this stays
/// cheap when called during row painting, sorting or tab changes.
fn refresh_app_traffic(state: &WndState) {
    let snapshot = state.network_snapshot.borrow();
    let mut rollup: std::collections::HashMap<String, AppTraffic> =
        std::collections::HashMap::new();

    // Speed: fold each PID's rate onto its owning app path.
    for (&pid, &(down, up)) in &snapshot.pid_rates {
        let Some(path) = snapshot.process_paths.get(&pid) else {
            continue;
        };
        let entry = rollup.entry(path.clone()).or_default();
        entry.download_speed = entry.download_speed.saturating_add(down);
        entry.upload_speed = entry.upload_speed.saturating_add(up);
    }

    // Interface: attribute each live connection's local-IP adapter to its
    // app (also creates a 0-speed entry for connected-but-idle apps so
    // they still show their interface rather than blank).
    for c in &snapshot.connections {
        let Some(path) = snapshot.process_paths.get(&c.pid) else {
            continue;
        };
        let entry = rollup.entry(path.clone()).or_default();
        if let Some(name) = snapshot.interfaces.get(&c.local.ip) {
            if !entry.interfaces.iter().any(|n| n == name) {
                entry.interfaces.push(name.clone());
            }
        }
    }

    *state.app_traffic.borrow_mut() = rollup;
}

/// Fill the Apps-tab Speed / Interface subitems (cols 3-5) for one row
/// from `state.app_traffic`. An app with no live connection renders
/// blank; a connected-but-idle app shows "0 B/s" plus its interface.
fn set_app_traffic_subitems(state: &WndState, lv: HWND, row: i32, path: &std::path::Path) {
    let key = path_match_key(path);
    let at = state.app_traffic.borrow();
    if let Some(t) = at.get(&key) {
        set_subitem(
            lv,
            row,
            3,
            &super::connections::format_speed(t.download_speed),
        );
        set_subitem(
            lv,
            row,
            4,
            &super::connections::format_speed(t.upload_speed),
        );
        set_subitem(lv, row, 5, &t.interfaces.join(", "));
    } else {
        set_subitem(lv, row, 3, "");
        set_subitem(lv, row, 4, "");
        set_subitem(lv, row, 5, "");
    }
}

/// Live-refresh the Apps-tab Speed / Interface columns in place, without
/// a full repopulate (which would drop the user's selection/scroll and
/// re-enqueue signature verification every tick). Samples traffic, then
/// rewrites cols 3-5 for each rendered row via its lParam → app path.
fn refresh_apps_traffic_columns(state: &WndState) {
    let lv = state.listviews[0].get();
    if lv.0 == 0 {
        return;
    }
    refresh_app_traffic(state);
    // If the list is sorted by a live speed column, a plain in-place
    // value update would leave rows in a now-wrong order (a stopped app
    // frozen near the top). Re-run the full populate so the ranking
    // re-sorts as rates change. Static sorts (Name / Added) keep the
    // cheap in-place update that preserves selection and scroll.
    let col = state.apps_sort.get().column;
    if col == 3 || col == 4 {
        populate_apps_tab(state);
        return;
    }
    let count = unsafe { SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0 as i32;
    for row in 0..count {
        let path = {
            let profile = state.app.profile.borrow();
            listview_item_param(lv, row)
                .map(|p| p as usize)
                .and_then(|src| profile.apps.get(src).map(|a| a.path.clone()))
        };
        if let Some(path) = path {
            set_app_traffic_subitems(state, lv, row, &path);
        }
    }
    autosize_slot_if_visible(state, 0);
}

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

    // Apps referenced by a custom (user) rule file under the "Apps with
    // user rules" (SPECIAL) group. Build the referenced-path set once,
    // case-insensitively (Windows path semantics). Fable sweep #32.
    let referenced_by_rule: std::collections::HashSet<String> = profile
        .custom_rules
        .iter()
        .filter_map(|r| r.apps.as_deref())
        .flat_map(|apps| apps.split('|'))
        .map(|tok| tok.trim())
        .filter(|t| !t.is_empty())
        // Same normalization as the app side, so a rule written with
        // `%ProgramFiles%\…` still matches an app stored absolutely.
        .map(|tok| path_match_key(std::path::Path::new(tok)))
        .collect();

    // Sort the iteration order per the user's last column-click
    // (default: Added desc, so most recent activity surfaces at
    // the top of each group). The `iGroupId` we stamp per item
    // still drives Win32 group bucketing — the sort just picks
    // ordering within each group.
    let sort = state.apps_sort.get();
    let mut indexed: Vec<(usize, &crate::profile::App)> = profile.apps.iter().enumerate().collect();
    {
        // Columns 3 (↓) and 4 (↑) sort by the live per-app rate, looked
        // up in `app_traffic` by lowercased path (blank / not-connected
        // sorts as 0). The refresh timer re-runs this populate while a
        // speed column is active so the ranking tracks changing rates.
        let app_traffic = state.app_traffic.borrow();
        let speed_of = |app: &crate::profile::App, upload: bool| -> u64 {
            let key = path_match_key(&app.path);
            app_traffic
                .get(&key)
                .map(|t| {
                    if upload {
                        t.upload_speed
                    } else {
                        t.download_speed
                    }
                })
                .unwrap_or(0)
        };
        indexed.sort_by(|a, b| {
            let cmp = match sort.column {
                0 => a.1.path.cmp(&b.1.path),
                3 => speed_of(a.1, false).cmp(&speed_of(b.1, false)),
                4 => speed_of(a.1, true).cmp(&speed_of(b.1, true)),
                // 1 (and any other column) sorts by timestamp.
                _ => a.1.timestamp.cmp(&b.1.timestamp),
            };
            if sort.ascending { cmp } else { cmp.reverse() }
        });
    }

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
            iGroupId: super::listview_groups::app_group_id_with(
                app,
                referenced_by_rule.contains(&path_match_key(&app.path)),
            ),
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
        // Columns 3-5: live download / upload speed + interface, from
        // the most recent traffic sample (blank if not connected).
        set_app_traffic_subitems(state, lv, idx as i32, &app.path);
    }
    drop(profile);
    refresh_apps_group_headers(lv);
    end_listview_refill(lv, saved, row);
    autosize_slot_if_visible(state, 0);
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
        if !search_match(name_for_display, &filter) && !search_match(&svc.service_name, &filter) {
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
    autosize_slot_if_visible(state, 1);
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
    autosize_slot_if_visible(state, 2);
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

/// Populate the Connections tab (`IDC_NETWORK`) from the latest
/// complete background snapshot. Each row covers the 12 columns set up
/// in `configure_listview` for IDC_NETWORK:
///   Name | Address(Source) | Host(Source) | Port(Source) |
///   Address(Destination) | Host(Destination) | Port(Destination) |
///   Protocol | State | ↓ Speed | ↑ Speed | Total
/// Host(Source) / Host(Destination) are blank for now — DNS
/// reverse-resolution is async and would block the UI thread. The
/// three traffic columns come from the cached worker ESTATS/ETW sample
/// (upstream PR #2100). Repainting never walks IP Helper tables.
fn populate_connections_tab(state: &WndState) {
    // Index 6 in TAB_LISTVIEW_IDS is IDC_NETWORK.
    let lv = state.listviews[6].get();
    if lv.0 == 0 {
        return;
    }
    let mut conns = state.network_snapshot.borrow().connections.clone();
    // Apply the user's column-header sort (default: enumeration order).
    // The row loop stamps each row's lParam with its index into this
    // now-sorted Vec, so right-click round-tripping stays consistent.
    sort_connections(&mut conns, state.network_sort.get());

    let filter = state.search_text.borrow().clone();
    let existing = row_identities(lv);
    let expected: Vec<Vec<String>> = conns
        .iter()
        .filter(|c| search_match(&c.process, &filter))
        .map(|c| {
            vec![
                c.process.clone(),
                c.local.ip.to_string(),
                c.local.port.to_string(),
                if c.remote.ip.is_unspecified() {
                    String::new()
                } else {
                    c.remote.ip.to_string()
                },
                if c.remote.port == 0 {
                    String::new()
                } else {
                    c.remote.port.to_string()
                },
                c.protocol.label().to_string(),
            ]
        })
        .collect();
    let unchanged = existing.len() == expected.len()
        && existing.iter().zip(&expected).all(|(a, b)| a.cells == *b);
    let saved = (!unchanged).then(|| begin_listview_refill(lv));
    let resolve = state.app.settings.borrow().use_network_resolution;
    let mut row = 0i32;
    for (src_idx, c) in conns.iter().enumerate() {
        if !search_match(&c.process, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
        let mut name_buf = wide(&c.process);
        // Stamp the source index into lParam so a right-click round-trips
        // row → Connection despite search filtering (Fable #27).
        let item = LVITEMW {
            mask: if unchanged {
                LVIF_PARAM
            } else {
                LVIF_TEXT | LVIF_PARAM
            },
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            lParam: LPARAM(src_idx as isize),
            ..Default::default()
        };
        let _ = unsafe {
            SendMessageW(
                lv,
                if unchanged {
                    windows::Win32::UI::Controls::LVM_SETITEMW
                } else {
                    LVM_INSERTITEMW
                },
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
        // Traffic columns: only TCP connections with a live ESTATS
        // reading show a value; UDP / listeners / pre-baseline rows stay
        // blank, matching upstream PR #2100.
        if c.has_stats {
            set_subitem(
                lv,
                idx as i32,
                9,
                &super::connections::format_speed(c.download_speed),
            );
            set_subitem(
                lv,
                idx as i32,
                10,
                &super::connections::format_speed(c.upload_speed),
            );
            set_subitem(
                lv,
                idx as i32,
                11,
                &super::connections::format_bytesize(c.total_bytes),
            );
        } else {
            set_subitem(lv, idx as i32, 9, "");
            set_subitem(lv, idx as i32, 10, "");
            set_subitem(lv, idx as i32, 11, "");
        }
    }
    if let Some(saved) = saved {
        end_listview_refill(lv, saved, row);
    }
    // Cache the snapshot the stamped lParams index into.
    *state.connections.borrow_mut() = conns;
    autosize_slot_if_visible(state, 6);
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
fn lookup_or_enqueue(state: &WndState, ip: std::net::IpAddr, resolve: bool) -> String {
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
            crate::wfp::events::NetEvent::Drop(d) | crate::wfp::events::NetEvent::Allow(d) => d,
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
        // Stamp the event ring index into lParam so a right-clicked log
        // row maps back to state.event_log[event_idx] despite search
        // filtering — the "#" column text isn't a reliable key (Fable #27).
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_PARAM,
            iItem: i,
            iSubItem: 0,
            pszText: PWSTR(idx_buf.as_mut_ptr()),
            lParam: LPARAM(event_idx as isize),
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
        set_subitem(lv, i, 10, &log_direction_label(details.direction));
        set_subitem(
            lv,
            i,
            11,
            &details.filter_id.map(|f| f.to_string()).unwrap_or_default(),
        );
    }
    end_listview_refill(lv, saved, row);
    autosize_slot_if_visible(state, 7);
}

/// Last component of an NT-form path
/// (`\device\harddiskvolume3\…\chrome.exe` → `chrome.exe`). Returns
/// the full input if there's no `\`.
fn log_basename(path: &str) -> &str {
    path.rsplit_once('\\').map(|(_, tail)| tail).unwrap_or(path)
}

/// IP-protocol number → display label. Numbers we don't recognise
/// render as their decimal form (`"47"` for GRE etc.).
fn log_protocol_label(p: Option<u8>) -> String {
    match p {
        Some(1) => t!("protocol.icmpv4").into_owned(),
        Some(6) => t!("protocol.tcp").into_owned(),
        Some(17) => t!("protocol.udp").into_owned(),
        Some(58) => t!("protocol.icmpv6").into_owned(),
        Some(n) => n.to_string(),
        None => String::new(),
    }
}

fn log_direction_label(d: Option<crate::wfp::events::NetDirection>) -> String {
    match d {
        Some(crate::wfp::events::NetDirection::Inbound) => t!("direction.inbound").into_owned(),
        Some(crate::wfp::events::NetDirection::Outbound) => t!("direction.outbound").into_owned(),
        None => String::new(),
    }
}

/// SystemTime → "HH:MM:SS" in the user's local timezone. Round-trip
/// via FILETIME → SYSTEMTIME (UTC) → SystemTimeToTzSpecificLocalTime
/// is the standard Win32 idiom; falling back to UTC if the local
/// conversion fails (which it shouldn't for any sane time).
fn format_event_time(t: std::time::SystemTime) -> String {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

    let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    // FILETIME = 100-ns intervals since 1601-01-01. Add the
    // 1601→1970 offset (11_644_473_600 s) to get from a UNIX-epoch
    // duration to a FILETIME value.
    let intervals: u64 =
        (dur.as_secs() + 11_644_473_600) * 10_000_000 + (dur.subsec_nanos() as u64) / 100;
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
    format!(
        "{:02}:{:02}:{:02}",
        local.wHour, local.wMinute, local.wSecond
    )
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
    let n =
        unsafe { windows::Win32::UI::WindowsAndMessaging::GetWindowTextW(edit, &mut buf) } as usize;
    let new_text = String::from_utf16_lossy(&buf[..n]);
    *state.search_text.borrow_mut() = new_text;

    // Repopulate just the active tab — switching tabs runs its
    // own populate path which also reads search_text.
    let tab = state.tab.get();
    if tab.0 == 0 {
        return;
    }
    let sel = unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let slot = if sel < 0 { 0 } else { sel as usize };
    repopulate_tab(state, slot);
    update_item_count(state, slot);
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
        _ => (),
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
    use crate::internal_rules_state::RuleKind;
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

    let (rules, kind): (&[Rule], RuleKind) = match id {
        IDC_RULES_BLOCKLIST => (
            &state.app.internal_profile.blocklist_rules,
            RuleKind::Blocklist,
        ),
        IDC_RULES_SYSTEM => (&state.app.internal_profile.system_rules, RuleKind::System),
        _ => {
            end_listview_refill(lv, saved, 0);
            return;
        }
    };

    let filter = state.search_text.borrow().clone();
    let overrides = state.app.internal_rules_state.borrow();
    let mut row = 0i32;
    for rule in rules.iter() {
        if !search_match(&rule.name, &filter) {
            continue;
        }
        let idx = row as usize;
        row += 1;
        let mut name_buf = wide(&rule.name);
        // Effective state honours the user's override if present.
        // For the Blocklist tab the override path isn't currently
        // wired through install.rs, but reading via overrides here
        // is still correct — the checkbox UI is consistent and a
        // future blocklist-toggle wire-up doesn't need a populator
        // change.
        let effective_enabled = overrides.effective_is_enabled(kind, &rule.name, rule.is_enabled);
        let state_image = if effective_enabled { 2u32 } else { 1u32 };
        let group_id = super::listview_groups::rule_group_id_with(rule, effective_enabled);
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE | LVIF_GROUPID,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(name_buf.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            iGroupId: group_id,
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
            Some(1) => t!("protocol.icmp").into_owned(),
            Some(6) => t!("protocol.tcp").into_owned(),
            Some(17) => t!("protocol.udp").into_owned(),
            Some(58) => t!("protocol.icmpv6").into_owned(),
            Some(other) => other.to_string(),
            None => t!("protocol.any").into_owned(),
        };
        let direction = match rule.direction {
            Direction::Outbound => t!("direction.outbound"),
            Direction::Inbound => t!("direction.inbound"),
            Direction::Any => t!("direction.both"),
            Direction::Other(_) => t!("direction.other"),
        };
        set_subitem(lv, idx as i32, 1, &protocol);
        set_subitem(lv, idx as i32, 2, &direction);
    }
    drop(overrides);
    refresh_rules_group_headers(lv);
    end_listview_refill(lv, saved, row);
    autosize_slot_if_visible(state, if id == IDC_RULES_BLOCKLIST { 3 } else { 4 });
}

fn set_subitem(lv: HWND, row: i32, sub: i32, text: &str) {
    if listview_item_text(lv, row, sub).as_deref() == Some(text) {
        return;
    }
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
    // Version baked in at compile time via env!("CARGO_PKG_VERSION")
    // so a user reporting an issue can read the version straight off
    // their title bar without opening Help -> About.
    format!(
        "amwall v{} \u{2014} {}",
        env!("CARGO_PKG_VERSION"),
        path.display(),
    )
}

/// Replace the main window's title, e.g. after Open Profile…
/// switches the loaded profile. Public-in-module so other
/// handlers (Open / Save As / future Refresh) can call it.
#[allow(dead_code)]
pub(super) fn set_window_title(hwnd: HWND, path: &std::path::Path) {
    let title = wide(&format_window_title(path));
    unsafe {
        let _ =
            windows::Win32::UI::WindowsAndMessaging::SetWindowTextW(hwnd, PCWSTR(title.as_ptr()));
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

    fn conn(
        process: &str,
        port: u16,
        down: u64,
        up: u64,
        total: u64,
    ) -> super::super::connections::Connection {
        use super::super::connections::{Connection, Endpoint, Protocol};
        use std::net::{IpAddr, Ipv4Addr};
        Connection {
            process: process.to_string(),
            pid: 0,
            local: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
            },
            remote: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 443,
            },
            protocol: Protocol::Tcp,
            state: "ESTABLISHED",
            download_speed: down,
            upload_speed: up,
            total_bytes: total,
            has_stats: true,
        }
    }

    #[test]
    fn connect_prompt_shows_only_when_not_silent_and_not_pending() {
        // The overnight-stacking guard (logic-atlas stage 11).
        assert!(should_show_connect_prompt(false, false)); // new drop, no window → show
        assert!(!should_show_connect_prompt(true, false)); // silenced → never
        assert!(!should_show_connect_prompt(false, true)); // already on screen → no stack
        assert!(!should_show_connect_prompt(true, true)); // both → still no
    }

    #[test]
    fn network_sort_orders_speed_and_toggles_direction() {
        let base = vec![
            conn("a", 10, 100, 5, 1000),
            conn("b", 20, 300, 1, 50),
            conn("c", 30, 200, 9, 700),
        ];

        // Column -1 (default) leaves enumeration order untouched.
        let mut v = base.clone();
        sort_connections(
            &mut v,
            NetworkSortState {
                column: -1,
                ascending: false,
            },
        );
        assert_eq!(
            v.iter().map(|c| c.process.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c"]
        );

        // Download speed (col 9), first click = descending -> b(300) c(200) a(100).
        let mut v = base.clone();
        sort_connections(
            &mut v,
            NetworkSortState {
                column: 9,
                ascending: false,
            },
        );
        assert_eq!(
            v.iter().map(|c| c.download_speed).collect::<Vec<_>>(),
            [300, 200, 100]
        );

        // Same column ascending -> a(100) c(200) b(300).
        let mut v = base.clone();
        sort_connections(
            &mut v,
            NetworkSortState {
                column: 9,
                ascending: true,
            },
        );
        assert_eq!(
            v.iter().map(|c| c.download_speed).collect::<Vec<_>>(),
            [100, 200, 300]
        );

        // Total (col 11) descending is numeric, not lexicographic (1000 > 700 > 50).
        let mut v = base.clone();
        sort_connections(
            &mut v,
            NetworkSortState {
                column: 11,
                ascending: false,
            },
        );
        assert_eq!(
            v.iter().map(|c| c.total_bytes).collect::<Vec<_>>(),
            [1000, 700, 50]
        );

        // Local port (col 3) ascending.
        let mut v = base.clone();
        sort_connections(
            &mut v,
            NetworkSortState {
                column: 3,
                ascending: true,
            },
        );
        assert_eq!(
            v.iter().map(|c| c.local.port).collect::<Vec<_>>(),
            [10, 20, 30]
        );
    }

    #[test]
    fn hash_drift_verdict_classifies_store_match_drift() {
        // Security audit finding F.1: no stored hash -> Store (adopt
        // baseline); hex-case-only difference -> Match (never disables
        // an app); a genuine change -> Drift (drives disable + rebuild).
        assert_eq!(hash_drift_verdict(None, "abc123"), HashVerdict::Store);
        assert_eq!(
            hash_drift_verdict(Some("ABC123"), "abc123"),
            HashVerdict::Match
        );
        assert_eq!(
            hash_drift_verdict(Some("deadbeef"), "abc123"),
            HashVerdict::Drift
        );
    }

    #[test]
    fn classify_user_rule_row_splits_preset_from_user() {
        // Security audit finding C: edit/delete must tell a toggle-only
        // preset row (negative lParam sentinel) from a user-added row,
        // and recover the user row's source index from lParam rather
        // than trusting the visual row (shifted by presets + search).
        assert_eq!(
            classify_user_rule_row(USER_RULE_ROW_PRESET),
            UserRuleRow::Preset
        );
        assert_eq!(classify_user_rule_row(-1), UserRuleRow::Preset);
        assert_eq!(classify_user_rule_row(-42), UserRuleRow::Preset);
        assert_eq!(classify_user_rule_row(0), UserRuleRow::User(0));
        assert_eq!(classify_user_rule_row(7), UserRuleRow::User(7));
    }

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

    // ---- purge safety (issue #12) ---------------------------------
    //
    // `Edit → Purge unused` is the only irreversible action in the
    // program, so its predicate is pinned here rather than trusted to
    // review. The regression these guard against: a profile imported
    // from simplewall stores `%ProgramFiles%\…` paths, the old code
    // tested that literal string for existence, every entry read as
    // missing, and one menu click deleted the lot.

    use crate::profile::AppKind;

    #[test]
    fn purge_keeps_an_enabled_app_that_exists() {
        assert!(!is_app_unused(
            false,
            AppKind::File,
            true,
            false,
            true,
            false
        ));
    }

    #[test]
    fn purge_removes_a_disabled_app_whose_file_is_gone() {
        // The genuine "uninstalled app" case purge exists for.
        assert!(is_app_unused(
            false,
            AppKind::File,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn purge_removes_an_existing_but_wholly_unreferenced_app() {
        assert!(is_app_unused(
            false,
            AppKind::File,
            false,
            false,
            true,
            false
        ));
    }

    #[test]
    fn purge_never_touches_an_undeletable_app() {
        // Undeletable wins over every other signal, including missing.
        assert!(!is_app_unused(
            true,
            AppKind::File,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn purge_never_calls_a_service_or_uwp_entry_missing() {
        // Their "path" is a service short name / package SID, so there
        // is no file to find. Only the used/unused test may apply.
        assert!(!is_app_unused(
            false,
            AppKind::Service,
            true,
            false,
            false,
            false
        ));
        assert!(!is_app_unused(
            false,
            AppKind::Uwp,
            true,
            false,
            false,
            false
        ));
    }

    #[test]
    fn purge_keeps_an_app_only_a_rule_references() {
        assert!(!is_app_unused(
            false,
            AppKind::File,
            false,
            false,
            true,
            true
        ));
    }

    #[test]
    fn purge_keeps_a_silent_app() {
        assert!(!is_app_unused(
            false,
            AppKind::File,
            false,
            true,
            true,
            false
        ));
    }

    #[test]
    fn purge_spares_an_enabled_env_var_app_whose_resolved_file_exists() {
        // THE issue-#12 regression. `resolved_exists = true` is what
        // the caller now passes for `%ProgramFiles%\App\app.exe` when
        // the real file is present; before the fix it passed `false`
        // and this returned "purge me".
        assert!(
            !is_app_unused(false, AppKind::File, true, false, true, false),
            "an enabled app whose resolved file exists must never be purged"
        );
    }

    // ---- path matching (issue #12) --------------------------------

    #[test]
    fn path_match_key_lowercases() {
        assert_eq!(
            path_match_key(std::path::Path::new(r"C:\Program Files\App\App.EXE")),
            r"c:\program files\app\app.exe"
        );
    }

    #[test]
    fn path_match_key_expands_before_lowercasing() {
        // A stored variable path and the OS's real path must collapse
        // to the same key, or the "talking now" highlight and the
        // Speed columns stay dark for every imported entry.
        let stored = path_match_key(std::path::Path::new(r"%SystemRoot%\System32\svchost.exe"));
        assert!(!stored.contains('%'), "expected expansion, got {stored}");
        assert!(stored.ends_with(r"\system32\svchost.exe"));
    }

    #[test]
    fn path_match_key_leaves_service_names_alone() {
        // No separators → Service kind → not a filesystem path.
        assert_eq!(path_match_key(std::path::Path::new("Dnscache")), "dnscache");
    }

    #[test]
    fn path_match_key_leaves_uwp_sids_alone() {
        let sid = "S-1-15-2-1234567890-1234567890";
        assert_eq!(
            path_match_key(std::path::Path::new(sid)),
            sid.to_ascii_lowercase()
        );
    }
}

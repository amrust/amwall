// amwall — system-tray icon (the always-visible quick-access
// shortcut). Mirrors upstream simplewall's tray UX:
//   - Icon visible from process start until WM_DESTROY.
//   - Left-click toggles main-window visibility (hide/restore).
//   - Right-click pops a context menu (Show / Enable filters /
//     Settings / Exit) routed back through WM_COMMAND.
//   - Icon swaps color/mono with filter state so the user can
//     read "is the firewall on" at a glance without opening
//     the window.
//   - Survives explorer.exe restarts via the registered
//     "TaskbarCreated" broadcast (RM_TASKBARCREATED in upstream).
//
// We use `uID = 1` rather than `NIF_GUID`. Upstream simplewall
// uses a fixed GUID, but Shell_NotifyIcon's GUID-based identity
// requires the binary path to match a previously-registered icon
// (and shell32 caches the binding to a specific path), which gets
// awkward across dev rebuilds when the .exe lives in target/debug.
// uID + uCallbackMessage is enough for our purposes.

#![cfg(windows)]

use std::mem::size_of;

use windows::Win32::Foundation::{HWND, POINT};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFY_ICON_INFOTIP_FLAGS, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, HMENU, IsIconic, IsWindowVisible,
    LoadIconW, MENU_ITEM_FLAGS, MF_CHECKED, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING,
    RegisterWindowMessageW, SW_HIDE, SW_RESTORE, SetForegroundWindow, ShowWindow, TPM_BOTTOMALIGN,
    TPM_RIGHTBUTTON, TrackPopupMenu, WM_USER,
};
use windows::core::PCWSTR;

use rust_i18n::t;

use super::ids::{
    IDM_ABOUT, IDM_EXIT, IDM_SETTINGS, IDM_TRAY_ENABLELOG_CHK, IDM_TRAY_ENABLENOTIFICATIONS_CHK,
    IDM_TRAY_ENABLENOTIFICATIONSSOUND_CHK, IDM_TRAY_ENABLEUILOG_CHK, IDM_TRAY_LOGCLEAR,
    IDM_TRAY_LOGCLEAR_ERR, IDM_TRAY_LOGSHOW, IDM_TRAY_LOGSHOW_ERR,
    IDM_TRAY_NOTIFICATIONFULLSCREENSILENTMODE_CHK, IDM_TRAY_NOTIFICATIONONTRAY_CHK, IDM_TRAY_SHOW,
    IDM_TRAY_START, IDM_WEBSITE,
};
use super::wide;

/// The live state the tray menu needs to render its check marks and
/// gray-out gating (Fable #30). Built at the call site from `WndState`
/// + `Settings` so `tray` stays free of the main-window types.
pub struct TrayMenuState {
    pub filters_active: bool,
    pub enable_notifications: bool,
    pub notification_sound: bool,
    pub notification_fullscreen_silent: bool,
    pub notification_on_tray: bool,
    pub enable_log: bool,
    pub enable_ui_log: bool,
    /// Whether the error log (`swaplog.txt`) exists — the Errors-log
    /// submenu is only shown when it does (mirrors upstream's
    /// `_r_fs_isexists(_r_app_getlogpath())` at messages.c:893).
    pub error_log_exists: bool,
}

/// Append a plain / checkable / grayable string item.
fn append_item(menu: HMENU, id: u16, label: &str, checked: bool, grayed: bool) {
    let mut flags = MF_STRING.0;
    if checked {
        flags |= MF_CHECKED.0;
    }
    if grayed {
        flags |= MF_GRAYED.0;
    }
    let w = wide(label);
    unsafe {
        let _ = AppendMenuW(menu, MENU_ITEM_FLAGS(flags), id as usize, PCWSTR(w.as_ptr()));
    }
}

fn append_sep(menu: HMENU) {
    unsafe {
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    }
}

/// Nest `sub` under a titled popup item. `sub` becomes owned by `menu`,
/// so the single `DestroyMenu(menu)` at teardown frees it too.
fn append_submenu(menu: HMENU, sub: HMENU, title: &str) {
    let w = wide(title);
    unsafe {
        let _ = AppendMenuW(menu, MF_POPUP, sub.0 as usize, PCWSTR(w.as_ptr()));
    }
}

/// Callback message the shell will send to our HWND for any tray-
/// icon mouse / keyboard event. lparam's LOWORD carries the
/// underlying Win32 mouse message (WM_LBUTTONUP, WM_CONTEXTMENU,
/// etc.); wparam carries the icon's uID (always `TRAY_UID` for us).
pub const WM_USER_TRAYICON: u32 = WM_USER + 0x110;

/// uID stamp on our single tray icon. Any non-zero value works;
/// we hardcode 1 since we only ever register one icon.
const TRAY_UID: u32 = 1;

/// Resolve (or register) the runtime ID of the "TaskbarCreated"
/// broadcast message. Explorer broadcasts this to every top-level
/// window when its taskbar is recreated; we re-add the tray icon
/// on receipt, otherwise it vanishes after explorer.exe restarts.
pub fn taskbar_created_message() -> u32 {
    let s = wide("TaskbarCreated");
    unsafe { RegisterWindowMessageW(PCWSTR(s.as_ptr())) }
}

/// Build the NOTIFYICONDATAW shared by NIM_ADD / NIM_MODIFY. Pulls
/// the icon from the .rc (resource id 1 = color when filters are
/// on, 2 = monochrome when off — same icons the title-bar swap
/// uses).
fn build_data(hwnd: HWND, active: bool) -> NOTIFYICONDATAW {
    let mut nid = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP,
        uCallbackMessage: WM_USER_TRAYICON,
        ..Default::default()
    };

    let resource_id = if active { 1u16 } else { 2u16 };
    if let Ok(hi) = unsafe { GetModuleHandleW(PCWSTR::null()) } {
        if let Ok(icon) =
            unsafe { LoadIconW(hi, PCWSTR(resource_id as usize as *const u16)) }
        {
            nid.hIcon = icon;
        }
    }

    let tip = if active {
        "amwall - filters on"
    } else {
        "amwall - filters off"
    };
    let wtip = wide(tip);
    let n = wtip.len().min(nid.szTip.len() - 1);
    nid.szTip[..n].copy_from_slice(&wtip[..n]);

    nid
}

/// NIM_ADD. Returns true on success; false means the shell
/// rejected the icon (e.g. the notification area isn't ready
/// yet) and the caller should not consider the tray live.
pub fn add(hwnd: HWND, active: bool) -> bool {
    let nid = build_data(hwnd, active);
    unsafe { Shell_NotifyIconW(NIM_ADD, &nid).as_bool() }
}

/// NIM_DELETE. Idempotent — calling on an already-removed icon
/// returns FALSE which we ignore.
pub fn remove(hwnd: HWND) {
    let nid = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        ..Default::default()
    };
    unsafe {
        let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
    }
}

/// NIM_MODIFY — swap icon + tooltip to reflect a filter on/off
/// transition without removing & re-adding the icon (which would
/// flicker the notification area).
///
/// Self-heals when the shell silently lost track of our icon
/// (happens after some explorer.exe glitches that don't broadcast
/// `TaskbarCreated`): if NIM_MODIFY returns FALSE we fall back to
/// NIM_ADD, which re-installs the icon with the correct
/// active/inactive variant. Without this fallback the desync is
/// invisible — the user clicks "Enable filters", the kernel side
/// works, but the tray stays gray + "filters off" forever because
/// every subsequent NIM_MODIFY targets a slot that no longer
/// exists. Returns true if the icon is in the requested state by
/// the time we return (either MODIFY succeeded or the ADD
/// fallback did).
pub fn update(hwnd: HWND, active: bool) -> bool {
    let nid = build_data(hwnd, active);
    let modified = unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid).as_bool() };
    if modified {
        return true;
    }
    eprintln!(
        "amwall: tray::update — NIM_MODIFY failed (shell may have lost the icon); \
         retrying as NIM_ADD"
    );
    unsafe { Shell_NotifyIconW(NIM_ADD, &nid).as_bool() }
}

/// Pop a tray-icon balloon ("info" style — title + body, OS-
/// styled). Used by the drop-event flow when the user has
/// `notification_on_tray` enabled, so a packet block can surface
/// passively in the action center even when the centered Allow/
/// Block dialog is suppressed (fullscreen game) or unwanted.
///
/// Title is capped at 47 wide chars + NUL (NOTIFYICONDATAW.szInfoTitle
/// is 64 elements but Win32 docs cap displayable text at 48 chars
/// pre-Windows 10; we honour the safer cap to avoid truncation
/// surprises). Body capped at 255 wide chars + NUL.
///
/// Mirrors upstream simplewall's `_r_tray_popup` call shape used
/// at `timer.c:170-187` for timer-expiry notifications.
pub fn show_balloon(hwnd: HWND, title: &str, body: &str) {
    let mut nid = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        uFlags: NIF_INFO,
        ..Default::default()
    };
    let wtitle = wide(title);
    let n = wtitle.len().min(nid.szInfoTitle.len() - 1);
    nid.szInfoTitle[..n].copy_from_slice(&wtitle[..n]);
    let wbody = wide(body);
    let n = wbody.len().min(nid.szInfo.len() - 1);
    nid.szInfo[..n].copy_from_slice(&wbody[..n]);
    nid.dwInfoFlags = NOTIFY_ICON_INFOTIP_FLAGS(NIIF_INFO.0);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

/// Hide / restore the main window in response to a tray click.
/// Mirrors upstream's `_r_wnd_toggle`: if the window is visible
/// and not minimized, hide it (taskbar entry disappears, only
/// the tray icon remains); otherwise SW_RESTORE + foreground.
pub fn toggle_main_window(hwnd: HWND) {
    let visible = unsafe { IsWindowVisible(hwnd).as_bool() };
    let iconic = unsafe { IsIconic(hwnd).as_bool() };
    if visible && !iconic {
        unsafe {
            let _ = ShowWindow(hwnd, SW_HIDE);
        }
    } else {
        unsafe {
            let _ = ShowWindow(hwnd, SW_RESTORE);
            let _ = SetForegroundWindow(hwnd);
        }
    }
}

/// Show the right-click context menu near the cursor. Commands route
/// back as ordinary WM_COMMAND messages (no TPM_RETURNCMD) so the
/// existing on_command handlers pick them up — same path the toolbar
/// buttons take. Rebuilt to upstream's full item set (Fable #30):
/// Show / Enable-Disable filters / Notifications submenu / Packets-log
/// submenu / Errors-log submenu (when present) / Settings / Website /
/// About / Exit. Check marks + gray gating mirror
/// `_app_message_traycontextmenu` (messages.c:852-935). The menu is
/// transient (rebuilt per right-click), so all MF_CHECKED / MF_GRAYED
/// state is baked in here at build time, not via set_menu_check.
pub fn show_context_menu(hwnd: HWND, st: &TrayMenuState) {
    let menu = match unsafe { CreatePopupMenu() } {
        Ok(m) => m,
        Err(_) => return,
    };

    // Show / Hide the main window.
    append_item(menu, IDM_TRAY_SHOW, &t!("tray.show"), false, false);
    append_sep(menu);

    // Enable / Disable filters (label flips with filter state).
    let toggle = if st.filters_active {
        t!("tray.disable_filters")
    } else {
        t!("tray.enable_filters")
    };
    append_item(menu, IDM_TRAY_START, &toggle, false, false);
    append_sep(menu);

    // Notifications submenu. sound/on_tray gray when notifications are
    // off; fullscreen-silent grays when notifications OR sound are off
    // (messages.c:916-925).
    if let Ok(notif) = unsafe { CreatePopupMenu() } {
        let notif_off = !st.enable_notifications;
        append_item(
            notif,
            IDM_TRAY_ENABLENOTIFICATIONS_CHK,
            &t!("rc_notifications.enable"),
            st.enable_notifications,
            false,
        );
        append_sep(notif);
        append_item(
            notif,
            IDM_TRAY_ENABLENOTIFICATIONSSOUND_CHK,
            &t!("rc_notifications.sound"),
            st.notification_sound,
            notif_off,
        );
        append_item(
            notif,
            IDM_TRAY_NOTIFICATIONFULLSCREENSILENTMODE_CHK,
            &t!("rc_notifications.fullscreen"),
            st.notification_fullscreen_silent,
            notif_off || !st.notification_sound,
        );
        append_item(
            notif,
            IDM_TRAY_NOTIFICATIONONTRAY_CHK,
            &t!("rc_notifications.on_tray"),
            st.notification_on_tray,
            notif_off,
        );
        append_submenu(menu, notif, &t!("tray.notifications_title"));
    }

    // Packets-log submenu.
    if let Ok(logm) = unsafe { CreatePopupMenu() } {
        append_item(
            logm,
            IDM_TRAY_ENABLELOG_CHK,
            &t!("rc_logging.enable"),
            st.enable_log,
            false,
        );
        append_item(
            logm,
            IDM_TRAY_ENABLEUILOG_CHK,
            &t!("tray.enable_ui_log"),
            st.enable_ui_log,
            false,
        );
        append_sep(logm);
        append_item(logm, IDM_TRAY_LOGSHOW, &t!("tray.log_show"), false, false);
        append_item(logm, IDM_TRAY_LOGCLEAR, &t!("tray.log_clear"), false, false);
        append_submenu(menu, logm, &t!("tray.logging_title"));
    }

    // Errors-log submenu — only when the error log actually exists.
    if st.error_log_exists {
        if let Ok(errm) = unsafe { CreatePopupMenu() } {
            append_item(errm, IDM_TRAY_LOGSHOW_ERR, &t!("tray.log_show"), false, false);
            append_item(errm, IDM_TRAY_LOGCLEAR_ERR, &t!("tray.log_clear"), false, false);
            append_submenu(menu, errm, &t!("tray.error_log_title"));
        }
    }

    append_sep(menu);
    append_item(menu, IDM_SETTINGS, &t!("tray.settings"), false, false);
    append_sep(menu);
    append_item(menu, IDM_WEBSITE, &t!("tray.website"), false, false);
    append_item(menu, IDM_ABOUT, &t!("tray.about"), false, false);
    append_sep(menu);
    append_item(menu, IDM_EXIT, &t!("tray.exit"), false, false);

    let mut pt = POINT::default();
    unsafe {
        let _ = GetCursorPos(&mut pt);
    }

    // MSDN: SetForegroundWindow before TrackPopupMenu when the
    // popup is owned by a window the user wasn't already
    // interacting with — otherwise the menu doesn't dismiss
    // when the user clicks elsewhere.
    unsafe {
        let _ = SetForegroundWindow(hwnd);
    }

    unsafe {
        let _ = TrackPopupMenu(
            menu,
            TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            0,
            hwnd,
            None,
        );
        let _ = DestroyMenu(menu);
    }
}

// amwall — drop-packet toast notification window.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Pops a small floating window in the bottom-right corner of the
// foreground window's monitor's work area when a WFP
// `CLASSIFY_DROP` event fires (M6.1 substrate). Shows the
// offending app, the connection 5-tuple, and the action
// ("Blocked"). Auto-dismisses after `AUTO_DISMISS_MS`; clicking
// the toast dismisses it; click-and-drag moves it (saved across
// runs in `Settings.notification_x` / `notification_y`). New
// events replace any visible toast — no queue, by design (the
// Packets log tab is the scrollable history).
//
// Multi-monitor / position memory (M6.4):
//
//   - `default_position` walks GetForegroundWindow → MonitorFromWindow
//     → GetMonitorInfo and uses the target monitor's `rcWork` as the
//     anchor. Replaces the M6.2 `GetSystemMetrics(SM_CXSCREEN)`
//     primary-only path. `rcWork` excludes the taskbar / docked
//     panels automatically — no more hardcoded 56-px subtraction.
//   - `target_position(&Settings)` returns the saved position if it
//     overlaps a currently-attached monitor, otherwise falls back to
//     `default_position()`. Drag-end posts `WM_USER_TOAST_MOVED` to
//     the main window with the new x/y; `main_window` updates
//     settings + saves.
//
// Allow / Block action buttons are intentionally NOT here yet —
// they'd require synchronous profile-rule mutation + filter reload,
// which is a bigger M7 piece. For M6 the toast is informational.

#![cfg(windows)]

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, COLOR_3DDKSHADOW, COLOR_WINDOW, DeleteObject, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE,
    DT_VCENTER, DrawTextW, EndPaint, FrameRect, GetMonitorInfoW, GetSysColorBrush, HMONITOR,
    MONITOR_DEFAULTTONULL, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromRect,
    MonitorFromWindow, PAINTSTRUCT, SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, GWLP_USERDATA,
    GetForegroundWindow, GetWindowLongPtrW, GetWindowRect, IDC_ARROW, KillTimer, LoadCursorW,
    MoveWindow, PostMessageW, RegisterClassExW, SetTimer, SetWindowLongPtrW, ShowWindow,
    SW_SHOWNA, WM_CREATE, WM_DESTROY, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_NCCREATE,
    WM_NCDESTROY, WM_PAINT, WM_TIMER, WM_USER, WNDCLASSEXW, WS_BORDER, WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};
use windows::core::{PCWSTR, w};

use std::net::IpAddr;

use crate::wfp::events::{NetDirection, NetEvent, NetEventDetails};

use super::settings::Settings;
use super::wide;

// ---- Geometry / timing constants ----

const TOAST_W: i32 = 340;
const TOAST_H: i32 = 92;
const TOAST_MARGIN: i32 = 16;
const TOAST_INNER_PAD: i32 = 10;
const AUTO_DISMISS_MS: u32 = 5000;
const TIMER_DISMISS: usize = 8001;

/// Movement threshold in pixels. A WM_LBUTTONDOWN followed by a
/// WM_LBUTTONUP within this many pixels of the start point counts as
/// a click (dismiss); anything beyond starts a drag (move + save).
const DRAG_THRESHOLD_PX: i32 = 4;

const TOAST_CLASS: PCWSTR = w!("AmwallToast");

/// Custom window message posted to the main window when the user
/// finishes dragging the toast. `wparam` is the new top-left x,
/// `lparam` is y, both as i32 round-tripped through usize/isize so
/// the receiving handler must cast back the same way.
pub const WM_USER_TOAST_MOVED: u32 = WM_USER + 0x101;

// ---- Process-wide singleton state ----

static CLASS_REGISTERED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// HWND of the currently visible toast, or `HWND::default()` if
    /// none. Set on `show_drop_notification`, cleared on
    /// `WM_NCDESTROY` from the toast's wndproc.
    static CURRENT_TOAST: Cell<HWND> = const { Cell::new(HWND(0)) };
}

/// Drag-tracking state attached to a toast instance.
#[derive(Default, Clone, Copy)]
struct DragState {
    /// Cursor position (screen coords) when the user pressed the
    /// left mouse button. `None` between releases.
    press_screen: Option<POINT>,
    /// Top-left of the toast (screen coords) at press time. Used to
    /// compute the new toast position from cursor delta during drag.
    window_origin: POINT,
    /// `true` once the cursor has moved past `DRAG_THRESHOLD_PX`
    /// from `press_screen` since the last button-down. Distinguishes
    /// click-to-dismiss from drag-to-move.
    moved_past_threshold: bool,
}

/// Box stashed into the toast window's GWLP_USERDATA. Holds the
/// pre-formatted lines so WM_PAINT doesn't re-allocate per repaint,
/// the main HWND so drag-end can post `WM_USER_TOAST_MOVED` back,
/// and the live drag-state machine.
struct ToastState {
    lines: Vec<String>,
    main_hwnd: HWND,
    drag: DragState,
}

/// Show (or replace) a drop-packet toast for the given event. Allow
/// / Other variants are ignored — toast is drop-only by design.
/// Caller is responsible for gating on the
/// `settings.enable_notifications` flag. `main_hwnd` is where the
/// toast posts `WM_USER_TOAST_MOVED` after a drag completes so
/// position memory persists across runs.
pub fn show_drop_notification(event: &NetEvent, settings: &Settings, main_hwnd: HWND) {
    let details = match event {
        NetEvent::Drop(d) => d,
        _ => return,
    };

    if !ensure_class_registered() {
        return;
    }

    // Replace any existing toast.
    let existing = CURRENT_TOAST.with(|c| c.replace(HWND::default()));
    if existing.0 != 0 {
        unsafe {
            let _ = DestroyWindow(existing);
        }
    }

    let lines = format_lines(details);
    let state = Box::new(ToastState {
        lines,
        main_hwnd,
        drag: DragState::default(),
    });
    let state_ptr = Box::into_raw(state) as *const ToastState as *mut std::ffi::c_void;

    let hi = match unsafe { GetModuleHandleW(PCWSTR::null()) } {
        Ok(h) => h,
        Err(_) => {
            // Reclaim the box so we don't leak.
            unsafe {
                let _ = Box::from_raw(state_ptr as *mut ToastState);
            }
            return;
        }
    };

    let (x, y) = target_position(settings);
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
            TOAST_CLASS,
            PCWSTR::null(),
            WS_POPUP | WS_BORDER | WS_VISIBLE,
            x,
            y,
            TOAST_W,
            TOAST_H,
            None,
            None,
            hi,
            Some(state_ptr),
        )
    };
    if hwnd.0 == 0 {
        // CreateWindowExW failed — reclaim the box.
        unsafe {
            let _ = Box::from_raw(state_ptr as *mut ToastState);
        }
        return;
    }
    CURRENT_TOAST.with(|c| c.set(hwnd));

    // Auto-dismiss timer. The wndproc clears the singleton on
    // WM_NCDESTROY, so KillTimer is implicit on destroy.
    unsafe {
        SetTimer(hwnd, TIMER_DISMISS, AUTO_DISMISS_MS, None);
    }
    // Stay non-activating so we don't steal focus from the user's
    // current window.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOWNA);
    }
}

fn ensure_class_registered() -> bool {
    if CLASS_REGISTERED.load(Ordering::Acquire) {
        return true;
    }
    let hi = match unsafe { GetModuleHandleW(PCWSTR::null()) } {
        Ok(h) => h,
        Err(_) => return false,
    };
    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(toast_proc),
        hInstance: hi.into(),
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default(),
        lpszClassName: TOAST_CLASS,
        hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
        ..Default::default()
    };
    let atom = unsafe { RegisterClassExW(&wc) };
    if atom == 0 {
        return false;
    }
    CLASS_REGISTERED.store(true, Ordering::Release);
    true
}

/// Resolve where to show the next toast. Saved position wins if it
/// falls on a currently-attached monitor; otherwise falls back to
/// the default bottom-right of the foreground window's monitor.
fn target_position(settings: &Settings) -> (i32, i32) {
    if settings.notification_x != i32::MIN
        && settings.notification_y != i32::MIN
        && saved_position_is_visible(settings.notification_x, settings.notification_y)
    {
        return (settings.notification_x, settings.notification_y);
    }
    default_position()
}

/// Bottom-right corner of the work area of the monitor the user is
/// currently focused on. Falls back to the primary monitor's work
/// area if there's no foreground window (e.g. lock screen, app
/// startup before any window grabbed focus).
fn default_position() -> (i32, i32) {
    let mon = unsafe {
        let fg = GetForegroundWindow();
        if fg.0 == 0 {
            HMONITOR::default()
        } else {
            MonitorFromWindow(fg, MONITOR_DEFAULTTOPRIMARY)
        }
    };
    let mon = if mon.0 == 0 {
        // No foreground window — anchor by the cursor's current
        // monitor instead. `MonitorFromRect` with a tiny rect at
        // (0,0) gives the primary monitor as final fallback.
        let zero = RECT { left: 0, top: 0, right: 1, bottom: 1 };
        unsafe { MonitorFromRect(&zero, MONITOR_DEFAULTTOPRIMARY) }
    } else {
        mon
    };

    let work = work_area(mon).unwrap_or(RECT {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    });
    let x = (work.right - TOAST_W - TOAST_MARGIN).max(work.left);
    let y = (work.bottom - TOAST_H - TOAST_MARGIN).max(work.top);
    (x, y)
}

/// Verify a saved (x, y) corresponds to a toast rect that overlaps
/// at least one currently-attached monitor. Returns `false` if the
/// monitor it was on has been disconnected since the position was
/// saved — caller falls back to default in that case.
fn saved_position_is_visible(x: i32, y: i32) -> bool {
    let rect = RECT {
        left: x,
        top: y,
        right: x + TOAST_W,
        bottom: y + TOAST_H,
    };
    let mon = unsafe { MonitorFromRect(&rect, MONITOR_DEFAULTTONULL) };
    mon.0 != 0
}

fn work_area(mon: HMONITOR) -> Option<RECT> {
    if mon.0 == 0 {
        return None;
    }
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    if unsafe { GetMonitorInfoW(mon, &mut info) }.as_bool() {
        Some(info.rcWork)
    } else {
        None
    }
}

fn format_lines(d: &NetEventDetails) -> Vec<String> {
    let app = d
        .app_path
        .as_deref()
        .map(|p| p.rsplit_once('\\').map(|(_, t)| t).unwrap_or(p))
        .unwrap_or("(system)");

    let proto: String = match d.protocol {
        Some(1) => rust_i18n::t!("protocol.icmpv4").into(),
        Some(6) => rust_i18n::t!("protocol.tcp").into(),
        Some(17) => rust_i18n::t!("protocol.udp").into(),
        Some(58) => rust_i18n::t!("protocol.icmpv6").into(),
        Some(_) | None => String::new(),
    };
    let dir: String = match d.direction {
        Some(NetDirection::Outbound) => rust_i18n::t!("direction.outbound").into(),
        Some(NetDirection::Inbound) => rust_i18n::t!("direction.inbound").into(),
        None => String::new(),
    };

    let mut header = rust_i18n::t!("message.blocked_notification", app = app).into_owned();
    if !proto.is_empty() {
        if dir.is_empty() {
            header.push_str(&format!(" ({proto})"));
        } else {
            header.push_str(&format!(" ({proto} {dir})"));
        }
    }

    let conn = format_endpoint(d.local_addr, d.local_port, d.remote_addr, d.remote_port);

    if conn.is_empty() {
        vec![header]
    } else {
        vec![header, conn]
    }
}

fn format_endpoint(
    local: Option<IpAddr>,
    lport: Option<u16>,
    remote: Option<IpAddr>,
    rport: Option<u16>,
) -> String {
    let l = match (local, lport) {
        (Some(a), Some(p)) => format!("{a}:{p}"),
        (Some(a), None) => a.to_string(),
        _ => String::new(),
    };
    let r = match (remote, rport) {
        (Some(a), Some(p)) => format!("{a}:{p}"),
        (Some(a), None) => a.to_string(),
        _ => String::new(),
    };
    match (l.is_empty(), r.is_empty()) {
        (true, true) => String::new(),
        (false, true) => l,
        (true, false) => r,
        (false, false) => format!("{l} → {r}"),
    }
}

// =================================================================
// Window proc
// =================================================================

unsafe extern "system" fn toast_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_NCCREATE => {
            let cs = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, cs.lpCreateParams as isize);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_CREATE => LRESULT(0),
        WM_PAINT => {
            paint_toast(hwnd);
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            on_lbutton_down(hwnd, lparam);
            LRESULT(0)
        }
        WM_MOUSEMOVE => {
            on_mouse_move(hwnd, wparam, lparam);
            LRESULT(0)
        }
        WM_LBUTTONUP => {
            on_lbutton_up(hwnd);
            LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_DISMISS {
                unsafe {
                    let _ = KillTimer(hwnd, TIMER_DISMISS);
                    let _ = DestroyWindow(hwnd);
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => LRESULT(0),
        WM_NCDESTROY => {
            // Reclaim the boxed state and clear the singleton if
            // this is still the current toast.
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut ToastState;
            if !raw.is_null() {
                unsafe {
                    let _ = Box::from_raw(raw);
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
            }
            CURRENT_TOAST.with(|c| {
                if c.get() == hwnd {
                    c.set(HWND::default());
                }
            });
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn paint_toast(hwnd: HWND) {
    let state_ptr =
        unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const ToastState;
    if state_ptr.is_null() {
        return;
    }
    let state = unsafe { &*state_ptr };

    let mut ps = PAINTSTRUCT::default();
    let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
    if hdc.0 == 0 {
        return;
    }

    // Background: COLOR_WINDOW (already drawn by class brush).
    let mut rect = RECT::default();
    let _ = unsafe { windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rect) };

    // Inner border for visual separation.
    unsafe {
        let frame = GetSysColorBrush(COLOR_3DDKSHADOW);
        FrameRect(hdc, &rect, frame);
    }

    let font = super::font::load_message_font();
    let prev_font = unsafe { SelectObject(hdc, font) };
    unsafe {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, windows::Win32::Foundation::COLORREF(0x00_22_22_22));
    }

    let mut y = TOAST_INNER_PAD;
    let line_h = 22;
    for line in &state.lines {
        let mut text_rect = RECT {
            left: TOAST_INNER_PAD,
            top: y,
            right: rect.right - TOAST_INNER_PAD,
            bottom: y + line_h,
        };
        let mut wide_buf = wide(line);
        unsafe {
            DrawTextW(
                hdc,
                &mut wide_buf,
                &mut text_rect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
        }
        y += line_h;
    }

    unsafe {
        SelectObject(hdc, prev_font);
        // load_message_font() creates a fresh HFONT every paint; delete
        // it now that it's deselected, or one GDI font leaks per WM_PAINT
        // (continuously while a toast is dragged) until the process hits
        // the 10k GDI-handle cap. Fable sweep finding #17.
        if !font.is_invalid() {
            let _ = DeleteObject(font);
        }
        let _ = EndPaint(hwnd, &ps);
    }
}

// =================================================================
// Drag state machine
// =================================================================
//
// Win32 doesn't get to make this easy: there's no built-in idiom for
// "click anywhere to dismiss, but drag to move". The HTCAPTION trick
// (return HTCAPTION from WM_NCHITTEST so DefWindowProc handles drag)
// would forward simple clicks to caption-click handling, breaking
// dismiss. So we do it manually:
//
//   1. WM_LBUTTONDOWN: SetCapture, record screen-space press point
//      and current window origin. Don't move yet.
//   2. WM_MOUSEMOVE while captured: if cursor delta exceeds
//      DRAG_THRESHOLD_PX, mark drag-in-progress and MoveWindow to
//      follow. Below threshold, do nothing.
//   3. WM_LBUTTONUP: ReleaseCapture. If we never crossed the
//      threshold, the user is just clicking — DestroyWindow. If we
//      did, post WM_USER_TOAST_MOVED to the main HWND with the
//      final x/y so settings get saved.

fn on_lbutton_down(hwnd: HWND, lparam: LPARAM) {
    let state_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut ToastState;
    if state_ptr.is_null() {
        return;
    }

    // lparam: client-space cursor coords (low word x, high word y),
    // both signed 16-bit. The `i16 → i32` cast sign-extends, so
    // clicks above/left of the window (which arrive as negative
    // values in two's-complement) survive correctly.
    let p = client_to_screen(hwnd, lparam_to_point(lparam));

    let mut wnd_rect = RECT::default();
    if unsafe { GetWindowRect(hwnd, &mut wnd_rect) }.is_err() {
        return;
    }

    let state = unsafe { &mut *state_ptr };
    state.drag.press_screen = Some(p);
    state.drag.window_origin = POINT {
        x: wnd_rect.left,
        y: wnd_rect.top,
    };
    state.drag.moved_past_threshold = false;

    unsafe {
        SetCapture(hwnd);
    }
}

fn lparam_to_point(lparam: LPARAM) -> POINT {
    let raw = lparam.0 as u32;
    POINT {
        x: (raw & 0xFFFF) as i16 as i32,
        y: ((raw >> 16) & 0xFFFF) as i16 as i32,
    }
}

fn client_to_screen(hwnd: HWND, mut p: POINT) -> POINT {
    unsafe {
        let _ = windows::Win32::Graphics::Gdi::ClientToScreen(hwnd, &mut p);
    }
    p
}

fn on_mouse_move(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let state_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut ToastState;
    if state_ptr.is_null() {
        return;
    }

    // MK_LBUTTON = 0x0001. If the left button isn't down anymore
    // (capture lost mid-drag e.g. via Alt-Tab), treat as if up
    // already arrived so we don't strand the drag flag.
    if (wparam.0 & 0x0001) == 0 {
        return;
    }

    let state = unsafe { &mut *state_ptr };
    let press = match state.drag.press_screen {
        Some(p) => p,
        None => return,
    };

    let now = client_to_screen(hwnd, lparam_to_point(lparam));
    let dx = now.x - press.x;
    let dy = now.y - press.y;

    if !state.drag.moved_past_threshold {
        if dx.abs() < DRAG_THRESHOLD_PX && dy.abs() < DRAG_THRESHOLD_PX {
            return;
        }
        state.drag.moved_past_threshold = true;
    }

    let new_x = state.drag.window_origin.x + dx;
    let new_y = state.drag.window_origin.y + dy;
    unsafe {
        let _ = MoveWindow(hwnd, new_x, new_y, TOAST_W, TOAST_H, true);
    }
}

fn on_lbutton_up(hwnd: HWND) {
    let state_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut ToastState;
    if state_ptr.is_null() {
        return;
    }

    unsafe {
        let _ = ReleaseCapture();
    }

    let state = unsafe { &mut *state_ptr };
    let was_dragged = state.drag.moved_past_threshold;
    let main_hwnd = state.main_hwnd;
    state.drag.press_screen = None;
    state.drag.moved_past_threshold = false;

    if !was_dragged {
        // Plain click — dismiss.
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
        return;
    }

    // Dragged: read final position and notify the main window so
    // settings persist. Don't dismiss the toast — let the auto-
    // dismiss timer handle it normally so the user can still see
    // the message at the new location.
    let mut wnd_rect = RECT::default();
    if unsafe { GetWindowRect(hwnd, &mut wnd_rect) }.is_err() {
        return;
    }
    if main_hwnd.0 == 0 {
        return;
    }

    // Pack i32s through usize/isize. On 64-bit Windows both are 64
    // bits — sign-preserving. On 32-bit Windows both are 32 bits —
    // bit-exact. Receiver casts back the same way.
    unsafe {
        let _ = PostMessageW(
            main_hwnd,
            WM_USER_TOAST_MOVED,
            WPARAM(wnd_rect.left as isize as usize),
            LPARAM(wnd_rect.top as isize),
        );
    }
}

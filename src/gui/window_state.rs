//! Restore the last normal/maximized state without treating every reveal as a restore.
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::UI::WindowsAndMessaging::{
    GetPropW, GetWindowPlacement, IsIconic, IsWindowVisible, RemovePropW, SW_HIDE, SW_RESTORE,
    SW_SHOW, SW_SHOWMAXIMIZED, SW_SHOWMINIMIZED, SetForegroundWindow, SetPropW, ShowWindow,
    WINDOWPLACEMENT, WPF_RESTORETOMAXIMIZED,
};
use windows::core::w;

/// A window started hidden has no Win32 maximized state yet. Keep that intended
/// state on the window itself until the first reveal, also covering tray hides.
pub(super) fn remember_hidden(hwnd: HWND, maximized: bool) {
    unsafe {
        let _ = SetPropW(
            hwnd,
            w!("Amwall.HiddenMaximized"),
            HANDLE(if maximized { 2 } else { 1 }),
        );
    }
}

fn placement_maximized(placement: &WINDOWPLACEMENT) -> bool {
    placement.showCmd == SW_SHOWMAXIMIZED.0 as u32
        || (placement.showCmd == SW_SHOWMINIMIZED.0 as u32
            && placement.flags.0 & WPF_RESTORETOMAXIMIZED.0 != 0)
}

/// Maximization survives both minimizing to the taskbar and hiding to the tray.
pub(super) fn restore_maximized(hwnd: HWND, placement: &WINDOWPLACEMENT) -> bool {
    if !unsafe { IsWindowVisible(hwnd) }.as_bool() {
        match unsafe { GetPropW(hwnd, w!("Amwall.HiddenMaximized")) }.0 {
            1 => return false,
            2 => return true,
            _ => {}
        }
    }
    placement_maximized(placement)
}

pub(super) fn hide(hwnd: HWND) {
    let mut placement = WINDOWPLACEMENT {
        length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
        ..Default::default()
    };
    if unsafe { GetWindowPlacement(hwnd, &mut placement) }.is_ok() {
        remember_hidden(hwnd, restore_maximized(hwnd, &placement));
    }
    unsafe {
        let _ = ShowWindow(hwnd, SW_HIDE);
    }
}

pub(super) fn show(hwnd: HWND) {
    let mut placement = WINDOWPLACEMENT {
        length: std::mem::size_of::<WINDOWPLACEMENT>() as u32,
        ..Default::default()
    };
    let command = if unsafe { IsIconic(hwnd) }.as_bool() {
        // Windows honors WPF_RESTORETOMAXIMIZED for a minimized window.
        SW_RESTORE
    } else if !unsafe { IsWindowVisible(hwnd) }.as_bool()
        && unsafe { GetWindowPlacement(hwnd, &mut placement) }.is_ok()
        && restore_maximized(hwnd, &placement)
    {
        SW_SHOWMAXIMIZED
    } else {
        // SW_RESTORE here would unmaximize an already maximized hidden window.
        SW_SHOW
    };
    unsafe {
        let _ = RemovePropW(hwnd, w!("Amwall.HiddenMaximized"));
        let _ = ShowWindow(hwnd, command);
        let _ = SetForegroundWindow(hwnd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    #[test]
    fn minimized_maximized_window_keeps_its_restore_state() {
        let mut placement = WINDOWPLACEMENT {
            showCmd: SW_SHOWMAXIMIZED.0 as u32,
            ..Default::default()
        };
        assert!(placement_maximized(&placement));
        placement.showCmd = SW_SHOWMINIMIZED.0 as u32;
        assert!(!placement_maximized(&placement));
        placement.flags = WPF_RESTORETOMAXIMIZED;
        assert!(placement_maximized(&placement));
        placement.showCmd = SW_SHOWNORMAL.0 as u32;
        assert!(
            !placement_maximized(&placement),
            "a restored normal window wins over stale flags"
        );
    }

    #[test]
    fn hidden_startup_retains_maximized_intent_without_showing_a_window() {
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, HMENU, WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW,
        };
        unsafe {
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("amwall placement regression"),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                300,
                200,
                HWND::default(),
                HMENU::default(),
                None,
                None,
            );
            assert_ne!(hwnd.0, 0);
            let placement = WINDOWPLACEMENT {
                showCmd: SW_HIDE.0 as u32,
                ..Default::default()
            };
            remember_hidden(hwnd, true);
            assert!(restore_maximized(hwnd, &placement));
            hide(hwnd);
            assert!(restore_maximized(hwnd, &placement));
            assert!(!IsWindowVisible(hwnd).as_bool());
            remember_hidden(hwnd, false);
            assert!(!restore_maximized(hwnd, &placement));
            let _ = DestroyWindow(hwnd);
        }
    }

    #[test]
    fn native_tray_reveal_and_taskbar_restore_keep_maximization() {
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, HMENU, IsZoomed, SW_MINIMIZE, WINDOW_EX_STYLE,
            WS_CHILD, WS_OVERLAPPEDWINDOW,
        };
        unsafe {
            // A hidden ancestor lets us exercise real show/minimize/maximize
            // transitions without exposing test windows on the user's desktop.
            let parent = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("placement parent"),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                800,
                600,
                HWND::default(),
                HMENU::default(),
                None,
                None,
            );
            assert_ne!(parent.0, 0);
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("placement child"),
                WS_OVERLAPPEDWINDOW | WS_CHILD,
                0,
                0,
                300,
                200,
                parent,
                HMENU::default(),
                None,
                None,
            );
            assert_ne!(hwnd.0, 0);
            let _ = ShowWindow(hwnd, SW_SHOWMAXIMIZED);
            assert!(IsZoomed(hwnd).as_bool());
            hide(hwnd);
            show(hwnd);
            assert!(
                IsZoomed(hwnd).as_bool(),
                "tray reveal must not normalize maximized windows"
            );
            let _ = ShowWindow(hwnd, SW_MINIMIZE);
            assert!(IsIconic(hwnd).as_bool());
            show(hwnd);
            assert!(
                IsZoomed(hwnd).as_bool(),
                "minimized windows retain maximized restore state"
            );
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
            hide(hwnd);
            show(hwnd);
            assert!(
                !IsZoomed(hwnd).as_bool(),
                "restored normal size must remain normal"
            );
            let _ = DestroyWindow(parent);
        }
    }
}

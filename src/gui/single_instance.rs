//! A GUI owns one profile/WFP writer per desktop session and elevation level.
//! Reopening a shortcut requests activation on the existing window's own thread.
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    BOOL, CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM, WAIT_ABANDONED,
    WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM,
};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, ChangeWindowMessageFilterEx, EnumWindows, GetPropW,
    GetWindowThreadProcessId, MSGFLT_ALLOW, PostMessageW, RegisterWindowMessageW, SetPropW,
};
use windows::core::{PCWSTR, w};

pub(super) fn activation_message() -> u32 {
    static MESSAGE: OnceLock<u32> = OnceLock::new();
    *MESSAGE.get_or_init(|| unsafe {
        RegisterWindowMessageW(w!(
            "Amwall.ActivateExisting.35AAB182-BC0A-4360-9731-5A3AA2F69C8B"
        ))
    })
}

struct Search {
    elevated: bool,
    window: HWND,
    priority: isize,
}

unsafe extern "system" fn find_window(hwnd: HWND, data: LPARAM) -> BOOL {
    let search = unsafe { &mut *(data.0 as *mut Search) };
    let level = unsafe { GetPropW(hwnd, w!("Amwall.GuiElevation")) }.0;
    // An elevated restart must not be swallowed by the unelevated process that
    // requested it. An ordinary shortcut can always reveal the elevated GUI.
    if matches!(level, 1 | 2) && (!search.elevated || level == 2) && level > search.priority {
        search.window = hwnd;
        search.priority = level;
    }
    BOOL(1)
}

/// Call before elevation prompts/tasks so an ordinary shortcut can reveal the
/// already-running elevated GUI without producing another UAC prompt.
pub(super) fn try_activate(elevated: bool) -> bool {
    let message = activation_message();
    if message == 0 {
        return false;
    }
    let mut search = Search {
        elevated,
        window: HWND::default(),
        priority: 0,
    };
    unsafe {
        let _ = EnumWindows(
            Some(find_window),
            LPARAM(&mut search as *mut Search as isize),
        );
        if search.window.0 == 0 {
            return false;
        }
        let mut pid = 0;
        GetWindowThreadProcessId(search.window, Some(&mut pid));
        if pid != 0 {
            let _ = AllowSetForegroundWindow(pid);
        }
        PostMessageW(search.window, message, WPARAM(0), LPARAM(0)).is_ok()
    }
}

pub(super) struct InstanceGuard {
    handle: HANDLE,
    owned: bool,
    // Windows mutex ownership belongs to the acquiring thread. Keep Drop on
    // that thread so it can release ownership before closing the final handle.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe {
            if self.owned {
                let _ = ReleaseMutex(self.handle);
            }
            let _ = CloseHandle(self.handle);
        }
    }
}

impl InstanceGuard {
    /// Bind only after creation succeeds. The only lower-integrity message we
    /// permit merely reveals the window; it never changes firewall state.
    pub(super) fn bind(&self, hwnd: HWND, elevated: bool) {
        unsafe {
            let _ = SetPropW(
                hwnd,
                w!("Amwall.GuiElevation"),
                HANDLE(if elevated { 2 } else { 1 }),
            );
            let message = activation_message();
            if message != 0 {
                let _ = ChangeWindowMessageFilterEx(hwnd, message, MSGFLT_ALLOW, None);
            }
        }
    }
}

/// Acquire after the elevation handoff, before reading/writing the profile or
/// starting WFP/ETW. Keep the returned guard alive for the complete message loop.
/// None means that the existing process was activated and this launch can exit.
pub(super) fn acquire(elevated: bool) -> Result<Option<InstanceGuard>, String> {
    let name = if elevated {
        w!("Local\\Amwall.Gui.Elevated.35AAB182-BC0A-4360-9731-5A3AA2F69C8B")
    } else {
        w!("Local\\Amwall.Gui.User.35AAB182-BC0A-4360-9731-5A3AA2F69C8B")
    };
    acquire_named(name, || try_activate(elevated))
}

fn acquire_named(
    name: PCWSTR,
    mut activate: impl FnMut() -> bool,
) -> Result<Option<InstanceGuard>, String> {
    let mutex = unsafe { CreateMutexW(None, true, name) }
        .map_err(|e| format!("Cannot open the amwall instance guard: {e}"))?;
    let already_running = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let mut guard = InstanceGuard {
        handle: mutex,
        owned: !already_running,
        _thread: std::marker::PhantomData,
    };
    if !already_running {
        return Ok(Some(guard));
    }
    // Cover two simultaneous launches: the first owns the mutex before its
    // HWND exists. This wait runs only in the extra process, never the live UI.
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if activate() {
            return Ok(None);
        }
        match unsafe { WaitForSingleObject(guard.handle, 25) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                // The previous GUI exited or crashed before it had a window
                // to activate. Existing waiter handles do not prevent takeover.
                guard.owned = true;
                return Ok(Some(guard));
            }
            WAIT_TIMEOUT => {}
            _ => {
                return Err(format!(
                    "Cannot wait for the amwall instance guard: {}",
                    unsafe { GetLastError() }.0,
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(
                "Another amwall window is still starting. Try reopening it in a moment.".into(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, HMENU, WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW,
    };

    fn private_mutex_name() -> Vec<u16> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        super::super::wide(&format!(
            "Local\\Amwall.Test.Instance.{}.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ))
    }

    fn assert_waiter_takes_over(abandon: bool) {
        let name = private_mutex_name();
        let owner_name = name.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            let mut guard = acquire_named(PCWSTR(owner_name.as_ptr()), || false)
                .unwrap()
                .unwrap();
            ready_tx.send(()).unwrap();
            exit_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            if abandon {
                // Simulate a terminating owner's handle cleanup without an
                // explicit ReleaseMutex. Thread exit abandons its ownership.
                guard.owned = false;
            }
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut exit_tx = Some(exit_tx);
        let replacement = acquire_named(PCWSTR(name.as_ptr()), || {
            // This callback runs only after the waiter opened its own handle,
            // keeping the same mutex object alive across the old owner's exit.
            if let Some(sender) = exit_tx.take() {
                sender.send(()).unwrap();
            }
            false
        })
        .unwrap()
        .unwrap();
        assert!(replacement.owned);
        owner.join().unwrap();
    }

    #[test]
    fn waiter_takes_over_a_released_mutex() {
        assert_waiter_takes_over(false);
    }

    #[test]
    fn waiter_takes_over_an_abandoned_mutex() {
        assert_waiter_takes_over(true);
    }

    #[test]
    fn activating_existing_window_does_not_release_its_mutex() {
        let name = private_mutex_name();
        let _owner = acquire_named(PCWSTR(name.as_ptr()), || false)
            .unwrap()
            .unwrap();
        std::thread::spawn(move || {
            assert!(
                acquire_named(PCWSTR(name.as_ptr()), || true)
                    .unwrap()
                    .is_none()
            );
            let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }.unwrap();
            assert_eq!(unsafe { WaitForSingleObject(handle, 0) }, WAIT_TIMEOUT);
            unsafe { CloseHandle(handle) }.unwrap();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn elevation_handoff_does_not_target_unelevated_window() {
        unsafe {
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("amwall instance regression"),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                200,
                100,
                HWND::default(),
                HMENU::default(),
                None,
                None,
            );
            assert_ne!(hwnd.0, 0);
            SetPropW(hwnd, w!("Amwall.GuiElevation"), HANDLE(1)).unwrap();
            let mut search = Search {
                elevated: true,
                window: HWND::default(),
                priority: 0,
            };
            find_window(hwnd, LPARAM(&mut search as *mut Search as isize));
            assert_eq!(search.window.0, 0);
            search.elevated = false;
            find_window(hwnd, LPARAM(&mut search as *mut Search as isize));
            assert_eq!(search.window, hwnd);
            SetPropW(hwnd, w!("Amwall.GuiElevation"), HANDLE(2)).unwrap();
            search.elevated = true;
            find_window(hwnd, LPARAM(&mut search as *mut Search as isize));
            assert_eq!(search.priority, 2);
            let _ = DestroyWindow(hwnd);
        }
    }
}

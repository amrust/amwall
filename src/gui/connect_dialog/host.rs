//! A separate native message loop keeps prompts responsive during main-window work.
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, mpsc};

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::VK_ESCAPE;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCWSTR, w};

const SHOW_PROMPT: u32 = WM_APP + 1;
const CANCEL_PROMPT: u32 = WM_APP + 2;
const SET_THEME: u32 = WM_APP + 3;
static HOST: OnceLock<Option<isize>> = OnceLock::new();
static STOPPING: AtomicBool = AtomicBool::new(false);

thread_local! {
    static PROMPTS: RefCell<HashMap<(isize, u64), HWND>> = RefCell::new(HashMap::new());
}

pub(super) struct Request {
    pub parent: isize,
    pub path: PathBuf,
    pub remote: String,
    pub signer: Option<String>,
    pub visible: bool,
    pub id: u64,
    pub dark: bool,
    #[cfg(test)]
    pub reply: Option<mpsc::Sender<isize>>,
}

pub(super) fn post(request: Request) -> bool {
    if STOPPING.load(Ordering::Acquire) {
        return false;
    }
    let Some(raw) = *HOST.get_or_init(start) else {
        return false;
    };
    let token = crate::gui::msg_slab::stash(request);
    if unsafe { PostMessageW(HWND(raw), SHOW_PROMPT, WPARAM(token), LPARAM(0)) }.is_err() {
        let _ = crate::gui::msg_slab::take::<Request>(token);
        return false;
    }
    true
}

pub(super) fn cancel(parent: HWND, id: u64) {
    let Some(Some(raw)) = HOST.get() else {
        return;
    };
    let token = crate::gui::msg_slab::stash((parent.0, id));
    if unsafe { PostMessageW(HWND(*raw), CANCEL_PROMPT, WPARAM(token), LPARAM(0)) }.is_err() {
        let _ = crate::gui::msg_slab::take::<(isize, u64)>(token);
    }
}

pub(super) fn set_dark_mode(dark: bool) {
    if let Some(Some(raw)) = HOST.get() {
        unsafe {
            let _ = PostMessageW(HWND(*raw), SET_THEME, WPARAM(usize::from(dark)), LPARAM(0));
        }
    }
}

/// Called by the prompt's NCDESTROY on this same thread.
pub(super) fn forget(parent: HWND, id: u64) {
    PROMPTS.with(|prompts| prompts.borrow_mut().remove(&(parent.0, id)));
}

pub(super) fn shutdown() {
    STOPPING.store(true, Ordering::Release);
    if let Some(Some(raw)) = HOST.get() {
        unsafe {
            let _ = PostMessageW(HWND(*raw), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
    }
}

fn start() -> Option<isize> {
    let (ready, rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("amwall-prompts".into())
        .spawn(move || unsafe {
            let com = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let instance = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
            let class = WNDCLASSW {
                lpfnWndProc: Some(host_proc),
                hInstance: instance.into(),
                lpszClassName: w!("AmwallPromptHost"),
                ..Default::default()
            };
            RegisterClassW(&class);
            // Hidden owner on this thread. Owning prompts from the main HWND would
            // introduce cross-thread SendMessage waits while that window is busy.
            let hwnd = CreateWindowExW(
                WS_EX_TOOLWINDOW,
                class.lpszClassName,
                w!(""),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                HWND::default(),
                HMENU::default(),
                instance,
                None,
            );
            let _ = ready.send((hwnd.0 != 0).then_some(hwnd.0));
            if hwnd.0 != 0 {
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, HWND::default(), 0, 0).0 > 0 {
                    let dialog = GetAncestor(msg.hwnd, GA_ROOT);
                    let is_prompt = PROMPTS
                        .with(|prompts| prompts.borrow().values().any(|hwnd| *hwnd == dialog));
                    // User dismissal records Block; internal cancellation below
                    // still destroys directly without applying a stale decision.
                    if is_prompt
                        && msg.message == WM_KEYDOWN
                        && msg.wParam.0 == VK_ESCAPE.0 as usize
                    {
                        SendMessageW(dialog, WM_CLOSE, WPARAM(0), LPARAM(0));
                        continue;
                    }
                    if is_prompt && IsDialogMessageW(dialog, &msg).as_bool() {
                        continue;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            if com.is_ok() {
                CoUninitialize();
            }
        })
        .ok()?;
    rx.recv().ok().flatten()
}

unsafe extern "system" fn host_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        SET_THEME => {
            let windows: Vec<_> =
                PROMPTS.with(|prompts| prompts.borrow().values().copied().collect());
            for dialog in windows {
                crate::gui::theme::apply(dialog, wparam.0 != 0);
            }
            LRESULT(0)
        }
        SHOW_PROMPT => {
            if let Some(request) = crate::gui::msg_slab::take::<Request>(wparam.0) {
                if STOPPING.load(Ordering::Acquire)
                    || !unsafe { IsWindow(HWND(request.parent)) }.as_bool()
                {
                    super::notify_closed(HWND(request.parent), request.path, request.id);
                    return LRESULT(0);
                }
                let created = super::create_prompt(hwnd, &request);
                if created.0 != 0 {
                    PROMPTS.with(|prompts| {
                        prompts
                            .borrow_mut()
                            .insert((request.parent, request.id), created);
                    });
                }
                #[cfg(test)]
                if let Some(reply) = request.reply {
                    let _ = reply.send(created.0);
                }
                if created.0 == 0 {
                    super::notify_closed(HWND(request.parent), request.path, request.id);
                }
            }
            LRESULT(0)
        }
        CANCEL_PROMPT => {
            if let Some(key) = crate::gui::msg_slab::take::<(isize, u64)>(wparam.0) {
                let prompt = PROMPTS.with(|prompts| prompts.borrow_mut().remove(&key));
                if let Some(prompt) = prompt {
                    unsafe {
                        let _ = DestroyWindow(prompt);
                    }
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe {
                PostQuitMessage(0);
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn native_cancel_is_scoped_to_prompt_id_and_escape_records_block() {
        unsafe {
            let parent = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("prompt cancellation test"),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                HWND::default(),
                HMENU::default(),
                None,
                None,
            );
            assert_ne!(parent.0, 0);
            let create = |id| {
                let (reply, receive) = mpsc::channel();
                assert!(post(Request {
                    parent: parent.0,
                    path: r"C:\cancel-test.exe".into(),
                    remote: "127.0.0.1".into(),
                    signer: None,
                    visible: false,
                    id,
                    dark: false,
                    reply: Some(reply),
                }));
                let hwnd = HWND(receive.recv_timeout(Duration::from_secs(3)).unwrap());
                assert_ne!(hwnd.0, 0);
                hwnd
            };
            let first = create(7001);
            cancel(parent, 9999);
            // The reply also serves as a queue barrier for the wrong-ID cancel.
            let second = create(7002);
            assert!(IsWindow(first).as_bool());
            let wait_closed = |hwnd| {
                let deadline = Instant::now() + Duration::from_secs(3);
                while IsWindow(hwnd).as_bool() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert!(!IsWindow(hwnd).as_bool());
            };
            cancel(parent, 7001);
            wait_closed(first);
            assert!(
                IsWindow(second).as_bool(),
                "an old cancellation must not close a later prompt"
            );
            PostMessageW(second, WM_KEYDOWN, WPARAM(VK_ESCAPE.0 as usize), LPARAM(0)).unwrap();
            wait_closed(second);
            let mut msg = MSG::default();
            assert!(
                PeekMessageW(
                    &mut msg,
                    parent,
                    super::super::WM_USER_CONNECT_ALLOW,
                    super::super::WM_USER_CONNECT_BLOCK,
                    PM_REMOVE
                )
                .as_bool(),
                "Escape must record Block"
            );
            assert_eq!(msg.message, super::super::WM_USER_CONNECT_BLOCK);
            let event =
                crate::gui::msg_slab::take::<super::super::PromptEvent>(msg.wParam.0).unwrap();
            assert_eq!(
                event.id, 7002,
                "only user dismissal may record Block; cancellation may not"
            );
            assert!(
                !PeekMessageW(
                    &mut msg,
                    parent,
                    super::super::WM_USER_CONNECT_ALLOW,
                    super::super::WM_USER_CONNECT_BLOCK,
                    PM_REMOVE
                )
                .as_bool(),
                "programmatic cancellation must not send a firewall choice"
            );
            let mut closed_ids = Vec::new();
            while PeekMessageW(
                &mut msg,
                parent,
                super::super::WM_USER_CONNECT_PROMPT_CLOSED,
                super::super::WM_USER_CONNECT_PROMPT_CLOSED,
                PM_REMOVE,
            )
            .as_bool()
            {
                if let Some(event) =
                    crate::gui::msg_slab::take::<super::super::PromptEvent>(msg.wParam.0)
                {
                    closed_ids.push(event.id);
                }
            }
            closed_ids.sort_unstable();
            assert_eq!(closed_ids, vec![7001, 7002]);
            let _ = DestroyWindow(parent);
        }
    }
}

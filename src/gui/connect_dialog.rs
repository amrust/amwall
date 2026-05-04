// amwall — connect-prompt modal dialog (the "first-connection"
// Allow/Block window). Modeless / non-focus-stealing.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Pops centered on screen via DS_CENTER when:
//   1. amwall's per-app filter set is active (default-deny is
//      installed at FW_WEIGHT_LOWEST).
//   2. Notifications are enabled (`Settings.enable_notifications`).
//   3. A drop event surfaces an app that's just been auto-
//      cataloged into the profile (one prompt per app, ever).
//
// Modeless on purpose: upstream simplewall's notification window
// doesn't grab focus from the user, and stealing focus from
// whatever they were typing into is awful UX. We use
// `CreateDialogParamW` + `ShowWindow(SW_SHOWNA)` with
// `WS_EX_NOACTIVATE` in the dialog template's EXSTYLE.
//
// Result delivery: the dialog can't return a value to the caller
// (it's modeless, the caller doesn't wait), so the user's choice
// flows back via `PostMessageW(parent, WM_USER_CONNECT_ALLOW,
// path_box, 0)` for Allow and `WM_USER_CONNECT_BLOCK` for Block.
// Block sets `is_silent=true` on the app so subsequent drops for
// the same exe don't re-prompt (matches upstream simplewall
// `notifications.c:87`: `ptr_app->is_silent = (button_id == IDC_BLOCK_BTN);`).
// X / dismiss just destroys the window without setting is_silent —
// the App already sits at `is_enabled=false` from auto-catalog, so
// "close without choosing" naturally means "stay blocked, may re-prompt".

#![cfg(windows)]

use std::cell::Cell;
use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    COLOR_3DDKSHADOW, CreateSolidBrush, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER,
    DeleteObject, DrawFocusRect, DrawTextW, FillRect, FrameRect, GetSysColorBrush, SetBkMode,
    SetTextColor, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{DRAWITEMSTRUCT, ODS_FOCUS, ODS_SELECTED};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateDialogParamW, DestroyWindow, GWLP_USERDATA, GetDlgItem, GetWindowLongPtrW,
    HWND_NOTOPMOST, HWND_TOPMOST, KillTimer, PostMessageW, SW_SHOWNA, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOSIZE, SetTimer, SetWindowLongPtrW, SetWindowPos, SetWindowTextW,
    ShowWindow, WM_COMMAND, WM_DRAWITEM, WM_INITDIALOG, WM_NCDESTROY, WM_TIMER,
};
use windows::core::PCWSTR;

use super::wide;

const IDD_CONNECT_PROMPT: u16 = 120;
const IDC_PROMPT_PATH: i32 = 1200;
const IDC_PROMPT_REMOTE: i32 = 1201;
const IDC_PROMPT_COUNTDOWN: i32 = 1202;
const IDC_PROMPT_ALLOW: i32 = 1;
const IDC_PROMPT_BLOCK: i32 = 2;

/// Safety timer — buttons are visibly disabled (greyed) for this
/// many milliseconds after the dialog appears. Prevents the user
/// from accidentally clicking when the prompt pops over a click
/// they were already executing. Matches upstream simplewall's
/// `NOTIFY_TIMER_SAFETY_TIMEOUT = 900`.
const SAFETY_TIMEOUT_MS: u32 = 900;

/// Timer tick rate while counting down. 100 ms gives a smooth
/// "0.9s → 0.8s → 0.7s …" countdown text without doing much
/// repaint work.
const COUNTDOWN_TICK_MS: u32 = 100;

/// Timer ID for the safety countdown.
const TIMER_SAFETY: usize = 0x1A1A;

/// Custom WM_USER message that the dialog posts back to its
/// parent (the main amwall HWND) when the user clicks Allow.
/// `wparam` holds a `Box<PathBuf>` cast to `usize` — the parent
/// reclaims it via `Box::from_raw` and uses the path to flip
/// `is_enabled = true` on the matching `profile.apps` entry.
pub const WM_USER_CONNECT_ALLOW: u32 =
    windows::Win32::UI::WindowsAndMessaging::WM_USER + 0x102;

/// Posted when the user clicks Block. Same `Box<PathBuf>`
/// payload shape as Allow; the parent flips `is_silent = true`
/// on the matching `profile.apps` entry so subsequent drops for
/// the same exe don't re-prompt. `is_enabled` is already false
/// from auto-catalog, so the user stays blocked — Block here is
/// the "stop bothering me about this app" signal, not a
/// state change to the block decision itself.
pub const WM_USER_CONNECT_BLOCK: u32 =
    windows::Win32::UI::WindowsAndMessaging::WM_USER + 0x103;

/// State stashed in the dialog's GWLP_USERDATA. Heap-allocated
/// because the dialog is modeless and lives past `show_async`'s
/// return; reclaimed on WM_NCDESTROY.
struct DialogState {
    parent: HWND,
    path: std::path::PathBuf,
    path_text: String,
    remote: String,
    /// Safety-armed flag. `false` until the SAFETY_TIMEOUT_MS
    /// countdown completes; while false, the buttons render
    /// greyed-out and clicks are ignored. Cell because the
    /// dialog state is borrowed re-entrantly across paint and
    /// timer callbacks.
    armed: Cell<bool>,
    /// Remaining countdown in milliseconds. Drives the
    /// "Click in N.Ns..." status text. 0 = armed.
    remaining_ms: Cell<u32>,
}

/// Show the centered Allow/Block prompt for `app_path`
/// connecting to `remote`. Returns immediately (modeless) — the
/// user's Allow choice arrives at `parent` as
/// `WM_USER_CONNECT_ALLOW`. Block / dismiss is silent.
///
/// `signer` is the leaf certificate display name from the
/// WinVerifyTrust cache when `Settings.use_certificates` is on.
/// When `Some`, the dialog appends "Signed by X" beneath the
/// remote endpoint so the user can decide based on whether the
/// publisher is trusted, not just the path. `None` falls back to
/// the prior behaviour (no signer line).
pub fn show_async(parent: HWND, app_path: &Path, remote: &str, signer: Option<&str>) {
    let displayed_remote = match signer {
        Some(s) if !s.is_empty() => format!("{remote}\nSigned by {s}"),
        _ => remote.to_string(),
    };
    let state = Box::new(DialogState {
        parent,
        path: app_path.to_path_buf(),
        path_text: wrap_path_for_display(&app_path.display().to_string(), 60),
        remote: displayed_remote,
        armed: Cell::new(false),
        remaining_ms: Cell::new(SAFETY_TIMEOUT_MS),
    });
    let raw = Box::into_raw(state) as isize;

    let hi = match unsafe { GetModuleHandleW(PCWSTR::null()) } {
        Ok(h) => h,
        Err(_) => {
            // Reclaim so we don't leak.
            unsafe {
                let _ = Box::from_raw(raw as *mut DialogState);
            }
            return;
        }
    };

    let hwnd = unsafe {
        CreateDialogParamW(
            hi,
            PCWSTR(IDD_CONNECT_PROMPT as usize as *const u16),
            parent,
            Some(dialog_proc),
            LPARAM(raw),
        )
    };
    if hwnd.0 == 0 {
        unsafe {
            let _ = Box::from_raw(raw as *mut DialogState);
        }
        return;
    }
    // SW_SHOWNA = "show without activating" — combined with the
    // template's WS_EX_NOACTIVATE, this is what keeps focus on
    // whatever the user was typing into.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOWNA);
    }

    // Pop to the top of z-order on appear. Without this, the
    // SW_SHOWNA + WS_EX_NOACTIVATE pair creates the window
    // *behind* whatever the user has focused, which means a
    // user typing into a maximised browser / IDE never sees the
    // prompt. The HWND_TOPMOST -> HWND_NOTOPMOST pair is the
    // standard Win32 pattern for "appear at top once, then
    // accept normal z-order": SetWindowPos to TOPMOST raises
    // the window above all non-topmost windows, then NOTOPMOST
    // clears the sticky flag while preserving the just-moved
    // position. SWP_NOACTIVATE keeps focus on the user's
    // active window (preserves the WS_EX_NOACTIVATE intent).
    unsafe {
        let _ = SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
        );
        let _ = SetWindowPos(
            hwnd,
            HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
        );
    }
}

unsafe extern "system" fn dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, lparam.0);
            }
            let state = unsafe { &*(lparam.0 as *const DialogState) };
            set_text(hwnd, IDC_PROMPT_PATH, &state.path_text);
            set_text(hwnd, IDC_PROMPT_REMOTE, &state.remote);
            set_text(hwnd, IDC_PROMPT_COUNTDOWN, &countdown_label(state.remaining_ms.get()));
            // Start the safety countdown. Buttons render greyed
            // (paint_action_button reads state.armed) until the
            // timer ticks down.
            unsafe {
                SetTimer(hwnd, TIMER_SAFETY, COUNTDOWN_TICK_MS, None);
            }
            // Return FALSE (0) so the dialog manager doesn't try
            // to set focus to the default control — combined
            // with WS_EX_NOACTIVATE this preserves the user's
            // current focus.
            0
        }
        WM_TIMER => {
            if wparam.0 != TIMER_SAFETY {
                return 0;
            }
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
            if raw == 0 {
                return 0;
            }
            let state = unsafe { &*(raw as *const DialogState) };
            let remaining = state.remaining_ms.get().saturating_sub(COUNTDOWN_TICK_MS);
            state.remaining_ms.set(remaining);
            if remaining == 0 {
                state.armed.set(true);
                set_text(hwnd, IDC_PROMPT_COUNTDOWN, "");
                unsafe {
                    let _ = KillTimer(hwnd, TIMER_SAFETY);
                }
                // Force the buttons to repaint with the armed
                // (full-color) brushes.
                invalidate_button(hwnd, IDC_PROMPT_ALLOW);
                invalidate_button(hwnd, IDC_PROMPT_BLOCK);
            } else {
                set_text(hwnd, IDC_PROMPT_COUNTDOWN, &countdown_label(remaining));
            }
            1
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
            if raw == 0 {
                return 0;
            }
            let state = unsafe { &*(raw as *const DialogState) };
            // Safety gate: ignore button clicks until the
            // countdown completes. Cheap and avoids the user
            // accidentally Allow'ing something on a stray click.
            if !state.armed.get()
                && (id == IDC_PROMPT_ALLOW || id == IDC_PROMPT_BLOCK)
            {
                return 0;
            }
            match id {
                IDC_PROMPT_ALLOW => {
                    // Hand the parent a Box<PathBuf> so it can
                    // find the right App slot. The parent's
                    // handler reclaims it.
                    let path_box = Box::new(state.path.clone());
                    let path_raw = Box::into_raw(path_box) as *mut c_void as isize;
                    unsafe {
                        let _ = PostMessageW(
                            state.parent,
                            WM_USER_CONNECT_ALLOW,
                            WPARAM(path_raw as usize),
                            LPARAM(0),
                        );
                        let _ = DestroyWindow(hwnd);
                    }
                    1
                }
                IDC_PROMPT_BLOCK => {
                    // App already at is_enabled=false from the
                    // catalog step. Posting BLOCK tells the
                    // parent to also set is_silent=true so
                    // future drops for this exe don't re-prompt.
                    let path_box = Box::new(state.path.clone());
                    let path_raw = Box::into_raw(path_box) as *mut c_void as isize;
                    unsafe {
                        let _ = PostMessageW(
                            state.parent,
                            WM_USER_CONNECT_BLOCK,
                            WPARAM(path_raw as usize),
                            LPARAM(0),
                        );
                        let _ = DestroyWindow(hwnd);
                    }
                    1
                }
                _ => 0,
            }
        }
        WM_DRAWITEM => {
            let dis = unsafe { &*(lparam.0 as *const DRAWITEMSTRUCT) };
            let armed = {
                let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
                if raw == 0 {
                    true
                } else {
                    let s = unsafe { &*(raw as *const DialogState) };
                    s.armed.get()
                }
            };
            paint_action_button(dis, armed);
            1
        }
        WM_NCDESTROY => {
            // Reclaim the heap-allocated state so we don't leak.
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
            if raw != 0 {
                unsafe {
                    let _ = Box::from_raw(raw as *mut DialogState);
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
            }
            0
        }
        _ => 0,
    }
}

fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    COLORREF(((b as u32) << 16) | ((g as u32) << 8) | (r as u32))
}

/// Paint a BS_OWNERDRAW Allow / Block button green / red. Three
/// states per button: idle, hovered (ODS_HOTLIGHT — but Win32
/// doesn't reliably set that on plain ownerdraw without
/// COMCTL theme integration, so we fold it into idle), and
/// pressed (ODS_SELECTED). Hover would need a subclass + mouse
/// tracking to surface; skipping for now.
fn paint_action_button(dis: &DRAWITEMSTRUCT, armed: bool) {
    // ODS_FLAGS is a typed-newtype around u32; bit-test via .0
    // on both sides since the wrapper doesn't implement BitAnd.
    let is_pressed = (dis.itemState.0 & ODS_SELECTED.0) != 0;
    let is_focused = (dis.itemState.0 & ODS_FOCUS.0) != 0;
    let is_allow = dis.CtlID == 1; // IDC_PROMPT_ALLOW
    let (fill, label) = if is_allow {
        let c = if !armed {
            // Muted green — clearly disabled but still
            // identifiably the "Allow" side.
            rgb(150, 180, 150)
        } else if is_pressed {
            rgb(40, 110, 40)
        } else {
            rgb(60, 160, 60)
        };
        (c, "Allow")
    } else {
        let c = if !armed {
            rgb(180, 150, 150)
        } else if is_pressed {
            rgb(150, 40, 40)
        } else {
            rgb(200, 60, 60)
        };
        (c, "Block")
    };

    let mut rect = dis.rcItem;
    let brush = unsafe { CreateSolidBrush(fill) };
    unsafe {
        FillRect(dis.hDC, &rect, brush);
        let _ = DeleteObject(brush);
    }

    // Subtle 1-px frame so adjacent buttons read as separate.
    unsafe {
        let frame = GetSysColorBrush(COLOR_3DDKSHADOW);
        FrameRect(dis.hDC, &rect, frame);
    }

    let mut wlabel = super::wide(label);
    unsafe {
        SetBkMode(dis.hDC, TRANSPARENT);
        SetTextColor(dis.hDC, rgb(255, 255, 255));
        DrawTextW(
            dis.hDC,
            &mut wlabel,
            &mut rect,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
        );
    }

    if is_focused {
        // 2-pixel inset focus rect so the dotted line doesn't
        // collide with the dark frame.
        let inset = RECT {
            left: rect.left + 3,
            top: rect.top + 3,
            right: rect.right - 3,
            bottom: rect.bottom - 3,
        };
        unsafe {
            let _ = DrawFocusRect(dis.hDC, &inset);
        }
    }
}

/// Word-wrap a Windows path for display in the prompt's static
/// control. Static controls only break on whitespace, and paths
/// don't have any — so without this, a long path runs off the
/// right edge of the field and gets clipped. We insert `\r\n`
/// after the last backslash that fits within `max_chars`, which
/// gives a clean "split at a directory boundary" wrap.
fn wrap_path_for_display(path: &str, max_chars: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= max_chars {
        return path.to_string();
    }
    let mut out = String::with_capacity(path.len() + 6);
    let mut start = 0;
    while chars.len() - start > max_chars {
        let segment_end = (start + max_chars).min(chars.len());
        let mut break_at = None;
        for i in (start + 1..segment_end).rev() {
            if chars[i] == '\\' {
                break_at = Some(i + 1);
                break;
            }
        }
        let cut = break_at.unwrap_or(segment_end);
        for &c in &chars[start..cut] {
            out.push(c);
        }
        out.push_str("\r\n");
        start = cut;
    }
    for &c in &chars[start..] {
        out.push(c);
    }
    out
}

fn countdown_label(remaining_ms: u32) -> String {
    if remaining_ms == 0 {
        String::new()
    } else {
        format!("Click in {:.1}s...", remaining_ms as f32 / 1000.0)
    }
}

fn invalidate_button(parent: HWND, id: i32) {
    use windows::Win32::Graphics::Gdi::InvalidateRect;
    let ctrl = unsafe { GetDlgItem(parent, id) };
    if ctrl.0 == 0 {
        return;
    }
    unsafe {
        let _ = InvalidateRect(ctrl, None, true);
    }
}

fn set_text(hwnd: HWND, id: i32, text: &str) {
    let ctrl = unsafe { GetDlgItem(hwnd, id) };
    if ctrl.0 == 0 {
        return;
    }
    let mut wbuf = wide(text);
    unsafe {
        let _ = SetWindowTextW(ctrl, PCWSTR(wbuf.as_mut_ptr()));
    }
}

#[cfg(test)]
mod tests {
    use super::wrap_path_for_display;

    #[test]
    fn short_path_unchanged() {
        let p = r"C:\Program Files\App\app.exe";
        assert_eq!(wrap_path_for_display(p, 60), p);
    }

    #[test]
    fn long_path_breaks_at_backslash() {
        let p = r"C:\Users\someverylongusername\AppData\Local\Programs\BraveSoftware\Brave-Browser\Application\brave.exe";
        let out = wrap_path_for_display(p, 60);
        assert!(out.contains("\r\n"));
        for line in out.split("\r\n") {
            assert!(line.chars().count() <= 60, "line too long: {line:?}");
        }
        assert_eq!(out.replace("\r\n", ""), p);
    }
}

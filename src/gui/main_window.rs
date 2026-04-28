// simplewall-rs — main window class + WndProc.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Win32 main window built programmatically (no .rc resources). The
// window owns a single ListView child that displays the profile's
// `custom_rules`.
//
// State plumbing follows the standard Win32-via-Rust pattern:
//   - `create` heap-allocates `App` (caller's responsibility — we
//     receive `Box<App>` and pass its raw pointer through
//     CreateWindowExW's lpParam).
//   - `WM_NCCREATE` extracts the lpParam from `CREATESTRUCTW` and
//     stores it in `GWLP_USERDATA` via `SetWindowLongPtrW`.
//   - Every other message handler reads the pointer back via
//     `GetWindowLongPtrW(GWLP_USERDATA)` and dereferences it.
//   - `WM_NCDESTROY` reclaims the Box so it drops cleanly.
//
// Any panic inside a WndProc would unwind through Win32 (UB across
// the FFI boundary), so handlers use std `Result<…, _>`-via-`match`
// patterns rather than `?` and `.expect()`.
//
// M5.1 deliberately ships read-only — the Open Profile dialog,
// menu accelerators, and any in-place editing land in M5.2.

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{HBRUSH, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCOLUMNW, LVIF_TEXT, LVITEMW, LVM_DELETEALLITEMS,
    LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETITEMTEXTW, LVS_REPORT, LVS_SHOWSELALWAYS,
    WC_LISTVIEWW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CW_USEDEFAULT, CreateMenu, CreatePopupMenu, CreateWindowExW, CREATESTRUCTW,
    DefWindowProcW, DestroyWindow, GWLP_USERDATA, GetClientRect, GetDlgItem,
    GetWindowLongPtrW, HMENU, IDC_ARROW, LoadCursorW, MF_POPUP, MF_SEPARATOR, MF_STRING,
    MoveWindow, RegisterClassExW, SW_SHOW, SendMessageW, SetWindowLongPtrW, ShowWindow,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_NCCREATE,
    WM_NCDESTROY, WM_SIZE, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW,
    WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR, w};

use super::app::App;
use super::{post_quit, wide};

/// Window class name. Win32 uses this string to look up our class
/// registration.
const CLASS_NAME: PCWSTR = w!("SimplewallRsMainWindow");

/// Initial window dimensions. M5.7 polish will pull these from a
/// saved preference; for now they're hardcoded to a common laptop-
/// friendly default.
const INITIAL_W: i32 = 900;
const INITIAL_H: i32 = 600;

// Menu / control IDs. Win32 sends these as the LOWORD of WPARAM in
// WM_COMMAND. Bare integers rather than an enum because the Win32
// ABI demands them.
const ID_FILE_EXIT: u16 = 101;
const ID_LISTVIEW: u16 = 1000;

/// Register the window class, create the main window, show it.
/// Ownership of `app` is transferred into the window's
/// `GWLP_USERDATA` and reclaimed on `WM_NCDESTROY`.
pub fn create(app: Box<App>) -> Result<HWND, String> {
    unsafe {
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

        // Stuff the Box<App> raw pointer through CreateWindowExW.
        // Consumed in WM_NCCREATE (parked into GWLP_USERDATA);
        // every later WndProc call reads it back from there.
        let app_ptr = Box::into_raw(app) as *mut std::ffi::c_void;

        let menu = build_main_menu().ok_or("build_main_menu failed")?;
        let title = wide("simplewall-rs");
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            CLASS_NAME,
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            INITIAL_W,
            INITIAL_H,
            None,
            menu,
            hinstance,
            Some(app_ptr),
        );
        if hwnd.0 == 0 {
            // App leaked here, but we're failing creation entirely;
            // process exit reaps it.
            return Err("CreateWindowExW failed".into());
        }

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);
        Ok(hwnd)
    }
}

/// Build the top menu: `File` { Exit }. M5.2 will add Open Profile…
/// once the file-dialog COM machinery is wired up.
fn build_main_menu() -> Option<HMENU> {
    unsafe {
        let menu = CreateMenu().ok()?;
        let file_menu = CreatePopupMenu().ok()?;

        let exit_label = wide("E&xit");
        let _ = AppendMenuW(file_menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(
            file_menu,
            MF_STRING,
            ID_FILE_EXIT as usize,
            PCWSTR(exit_label.as_ptr()),
        );

        let file_label = wide("&File");
        let _ = AppendMenuW(
            menu,
            MF_POPUP,
            file_menu.0 as usize,
            PCWSTR(file_label.as_ptr()),
        );
        Some(menu)
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
            // CREATESTRUCTW.lpCreateParams holds the Box<App>
            // pointer we passed via lpParam. Park it into
            // GWLP_USERDATA so every later message can find it.
            let cs = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
            let app_ptr = cs.lpCreateParams;
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, app_ptr as isize);
            }
            // Continue with default processing so the window is
            // actually created.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_CREATE => match on_create(hwnd) {
            Ok(()) => LRESULT(0),
            Err(e) => {
                eprintln!("simplewall-rs: WM_CREATE failed: {e}");
                LRESULT(-1) // Tell Win32 to abort window creation.
            }
        },
        WM_SIZE => {
            on_size(hwnd);
            LRESULT(0)
        }
        WM_COMMAND => {
            on_command(hwnd, wparam.0 as u32 & 0xFFFF);
            LRESULT(0)
        }
        WM_DESTROY => {
            post_quit(0);
            LRESULT(0)
        }
        WM_NCDESTROY => {
            // Reclaim the Box<App> so it drops.
            let app_ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut App;
            if !app_ptr.is_null() {
                unsafe {
                    let _ = Box::from_raw(app_ptr);
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// `WM_CREATE`: build the ListView child, configure its columns,
/// populate it from `app.profile.custom_rules`.
fn on_create(hwnd: HWND) -> Result<(), String> {
    let listview = create_rules_listview(hwnd)?;
    set_listview_columns(listview)?;
    if let Some(app) = unsafe { app_ref(hwnd) } {
        repopulate_rule_list(listview, app);
    }
    Ok(())
}

/// `WM_SIZE`: keep the ListView filling the client area. Future
/// toolbar / status bar will reserve space at top + bottom; for now
/// the ListView gets everything.
fn on_size(hwnd: HWND) {
    unsafe {
        let listview = find_listview(hwnd);
        if listview.0 == 0 {
            return;
        }
        let mut rect = std::mem::zeroed();
        if GetClientRect(hwnd, &mut rect).is_err() {
            return;
        }
        let _ = MoveWindow(
            listview,
            0,
            0,
            rect.right - rect.left,
            rect.bottom - rect.top,
            true,
        );
    }
}

/// `WM_COMMAND`: dispatch on the menu/button id.
fn on_command(hwnd: HWND, id: u32) {
    if id as u16 == ID_FILE_EXIT {
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
    }
}

fn create_rules_listview(parent: HWND) -> Result<HWND, String> {
    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
        let style =
            WS_CHILD | WS_VISIBLE | WS_BORDER | WINDOW_STYLE(LVS_REPORT | LVS_SHOWSELALWAYS);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WC_LISTVIEWW,
            PCWSTR::null(),
            style,
            0,
            0,
            INITIAL_W,
            INITIAL_H,
            parent,
            HMENU(ID_LISTVIEW as isize),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            return Err("CreateWindowExW(WC_LISTVIEW) failed".into());
        }
        Ok(hwnd)
    }
}

fn set_listview_columns(listview: HWND) -> Result<(), String> {
    let columns: &[(&str, i32)] = &[
        ("Name", 220),
        ("Direction", 90),
        ("Action", 80),
        ("Protocol", 80),
        ("Apps", 200),
        ("Rule (remote)", 220),
    ];
    for (i, (label, width)) in columns.iter().enumerate() {
        let mut buf = wide(label);
        let col = LVCOLUMNW {
            mask: LVCF_TEXT | LVCF_WIDTH,
            fmt: LVCFMT_LEFT,
            cx: *width,
            pszText: PWSTR(buf.as_mut_ptr()),
            ..Default::default()
        };
        let res = unsafe {
            SendMessageW(
                listview,
                LVM_INSERTCOLUMNW,
                WPARAM(i),
                LPARAM(&col as *const _ as isize),
            )
        };
        if res.0 == -1 {
            return Err(format!("LVM_INSERTCOLUMN failed at index {i}"));
        }
    }
    Ok(())
}

/// Wipe the ListView and re-fill from the current profile's custom
/// rules. Called on app start (after the ListView is created) and
/// from M5.2's Open Profile… dispatch.
pub(super) fn repopulate_rule_list(listview: HWND, app: &App) {
    use crate::profile::{Action, Direction};

    unsafe {
        let _ = SendMessageW(listview, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    }

    for (idx, rule) in app.profile.custom_rules.iter().enumerate() {
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
                listview,
                LVM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&item as *const _ as isize),
            )
        };

        let direction = match rule.direction {
            Direction::Outbound => "Outbound",
            Direction::Inbound => "Inbound",
            Direction::Any => "Any",
            Direction::Other(_) => "Other",
        };
        let action = match rule.action {
            Action::Permit => "Permit",
            Action::Block => "Block",
        };
        let protocol = rule.protocol.map(|p| match p {
            1 => "ICMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            58 => "ICMPv6".to_string(),
            other => other.to_string(),
        });
        let apps = rule.apps.clone().unwrap_or_default();
        let remote = rule.remote.clone().unwrap_or_default();

        set_subitem(listview, idx as i32, 1, direction);
        set_subitem(listview, idx as i32, 2, action);
        set_subitem(
            listview,
            idx as i32,
            3,
            protocol.as_deref().unwrap_or("—"),
        );
        set_subitem(listview, idx as i32, 4, &apps);
        set_subitem(listview, idx as i32, 5, &remote);
    }
}

fn set_subitem(listview: HWND, row: i32, sub: i32, text: &str) {
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
            listview,
            LVM_SETITEMTEXTW,
            WPARAM(row as usize),
            LPARAM(&item as *const _ as isize),
        );
    }
}

// ---- low-level helpers ----

unsafe fn app_ref<'a>(hwnd: HWND) -> Option<&'a App> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const App;
    if raw.is_null() {
        None
    } else {
        Some(unsafe { &*raw })
    }
}

unsafe fn find_listview(parent: HWND) -> HWND {
    unsafe { GetDlgItem(parent, ID_LISTVIEW as i32) }
}

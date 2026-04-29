// amwall — toolbar / rebar / search.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Upstream simplewall puts a Win32 *rebar* control between the menu
// bar and the tab control. The rebar hosts two bands: the toolbar
// (15 buttons in fixed slots) on the left, the search edit on the
// right. We mirror that exactly — same button order, same command
// IDs (so anyone reading upstream's `_app_toolbar_init` in
// controls.c:853-944 recognises the layout).
//
// Two upstream-specific deltas:
//
//   1. Buttons are text-only in M5.3. Upstream pulls 18×18 PNGs from
//      its image list (FamFamFam Silk via `assets/icons/silk/`); we
//      vendored those in `a9a500d` but actually wiring the image
//      list is M5.9 polish. Until then `BTNS_AUTOSIZE | BTNS_SHOWTEXT`
//      gets us readable buttons sized to their label.
//
//   2. Upstream's last button is "Donate" (IDM_DONATE) and opens a
//      PayPal URL. amwall replaces it with "Releases"
//      (IDM_RELEASES, same numeric slot 302) which opens our
//      GitHub releases page via ShellExecuteW.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    BTNS_AUTOSIZE, BTNS_BUTTON, BTNS_SHOWTEXT, CCS_NODIVIDER, I_IMAGENONE, TBBUTTON,
    TBSTATE_ENABLED, TBSTYLE_EX_DOUBLEBUFFER, TBSTYLE_EX_MIXEDBUTTONS, TBSTYLE_FLAT, TBSTYLE_LIST,
    TBSTYLE_TOOLTIPS, TBSTYLE_TRANSPARENT, TBSTYLE_WRAPABLE, TB_ADDBUTTONS, TB_AUTOSIZE,
    TB_BUTTONSTRUCTSIZE, TB_SETEXTENDEDSTYLE, TOOLBARCLASSNAMEW, WC_EDITW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, ES_AUTOHSCROLL, ES_LEFT, HMENU, SendMessageW, WINDOW_EX_STYLE,
    WINDOW_STYLE, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_EX_CLIENTEDGE,
    WS_VISIBLE,
};
use windows::core::{PCWSTR, w};

use super::ids::{
    IDC_SEARCH, IDC_TOOLBAR, IDM_OPENRULESEDITOR, IDM_REFRESH, IDM_RELEASES,
    IDM_SETTINGS, IDM_TRAY_ENABLELOG_CHK, IDM_TRAY_ENABLENOTIFICATIONS_CHK,
    IDM_TRAY_ENABLEUILOG_CHK, IDM_TRAY_LOGCLEAR, IDM_TRAY_LOGSHOW, IDM_TRAY_START,
};

/// HWNDs created by `create`. The main window stores these and
/// owns the layout — toolbar + search are direct children of the
/// main window, no rebar wrapper. (The rebar attempted to mediate
/// between TBSTYLE_WRAPABLE and the search edit's row, but it
/// caches band heights in ways that fight the wrap. Doing the
/// layout ourselves is simpler and works.)
pub struct Toolbar {
    pub toolbar: HWND,
    pub search: HWND,
}

/// Build the toolbar + search edit as direct children of `parent`.
/// Caller positions them via `MoveWindow` in `on_size`.
pub fn create(parent: HWND, dpi: u32) -> Result<Toolbar, String> {
    let toolbar = create_toolbar(parent)?;
    let icons = super::icons::build(dpi);
    super::icons::attach_to_toolbar(toolbar, icons.himagelist);
    populate_toolbar(toolbar, &icons)?;
    let search = create_search(parent)?;
    Ok(Toolbar { toolbar, search })
}

/// Toolbar's content height in device pixels — bottom-most pixel
/// occupied by any button or separator after wrap. The toolbar's
/// own reported size has comctl32-internal trailing padding (~16
/// px on Win11), so reading `GetClientRect` over-allocates. Walk
/// the items and take `max(rect.bottom)` instead — that's the
/// true bottom of rendered content.
pub fn toolbar_layout_height(toolbar: HWND) -> i32 {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::UI::Controls::{TB_BUTTONCOUNT, TB_GETITEMRECT};
    if toolbar.0 == 0 {
        return 0;
    }
    let count =
        unsafe { SendMessageW(toolbar, TB_BUTTONCOUNT, WPARAM(0), LPARAM(0)) }.0 as i32;
    if count <= 0 {
        return 0;
    }
    let mut max_bottom = 0i32;
    for i in 0..count {
        let mut rect = RECT::default();
        let r = unsafe {
            SendMessageW(
                toolbar,
                TB_GETITEMRECT,
                WPARAM(i as usize),
                LPARAM(&mut rect as *mut _ as isize),
            )
        };
        if r.0 != 0 && rect.bottom > max_bottom {
            max_bottom = rect.bottom;
        }
    }
    max_bottom.max(1)
}

/// Clip the toolbar's painted area to a rect of (0, 0, w, h) so
/// the comctl32-internal trailing padding (~16 px) and any
/// inter-row gap caused by separator-stretched row heights
/// becomes transparent. The toolbar's logical window rect stays
/// at whatever it auto-grew to during WM_SIZE — only painting is
/// constrained.
pub fn clip_to_content(toolbar: HWND, w: i32, h: i32) {
    use windows::Win32::Graphics::Gdi::{CreateRectRgn, SetWindowRgn};
    if toolbar.0 == 0 || w <= 0 || h <= 0 {
        return;
    }
    let hrgn = unsafe { CreateRectRgn(0, 0, w, h) };
    if hrgn.0 == 0 {
        return;
    }
    // SetWindowRgn takes ownership of the region — don't free it
    // ourselves. bRedraw=true so the clipped area repaints.
    unsafe {
        SetWindowRgn(toolbar, hrgn, true);
    }
}


fn create_toolbar(parent: HWND) -> Result<HWND, String> {
    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
        // Style cocktail mirrors upstream:
        //   FLAT       — flat (Office-style) buttons, no 3-D border
        //   LIST       — text right-of-icon (we have no icon yet, so text is
        //                button-shaped; M5.9 will swap in the imagelist)
        //   TRANSPARENT — let the rebar's gradient show through
        //   TOOLTIPS    — tooltip support (TBN_GETINFOTIP)
        //   AUTOSIZE    — buttons size to their content
        //   CCS_NOPARENTALIGN + NODIVIDER — defer positioning to the rebar
        let style = WS_CHILD
            | WS_VISIBLE
            | WS_CLIPSIBLINGS
            // CCS_NOPARENTALIGN intentionally NOT set: with it,
            // the toolbar refuses to be repositioned by its parent
            // (the rebar), so it keeps its create-time width and
            // never sees a "you're now narrower" WM_SIZE — which
            // means TBSTYLE_WRAPABLE never fires. Without it, the
            // rebar sizes the toolbar to the band's width on
            // resize and the toolbar wraps its buttons to multiple
            // rows when needed.
            | WINDOW_STYLE(CCS_NODIVIDER as u32)
            | WINDOW_STYLE(TBSTYLE_FLAT)
            | WINDOW_STYLE(TBSTYLE_LIST)
            | WINDOW_STYLE(TBSTYLE_TRANSPARENT)
            | WINDOW_STYLE(TBSTYLE_TOOLTIPS)
            // TBSTYLE_AUTOSIZE intentionally NOT set: it makes the
            // toolbar's WM_SIZE handler grow the window back to
            // its preferred (rows × 2 - 1 with our separators)
            // height after we MoveWindow it to a smaller value,
            // leaving an extra blank row below the wrapped
            // buttons. Without AUTOSIZE the size we set sticks
            // and the toolbar paints inside whatever rect we give.
            // TBSTYLE_WRAPABLE: when the band is too narrow for
            // all buttons to fit on a single line, the toolbar
            // wraps the overflow buttons to a second (third, …)
            // line. Combined with RBBS_VARIABLEHEIGHT on the
            // band, the rebar's reported height grows to match,
            // and main_window's on_size reads that height to
            // shift the tab control down accordingly. Resizing
            // wider snaps the wrapped buttons back up.
            | WINDOW_STYLE(TBSTYLE_WRAPABLE);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            TOOLBARCLASSNAMEW,
            PCWSTR::null(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            parent,
            HMENU(IDC_TOOLBAR as isize),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            return Err("CreateWindowExW(TOOLBARCLASSNAMEW) failed".into());
        }

        // Required boilerplate before TB_ADDBUTTONS — tells the
        // control which TBBUTTON struct version we're sending.
        let _ = SendMessageW(
            hwnd,
            TB_BUTTONSTRUCTSIZE,
            WPARAM(std::mem::size_of::<TBBUTTON>()),
            LPARAM(0),
        );

        // Trim the toolbar's per-button padding to 0,0. Default
        // padding under TBSTYLE_LIST adds a few pixels of vertical
        // breathing room which, multiplied across wrapped rows,
        // produces a noticeable empty band below the last row.
        // LOWORD(lparam) = horizontal padding, HIWORD(lparam) =
        // vertical.
        const TB_SETPADDING: u32 = 1111;
        let _ = SendMessageW(hwnd, TB_SETPADDING, WPARAM(0), LPARAM(0));
        // Intentionally NOT setting TBSTYLE_EX_HIDECLIPPEDBUTTONS:
        // when the toolbar band is too narrow for all buttons,
        // the rightmost button stays partially visible (clipped at
        // the band's edge) instead of disappearing entirely. That
        // half-cut button is the strongest "more buttons here"
        // visual hint we can give without going to a custom paint
        // overlay; combined with the chevron (>>) at the band's
        // right edge, the user has two cues that buttons are
        // hidden.
        let ext = TBSTYLE_EX_DOUBLEBUFFER | TBSTYLE_EX_MIXEDBUTTONS;
        let _ = SendMessageW(
            hwnd,
            TB_SETEXTENDEDSTYLE,
            WPARAM(0),
            LPARAM(ext as isize),
        );
        Ok(hwnd)
    }
}

fn populate_toolbar(toolbar: HWND, icons: &super::icons::IconSet) -> Result<(), String> {
    // Buttons in upstream's _app_toolbar_init order. iString is a
    // pointer to a static UTF-16 literal (via `w!`); pointers to
    // .rdata literals are 'static so toolbars can keep them
    // forever without lifetime concerns.
    //
    // BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT — text *and*
    // icon both visible (TBSTYLE_LIST puts text right-of-icon).
    let lookup = |id: u16| super::icons::index_for(icons, id);
    let buttons: [TBBUTTON; 15] = [
        button(IDM_TRAY_START, w!("Enable filters"), lookup(IDM_TRAY_START)),
        separator(),
        button(IDM_OPENRULESEDITOR, w!("Create rule"), lookup(IDM_OPENRULESEDITOR)),
        separator(),
        button(
            IDM_TRAY_ENABLENOTIFICATIONS_CHK,
            w!("Notifications"),
            lookup(IDM_TRAY_ENABLENOTIFICATIONS_CHK),
        ),
        button(
            IDM_TRAY_ENABLELOG_CHK,
            w!("Log to file"),
            lookup(IDM_TRAY_ENABLELOG_CHK),
        ),
        button(
            IDM_TRAY_ENABLEUILOG_CHK,
            w!("Log UI"),
            lookup(IDM_TRAY_ENABLEUILOG_CHK),
        ),
        separator(),
        button(IDM_REFRESH, w!("Refresh"), lookup(IDM_REFRESH)),
        button(IDM_SETTINGS, w!("Settings"), lookup(IDM_SETTINGS)),
        separator(),
        button(IDM_TRAY_LOGSHOW, w!("Show log"), lookup(IDM_TRAY_LOGSHOW)),
        button(IDM_TRAY_LOGCLEAR, w!("Clear log"), lookup(IDM_TRAY_LOGCLEAR)),
        separator(),
        button(IDM_RELEASES, w!("Releases"), lookup(IDM_RELEASES)),
    ];
    let res = unsafe {
        SendMessageW(
            toolbar,
            TB_ADDBUTTONS,
            WPARAM(buttons.len()),
            LPARAM(buttons.as_ptr() as isize),
        )
    };
    if res.0 == 0 {
        return Err("TB_ADDBUTTONS failed".into());
    }
    // TB_AUTOSIZE re-flows after the buttons are in. Required for
    // the rebar band to query an accurate ideal size.
    unsafe {
        let _ = SendMessageW(toolbar, TB_AUTOSIZE, WPARAM(0), LPARAM(0));
    }
    Ok(())
}

fn button(id: u16, label: PCWSTR, image_index: i32) -> TBBUTTON {
    TBBUTTON {
        // image_index is the imagelist slot from `icons::build`,
        // or `I_IMAGENONE` (-2) if that icon failed to decode —
        // the toolbar then renders text-only for that button.
        iBitmap: if image_index < 0 { I_IMAGENONE } else { image_index },
        idCommand: id as i32,
        fsState: TBSTATE_ENABLED as u8,
        // BTNS_SHOWTEXT keeps the label visible alongside the
        // icon under TBSTYLE_LIST. Without it the toolbar would
        // hide text once we provided icons.
        fsStyle: (BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT) as u8,
        bReserved: [0; 6],
        dwData: 0,
        iString: label.0 as isize,
    }
}

fn separator() -> TBBUTTON {
    TBBUTTON {
        iBitmap: 0,
        idCommand: 0,
        fsState: TBSTATE_ENABLED as u8,
        // BTNS_SEP is 1; not re-exported by Controls module in
        // windows-rs 0.54, so spelt as the literal bit.
        fsStyle: 1, // BTNS_SEP
        bReserved: [0; 6],
        dwData: 0,
        iString: 0,
    }
}

fn create_search(parent: HWND) -> Result<HWND, String> {
    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
        // Same flag set upstream uses (controls.c:921-934). Visible
        // by default — upstream gates this on an "IsShowSearchBar"
        // setting we don't have yet; default-on means the search
        // band is at least findable while the toggle is M5.5+.
        let hwnd = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_EDITW,
            PCWSTR::null(),
            WS_CHILD
                | WS_VISIBLE
                | WS_CLIPSIBLINGS
                | WS_CLIPCHILDREN
                | WS_BORDER
                | WINDOW_STYLE(ES_LEFT as u32)
                | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            parent,
            HMENU(IDC_SEARCH as isize),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            return Err("CreateWindowExW(WC_EDITW) failed".into());
        }
        Ok(hwnd)
    }
}


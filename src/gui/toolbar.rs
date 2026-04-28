// simplewall-rs — toolbar / rebar / search.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
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
//      PayPal URL. simplewall-rs replaces it with "Releases"
//      (IDM_RELEASES, same numeric slot 302) which opens our
//      GitHub releases page via ShellExecuteW.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    BTNS_AUTOSIZE, BTNS_BUTTON, BTNS_SHOWTEXT, CCS_NODIVIDER, CCS_NOPARENTALIGN, I_IMAGENONE,
    RBBIM_CHILD, RBBIM_CHILDSIZE, RBBIM_ID, RBBIM_STYLE, RBBS_CHILDEDGE, RBBS_NOGRIPPER,
    RBBS_USECHEVRON, RBBS_VARIABLEHEIGHT, RBS_BANDBORDERS, RBS_VARHEIGHT, RB_INSERTBANDW,
    REBARBANDINFOW, REBARCLASSNAMEW, TBBUTTON, TBSTATE_ENABLED, TBSTYLE_AUTOSIZE,
    TBSTYLE_EX_DOUBLEBUFFER, TBSTYLE_EX_HIDECLIPPEDBUTTONS, TBSTYLE_EX_MIXEDBUTTONS,
    TBSTYLE_FLAT, TBSTYLE_LIST, TBSTYLE_TOOLTIPS, TBSTYLE_TRANSPARENT, TB_ADDBUTTONS,
    TB_AUTOSIZE, TB_BUTTONSTRUCTSIZE, TB_GETBUTTONSIZE, TB_SETEXTENDEDSTYLE,
    TOOLBARCLASSNAMEW, WC_EDITW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, ES_AUTOHSCROLL, ES_LEFT, GetClientRect, HMENU,
    SendMessageW, WINDOW_EX_STYLE, WINDOW_STYLE, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN,
    WS_CLIPSIBLINGS, WS_EX_CLIENTEDGE, WS_VISIBLE,
};
use windows::core::{PCWSTR, w};

use super::ids::{
    IDC_REBAR, IDC_SEARCH, IDC_TOOLBAR, IDM_OPENRULESEDITOR, IDM_REFRESH, IDM_RELEASES,
    IDM_SETTINGS, IDM_TRAY_ENABLELOG_CHK, IDM_TRAY_ENABLENOTIFICATIONS_CHK,
    IDM_TRAY_ENABLEUILOG_CHK, IDM_TRAY_LOGCLEAR, IDM_TRAY_LOGSHOW, IDM_TRAY_START,
};

/// Logical width of the search edit band. DPI-scaled at create time.
const SEARCH_LOGICAL_W: i32 = 200;

/// `REBARBANDINFOW_V6_SIZE` from Win32 — the offset of `cxHeader`,
/// i.e. the size of the struct up through `lParam`. ComCtl32 rejects
/// `RB_INSERTBANDW` if `cbSize` matches neither the pre-Vista size
/// (this constant) nor the post-Vista one. windows-rs always gives
/// us the full struct including chevron/header fields, so we have
/// to pass the V6 size explicitly to stay compatible with both
/// ComCtl32 v5 (no manifest) and v6 (with manifest).
const REBARBANDINFOW_V6_SIZE: u32 =
    std::mem::offset_of!(REBARBANDINFOW, cxHeader) as u32;

/// HWNDs created by `create`. The main window stores this and uses it
/// to (a) forward WM_SIZE so the rebar self-sizes, and (b) read back
/// the rebar's height for tab-control layout.
pub struct Toolbar {
    pub rebar: HWND,
    pub toolbar: HWND,
    pub search: HWND,
}

/// Build the rebar + toolbar + search edit and insert both bands.
/// Returns the populated `Toolbar` so the caller can stash the
/// HWNDs for later layout queries.
pub fn create(parent: HWND, dpi: u32) -> Result<Toolbar, String> {
    let rebar = create_rebar(parent)?;
    let toolbar = create_toolbar(rebar)?;
    // Build the imagelist *before* populating the toolbar so each
    // TBBUTTON's iBitmap can resolve to the right index.
    let icons = super::icons::build(dpi);
    super::icons::attach_to_toolbar(toolbar, icons.himagelist);
    populate_toolbar(toolbar, &icons)?;
    let search = create_search(rebar)?;
    insert_bands(rebar, toolbar, search, dpi)?;
    Ok(Toolbar {
        rebar,
        toolbar,
        search,
    })
}

/// Get the current height of the rebar in device pixels. Called from
/// WM_SIZE so the tab control can be positioned just below it.
pub fn rebar_height(rebar: HWND) -> i32 {
    if rebar.0 == 0 {
        return 0;
    }
    let mut rect = windows::Win32::Foundation::RECT::default();
    if unsafe { GetClientRect(rebar, &mut rect) }.is_err() {
        return 0;
    }
    rect.bottom - rect.top
}

fn create_rebar(parent: HWND) -> Result<HWND, String> {
    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null())
            .map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
        // RBS_VARHEIGHT lets the toolbar band auto-grow with the
        // toolbar's preferred height (matches upstream).
        // RBS_BANDBORDERS draws the thin separators between bands.
        // CCS_NODIVIDER removes the unwanted top divider line.
        let style = WS_CHILD
            | WS_VISIBLE
            | WS_CLIPSIBLINGS
            | WS_CLIPCHILDREN
            | WINDOW_STYLE(RBS_VARHEIGHT | RBS_BANDBORDERS)
            | WINDOW_STYLE(CCS_NODIVIDER as u32);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            REBARCLASSNAMEW,
            PCWSTR::null(),
            style,
            0,
            0,
            0,
            0,
            parent,
            HMENU(IDC_REBAR as isize),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            return Err("CreateWindowExW(REBARCLASSNAMEW) failed".into());
        }
        Ok(hwnd)
    }
}

fn create_toolbar(rebar: HWND) -> Result<HWND, String> {
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
            | WINDOW_STYLE(CCS_NOPARENTALIGN as u32)
            | WINDOW_STYLE(CCS_NODIVIDER as u32)
            | WINDOW_STYLE(TBSTYLE_FLAT)
            | WINDOW_STYLE(TBSTYLE_LIST)
            | WINDOW_STYLE(TBSTYLE_TRANSPARENT)
            | WINDOW_STYLE(TBSTYLE_TOOLTIPS)
            | WINDOW_STYLE(TBSTYLE_AUTOSIZE);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            TOOLBARCLASSNAMEW,
            PCWSTR::null(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rebar,
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
        let ext = TBSTYLE_EX_DOUBLEBUFFER
            | TBSTYLE_EX_MIXEDBUTTONS
            | TBSTYLE_EX_HIDECLIPPEDBUTTONS;
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

fn create_search(rebar: HWND) -> Result<HWND, String> {
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
            rebar,
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

fn insert_bands(
    rebar: HWND,
    toolbar: HWND,
    search: HWND,
    dpi: u32,
) -> Result<(), String> {
    let button_size =
        unsafe { SendMessageW(toolbar, TB_GETBUTTONSIZE, WPARAM(0), LPARAM(0)) }.0 as u32;
    // LOWORD = width, HIWORD = height. Win32 wraps both in the same
    // LRESULT.
    let btn_w = (button_size & 0xFFFF) as i32;
    let btn_h = ((button_size >> 16) & 0xFFFF) as i32;

    let mut tb_band = REBARBANDINFOW {
        cbSize: REBARBANDINFOW_V6_SIZE,
        fMask: RBBIM_ID | RBBIM_STYLE | RBBIM_CHILD | RBBIM_CHILDSIZE,
        fStyle: RBBS_VARIABLEHEIGHT | RBBS_NOGRIPPER | RBBS_USECHEVRON,
        wID: IDC_TOOLBAR as u32,
        hwndChild: toolbar,
        cxMinChild: btn_w as u32,
        cyMinChild: btn_h as u32,
        ..Default::default()
    };
    let res = unsafe {
        SendMessageW(
            rebar,
            RB_INSERTBANDW,
            WPARAM(usize::MAX),
            LPARAM(&mut tb_band as *mut _ as isize),
        )
    };
    if res.0 == 0 {
        return Err("RB_INSERTBANDW(toolbar) failed".into());
    }

    let search_w = scale_dpi(SEARCH_LOGICAL_W, dpi) as u32;
    let mut sb_band = REBARBANDINFOW {
        cbSize: REBARBANDINFOW_V6_SIZE,
        fMask: RBBIM_ID | RBBIM_STYLE | RBBIM_CHILD | RBBIM_CHILDSIZE,
        // CHILDEDGE adds the small inset around the edit so it
        // doesn't collide with adjacent bands; NOGRIPPER hides the
        // drag handle.
        fStyle: RBBS_CHILDEDGE | RBBS_NOGRIPPER,
        wID: IDC_SEARCH as u32,
        hwndChild: search,
        cxMinChild: search_w,
        cyMinChild: btn_h.max(20) as u32,
        ..Default::default()
    };
    let res = unsafe {
        SendMessageW(
            rebar,
            RB_INSERTBANDW,
            WPARAM(usize::MAX),
            LPARAM(&mut sb_band as *mut _ as isize),
        )
    };
    if res.0 == 0 {
        return Err("RB_INSERTBANDW(search) failed".into());
    }
    Ok(())
}

/// Same DPI-scale function as `main_window` — duplicated here to
/// avoid a circular `use` between the two modules. Trivial enough
/// that copy-and-paste is cheaper than a shared helper.
fn scale_dpi(logical: i32, dpi: u32) -> i32 {
    let n = logical as i64 * dpi as i64;
    (n / 96) as i32
}

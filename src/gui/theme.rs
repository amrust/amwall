// amwall — native dark theme.
// Copyright (C) 2026 amwall contributors. Licensed GPL-3.0-or-later.
//
// Mirrors simplewall's shared routine/src/rapp.c:4693-4933: theme the
// window tree, use explicit list-view colors and custom native-control
// painting where Windows has no dark theme. Palette: routine/src/rapp.h:29-36.
// Input, layout, accessibility and focus remain owned by the native controls.

#![cfg(windows)]

use std::cell::Cell;
use std::mem::size_of;
use std::sync::OnceLock;

use windows::Win32::Foundation::{COLORREF, HANDLE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetFocus, IsWindowEnabled, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows::Win32::UI::Shell::{
    DefSubclassProc, GetWindowSubclass, RemoveWindowSubclass, SetWindowSubclass,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{PCSTR, PCWSTR, PWSTR, s, w};

pub const BACKGROUND: COLORREF = COLORREF(0x002a2a2a);
pub const SURFACE: COLORREF = COLORREF(0x00404040);
pub const TEXT: COLORREF = COLORREF(0x00f4f4f4);
const MUTED: COLORREF = COLORREF(0x00b0b0b0);
const BORDER: COLORREF = COLORREF(0x00686868);
const ACCENT: COLORREF = COLORREF(0x005080f0);
const SUBCLASS_ID: usize = 0x414d_5448;

// The optional menu-bar protocol used by simplewall, verified against
// routine/src/rtypes.h:245-299. Only consumed when Windows sends these
// messages; unsupported systems keep the ordinary native menu rendering.
const WM_UAHDRAWMENU: u32 = 0x91;
const WM_UAHDRAWMENUITEM: u32 = 0x92;
#[repr(C)]
struct UahMenu {
    menu: HMENU,
    dc: HDC,
    flags: u32,
}
#[repr(C)]
struct UahMenuItem {
    position: i32,
    item_metrics: [u32; 8],
    popup_metrics: [u32; 5],
}
#[repr(C)]
struct UahDrawMenuItem {
    draw: DRAWITEMSTRUCT,
    menu: UahMenu,
    item: UahMenuItem,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Window,
    List,
    Header,
    Tab,
    Toolbar,
    Status,
    Button,
    Combo,
    Other,
}

struct State {
    requested: Cell<bool>,
    dark: Cell<bool>,
    kind: Kind,
    background: HBRUSH,
    surface: HBRUSH,
    hot: Cell<POINT>,
}

impl Drop for State {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteObject(self.background);
            let _ = DeleteObject(self.surface);
        }
    }
}

fn class(hwnd: HWND) -> String {
    let mut name = [0u16; 96];
    let len = unsafe { GetClassNameW(hwnd, &mut name) }.max(0) as usize;
    String::from_utf16_lossy(&name[..len])
}

fn kind(hwnd: HWND) -> Kind {
    match class(hwnd).as_str() {
        "SysListView32" => Kind::List,
        "SysHeader32" => Kind::Header,
        "SysTabControl32" => Kind::Tab,
        "ToolbarWindow32" => Kind::Toolbar,
        "msctls_statusbar32" => Kind::Status,
        "Button" => Kind::Button,
        "ComboBox"
            if unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as i32 & 3 == CBS_DROPDOWNLIST =>
        {
            Kind::Combo
        }
        "#32770" | "AmwallMainWindow" => Kind::Window,
        _ if unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as u32 & WS_CHILD.0 == 0 => Kind::Window,
        _ => Kind::Other,
    }
}

fn state_ptr(hwnd: HWND) -> Option<*const State> {
    let mut data = 0;
    let installed =
        unsafe { GetWindowSubclass(hwnd, Some(subclass), SUBCLASS_ID, Some(&mut data)) }.as_bool();
    (installed && data != 0).then_some(data as *const State)
}

pub fn is_dark(hwnd: HWND) -> bool {
    state_ptr(hwnd).is_some_and(|state| unsafe { (*state).dark.get() })
}

/// The saved preference, which survives a temporary high-contrast override.
/// Query on the window's owning thread before sending it to another UI thread.
pub fn requested(hwnd: HWND) -> bool {
    state_ptr(hwnd).is_some_and(|state| unsafe { (*state).requested.get() })
}

fn high_contrast() -> bool {
    let mut value = HIGHCONTRASTW {
        cbSize: size_of::<HIGHCONTRASTW>() as u32,
        ..Default::default()
    };
    unsafe {
        SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            value.cbSize,
            Some(&mut value as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
        .is_ok()
            && value.dwFlags.contains(HCF_HIGHCONTRASTON)
    }
}

/// Newly created dialogs and lazy property pages inherit their owner's preference.
/// Preserve the preference even while Windows high-contrast mode overrides it.
pub fn inherit(hwnd: HWND, parent: HWND) {
    apply(hwnd, requested(parent));
}

/// Apply a preference to an existing tree without recreating controls or changing
/// visibility. Repeated calls reuse each subclass and its two owned GDI brushes.
pub fn apply(hwnd: HWND, requested: bool) {
    if hwnd.0 == 0 {
        return;
    }
    let dark = requested && !high_contrast();
    set_native_menu_mode(dark);
    apply_tree(hwnd, requested, dark);
    unsafe {
        let _ = DrawMenuBar(hwnd);
        let _ = RedrawWindow(
            hwnd,
            None,
            None,
            RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN,
        );
    }
}

fn apply_tree(hwnd: HWND, requested: bool, dark: bool) {
    apply_one(hwnd, requested, dark);
    let mut child = unsafe { GetWindow(hwnd, GW_CHILD) };
    while child.0 != 0 {
        apply_tree(child, requested, dark);
        child = unsafe { GetWindow(child, GW_HWNDNEXT) };
    }
}

fn apply_one(hwnd: HWND, requested: bool, dark: bool) {
    let control_kind = kind(hwnd);
    if let Some(state) = state_ptr(hwnd) {
        unsafe {
            (*state).requested.set(requested);
            (*state).dark.set(dark);
        }
    } else {
        let state = Box::new(State {
            requested: Cell::new(requested),
            dark: Cell::new(dark),
            kind: control_kind,
            background: unsafe { CreateSolidBrush(BACKGROUND) },
            surface: unsafe { CreateSolidBrush(SURFACE) },
            hot: Cell::new(POINT {
                x: i32::MIN,
                y: i32::MIN,
            }),
        });
        let raw = Box::into_raw(state);
        if !unsafe { SetWindowSubclass(hwnd, Some(subclass), SUBCLASS_ID, raw as usize) }.as_bool()
        {
            unsafe {
                drop(Box::from_raw(raw));
            }
            return;
        }
    }
    unsafe {
        let value = i32::from(dark);
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &value as *const _ as *const _,
            size_of::<i32>() as u32,
        );
        let theme = if dark {
            w!("DarkMode_Explorer")
        } else {
            w!("Explorer")
        };
        let _ = SetWindowTheme(hwnd, theme, PCWSTR::null());
        if control_kind == Kind::List {
            let bg = if dark {
                BACKGROUND.0
            } else {
                GetSysColor(COLOR_WINDOW)
            };
            let text = if dark {
                TEXT.0
            } else {
                GetSysColor(COLOR_WINDOWTEXT)
            };
            for (msg, color) in [
                (LVM_SETBKCOLOR, bg),
                (LVM_SETTEXTBKCOLOR, bg),
                (LVM_SETTEXTCOLOR, text),
            ] {
                SendMessageW(hwnd, msg, WPARAM(0), LPARAM(color as isize));
            }
            let mut metrics = LVGROUPMETRICS {
                cbSize: size_of::<LVGROUPMETRICS>() as u32,
                mask: LVGMF_TEXTCOLOR,
                crHeader: COLORREF(text),
                crFooter: COLORREF(text),
                ..Default::default()
            };
            SendMessageW(
                hwnd,
                LVM_SETGROUPMETRICS,
                WPARAM(0),
                LPARAM(&mut metrics as *mut _ as isize),
            );
            let tip = HWND(SendMessageW(hwnd, LVM_GETTOOLTIPS, WPARAM(0), LPARAM(0)).0);
            if tip.0 != 0 {
                let _ = SetWindowTheme(tip, theme, PCWSTR::null());
            }
        } else if control_kind == Kind::Toolbar {
            let tip = HWND(SendMessageW(hwnd, TB_GETTOOLTIPS, WPARAM(0), LPARAM(0)).0);
            if tip.0 != 0 {
                let _ = SetWindowTheme(tip, theme, PCWSTR::null());
            }
        } else if control_kind == Kind::Combo {
            let mut info = COMBOBOXINFO {
                cbSize: size_of::<COMBOBOXINFO>() as u32,
                ..Default::default()
            };
            if GetComboBoxInfo(hwnd, &mut info).is_ok() && info.hwndList.0 != 0 {
                let _ = SetWindowTheme(info.hwndList, theme, PCWSTR::null());
            }
        }
    }
}

type PreferredAppMode = unsafe extern "system" fn(i32) -> i32;
type FlushMenuThemes = unsafe extern "system" fn();

fn set_native_menu_mode(dark: bool) {
    // Same optional uxtheme exports as routine/rapp.c:4886-4922. Ordinal 135
    // changed signature in Windows 10 1903: never call it on older systems.
    // The system DLL remains loaded for the lifetime of the cached functions.
    static FUNCTIONS: OnceLock<Option<(PreferredAppMode, FlushMenuThemes)>> = OnceLock::new();
    let functions = FUNCTIONS.get_or_init(|| unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        let rtl = GetProcAddress(ntdll, s!("RtlGetVersion"))?;
        let rtl: unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32 = std::mem::transmute(rtl);
        let mut version = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        if rtl(&mut version) != 0 || version.dwBuildNumber < 18362 {
            return None;
        }
        let module =
            LoadLibraryExW(w!("uxtheme.dll"), HANDLE(0), LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?;
        let mode = GetProcAddress(module, PCSTR(135usize as *const u8))?;
        let flush = GetProcAddress(module, PCSTR(136usize as *const u8))?;
        Some((
            std::mem::transmute::<unsafe extern "system" fn() -> isize, PreferredAppMode>(mode),
            std::mem::transmute::<unsafe extern "system" fn() -> isize, FlushMenuThemes>(flush),
        ))
    });
    if let Some((mode, flush)) = functions {
        unsafe {
            mode(if dark { 2 } else { 0 });
            flush();
        }
    }
}

/// Preserve the semantic hue of configured row highlighting, with enough
/// contrast for the dark foreground. Original settings are never rewritten.
pub fn dark_highlight(color: COLORREF) -> COLORREF {
    let channel = |shift: u32| (((color.0 >> shift) & 255) * 3 / 10 + 24).min(100);
    COLORREF(channel(0) | (channel(8) << 8) | (channel(16) << 16))
}

unsafe extern "system" fn subclass(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    data: usize,
) -> LRESULT {
    if msg == WM_NCDESTROY {
        unsafe {
            let _ = RemoveWindowSubclass(hwnd, Some(subclass), SUBCLASS_ID);
            let result = DefSubclassProc(hwnd, msg, wparam, lparam);
            drop(Box::from_raw(data as *mut State));
            return result;
        }
    }
    let state = unsafe { &*(data as *const State) };
    if msg == WM_SETTINGCHANGE && state.kind == Kind::Window {
        apply(hwnd, state.requested.get());
    }
    if !state.dark.get() {
        return unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
    }
    match msg {
        WM_UAHDRAWMENU if lparam.0 != 0 => {
            let menu = unsafe { &*(lparam.0 as *const UahMenu) };
            let mut info = MENUBARINFO {
                cbSize: size_of::<MENUBARINFO>() as u32,
                ..Default::default()
            };
            let mut window = RECT::default();
            if unsafe { GetMenuBarInfo(hwnd, OBJID_MENU, 0, &mut info) }.is_ok()
                && unsafe { GetWindowRect(hwnd, &mut window) }.is_ok()
            {
                let rect = RECT {
                    left: info.rcBar.left - window.left,
                    top: info.rcBar.top - window.top,
                    right: info.rcBar.right - window.left,
                    bottom: info.rcBar.bottom - window.top,
                };
                fill(menu.dc, &rect, BACKGROUND);
                return LRESULT(1);
            }
        }
        WM_UAHDRAWMENUITEM if lparam.0 != 0 => {
            let item = unsafe { &*(lparam.0 as *const UahDrawMenuItem) };
            let mut label = vec![0u16; 512];
            let len = unsafe {
                GetMenuStringW(
                    item.menu.menu,
                    item.item.position as u32,
                    Some(&mut label),
                    MF_BYPOSITION,
                )
            }
            .max(0) as usize;
            label.truncate(len);
            let active = item.draw.itemState.0 & (ODS_HOTLIGHT.0 | ODS_SELECTED.0) != 0;
            let disabled = item.draw.itemState.0 & (ODS_GRAYED.0 | ODS_DISABLED.0) != 0;
            let mut rect = item.draw.rcItem;
            let saved = unsafe { SaveDC(item.menu.dc) };
            fill(
                item.menu.dc,
                &rect,
                if active { SURFACE } else { BACKGROUND },
            );
            let flags = DT_CENTER
                | DT_SINGLELINE
                | DT_VCENTER
                | if item.draw.itemState.0 & ODS_NOACCEL.0 != 0 {
                    DT_HIDEPREFIX
                } else {
                    DRAW_TEXT_FORMAT(0)
                };
            draw_text(
                item.menu.dc,
                &mut label,
                &mut rect,
                flags,
                if disabled { MUTED } else { TEXT },
            );
            unsafe {
                let _ = RestoreDC(item.menu.dc, saved);
            }
            return LRESULT(1);
        }
        WM_CTLCOLORBTN | WM_CTLCOLORDLG | WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT
        | WM_CTLCOLORLISTBOX => {
            let dc = HDC(wparam.0 as isize);
            let edit = msg == WM_CTLCOLOREDIT || msg == WM_CTLCOLORLISTBOX;
            let enabled = lparam.0 == 0 || unsafe { IsWindowEnabled(HWND(lparam.0)) }.as_bool();
            unsafe {
                SetTextColor(dc, if enabled { TEXT } else { MUTED });
                SetBkColor(dc, if edit { SURFACE } else { BACKGROUND });
                SetBkMode(dc, TRANSPARENT);
            }
            return LRESULT(if edit {
                state.surface.0
            } else {
                state.background.0
            });
        }
        WM_ERASEBKGND
            if matches!(
                state.kind,
                Kind::Window
                    | Kind::Tab
                    | Kind::Header
                    | Kind::Status
                    | Kind::Toolbar
                    | Kind::Combo
            ) =>
        {
            let mut rect = RECT::default();
            unsafe {
                let _ = GetClientRect(hwnd, &mut rect);
                FillRect(HDC(wparam.0 as isize), &rect, state.background);
            }
            return LRESULT(1);
        }
        WM_PAINT | WM_PRINTCLIENT
            if matches!(
                state.kind,
                Kind::Tab | Kind::Header | Kind::Status | Kind::Combo
            ) || (state.kind == Kind::Button
                && unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as i32 & BS_TYPEMASK
                    == BS_GROUPBOX) =>
        {
            let mut paint = PAINTSTRUCT::default();
            let dc = if msg == WM_PAINT {
                unsafe { BeginPaint(hwnd, &mut paint) }
            } else {
                HDC(wparam.0 as isize)
            };
            if !dc.is_invalid() {
                paint_control(hwnd, dc, state);
                if msg == WM_PAINT {
                    unsafe {
                        let _ = EndPaint(hwnd, &paint);
                    }
                }
            }
            return LRESULT(0);
        }
        WM_MOUSEMOVE if matches!(state.kind, Kind::Tab | Kind::Header) => {
            let point = POINT {
                x: lparam.0 as i16 as i32,
                y: (lparam.0 >> 16) as i16 as i32,
            };
            if state.hot.get() != point {
                state.hot.set(point);
                let mut tracking = TRACKMOUSEEVENT {
                    cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                    dwFlags: TME_LEAVE,
                    hwndTrack: hwnd,
                    ..Default::default()
                };
                unsafe {
                    let _ = TrackMouseEvent(&mut tracking);
                    let _ = InvalidateRect(hwnd, None, false);
                }
            }
        }
        WM_MOUSELEAVE => {
            state.hot.set(POINT {
                x: i32::MIN,
                y: i32::MIN,
            });
            unsafe {
                let _ = InvalidateRect(hwnd, None, false);
            }
        }
        WM_NOTIFY if lparam.0 != 0 => {
            let header = unsafe { &*(lparam.0 as *const NMHDR) };
            if header.code == NM_CUSTOMDRAW {
                let original = unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
                return unsafe { custom_draw(lparam, original) };
            }
        }
        _ => {}
    }
    unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
}

unsafe fn custom_draw(lparam: LPARAM, original: LRESULT) -> LRESULT {
    let draw = unsafe { &mut *(lparam.0 as *mut NMCUSTOMDRAW) };
    let control_kind = state_ptr(draw.hdr.hwndFrom)
        .map(|state| unsafe { (*state).kind })
        .unwrap_or_else(|| kind(draw.hdr.hwndFrom));
    match control_kind {
        Kind::List => {
            let draw = unsafe { &mut *(lparam.0 as *mut NMLVCUSTOMDRAW) };
            // ComCtl32 v6 ignores LVGROUPMETRICS.crHeader and clrText for
            // themed groups. Their draw stages are PRE/POSTPAINT, not the
            // ITEMPREPAINT used for ordinary rows. Keep native group drawing
            // and accessibility, then recolor its label, divider and glyph.
            if draw.dwItemType == LVCDI_GROUP {
                if draw.nmcd.dwDrawStage == CDDS_PREPAINT {
                    return LRESULT(original.0 | CDRF_NOTIFYPOSTPAINT as isize);
                }
                if draw.nmcd.dwDrawStage == CDDS_POSTPAINT {
                    paint_group_heading(draw);
                }
                return original;
            }
            if draw.nmcd.dwDrawStage == CDDS_PREPAINT {
                return LRESULT(original.0 | CDRF_NOTIFYITEMDRAW as isize);
            }
            if draw.nmcd.dwDrawStage == CDDS_ITEMPREPAINT {
                if draw.clrTextBk != BACKGROUND && draw.clrTextBk.0 != CLR_DEFAULT as u32 {
                    draw.clrTextBk = dark_highlight(draw.clrTextBk);
                }
                draw.clrText = TEXT;
                return LRESULT(original.0 | CDRF_NEWFONT as isize);
            }
        }
        Kind::Toolbar => {
            let draw = unsafe { &mut *(lparam.0 as *mut NMTBCUSTOMDRAW) };
            if draw.nmcd.dwDrawStage == CDDS_PREPAINT {
                fill(draw.nmcd.hdc, &draw.nmcd.rc, BACKGROUND);
                return LRESULT(CDRF_NOTIFYITEMDRAW as isize);
            }
            if draw.nmcd.dwDrawStage == CDDS_ITEMPREPAINT {
                draw.clrText = TEXT;
                draw.clrTextHighlight = TEXT;
                draw.clrBtnFace = BACKGROUND;
                draw.clrBtnHighlight = SURFACE;
                draw.clrHighlightHotTrack = SURFACE;
                draw.nStringBkMode = TRANSPARENT.0 as i32;
                draw.nHLStringBkMode = TRANSPARENT.0 as i32;
                return LRESULT(
                    (TBCDRF_USECDCOLORS | TBCDRF_HILITEHOTTRACK | TBCDRF_NOBACKGROUND) as isize,
                );
            }
        }
        Kind::Button if draw.dwDrawStage == CDDS_PREPAINT && paint_button(draw) => {
            return LRESULT(CDRF_SKIPDEFAULT as isize);
        }
        _ => {}
    }
    original
}

fn paint_group_heading(draw: &NMLVCUSTOMDRAW) {
    let hwnd = draw.nmcd.hdr.hwndFrom;
    let group_id = draw.nmcd.dwItemSpec;
    let mut label = [0u16; 1024];
    let mut group = LVGROUP {
        cbSize: size_of::<LVGROUP>() as u32,
        mask: LVGF_HEADER | LVGF_STATE,
        pszHeader: PWSTR(label.as_mut_ptr()),
        cchHeader: label.len() as i32,
        stateMask: LIST_VIEW_GROUP_STATE_FLAGS(LVGS_COLLAPSED.0 | LVGS_COLLAPSIBLE.0),
        ..Default::default()
    };
    let mut rect = RECT {
        top: LVGGR_LABEL as i32,
        ..Default::default()
    };
    unsafe {
        if SendMessageW(
            hwnd,
            LVM_GETGROUPINFO,
            WPARAM(group_id),
            LPARAM(&mut group as *mut _ as isize),
        )
        .0 == -1
            || SendMessageW(
                hwnd,
                LVM_GETGROUPRECT,
                WPARAM(group_id),
                LPARAM(&mut rect as *mut _ as isize),
            )
            .0 == 0
            || rect.right <= rect.left
            || rect.bottom <= rect.top
        {
            return;
        }
        let len = label.iter().position(|&ch| ch == 0).unwrap_or(label.len());
        let label_rect = rect;
        let saved = SaveDC(draw.nmcd.hdc);
        // Bounds come from the native group layout; only rendering changes.
        fill(draw.nmcd.hdc, &rect, BACKGROUND);
        let theme = OpenThemeData(hwnd, w!("ListView"));
        let options = DTTOPTS {
            dwSize: size_of::<DTTOPTS>() as u32,
            dwFlags: DTT_TEXTCOLOR,
            crText: TEXT,
            ..Default::default()
        };
        let flags = DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS;
        let state = if group.state.0 & LVGS_COLLAPSED.0 != 0 {
            LVGH_CLOSE
        } else {
            LVGH_OPEN
        };
        if theme.is_invalid()
            || DrawThemeTextEx(
                theme,
                draw.nmcd.hdc,
                LVP_GROUPHEADER.0,
                state.0,
                &label[..len],
                flags,
                &mut rect,
                Some(&options),
            )
            .is_err()
        {
            let font = SendMessageW(hwnd, WM_GETFONT, WPARAM(0), LPARAM(0));
            if font.0 != 0 {
                SelectObject(draw.nmcd.hdc, HFONT(font.0));
            }
            draw_text(draw.nmcd.hdc, &mut label[..len], &mut rect, flags, TEXT);
        }
        if !theme.is_invalid() {
            let _ = CloseThemeData(theme);
        }
        let chevron = if group.state.0 & LVGS_COLLAPSIBLE.0 != 0 {
            paint_group_chevron(
                hwnd,
                draw.nmcd.hdc,
                draw.rcText,
                group.state.0 & LVGS_COLLAPSED.0 != 0,
            )
        } else {
            None
        };
        paint_group_divider(hwnd, draw.nmcd.hdc, draw.rcText, label_rect, chevron);
        let _ = RestoreDC(draw.nmcd.hdc, saved);
    }
}

fn paint_group_chevron(hwnd: HWND, dc: HDC, header: RECT, collapsed: bool) -> Option<RECT> {
    // The hit-test target is maintained by the native ListView. Find that
    // target instead of assuming a glyph offset that changes with DPI, font,
    // theme, or RTL layout. Only the edge containing the target is searched;
    // binary searches then find its exact rectangle with a few local messages.
    let hit = |x: i32, y: i32| {
        let mut info = LVHITTESTINFO {
            pt: POINT { x, y },
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                hwnd,
                LVM_HITTEST,
                WPARAM(usize::MAX),
                LPARAM(&mut info as *mut _ as isize),
            );
        }
        info.flags.0 & LVHT_EX_GROUP_COLLAPSE.0 != 0
    };
    let y = (header.top + header.bottom) / 2;
    let rtl = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } as u32 & WS_EX_LAYOUTRTL.0 != 0;
    let search_width = scale(hwnd, 64).min(header.right - header.left).max(0);
    let x = (0..search_width)
        .step_by(scale(hwnd, 2).max(1) as usize)
        .map(|offset| {
            if rtl {
                header.left + offset
            } else {
                header.right - 1 - offset
            }
        })
        .find(|&x| hit(x, y));
    let x = x?;
    let first_true = |mut low: i32, mut high: i32, horizontal: bool| {
        while low < high {
            let middle = low + (high - low) / 2;
            if if horizontal {
                hit(middle, y)
            } else {
                hit(x, middle)
            } {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    };
    let last_true = |mut low: i32, mut high: i32, horizontal: bool| {
        while low < high {
            let middle = low + (high - low + 1) / 2;
            if if horizontal {
                hit(middle, y)
            } else {
                hit(x, middle)
            } {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        low
    };
    let rect = RECT {
        left: first_true(header.left, x, true),
        right: last_true(x, header.right - 1, true) + 1,
        top: first_true(header.top, y, false),
        bottom: last_true(y, header.bottom - 1, false) + 1,
    };
    let center_x = (rect.left + rect.right) / 2;
    let center_y = (rect.top + rect.bottom) / 2;
    let half_width = scale(hwnd, 4).min((rect.right - rect.left) / 2);
    let half_height = scale(hwnd, 2).min((rect.bottom - rect.top) / 2);
    if half_width <= 0 || half_height <= 0 {
        return Some(rect);
    }
    fill(dc, &rect, BACKGROUND);
    let direction = if collapsed { 1 } else { -1 };
    unsafe {
        let pen = CreatePen(PS_SOLID, scale(hwnd, 2), TEXT);
        let previous = SelectObject(dc, pen);
        let _ = MoveToEx(
            dc,
            center_x - half_width,
            center_y - direction * half_height,
            None,
        );
        let _ = LineTo(dc, center_x, center_y + direction * half_height);
        let _ = LineTo(
            dc,
            center_x + half_width,
            center_y - direction * half_height,
        );
        SelectObject(dc, previous);
        let _ = DeleteObject(pen);
    }
    Some(rect)
}

fn paint_group_divider(hwnd: HWND, dc: HDC, header: RECT, label: RECT, chevron: Option<RECT>) {
    // The space between the native label and collapse target contains the
    // themed blue separator. Clear that strip and draw a neutral divider,
    // keeping both native content rectangles and all hit targets intact.
    let rtl = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } as u32 & WS_EX_LAYOUTRTL.0 != 0;
    let mut strip = if rtl {
        RECT {
            left: chevron.map_or(header.left, |rect| rect.right),
            right: label.left,
            ..header
        }
    } else {
        RECT {
            left: label.right,
            right: chevron.map_or(header.right, |rect| rect.left),
            ..header
        }
    };
    if strip.right <= strip.left {
        return;
    }
    fill(dc, &strip, BACKGROUND);
    let gap = scale(hwnd, 5);
    strip.left += gap;
    strip.right -= gap;
    if strip.right <= strip.left {
        return;
    }
    strip.top = (header.top + header.bottom) / 2;
    strip.bottom = strip.top + scale(hwnd, 1).max(1);
    fill(dc, &strip, BORDER);
}

fn text(hwnd: HWND) -> Vec<u16> {
    let len = unsafe { GetWindowTextLengthW(hwnd) }.max(0) as usize;
    let mut value = vec![0; len + 1];
    let len = unsafe { GetWindowTextW(hwnd, &mut value) }.max(0) as usize;
    value.truncate(len);
    value
}

fn fill(dc: HDC, rect: &RECT, color: COLORREF) {
    unsafe {
        SetDCBrushColor(dc, color);
        FillRect(dc, rect, HBRUSH(GetStockObject(DC_BRUSH).0));
    }
}

fn frame(dc: HDC, rect: &RECT, color: COLORREF) {
    unsafe {
        SetDCBrushColor(dc, color);
        FrameRect(dc, rect, HBRUSH(GetStockObject(DC_BRUSH).0));
    }
}

fn draw_text(dc: HDC, text: &mut [u16], rect: &mut RECT, flags: DRAW_TEXT_FORMAT, color: COLORREF) {
    unsafe {
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, color);
        DrawTextW(dc, text, rect, flags);
    }
}

fn scale(hwnd: HWND, value: i32) -> i32 {
    value * unsafe { GetDpiForWindow(hwnd) }.max(96) as i32 / 96
}

fn paint_control(hwnd: HWND, dc: HDC, state: &State) {
    let saved = unsafe { SaveDC(dc) };
    let font = unsafe { SendMessageW(hwnd, WM_GETFONT, WPARAM(0), LPARAM(0)) };
    if font.0 != 0 {
        unsafe {
            SelectObject(dc, HFONT(font.0));
        }
    }
    let mut client = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut client);
    }
    // A group box overlaps sibling controls rather than owning them. Filling
    // its whole rectangle would erase those controls while switching pages.
    if state.kind != Kind::Button {
        fill(dc, &client, BACKGROUND);
    }
    match state.kind {
        Kind::Tab => paint_tabs(hwnd, dc, state),
        Kind::Header => paint_headers(hwnd, dc, state),
        Kind::Status => paint_status(hwnd, dc),
        Kind::Combo => paint_combo(hwnd, dc, client),
        Kind::Button => {
            client.top += scale(hwnd, 7);
            frame(dc, &client, BORDER);
            let mut label = text(hwnd);
            let mut rect = client;
            rect.left += scale(hwnd, 10);
            rect.top = 0;
            unsafe {
                DrawTextW(dc, &mut label, &mut rect, DT_CALCRECT | DT_SINGLELINE);
            }
            fill(dc, &rect, BACKGROUND);
            draw_text(dc, &mut label, &mut rect, DT_SINGLELINE, TEXT);
        }
        _ => {}
    }
    unsafe {
        let _ = RestoreDC(dc, saved);
    }
}

fn paint_tabs(hwnd: HWND, dc: HDC, state: &State) {
    let count = unsafe { SendMessageW(hwnd, TCM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0;
    let selected = unsafe { SendMessageW(hwnd, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0;
    for index in 0..count {
        let mut rect = RECT::default();
        unsafe {
            SendMessageW(
                hwnd,
                TCM_GETITEMRECT,
                WPARAM(index as usize),
                LPARAM(&mut rect as *mut _ as isize),
            );
        }
        let mut label = vec![0u16; 512];
        let mut item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: PWSTR(label.as_mut_ptr()),
            cchTextMax: label.len() as i32,
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                hwnd,
                TCM_GETITEMW,
                WPARAM(index as usize),
                LPARAM(&mut item as *mut _ as isize),
            );
        }
        label.truncate(label.iter().position(|&x| x == 0).unwrap_or(label.len()));
        let hot = unsafe { PtInRect(&rect, state.hot.get()) }.as_bool();
        fill(
            dc,
            &rect,
            if index == selected || hot {
                SURFACE
            } else {
                BACKGROUND
            },
        );
        if index == selected {
            let stripe = RECT {
                top: rect.bottom - scale(hwnd, 2),
                ..rect
            };
            fill(dc, &stripe, ACCENT);
            if unsafe { GetFocus() } == hwnd {
                let mut focus = rect;
                focus.left += 3;
                focus.right -= 3;
                focus.top += 3;
                focus.bottom -= 3;
                unsafe {
                    let _ = DrawFocusRect(dc, &focus);
                }
            }
        }
        draw_text(
            dc,
            &mut label,
            &mut rect,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_HIDEPREFIX,
            TEXT,
        );
    }
}

fn paint_headers(hwnd: HWND, dc: HDC, state: &State) {
    let count = unsafe { SendMessageW(hwnd, HDM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0;
    for index in 0..count {
        let mut rect = RECT::default();
        unsafe {
            SendMessageW(
                hwnd,
                HDM_GETITEMRECT,
                WPARAM(index as usize),
                LPARAM(&mut rect as *mut _ as isize),
            );
        }
        let mut label = vec![0u16; 512];
        let mut item = HDITEMW {
            mask: HDI_TEXT | HDI_FORMAT,
            pszText: PWSTR(label.as_mut_ptr()),
            cchTextMax: label.len() as i32,
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                hwnd,
                HDM_GETITEMW,
                WPARAM(index as usize),
                LPARAM(&mut item as *mut _ as isize),
            );
        }
        label.truncate(label.iter().position(|&x| x == 0).unwrap_or(label.len()));
        fill(
            dc,
            &rect,
            if unsafe { PtInRect(&rect, state.hot.get()) }.as_bool() {
                SURFACE
            } else {
                BACKGROUND
            },
        );
        let line = RECT {
            left: rect.right - 1,
            ..rect
        };
        fill(dc, &line, SURFACE);
        rect.left += scale(hwnd, 7);
        rect.right -= scale(hwnd, 7);
        if item.fmt.0 & (HDF_SORTUP.0 | HDF_SORTDOWN.0) != 0 {
            let mut arrow = RECT {
                left: rect.right - scale(hwnd, 12),
                ..rect
            };
            let mut glyph = if item.fmt.0 & HDF_SORTUP.0 != 0 {
                "▲"
            } else {
                "▼"
            }
            .encode_utf16()
            .collect::<Vec<_>>();
            draw_text(
                dc,
                &mut glyph,
                &mut arrow,
                DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
                MUTED,
            );
            rect.right = arrow.left;
        }
        let align = if item.fmt.0 & HDF_RIGHT.0 != 0 {
            DT_RIGHT
        } else if item.fmt.0 & HDF_CENTER.0 != 0 {
            DT_CENTER
        } else {
            DT_LEFT
        };
        draw_text(
            dc,
            &mut label,
            &mut rect,
            align | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX,
            TEXT,
        );
    }
}

fn paint_status(hwnd: HWND, dc: HDC) {
    let count = unsafe { SendMessageW(hwnd, SB_GETPARTS, WPARAM(0), LPARAM(0)) }.0;
    for index in 0..count {
        let mut rect = RECT::default();
        unsafe {
            SendMessageW(
                hwnd,
                SB_GETRECT,
                WPARAM(index as usize),
                LPARAM(&mut rect as *mut _ as isize),
            );
        }
        let len =
            unsafe { SendMessageW(hwnd, SB_GETTEXTLENGTHW, WPARAM(index as usize), LPARAM(0)) }.0
                as usize
                & 0xffff;
        let mut label = vec![0u16; len + 1];
        unsafe {
            SendMessageW(
                hwnd,
                SB_GETTEXTW,
                WPARAM(index as usize),
                LPARAM(label.as_mut_ptr() as isize),
            );
        }
        label.truncate(len);
        let line = RECT {
            left: rect.right - 1,
            ..rect
        };
        fill(dc, &line, SURFACE);
        rect.left += scale(hwnd, 5);
        rect.right -= scale(hwnd, 5);
        draw_text(
            dc,
            &mut label,
            &mut rect,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX,
            TEXT,
        );
    }
}

fn paint_combo(hwnd: HWND, dc: HDC, client: RECT) {
    let enabled = unsafe { IsWindowEnabled(hwnd) }.as_bool();
    let color = if enabled { TEXT } else { MUTED };
    fill(dc, &client, SURFACE);
    frame(
        dc,
        &client,
        if unsafe { GetFocus() } == hwnd {
            ACCENT
        } else {
            BORDER
        },
    );
    let button_width = scale(hwnd, 24);
    let mut arrow = RECT {
        left: client.right - button_width,
        ..client
    };
    draw_text(
        dc,
        &mut [0x25bc],
        &mut arrow,
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        color,
    );
    let index = unsafe { SendMessageW(hwnd, CB_GETCURSEL, WPARAM(0), LPARAM(0)) }.0;
    if index < 0 {
        return;
    }
    let len = unsafe { SendMessageW(hwnd, CB_GETLBTEXTLEN, WPARAM(index as usize), LPARAM(0)) }.0;
    if !(0..=32767).contains(&len) {
        return;
    }
    let mut label = vec![0; len as usize + 1];
    unsafe {
        SendMessageW(
            hwnd,
            CB_GETLBTEXT,
            WPARAM(index as usize),
            LPARAM(label.as_mut_ptr() as isize),
        );
    }
    label.truncate(len as usize);
    let mut rect = RECT {
        left: client.left + scale(hwnd, 6),
        right: arrow.left,
        ..client
    };
    draw_text(
        dc,
        &mut label,
        &mut rect,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX,
        color,
    );
}

fn paint_button(draw: &NMCUSTOMDRAW) -> bool {
    let hwnd = draw.hdr.hwndFrom;
    let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as i32;
    let kind = style & BS_TYPEMASK;
    if kind == BS_OWNERDRAW || kind == BS_GROUPBOX {
        return false;
    }
    let check = matches!(
        kind,
        BS_CHECKBOX
            | BS_AUTOCHECKBOX
            | BS_3STATE
            | BS_AUTO3STATE
            | BS_RADIOBUTTON
            | BS_AUTORADIOBUTTON
    );
    let pressed = draw.uItemState.contains(CDIS_SELECTED);
    let hot = draw.uItemState.contains(CDIS_HOT);
    let disabled = draw.uItemState.contains(CDIS_DISABLED);
    let saved = unsafe { SaveDC(draw.hdc) };
    let mut rect = draw.rc;
    fill(
        draw.hdc,
        &rect,
        if check {
            BACKGROUND
        } else if pressed {
            COLORREF(0x00525252)
        } else if hot {
            SURFACE
        } else {
            COLORREF(0x00343434)
        },
    );
    if check {
        let side = scale(hwnd, 16);
        let glyph = RECT {
            left: rect.left,
            top: rect.top + (rect.bottom - rect.top - side) / 2,
            right: rect.left + side,
            bottom: rect.top + (rect.bottom - rect.top + side) / 2,
        };
        let checked = unsafe { SendMessageW(hwnd, BM_GETCHECK, WPARAM(0), LPARAM(0)) }.0 as u32;
        let radio = matches!(kind, BS_RADIOBUTTON | BS_AUTORADIOBUTTON);
        let theme = unsafe { OpenThemeData(hwnd, w!("Button")) };
        if !theme.is_invalid() {
            let state = if disabled {
                4
            } else if pressed {
                3
            } else if hot {
                2
            } else {
                1
            } + if checked == BST_INDETERMINATE.0 {
                8
            } else if checked == BST_CHECKED.0 {
                4
            } else {
                0
            };
            unsafe {
                let _ = DrawThemeBackground(
                    theme,
                    draw.hdc,
                    if radio {
                        BP_RADIOBUTTON.0
                    } else {
                        BP_CHECKBOX.0
                    },
                    state,
                    &glyph,
                    None,
                );
                let _ = CloseThemeData(theme);
            }
        }
        rect.left += side + scale(hwnd, 5);
    } else {
        frame(
            draw.hdc,
            &rect,
            if style & BS_DEFPUSHBUTTON != 0 {
                ACCENT
            } else {
                BORDER
            },
        );
    }
    let mut label = text(hwnd);
    draw_text(
        draw.hdc,
        &mut label,
        &mut rect,
        if check {
            DT_LEFT | DT_VCENTER | DT_SINGLELINE
        } else {
            DT_CENTER | DT_VCENTER | DT_SINGLELINE
        },
        if disabled { MUTED } else { TEXT },
    );
    if draw.uItemState.contains(CDIS_FOCUS) {
        rect.left += 3;
        rect.right -= 3;
        rect.top += 3;
        rect.bottom -= 3;
        unsafe {
            let _ = DrawFocusRect(draw.hdc, &rect);
        }
    }
    unsafe {
        let _ = RestoreDC(draw.hdc, saved);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestWindow(HWND);
    impl TestWindow {
        fn new(class: PCWSTR, parent: HWND, style: WINDOW_STYLE) -> Self {
            let hwnd = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    class,
                    w!("Theme test"),
                    style,
                    0,
                    0,
                    420,
                    160,
                    parent,
                    None,
                    None,
                    None,
                )
            };
            assert_ne!(hwnd.0, 0);
            Self(hwnd)
        }
    }
    impl Drop for TestWindow {
        fn drop(&mut self) {
            unsafe {
                let _ = DestroyWindow(self.0);
            }
        }
    }

    fn initialize() {
        unsafe {
            let _ = InitCommonControlsEx(&INITCOMMONCONTROLSEX {
                dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
                dwICC: ICC_WIN95_CLASSES,
            });
        }
    }

    #[test]
    fn native_theme_toggles_colors_without_recreating_controls_or_losing_state() {
        initialize();
        let root = TestWindow::new(w!("STATIC"), HWND(0), WS_OVERLAPPEDWINDOW);
        let lv = TestWindow::new(WC_LISTVIEWW, root.0, WS_CHILD | WINDOW_STYLE(LVS_REPORT));
        let check = TestWindow::new(
            w!("BUTTON"),
            root.0,
            WS_CHILD | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
        );
        unsafe {
            SendMessageW(
                check.0,
                BM_SETCHECK,
                WPARAM(BST_CHECKED.0 as usize),
                LPARAM(0),
            );
        }
        // Bypass the user's current accessibility preference only in this
        // isolated control-tree test; public apply always honors it.
        apply_tree(root.0, true, true);
        assert!(is_dark(lv.0));
        assert_eq!(
            unsafe { SendMessageW(lv.0, LVM_GETBKCOLOR, WPARAM(0), LPARAM(0)) }.0,
            BACKGROUND.0 as isize
        );
        assert_eq!(
            unsafe { SendMessageW(lv.0, LVM_GETTEXTCOLOR, WPARAM(0), LPARAM(0)) }.0,
            TEXT.0 as isize
        );
        let state = state_ptr(lv.0).unwrap();
        for _ in 0..3 {
            apply_tree(root.0, false, false);
            assert!(!is_dark(lv.0));
            assert_eq!(
                unsafe { SendMessageW(lv.0, LVM_GETBKCOLOR, WPARAM(0), LPARAM(0)) }.0,
                unsafe { GetSysColor(COLOR_WINDOW) } as isize
            );
            apply_tree(root.0, true, true);
            assert_eq!(state_ptr(lv.0).unwrap(), state);
            assert_eq!(
                unsafe { SendMessageW(check.0, BM_GETCHECK, WPARAM(0), LPARAM(0)) }.0,
                BST_CHECKED.0 as isize
            );
            assert_eq!(
                unsafe { GetWindowLongPtrW(lv.0, GWL_STYLE) } as u32 & WS_VISIBLE.0,
                0
            );
        }
        // The subclass is removed on teardown (its State owns the brushes).
        let old_hwnd = lv.0;
        drop(lv);
        assert!(state_ptr(old_hwnd).is_none());
    }

    #[test]
    fn native_dark_tabs_header_and_status_paint_their_surface_and_text() {
        initialize();
        let root = TestWindow::new(w!("STATIC"), HWND(0), WS_OVERLAPPEDWINDOW);
        let tab = TestWindow::new(WC_TABCONTROLW, root.0, WS_CHILD);
        let header = TestWindow::new(WC_HEADERW, root.0, WS_CHILD);
        let status = TestWindow::new(STATUSCLASSNAMEW, root.0, WS_CHILD);
        let combo = TestWindow::new(
            w!("COMBOBOX"),
            root.0,
            WS_CHILD | WINDOW_STYLE((CBS_DROPDOWNLIST | CBS_HASSTRINGS) as u32),
        );
        let mut label = super::super::wide("Connections");
        let mut tab_item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: PWSTR(label.as_mut_ptr()),
            ..Default::default()
        };
        let mut header_item = HDITEMW {
            mask: HDI_TEXT | HDI_WIDTH | HDI_FORMAT,
            cxy: 210,
            pszText: PWSTR(label.as_mut_ptr()),
            fmt: HDF_STRING,
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                tab.0,
                TCM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&mut tab_item as *mut _ as isize),
            );
            SendMessageW(
                header.0,
                HDM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&mut header_item as *mut _ as isize),
            );
            SendMessageW(
                status.0,
                SB_SETTEXTW,
                WPARAM(0),
                LPARAM(label.as_mut_ptr() as isize),
            );
            SendMessageW(
                combo.0,
                CB_ADDSTRING,
                WPARAM(0),
                LPARAM(label.as_mut_ptr() as isize),
            );
            SendMessageW(combo.0, CB_SETCURSEL, WPARAM(0), LPARAM(0));
        }
        apply_tree(root.0, true, true);
        unsafe {
            let dc = CreateCompatibleDC(None);
            let bitmap = CreateBitmap(420, 160, 1, 32, None);
            let previous = SelectObject(dc, bitmap);
            for control in [tab.0, header.0, status.0, combo.0] {
                let mut bounds = RECT::default();
                GetClientRect(control, &mut bounds).unwrap();
                fill(
                    dc,
                    &RECT {
                        left: 0,
                        top: 0,
                        right: 420,
                        bottom: 160,
                    },
                    COLORREF(0x00ff00ff),
                );
                SendMessageW(
                    control,
                    WM_PRINTCLIENT,
                    WPARAM(dc.0 as usize),
                    LPARAM(PRF_CLIENT as isize),
                );
                assert_eq!(
                    GetPixel(dc, bounds.right - 2, 2),
                    if control == combo.0 {
                        SURFACE
                    } else {
                        BACKGROUND
                    },
                    "{} surface",
                    class(control)
                );
                let text_pixels = (0..bounds.bottom)
                    .flat_map(|y| (0..210.min(bounds.right)).map(move |x| (x, y)))
                    .filter(|&(x, y)| GetPixel(dc, x, y) == TEXT)
                    .count();
                assert!(
                    text_pixels > 0,
                    "{} did not paint readable text",
                    class(control)
                );
            }
            SelectObject(dc, previous);
            let _ = DeleteObject(bitmap);
            let _ = DeleteDC(dc);
        }
    }

    #[test]
    fn semantic_highlights_keep_hue_and_readable_dark_brightness() {
        let green = dark_highlight(COLORREF(0x0088ff88));
        assert!(((green.0 >> 8) & 255) > (green.0 & 255));
        for color in [
            COLORREF(0),
            COLORREF(0x00ffffff),
            COLORREF(0x00ffff00),
            COLORREF(0x0000ffff),
        ] {
            let mapped = dark_highlight(color);
            for shift in [0, 8, 16] {
                assert!(((mapped.0 >> shift) & 255) <= 100);
            }
        }
    }

    #[test]
    fn native_group_heading_is_readable_in_dark_mode_and_restores_native_light() {
        initialize();
        let root = TestWindow::new(w!("STATIC"), HWND(0), WS_OVERLAPPEDWINDOW);
        let list = TestWindow::new(
            WC_LISTVIEWW,
            root.0,
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(LVS_REPORT),
        );
        let font = super::super::font::load_message_font();
        let mut column = LVCOLUMNW {
            mask: LVCF_WIDTH,
            cx: 380,
            ..Default::default()
        };
        let mut label = super::super::wide("Blocked (1/1)");
        let mut row_text = super::super::wide("browser.exe");
        let mut row = LVITEMW {
            mask: LVIF_TEXT | LVIF_GROUPID,
            iItem: 0,
            iGroupId: 37,
            pszText: PWSTR(row_text.as_mut_ptr()),
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                list.0,
                LVM_INSERTCOLUMNW,
                WPARAM(0),
                LPARAM(&mut column as *mut _ as isize),
            );
            super::super::listview_groups::enable(list.0);
            assert!(super::super::listview_groups::insert(list.0, 37, &mut label) >= 0);
            SendMessageW(
                list.0,
                LVM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&mut row as *mut _ as isize),
            );
            super::super::font::apply_recursive(root.0, font);
            let dc = CreateCompatibleDC(None);
            let bitmap = CreateBitmap(420, 160, 1, 32, None);
            let previous = SelectObject(dc, bitmap);
            let render = || {
                fill(
                    dc,
                    &RECT {
                        left: 0,
                        top: 0,
                        right: 420,
                        bottom: 160,
                    },
                    COLORREF(SendMessageW(list.0, LVM_GETBKCOLOR, WPARAM(0), LPARAM(0)).0 as u32),
                );
                SendMessageW(
                    list.0,
                    WM_PRINTCLIENT,
                    WPARAM(dc.0 as usize),
                    LPARAM(PRF_CLIENT as isize),
                );
                let mut rect = RECT {
                    top: LVGGR_LABEL as i32,
                    ..Default::default()
                };
                assert_ne!(
                    SendMessageW(
                        list.0,
                        LVM_GETGROUPRECT,
                        WPARAM(37),
                        LPARAM(&mut rect as *mut _ as isize)
                    )
                    .0,
                    0
                );
                (rect.top..rect.bottom)
                    .flat_map(|y| (rect.left..rect.right).map(move |x| GetPixel(dc, x, y).0))
                    .collect::<Vec<_>>()
            };
            let glyph_pixels = || {
                let mut header = RECT {
                    top: LVGGR_HEADER as i32,
                    ..Default::default()
                };
                assert_ne!(
                    SendMessageW(
                        list.0,
                        LVM_GETGROUPRECT,
                        WPARAM(37),
                        LPARAM(&mut header as *mut _ as isize)
                    )
                    .0,
                    0
                );
                let mut pixels = Vec::new();
                for y in header.top..header.bottom {
                    for x in header.left..header.right {
                        let mut hit = LVHITTESTINFO {
                            pt: POINT { x, y },
                            ..Default::default()
                        };
                        SendMessageW(
                            list.0,
                            LVM_HITTEST,
                            WPARAM(usize::MAX),
                            LPARAM(&mut hit as *mut _ as isize),
                        );
                        if hit.flags.0 & LVHT_EX_GROUP_COLLAPSE.0 != 0 {
                            pixels.push(GetPixel(dc, x, y).0);
                        }
                    }
                }
                pixels
            };
            let header_pixels = || {
                let mut header = RECT {
                    top: LVGGR_HEADER as i32,
                    ..Default::default()
                };
                assert_ne!(
                    SendMessageW(
                        list.0,
                        LVM_GETGROUPRECT,
                        WPARAM(37),
                        LPARAM(&mut header as *mut _ as isize)
                    )
                    .0,
                    0
                );
                (header.top..header.bottom)
                    .flat_map(|y| (header.left..header.right).map(move |x| GetPixel(dc, x, y).0))
                    .collect::<Vec<_>>()
            };
            apply_tree(root.0, false, false);
            let light = render();
            let light_glyph = glyph_pixels();
            let light_header = header_pixels();
            apply_tree(root.0, true, true);
            let dark = render();
            let readable = |pixels: &[u32]| {
                pixels
                    .iter()
                    .filter(|&&color| {
                        (color & 255) > 200
                            && ((color >> 8) & 255) > 200
                            && ((color >> 16) & 255) > 200
                    })
                    .count()
            };
            assert!(
                readable(&dark) > 20,
                "native group heading lacks readable foreground pixels"
            );
            let blue_pixels = |pixels: &[u32]| {
                pixels
                    .iter()
                    .filter(|&&color| {
                        ((color >> 16) & 255) > (color & 255) + 20
                            && ((color >> 16) & 255) > ((color >> 8) & 255) + 20
                    })
                    .count()
            };
            let dark_glyph = glyph_pixels();
            // ClearType white text has colored subpixel edges. No native
            // blue may remain outside that already-verified white label.
            assert_eq!(
                blue_pixels(&header_pixels()),
                blue_pixels(&dark),
                "expanded group header retained blue pixels outside white text anti-aliasing"
            );
            assert!(
                header_pixels().contains(&BORDER.0),
                "expanded group separator is missing its neutral color"
            );
            assert!(
                readable(&dark_glyph) > 5,
                "expanded group arrow lacks readable foreground pixels"
            );
            assert_eq!(
                blue_pixels(&dark_glyph),
                0,
                "expanded group arrow retained native blue pixels"
            );
            // Compare exact native pixels before clicking changes the
            // ListView's own focus/hot state on the collapse button.
            apply_tree(root.0, false, false);
            assert!(render() == light);
            assert!(
                header_pixels() == light_header,
                "dark toggle changed native light header rendering"
            );
            assert!(
                glyph_pixels() == light_glyph,
                "dark toggle changed native light arrow rendering"
            );
            apply_tree(root.0, true, false);
            assert!(render() == light);
            assert!(
                header_pixels() == light_header,
                "high-contrast override changed native header rendering"
            );
            assert!(
                glyph_pixels() == light_glyph,
                "high-contrast override changed the native arrow"
            );
            apply_tree(root.0, true, true);
            render();

            // Find and click the actual native collapse hit target. Group
            // painting must not consume or shift the chevron's input region.
            let mut header = RECT {
                top: LVGGR_HEADER as i32,
                ..Default::default()
            };
            assert_ne!(
                SendMessageW(
                    list.0,
                    LVM_GETGROUPRECT,
                    WPARAM(37),
                    LPARAM(&mut header as *mut _ as isize)
                )
                .0,
                0
            );
            let y = (header.top + header.bottom) / 2;
            let x = (header.left..header.right)
                .find(|&x| {
                    let mut hit = LVHITTESTINFO {
                        pt: POINT { x, y },
                        ..Default::default()
                    };
                    SendMessageW(
                        list.0,
                        LVM_HITTEST,
                        WPARAM(usize::MAX),
                        LPARAM(&mut hit as *mut _ as isize),
                    );
                    hit.flags.0 & LVHT_EX_GROUP_COLLAPSE.0 != 0
                })
                .expect("native group collapse target");
            let point = LPARAM((((y as u32) << 16) | x as u32) as isize);
            let click = || {
                // MK_LBUTTON = 1 (Win32 SystemServices modifier flags).
                // Native group tracking pumps messages inside LBUTTONDOWN;
                // queue release before entering that native tracking loop.
                PostMessageW(list.0, WM_LBUTTONUP, WPARAM(0), point).unwrap();
                SendMessageW(list.0, WM_LBUTTONDOWN, WPARAM(1), point);
            };
            click();
            assert_ne!(
                SendMessageW(
                    list.0,
                    LVM_GETGROUPSTATE,
                    WPARAM(37),
                    LPARAM(LVGS_COLLAPSED.0 as isize)
                )
                .0,
                0
            );
            let collapsed_label = render();
            assert!(
                readable(&collapsed_label) > 20,
                "collapsed group heading lacks readable foreground pixels"
            );
            let collapsed_glyph = glyph_pixels();
            assert_eq!(
                blue_pixels(&header_pixels()),
                blue_pixels(&collapsed_label),
                "collapsed group header retained blue pixels outside white text anti-aliasing"
            );
            assert!(
                header_pixels().contains(&BORDER.0),
                "collapsed group separator is missing its neutral color"
            );
            assert!(
                readable(&collapsed_glyph) > 5,
                "collapsed group arrow lacks readable foreground pixels"
            );
            assert_eq!(
                blue_pixels(&collapsed_glyph),
                0,
                "collapsed group arrow retained native blue pixels"
            );
            assert!(
                collapsed_glyph != dark_glyph,
                "collapsed and expanded arrows should point in different directions"
            );
            click();
            assert_eq!(
                SendMessageW(
                    list.0,
                    LVM_GETGROUPSTATE,
                    WPARAM(37),
                    LPARAM(LVGS_COLLAPSED.0 as isize)
                )
                .0,
                0
            );
            apply_tree(root.0, false, false);
            assert!(
                render() == light,
                "disabling dark mode changed native light heading rendering"
            );
            let light_glyph_after_click = glyph_pixels();
            // A high-contrast override preserves the user's dark preference
            // but uses exactly the same system-rendered group heading.
            apply_tree(root.0, true, false);
            assert!(requested(list.0));
            assert!(!is_dark(list.0));
            assert!(
                render() == light,
                "high-contrast override did not restore native colors"
            );
            assert!(
                glyph_pixels() == light_glyph_after_click,
                "high-contrast override did not restore the native arrow"
            );
            SelectObject(dc, previous);
            let _ = DeleteObject(bitmap);
            let _ = DeleteDC(dc);
        }
        drop(root);
        unsafe {
            let _ = DeleteObject(font);
        }
    }

    #[test]
    #[ignore = "writes local native-control rendering artifacts for visual review"]
    fn render_theme_preview() {
        initialize();
        unsafe extern "system" fn preview_proc(
            hwnd: HWND,
            msg: u32,
            wp: WPARAM,
            lp: LPARAM,
        ) -> LRESULT {
            unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
        }
        let font = super::super::font::load_message_font();
        let class_name = w!("AmwallThemePreview");
        unsafe {
            RegisterClassW(&WNDCLASSW {
                lpfnWndProc: Some(preview_proc),
                lpszClassName: class_name,
                hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as isize),
                ..Default::default()
            });
        }
        let root = TestWindow::new(class_name, HWND(0), WS_OVERLAPPEDWINDOW);
        unsafe {
            MoveWindow(root.0, 0, 0, 920, 620, false).unwrap();
        }
        let toolbar = super::super::toolbar::create(root.0, 96).unwrap();
        let toolbar_height = super::super::toolbar::layout(toolbar.toolbar, 900);
        unsafe {
            MoveWindow(toolbar.search, 650, toolbar_height + 8, 240, 24, false).unwrap();
        }
        let tabs = TestWindow::new(
            WC_TABCONTROLW,
            root.0,
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        );
        let list = TestWindow::new(
            WC_LISTVIEWW,
            root.0,
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WINDOW_STYLE(LVS_REPORT),
        );
        let group = TestWindow::new(
            w!("BUTTON"),
            root.0,
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_GROUPBOX as u32),
        );
        let check = TestWindow::new(
            w!("BUTTON"),
            root.0,
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
        );
        let edit = TestWindow::new(w!("EDIT"), root.0, WS_CHILD | WS_VISIBLE | WS_BORDER);
        let combo = TestWindow::new(
            w!("COMBOBOX"),
            root.0,
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(CBS_DROPDOWNLIST as u32),
        );
        let button = TestWindow::new(
            w!("BUTTON"),
            root.0,
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
        );
        let status = TestWindow::new(STATUSCLASSNAMEW, root.0, WS_CHILD | WS_VISIBLE);
        unsafe {
            let tab_y = toolbar_height + 42;
            MoveWindow(tabs.0, 8, tab_y, 886, 340, false).unwrap();
            MoveWindow(list.0, 10, tab_y + 30, 610, 290, false).unwrap();
            MoveWindow(group.0, 638, tab_y + 38, 245, 243, false).unwrap();
            SetWindowTextW(group.0, w!("Connection settings")).unwrap();
            MoveWindow(check.0, 650, tab_y + 64, 220, 26, false).unwrap();
            SetWindowTextW(check.0, w!("Notify for blocked connections")).unwrap();
            SendMessageW(
                check.0,
                BM_SETCHECK,
                WPARAM(BST_CHECKED.0 as usize),
                LPARAM(0),
            );
            MoveWindow(edit.0, 650, tab_y + 110, 220, 25, false).unwrap();
            SetWindowTextW(edit.0, w!("Search applications")).unwrap();
            MoveWindow(combo.0, 650, tab_y + 152, 220, 100, false).unwrap();
            SendMessageW(
                combo.0,
                CB_ADDSTRING,
                WPARAM(0),
                LPARAM(w!("TCP / UDP").as_ptr() as isize),
            );
            SendMessageW(combo.0, CB_SETCURSEL, WPARAM(0), LPARAM(0));
            MoveWindow(button.0, 710, tab_y + 210, 100, 30, false).unwrap();
            SetWindowTextW(button.0, w!("Apply")).unwrap();
            MoveWindow(status.0, 0, 570, 900, 25, false).unwrap();
            SendMessageW(
                status.0,
                SB_SETTEXTW,
                WPARAM(0),
                LPARAM(w!("3 connections — native dark-mode preview").as_ptr() as isize),
            );
            for (i, title) in ["Apps", "Services", "Connections", "Log"]
                .iter()
                .enumerate()
            {
                let mut text = super::super::wide(title);
                let mut item = TCITEMW {
                    mask: TCIF_TEXT,
                    pszText: PWSTR(text.as_mut_ptr()),
                    ..Default::default()
                };
                SendMessageW(
                    tabs.0,
                    TCM_INSERTITEMW,
                    WPARAM(i),
                    LPARAM(&mut item as *mut _ as isize),
                );
            }
            SendMessageW(tabs.0, TCM_SETCURSEL, WPARAM(2), LPARAM(0));
            for (i, title) in ["Application", "Remote address", "Protocol"]
                .iter()
                .enumerate()
            {
                let mut text = super::super::wide(title);
                let mut item = LVCOLUMNW {
                    mask: LVCF_TEXT | LVCF_WIDTH,
                    pszText: PWSTR(text.as_mut_ptr()),
                    cx: if i == 2 { 110 } else { 235 },
                    ..Default::default()
                };
                SendMessageW(
                    list.0,
                    LVM_INSERTCOLUMNW,
                    WPARAM(i),
                    LPARAM(&mut item as *mut _ as isize),
                );
            }
            super::super::listview_groups::enable(list.0);
            let mut heading = super::super::wide("Blocked (3/3)");
            assert!(super::super::listview_groups::insert(list.0, 37, &mut heading) >= 0);
            for (row, cells) in [
                ["browser.exe", "93.184.215.14:443", "TCP"],
                ["amwall.exe", "127.0.0.1:8080", "TCP"],
                ["svchost.exe", "192.168.1.1:53", "UDP"],
            ]
            .iter()
            .enumerate()
            {
                for (column, value) in cells.iter().enumerate() {
                    let mut text = super::super::wide(value);
                    let mut item = LVITEMW {
                        mask: if column == 0 {
                            LVIF_TEXT | LVIF_GROUPID
                        } else {
                            LVIF_TEXT
                        },
                        iItem: row as i32,
                        iGroupId: 37,
                        iSubItem: column as i32,
                        pszText: PWSTR(text.as_mut_ptr()),
                        ..Default::default()
                    };
                    SendMessageW(
                        list.0,
                        if column == 0 {
                            LVM_INSERTITEMW
                        } else {
                            LVM_SETITEMW
                        },
                        WPARAM(0),
                        LPARAM(&mut item as *mut _ as isize),
                    );
                }
            }
            super::super::font::apply_recursive(root.0, font);
            let dc = CreateCompatibleDC(None);
            let mut pixels = std::ptr::null_mut();
            let info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: 904,
                    biHeight: -581,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut pixels, None, 0).unwrap();
            let previous = SelectObject(dc, bitmap);
            for dark in [false, true] {
                apply_tree(root.0, dark, dark);
                fill(
                    dc,
                    &RECT {
                        left: 0,
                        top: 0,
                        right: 904,
                        bottom: 581,
                    },
                    if dark {
                        BACKGROUND
                    } else {
                        COLORREF(0x00ffffff)
                    },
                );
                SendMessageW(
                    root.0,
                    WM_PRINT,
                    WPARAM(dc.0 as usize),
                    LPARAM((PRF_CLIENT | PRF_ERASEBKGND | PRF_CHILDREN) as isize),
                );
                let _ = GdiFlush();
                let mut rgba =
                    std::slice::from_raw_parts(pixels as *const u8, 904 * 581 * 4).to_vec();
                for pixel in rgba.chunks_exact_mut(4) {
                    pixel.swap(0, 2);
                    pixel[3] = 255;
                }
                image::RgbaImage::from_raw(904, 581, rgba)
                    .unwrap()
                    .save(format!(
                        "target/theme-preview-{}.png",
                        if dark { "dark" } else { "light" }
                    ))
                    .unwrap();
            }
            SelectObject(dc, previous);
            let _ = DeleteObject(bitmap);
            let _ = DeleteDC(dc);
        }
        drop(root);
        unsafe {
            let _ = DeleteObject(font);
        }
    }
}

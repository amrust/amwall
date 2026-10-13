// amwall — listview column auto-sizing.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
//! Auto-size every listview column to fit its header and longest cell.
//!
//! Why this exists as its own module: the previous implementation sent
//! `LVSCW_AUTOSIZE` (-1), which fits a column to its *items* and
//! ignores the header entirely. In any locale whose header words are
//! wider than the data beneath them the header clipped — reported as
//! "everything looks abbreviated in my language" (issue #11). Upstream
//! measures the header string first and only then widens for content,
//! which is what this module reproduces. Unlike upstream's 158-pixel
//! ceiling and expanding Name column, Amwall fits all columns to their
//! actual contents, as requested for the live Connections view.
//!
//! The arithmetic is split out as the pure [`plan_column_widths`] so it
//! is unit-testable without a live window; the Win32 half is confined
//! to measurement (`GetTextExtentPoint32W` against the listview's and
//! the header's own fonts) plus the final `LVM_SETCOLUMNWIDTH`.

use std::collections::HashMap;
use windows::Win32::Foundation::{HWND, LPARAM, SIZE, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetDC, GetTextExtentPoint32W, HDC, HGDIOBJ, ReleaseDC, SelectObject,
};
use windows::Win32::UI::Controls::{
    HDF_SORTDOWN, HDF_SORTUP, HDI_FORMAT, HDITEMW, HDM_GETITEMCOUNT, HDM_GETITEMW, HIMAGELIST,
    ImageList_GetIconSize, LV_VIEW_DETAILS, LVCF_TEXT, LVCOLUMNW, LVITEMW, LVM_GETCOLUMNW,
    LVM_GETCOLUMNWIDTH, LVM_GETEXTENDEDLISTVIEWSTYLE, LVM_GETHEADER, LVM_GETIMAGELIST,
    LVM_GETITEMCOUNT, LVM_GETITEMTEXTW, LVM_GETVIEW, LVM_SETCOLUMNWIDTH, LVS_EX_CHECKBOXES,
    LVSIL_SMALL, LVSIL_STATE,
};
use windows::Win32::UI::HiDpi::GetSystemMetricsForDpi;
use windows::Win32::UI::WindowsAndMessaging::{SM_CXMENUCHECK, SendMessageW, WM_GETFONT};
use windows::core::PWSTR;

/// The common control interprets the low 16 bits of `LVM_SETCOLUMNWIDTH`
/// as signed (negative values select native autosizing). This is the
/// native control's representable limit, not a content-fitting cap.
const MAX_NATIVE_WIDTH: i32 = i16::MAX as i32;
const TEXT_PADDING_LOGICAL: i32 = 16;

/// One column's definition: which localized string titles it, how wide
/// it used to be hardcoded, and whether it renders right-aligned.
///
/// Single source of truth so `configure_listview` (which creates the
/// columns) and `diagnostics` (which reports whether a localized header
/// fits) cannot drift apart.
pub struct ColumnDef {
    /// i18n key, e.g. `column.name`.
    pub key: &'static str,
    /// Literal prefix glued in front of the localized text — the
    /// download/upload arrows on the speed columns.
    pub prefix: &'static str,
    /// The fixed logical width amwall shipped before auto-sizing. Still
    /// the creation-time width (auto-sizing corrects it on first
    /// paint), and the yardstick the diagnostics report measures
    /// localized headers against.
    pub legacy_width: i32,
    pub right: bool,
}

impl ColumnDef {
    /// Localized header text as the listview will actually show it.
    pub fn label(&self) -> String {
        format!("{}{}", self.prefix, rust_i18n::t!(self.key))
    }
}

const fn col(key: &'static str, legacy_width: i32, right: bool) -> ColumnDef {
    ColumnDef {
        key,
        prefix: "",
        legacy_width,
        right,
    }
}
const fn col_pfx(
    key: &'static str,
    prefix: &'static str,
    legacy_width: i32,
    right: bool,
) -> ColumnDef {
    ColumnDef {
        key,
        prefix,
        legacy_width,
        right,
    }
}

/// Apps / Services / UWP tabs.
pub const APPS_COLUMNS: &[ColumnDef] = &[
    col("column.name", 260, false),
    col("column.added", 130, true),
    col("column.path", 300, false),
    col_pfx("column.speed", "\u{2193} ", 85, true),
    col_pfx("column.speed", "\u{2191} ", 85, true),
    col("column.interface", 130, false),
];

/// Blocklist / System / Custom rules tabs.
pub const RULES_COLUMNS: &[ColumnDef] = &[
    col("column.name", 280, false),
    col("column.protocol", 80, true),
    col("column.direction", 80, true),
];

/// Connections tab.
pub const NETWORK_COLUMNS: &[ColumnDef] = &[
    col("column.name", 180, false),
    col("column.address_src", 110, false),
    col("column.host_src", 140, false),
    col("column.port_src", 60, true),
    col("column.address_dst", 110, false),
    col("column.host_dst", 140, false),
    col("column.port_dst", 60, true),
    col("column.protocol", 70, true),
    col("column.state", 70, true),
    col_pfx("column.speed", "\u{2193} ", 90, true),
    col_pfx("column.speed", "\u{2191} ", 90, true),
    col("column.total", 90, true),
];

/// Packets-log tab.
pub const LOG_COLUMNS: &[ColumnDef] = &[
    col("column.index", 50, true),
    col("column.name", 140, false),
    col("column.date", 110, false),
    col("column.address_src", 110, false),
    col("column.host_src", 120, false),
    col("column.port_src", 60, true),
    col("column.address_dst", 110, false),
    col("column.host_dst", 120, false),
    col("column.port_dst", 60, true),
    col("column.protocol", 70, false),
    col("column.direction", 70, false),
    col("column.filter", 140, false),
];

/// The column set a given listview uses, or `None` for an id that is
/// not one of the eight tabs.
pub fn columns_for(listview_id: i32) -> Option<&'static [ColumnDef]> {
    use crate::gui::ids::{
        IDC_APPS_PROFILE, IDC_APPS_SERVICE, IDC_APPS_UWP, IDC_LOG, IDC_NETWORK,
        IDC_RULES_BLOCKLIST, IDC_RULES_CUSTOM, IDC_RULES_SYSTEM,
    };
    match listview_id {
        x if x == IDC_APPS_PROFILE || x == IDC_APPS_SERVICE || x == IDC_APPS_UWP => {
            Some(APPS_COLUMNS)
        }
        x if x == IDC_RULES_BLOCKLIST || x == IDC_RULES_SYSTEM || x == IDC_RULES_CUSTOM => {
            Some(RULES_COLUMNS)
        }
        x if x == IDC_NETWORK => Some(NETWORK_COLUMNS),
        x if x == IDC_LOG => Some(LOG_COLUMNS),
        _ => None,
    }
}

/// Decide the final pixel width of every column.
///
/// All inputs are device pixels and already include inter-column
/// spacing. Missing cells are empty. Logical column indices are retained
/// regardless of the user's heading order.
pub fn plan_column_widths(header_px: &[i32], widest_cell_px: &[i32]) -> Vec<i32> {
    header_px
        .iter()
        .enumerate()
        .map(|(col, &header)| {
            header
                .max(widest_cell_px.get(col).copied().unwrap_or(0))
                .clamp(1, MAX_NATIVE_WIDTH)
        })
        .collect()
}

/// Measure and apply. No-op (rather than an error) when anything the
/// measurement needs is unavailable — a mis-sized column is a cosmetic
/// problem and must never take the window down.
/// Returns whether a width changed, so callers can avoid extra paints
/// and settings writes during periodic refreshes.
pub fn autosize_listview(lv: HWND, dpi: u32, manual_columns: &[bool]) -> bool {
    if lv.0 == 0 {
        return false;
    }
    let header = HWND(unsafe { SendMessageW(lv, LVM_GETHEADER, WPARAM(0), LPARAM(0)) }.0);
    if header.0 == 0 {
        return false;
    }
    let col_count = unsafe { SendMessageW(header, HDM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }
        .0
        .max(0) as usize;
    if col_count == 0 {
        return false;
    }

    let hdc_lv = unsafe { GetDC(lv) };
    let hdc_hdr = unsafe { GetDC(header) };
    if hdc_lv.is_invalid() || hdc_hdr.is_invalid() {
        release_dc(lv, hdc_lv);
        release_dc(header, hdc_hdr);
        return false;
    }
    // Measure with the same fonts the controls actually render in;
    // a raw DC carries the ancient System font and would under-measure
    // every string. Upstream does the same via `_r_dc_fixfont`.
    let old_lv = select_control_font(hdc_lv, lv);
    let old_hdr = select_control_font(hdc_hdr, header);

    let spacing = scale(TEXT_PADDING_LOGICAL, dpi).max(1);
    // The primary column contains app icons and, for apps/rules, state
    // images (checkboxes). Their real image-list dimensions already
    // include monitor DPI; adding them keeps the longest Name visible.
    let first_column_images =
        image_list_width(lv, LVSIL_SMALL).saturating_add(state_image_width(lv, dpi));
    let is_details =
        unsafe { SendMessageW(lv, LVM_GETVIEW, WPARAM(0), LPARAM(0)) }.0 as u32 == LV_VIEW_DETAILS;
    let row_count = unsafe { SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }
        .0
        .max(0);

    let mut header_px = Vec::with_capacity(col_count);
    let mut cell_px = Vec::with_capacity(col_count);
    let mut text_widths = HashMap::new();
    let mut text_buffer = vec![0u16; 256];
    for col in 0..col_count {
        if manual_columns.get(col).copied().unwrap_or(false) {
            header_px.push(0);
            cell_px.push(0);
            continue;
        }
        header_px.push(
            measure_header(hdc_hdr, lv, col, &mut text_buffer)
                .saturating_add(spacing)
                .saturating_add(sort_arrow_width(header, col, dpi)),
        );
        cell_px.push(if is_details {
            let padding = spacing.saturating_add(if col == 0 { first_column_images } else { 0 });
            widest_cell(
                hdc_lv,
                lv,
                col,
                row_count,
                &mut text_buffer,
                &mut text_widths,
            )
            .saturating_add(padding)
        } else {
            0
        });
    }

    let widths = plan_column_widths(&header_px, &cell_px);

    restore_font(hdc_lv, old_lv);
    restore_font(hdc_hdr, old_hdr);
    release_dc(lv, hdc_lv);
    release_dc(header, hdc_hdr);

    let mut changed = false;
    for (col, width) in widths.iter().enumerate() {
        if manual_columns.get(col).copied().unwrap_or(false) {
            continue;
        }
        unsafe {
            // Live connection updates often retain the same longest
            // value. Avoid redundant header notifications and repaint.
            if SendMessageW(lv, LVM_GETCOLUMNWIDTH, WPARAM(col), LPARAM(0)).0 == *width as isize {
                continue;
            }
            changed |=
                SendMessageW(lv, LVM_SETCOLUMNWIDTH, WPARAM(col), LPARAM(*width as isize)).0 != 0;
        }
    }
    changed
}

/// Widest cell text in `col`. Cache repeated values during this pass:
/// addresses, ports and protocol/state labels recur across many rows,
/// and measuring each distinct string once avoids repeated GDI work.
fn widest_cell(
    hdc: HDC,
    lv: HWND,
    col: usize,
    row_count: isize,
    buf: &mut Vec<u16>,
    text_widths: &mut HashMap<Vec<u16>, i32>,
) -> i32 {
    let mut widest = 0i32;
    for row in 0..row_count {
        let n = read_cell(lv, row as usize, col, buf);
        let width = if let Some(&cached) = text_widths.get(&buf[..n]) {
            cached
        } else {
            let measured = text_px(hdc, &buf[..n]);
            text_widths.insert(buf[..n].to_vec(), measured);
            measured
        };
        widest = widest.max(width);
        if widest >= MAX_NATIVE_WIDTH {
            return MAX_NATIVE_WIDTH;
        }
    }
    widest
}

fn read_cell(lv: HWND, row: usize, col: usize, buf: &mut Vec<u16>) -> usize {
    loop {
        let mut item = LVITEMW {
            iSubItem: col as i32,
            pszText: PWSTR(buf.as_mut_ptr()),
            cchTextMax: buf.len() as i32,
            ..Default::default()
        };
        let len = unsafe {
            SendMessageW(
                lv,
                LVM_GETITEMTEXTW,
                WPARAM(row),
                LPARAM(&mut item as *mut _ as isize),
            )
        }
        .0
        .max(0) as usize;
        if len + 1 < buf.len() || buf.len() >= 65_536 {
            return len.min(buf.len() - 1);
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// Rendered width of column `col`'s header string, in pixels.
fn measure_header(hdc: HDC, lv: HWND, col: usize, buf: &mut Vec<u16>) -> i32 {
    loop {
        buf.fill(0);
        let mut column = LVCOLUMNW {
            mask: LVCF_TEXT,
            pszText: PWSTR(buf.as_mut_ptr()),
            cchTextMax: buf.len() as i32,
            ..Default::default()
        };
        let ok = unsafe {
            SendMessageW(
                lv,
                LVM_GETCOLUMNW,
                WPARAM(col),
                LPARAM(&mut column as *mut _ as isize),
            )
        }
        .0 != 0;
        if !ok {
            return 0;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        if n + 1 < buf.len() || buf.len() >= 65_536 {
            return text_px(hdc, &buf[..n]);
        }
        buf.resize(buf.len() * 2, 0);
    }
}

fn image_list_width(lv: HWND, kind: u32) -> i32 {
    let images = HIMAGELIST(
        unsafe { SendMessageW(lv, LVM_GETIMAGELIST, WPARAM(kind as usize), LPARAM(0)) }.0,
    );
    if images.0 == 0 {
        return 0;
    }
    let mut width = 0;
    unsafe {
        let _ = ImageList_GetIconSize(images, Some(&mut width), None);
    }
    width.max(0)
}

fn state_image_width(lv: HWND, dpi: u32) -> i32 {
    let width = image_list_width(lv, LVSIL_STATE);
    let extended =
        unsafe { SendMessageW(lv, LVM_GETEXTENDEDLISTVIEWSTYLE, WPARAM(0), LPARAM(0)) }.0 as u32;
    if width == 0 && extended & LVS_EX_CHECKBOXES != 0 {
        // Themed v6 controls can draw checkboxes without exposing a
        // state image list. Still reserve the native checkbox width.
        unsafe { GetSystemMetricsForDpi(SM_CXMENUCHECK, dpi) }.max(0)
    } else {
        width
    }
}

fn sort_arrow_width(header: HWND, col: usize, dpi: u32) -> i32 {
    let mut item = HDITEMW {
        mask: HDI_FORMAT,
        ..Default::default()
    };
    let ok = unsafe {
        SendMessageW(
            header,
            HDM_GETITEMW,
            WPARAM(col),
            LPARAM(&mut item as *mut _ as isize),
        )
    }
    .0 != 0;
    if ok && item.fmt.0 & (HDF_SORTUP.0 | HDF_SORTDOWN.0) != 0 {
        scale(12, dpi)
    } else {
        0
    }
}

fn text_px(hdc: HDC, s: &[u16]) -> i32 {
    if s.is_empty() {
        return 0;
    }
    let mut size = SIZE::default();
    unsafe {
        let _ = GetTextExtentPoint32W(hdc, s, &mut size);
    }
    size.cx
}

/// Select `control`'s own font into `hdc`, returning the previous
/// object so the caller can restore it. `None` when the control has no
/// explicit font (the DC's default is then already correct enough).
fn select_control_font(hdc: HDC, control: HWND) -> Option<HGDIOBJ> {
    let font = unsafe { SendMessageW(control, WM_GETFONT, WPARAM(0), LPARAM(0)) }.0;
    if font == 0 {
        return None;
    }
    let prev = unsafe { SelectObject(hdc, HGDIOBJ(font)) };
    if prev.is_invalid() { None } else { Some(prev) }
}

fn restore_font(hdc: HDC, prev: Option<HGDIOBJ>) {
    if let Some(prev) = prev {
        unsafe {
            SelectObject(hdc, prev);
        }
    }
}

fn release_dc(hwnd: HWND, hdc: HDC) {
    if !hdc.is_invalid() {
        unsafe {
            ReleaseDC(hwnd, hdc);
        }
    }
}

/// Local copy of `main_window::scale_dpi` — kept here so this module
/// has no dependency on the 7k-line window module.
fn scale(logical: i32, dpi: u32) -> i32 {
    (logical as i64 * dpi as i64 / 96) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::UI::Controls::{
        ICC_LISTVIEW_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx, LVCF_WIDTH, LVIF_TEXT,
        LVM_GETCOLUMNORDERARRAY, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETCOLUMNORDERARRAY,
        LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMTEXTW, LVS_EX_CHECKBOXES, LVS_REPORT,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, HMENU, WINDOW_EX_STYLE, WINDOW_STYLE, WS_CHILD,
        WS_OVERLAPPEDWINDOW,
    };
    use windows::core::{PCWSTR, w};

    #[test]
    fn header_wider_than_content_wins() {
        // The issue-#11 case: a localized header longer than its data.
        // Before the fix LVSCW_AUTOSIZE fitted the content (40) and
        // clipped the header.
        let w = plan_column_widths(&[30, 120], &[20, 40]);
        assert_eq!(w[0], 30, "the Name column also fits its heading");
        assert_eq!(w[1], 120, "header must not be clipped by short content");
    }

    #[test]
    fn content_wider_than_header_wins() {
        let w = plan_column_widths(&[20, 50], &[300, 130]);
        assert_eq!(w, vec![300, 130]);
    }

    #[test]
    fn long_headers_and_content_have_no_arbitrary_ceiling() {
        let w = plan_column_widths(&[500, 40], &[0, 9000]);
        assert_eq!(w, vec![500, 9000]);
    }

    #[test]
    fn missing_cell_measurements_are_treated_as_empty() {
        // widest_cell_px shorter than header_px must not panic.
        let w = plan_column_widths(&[0, 70], &[]);
        assert_eq!(w[1], 70);
    }

    #[test]
    fn widths_fit_the_native_message_range() {
        assert_eq!(plan_column_widths(&[-10, i32::MAX], &[]), vec![1, 32_767]);
    }

    #[test]
    fn empty_input_yields_empty_plan() {
        assert!(plan_column_widths(&[], &[]).is_empty());
    }

    #[test]
    fn scale_matches_reference_dpi() {
        assert_eq!(scale(158, 96), 158);
        assert_eq!(scale(100, 192), 200);
    }

    struct TestListview {
        parent: HWND,
        lv: HWND,
    }

    impl TestListview {
        fn new(headers: &[&str]) -> Self {
            unsafe {
                InitCommonControlsEx(&INITCOMMONCONTROLSEX {
                    dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
                    dwICC: ICC_LISTVIEW_CLASSES,
                })
                .unwrap();
                let parent = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    w!("STATIC"),
                    w!("column sizing regression"),
                    WS_OVERLAPPEDWINDOW,
                    0,
                    0,
                    320,
                    240,
                    HWND::default(),
                    HMENU::default(),
                    HMODULE::default(),
                    None,
                );
                assert_ne!(parent.0, 0);
                let lv = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    w!("SysListView32"),
                    PCWSTR::null(),
                    WS_CHILD | WINDOW_STYLE(LVS_REPORT),
                    0,
                    0,
                    300,
                    200,
                    parent,
                    HMENU::default(),
                    HMODULE::default(),
                    None,
                );
                assert_ne!(lv.0, 0);
                for (col, text) in headers.iter().enumerate() {
                    let mut text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
                    let column = LVCOLUMNW {
                        mask: LVCF_TEXT | LVCF_WIDTH,
                        cx: 50,
                        pszText: PWSTR(text.as_mut_ptr()),
                        ..Default::default()
                    };
                    assert_eq!(
                        SendMessageW(
                            lv,
                            LVM_INSERTCOLUMNW,
                            WPARAM(col),
                            LPARAM(&column as *const _ as isize)
                        )
                        .0,
                        col as isize
                    );
                }
                Self { parent, lv }
            }
        }

        fn row(&self, row: usize, cells: &[&str]) {
            for (col, text) in cells.iter().enumerate() {
                let mut text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
                let item = LVITEMW {
                    mask: LVIF_TEXT,
                    iItem: row as i32,
                    iSubItem: col as i32,
                    pszText: PWSTR(text.as_mut_ptr()),
                    ..Default::default()
                };
                unsafe {
                    SendMessageW(
                        self.lv,
                        if col == 0 {
                            LVM_INSERTITEMW
                        } else {
                            LVM_SETITEMTEXTW
                        },
                        WPARAM(row),
                        LPARAM(&item as *const _ as isize),
                    );
                }
            }
        }

        fn width(&self, col: usize) -> i32 {
            unsafe { SendMessageW(self.lv, LVM_GETCOLUMNWIDTH, WPARAM(col), LPARAM(0)) }.0 as i32
        }

        fn text_width(&self, text: &str, header: bool) -> i32 {
            let control = if header {
                HWND(unsafe { SendMessageW(self.lv, LVM_GETHEADER, WPARAM(0), LPARAM(0)) }.0)
            } else {
                self.lv
            };
            let hdc = unsafe { GetDC(control) };
            let old_font = select_control_font(hdc, control);
            let width = text_px(hdc, &text.encode_utf16().collect::<Vec<_>>());
            restore_font(hdc, old_font);
            release_dc(control, hdc);
            width
        }
    }

    impl Drop for TestListview {
        fn drop(&mut self) {
            unsafe {
                let _ = DestroyWindow(self.parent);
            }
        }
    }

    #[test]
    fn native_autosize_measures_every_cell_and_long_header_without_reordering() {
        let heading = "A localized heading ".repeat(25);
        let value = "W".repeat(800);
        let control = TestListview::new(&["Name", &heading]);
        control.row(0, &["short", "1"]);
        control.row(1, &[&value, "2"]);
        let order = [1i32, 0];
        unsafe {
            SendMessageW(
                control.lv,
                LVM_SETCOLUMNORDERARRAY,
                WPARAM(2),
                LPARAM(order.as_ptr() as isize),
            );
        }

        assert!(autosize_listview(control.lv, 96, &[]));
        assert_eq!(
            control.width(0),
            control.text_width(&value, false) + TEXT_PADDING_LOGICAL
        );
        assert_eq!(
            control.width(1),
            control.text_width(&heading, true) + TEXT_PADDING_LOGICAL
        );
        let mut actual_order = [0i32; 2];
        unsafe {
            SendMessageW(
                control.lv,
                LVM_GETCOLUMNORDERARRAY,
                WPARAM(2),
                LPARAM(actual_order.as_mut_ptr() as isize),
            );
        }
        assert_eq!(actual_order, order);
        // Repeated fitting does not fill spare space or drift in width.
        let widths = [control.width(0), control.width(1)];
        assert!(!autosize_listview(control.lv, 96, &[]));
        assert_eq!([control.width(0), control.width(1)], widths);
        control.row(2, &[&"W".repeat(5_000), "3"]);
        assert!(autosize_listview(control.lv, 96, &[]));
        assert_eq!(
            control.width(0),
            MAX_NATIVE_WIDTH,
            "large content must not wrap into a negative native width"
        );
    }

    #[test]
    fn native_autosize_respects_manual_columns_and_checkbox_padding() {
        let control = TestListview::new(&["Name", "Status"]);
        control.row(0, &["a considerably longer application name", "Connected"]);
        autosize_listview(control.lv, 96, &[]);
        let without_checkbox = control.width(0);
        unsafe {
            SendMessageW(
                control.lv,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                WPARAM(LVS_EX_CHECKBOXES as usize),
                LPARAM(LVS_EX_CHECKBOXES as isize),
            );
        }
        let checkbox_width = state_image_width(control.lv, 96);
        assert!(checkbox_width > 0);
        autosize_listview(control.lv, 96, &[]);
        assert_eq!(control.width(0), without_checkbox + checkbox_width);
        unsafe {
            SendMessageW(control.lv, LVM_SETCOLUMNWIDTH, WPARAM(0), LPARAM(83));
        }
        autosize_listview(control.lv, 192, &[true]);
        assert_eq!(
            control.width(0),
            83,
            "manual width is never reapplied or overwritten"
        );
        assert_eq!(
            control.width(1),
            control.text_width("Connected", false) + TEXT_PADDING_LOGICAL * 2
        );
    }
}

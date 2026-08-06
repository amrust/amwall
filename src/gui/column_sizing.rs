// amwall — listview column auto-sizing.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
//! Auto-size listview columns to fit their **header text and their
//! content**, mirroring upstream `_app_listview_resize`
//! (simplewall-master/src/listview.c:789-925).
//!
//! Why this exists as its own module: the previous implementation sent
//! `LVSCW_AUTOSIZE` (-1), which fits a column to its *items* and
//! ignores the header entirely. In any locale whose header words are
//! wider than the data beneath them the header clipped — reported as
//! "everything looks abbreviated in my language" (issue #11). Upstream
//! measures the header string first and only then widens for content,
//! which is what this module reproduces.
//!
//! The arithmetic is split out as the pure [`plan_column_widths`] so it
//! is unit-testable without a live window; the Win32 half is confined
//! to measurement (`GetTextExtentPoint32W` against the listview's and
//! the header's own fonts) plus the final `LVM_SETCOLUMNWIDTH`.

use windows::Win32::Foundation::{HWND, LPARAM, RECT, SIZE, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetDC, GetTextExtentPoint32W, HDC, HGDIOBJ, ReleaseDC, SelectObject,
};
use windows::Win32::UI::Controls::{
    HDM_GETITEMCOUNT, LVCF_TEXT, LVCOLUMNW, LVITEMW, LVM_GETCOLUMNW, LVM_GETHEADER,
    LVM_GETITEMCOUNT, LVM_GETITEMTEXTW, LVM_GETVIEW, LVM_SETCOLUMNWIDTH, LV_VIEW_DETAILS,
};
use windows::Win32::UI::HiDpi::GetSystemMetricsForDpi;
use windows::Win32::UI::WindowsAndMessaging::{
    GetClientRect, SM_CXSMICON, SendMessageW, WM_GETFONT,
};
use windows::core::PWSTR;

/// Per-column ceiling in logical (96-DPI) pixels. Upstream
/// `listview.c:849` — `max_width = _r_dc_getdpi (158, dpi_value)`.
/// Without this a single very long path would stretch one column
/// across the whole window.
pub const MAX_COLUMN_LOGICAL: i32 = 158;

/// Upstream's shortcut for the Log tab's `#` column: rather than
/// measuring every row's index string, assume a fixed width
/// (`listview.c:892` — `_r_dc_getdpi (50, dpi_value)`).
const LOG_INDEX_CELL_LOGICAL: i32 = 50;

/// How a given tab's columns should be sized.
pub struct AutosizeSpec {
    /// The column that absorbs whatever width is left over. Upstream
    /// calls this `column_general_id` and uses 0 for every tab except
    /// the Log, where column 0 is the `#` counter and column 1 (Name)
    /// takes the slack instead (`listview.c:855-856`).
    pub general_col: usize,
    /// Columns whose cell width is a fixed logical value rather than
    /// measured across every row. Mirrors upstream's `#`-column
    /// shortcut; also keeps a 2000-row log from being re-measured on
    /// every append.
    pub fixed_cell_logical: &'static [(usize, i32)],
}

impl AutosizeSpec {
    /// The Log tab: `#` is column 0 and is fixed-width, so Name
    /// (column 1) is the general column.
    pub const LOG: Self = Self {
        general_col: 1,
        fixed_cell_logical: &[(0, LOG_INDEX_CELL_LOGICAL)],
    };
    /// Every other tab: column 0 (Name) absorbs the remainder.
    pub const DEFAULT: Self = Self {
        general_col: 0,
        fixed_cell_logical: &[],
    };
}

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
    ColumnDef { key, prefix: "", legacy_width, right }
}
const fn col_pfx(
    key: &'static str,
    prefix: &'static str,
    legacy_width: i32,
    right: bool,
) -> ColumnDef {
    ColumnDef { key, prefix, legacy_width, right }
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
/// Faithful to upstream `_app_listview_resize`'s arithmetic
/// (listview.c:857-920):
///
/// * every column except `general_col` starts at its **header** width,
/// * a column narrower than `max_width` may then be widened by its
///   widest **cell**, but never past `max_width`,
/// * `general_col` receives whatever width is left, floored at
///   `max_width` (so a narrow window overflows into a horizontal
///   scrollbar rather than collapsing the name column).
///
/// All inputs are device pixels and already include inter-column
/// spacing. Columns missing from `widest_cell_px` are treated as empty.
pub fn plan_column_widths(
    header_px: &[i32],
    widest_cell_px: &[i32],
    max_width: i32,
    total_width: i32,
    general_col: usize,
) -> Vec<i32> {
    let mut widths = vec![0i32; header_px.len()];
    let mut calculated = 0i32;

    for (i, &header) in header_px.iter().enumerate() {
        if i == general_col {
            continue;
        }
        let width = if header >= max_width {
            max_width
        } else {
            let cell = widest_cell_px.get(i).copied().unwrap_or(0);
            if cell >= max_width {
                max_width
            } else {
                header.max(cell)
            }
        };
        widths[i] = width;
        calculated = calculated.saturating_add(width);
    }

    if let Some(slot) = widths.get_mut(general_col) {
        *slot = total_width.saturating_sub(calculated).max(max_width);
    }
    widths
}

/// Measure and apply. No-op (rather than an error) when anything the
/// measurement needs is unavailable — a mis-sized column is a cosmetic
/// problem and must never take the window down.
pub fn autosize_listview(lv: HWND, dpi: u32, spec: &AutosizeSpec) {
    if lv.0 == 0 {
        return;
    }
    let header = HWND(unsafe { SendMessageW(lv, LVM_GETHEADER, WPARAM(0), LPARAM(0)) }.0);
    if header.0 == 0 {
        return;
    }
    let col_count =
        unsafe { SendMessageW(header, HDM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0 as usize;
    if col_count == 0 {
        return;
    }

    let hdc_lv = unsafe { GetDC(lv) };
    let hdc_hdr = unsafe { GetDC(header) };
    if hdc_lv.is_invalid() || hdc_hdr.is_invalid() {
        release_dc(lv, hdc_lv);
        release_dc(header, hdc_hdr);
        return;
    }
    // Measure with the same fonts the controls actually render in;
    // a raw DC carries the ancient System font and would under-measure
    // every string. Upstream does the same via `_r_dc_fixfont`.
    let old_lv = select_control_font(hdc_lv, lv);
    let old_hdr = select_control_font(hdc_hdr, header);

    let max_width = scale(MAX_COLUMN_LOGICAL, dpi);
    let spacing = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi) }.max(0);
    let is_details =
        unsafe { SendMessageW(lv, LVM_GETVIEW, WPARAM(0), LPARAM(0)) }.0 as u32 == LV_VIEW_DETAILS;
    let row_count = unsafe { SendMessageW(lv, LVM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) }.0.max(0);

    let mut header_px = Vec::with_capacity(col_count);
    let mut cell_px = Vec::with_capacity(col_count);
    for col in 0..col_count {
        header_px.push(measure_header(hdc_hdr, lv, col) + spacing);
        cell_px.push(if col == spec.general_col {
            0 // skipped by the planner anyway
        } else if let Some(&(_, logical)) =
            spec.fixed_cell_logical.iter().find(|(c, _)| *c == col)
        {
            scale(logical, dpi)
        } else if is_details {
            widest_cell(hdc_lv, lv, col, row_count, max_width, spacing)
        } else {
            0
        });
    }

    let mut rc = RECT::default();
    let total_width = if unsafe { GetClientRect(lv, &mut rc) }.is_ok() {
        rc.right - rc.left
    } else {
        0
    };

    let widths = plan_column_widths(
        &header_px,
        &cell_px,
        max_width,
        total_width,
        spec.general_col,
    );

    restore_font(hdc_lv, old_lv);
    restore_font(hdc_hdr, old_hdr);
    release_dc(lv, hdc_lv);
    release_dc(header, hdc_hdr);

    for (col, width) in widths.iter().enumerate() {
        unsafe {
            let _ = SendMessageW(
                lv,
                LVM_SETCOLUMNWIDTH,
                WPARAM(col),
                LPARAM(*width as isize),
            );
        }
    }
}

/// Widest cell text in `col`, in pixels, including `spacing`.
///
/// Upstream's early-out matters here (`listview.c:900-906`): once a row
/// reaches `max_width` the column is already capped, so scanning the
/// rest is wasted work. On the Log and Network tabs that is the
/// difference between measuring a dozen rows and measuring thousands.
fn widest_cell(
    hdc: HDC,
    lv: HWND,
    col: usize,
    row_count: isize,
    max_width: i32,
    spacing: i32,
) -> i32 {
    let mut widest = 0i32;
    let mut buf = [0u16; 512];
    for row in 0..row_count {
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
                WPARAM(row as usize),
                LPARAM(&mut item as *mut _ as isize),
            )
        }
        .0;
        if len <= 0 {
            continue;
        }
        let n = (len as usize).min(buf.len());
        let width = text_px(hdc, &buf[..n]) + spacing;
        if width >= max_width {
            return max_width;
        }
        if width > widest {
            widest = width;
        }
    }
    widest
}

/// Rendered width of column `col`'s header string, in pixels.
fn measure_header(hdc: HDC, lv: HWND, col: usize) -> i32 {
    let mut buf = [0u16; 256];
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
    text_px(hdc, &buf[..n])
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

    const MAX: i32 = 158;

    #[test]
    fn header_wider_than_content_wins() {
        // The issue-#11 case: a localized header longer than its data.
        // Before the fix LVSCW_AUTOSIZE fitted the content (40) and
        // clipped the header.
        let w = plan_column_widths(&[0, 120], &[0, 40], MAX, 1000, 0);
        assert_eq!(w[1], 120, "header must not be clipped by short content");
    }

    #[test]
    fn content_wider_than_header_wins() {
        let w = plan_column_widths(&[0, 50], &[0, 130], MAX, 1000, 0);
        assert_eq!(w[1], 130);
    }

    #[test]
    fn header_alone_is_clamped_at_max_width() {
        let w = plan_column_widths(&[0, 500], &[0, 0], MAX, 1000, 0);
        assert_eq!(w[1], MAX);
    }

    #[test]
    fn content_alone_is_clamped_at_max_width() {
        // A very long path must not stretch its column across the window.
        let w = plan_column_widths(&[0, 40], &[0, 9000], MAX, 1000, 0);
        assert_eq!(w[1], MAX);
    }

    #[test]
    fn general_column_absorbs_the_remainder() {
        let w = plan_column_widths(&[0, 100, 60], &[0, 0, 0], MAX, 500, 0);
        assert_eq!(w[1], 100);
        assert_eq!(w[2], 60);
        assert_eq!(w[0], 500 - 160, "general column takes what is left");
    }

    #[test]
    fn general_column_never_falls_below_max_width() {
        // Window narrower than the fixed columns: upstream floors the
        // general column at max_width and lets the listview scroll.
        let w = plan_column_widths(&[0, 150, 150], &[0, 0, 0], MAX, 200, 0);
        assert_eq!(w[0], MAX);
    }

    #[test]
    fn general_column_can_be_a_non_zero_index() {
        // Log tab: column 0 is the fixed-width `#`, column 1 takes slack.
        let w = plan_column_widths(&[30, 0, 80], &[30, 0, 40], MAX, 600, 1);
        assert_eq!(w[0], 30);
        assert_eq!(w[2], 80);
        assert_eq!(w[1], 600 - 110);
    }

    #[test]
    fn missing_cell_measurements_are_treated_as_empty() {
        // widest_cell_px shorter than header_px must not panic.
        let w = plan_column_widths(&[0, 70], &[], MAX, 400, 0);
        assert_eq!(w[1], 70);
    }

    #[test]
    fn out_of_range_general_column_does_not_panic() {
        let w = plan_column_widths(&[40, 50], &[0, 0], MAX, 400, 9);
        assert_eq!(w, vec![40, 50]);
    }

    #[test]
    fn empty_input_yields_empty_plan() {
        assert!(plan_column_widths(&[], &[], MAX, 400, 0).is_empty());
    }

    #[test]
    fn log_spec_targets_the_name_column() {
        assert_eq!(AutosizeSpec::LOG.general_col, 1);
        assert_eq!(AutosizeSpec::LOG.fixed_cell_logical, &[(0, 50)]);
        assert_eq!(AutosizeSpec::DEFAULT.general_col, 0);
    }

    #[test]
    fn scale_matches_reference_dpi() {
        assert_eq!(scale(158, 96), 158);
        assert_eq!(scale(100, 192), 200);
    }
}

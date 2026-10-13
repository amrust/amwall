// amwall — persistent, DPI-independent listview layouts.
// Copyright (C) 2026 amwall contributors. Licensed GPL-3.0-or-later.

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    LVM_GETCOLUMNORDERARRAY, LVM_GETCOLUMNWIDTH, LVM_SETCOLUMNORDERARRAY, LVM_SETCOLUMNWIDTH,
};
use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

/// Common controls interpret column widths as signed 16-bit pixels;
/// larger values collide with the native autosize sentinels.
const MAX_COLUMN_WIDTH: i32 = i16::MAX as i32;

/// Stable settings keys, independent of translated tab titles and control IDs.
pub const VIEW_KEYS: [&str; 8] = [
    "apps",
    "services",
    "uwp",
    "blocklist",
    "system_rules",
    "user_rules",
    "connections",
    "log",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnLayout {
    /// Widths in logical (96-DPI) pixels, indexed by column identity.
    pub widths: Vec<i32>,
    /// Column identities in left-to-right display order.
    pub order: Vec<i32>,
}

impl ColumnLayout {
    pub fn valid_for(&self, count: usize) -> bool {
        if count == 0
            || self.widths.len() != count
            || self.order.len() != count
            || self
                .widths
                .iter()
                .any(|w| !(1..=MAX_COLUMN_WIDTH).contains(w))
        {
            return false;
        }
        let mut order = self.order.clone();
        order.sort_unstable();
        order.iter().copied().eq(0..count as i32)
    }

    pub fn encode(&self) -> String {
        let join = |values: &[i32]| {
            values
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        format!("{};{}", join(&self.widths), join(&self.order))
    }

    pub fn decode(value: &str, count: usize) -> Option<Self> {
        let (widths, order) = value.split_once(';')?;
        let parse = |s: &str| {
            s.split(',')
                .map(|v| v.trim().parse::<i32>())
                .collect::<Result<Vec<_>, _>>()
                .ok()
        };
        let layout = Self {
            widths: parse(widths)?,
            order: parse(order)?,
        };
        layout.valid_for(count).then_some(layout)
    }

    pub fn capture(lv: HWND, count: usize, dpi: u32) -> Option<Self> {
        let mut order = vec![0i32; count];
        let result = unsafe {
            SendMessageW(
                lv,
                LVM_GETCOLUMNORDERARRAY,
                WPARAM(count),
                LPARAM(order.as_mut_ptr() as isize),
            )
        };
        if result.0 == 0 {
            return None;
        }
        let widths = (0..count)
            .map(|col| {
                let px = unsafe { SendMessageW(lv, LVM_GETCOLUMNWIDTH, WPARAM(col), LPARAM(0)) }.0
                    as i32;
                // A divider may be dragged fully closed. Keep it recoverable on restart.
                rescale(px, dpi, 96).clamp(1, MAX_COLUMN_WIDTH)
            })
            .collect();
        let layout = Self { widths, order };
        layout.valid_for(count).then_some(layout)
    }

    pub fn apply(&self, lv: HWND, count: usize, dpi: u32) {
        if !self.valid_for(count) {
            return;
        }
        for (col, width) in self.widths.iter().enumerate() {
            unsafe {
                SendMessageW(
                    lv,
                    LVM_SETCOLUMNWIDTH,
                    WPARAM(col),
                    LPARAM(native_width(*width, dpi) as isize),
                );
            }
        }
        unsafe {
            SendMessageW(
                lv,
                LVM_SETCOLUMNORDERARRAY,
                WPARAM(count),
                LPARAM(self.order.as_ptr() as isize),
            );
        }
    }
}

fn native_width(logical: i32, dpi: u32) -> i32 {
    rescale(logical, 96, dpi).clamp(1, MAX_COLUMN_WIDTH)
}

pub fn rescale(width: i32, from: u32, to: u32) -> i32 {
    ((i64::from(width) * i64::from(to.max(1)) + i64::from(from.max(1)) / 2)
        / i64::from(from.max(1)))
    .clamp(1, i64::from(i32::MAX)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_round_trip_and_invalid_files() {
        let layout = ColumnLayout {
            widths: vec![320, 80, 201],
            order: vec![2, 0, 1],
        };
        assert_eq!(ColumnLayout::decode(&layout.encode(), 3), Some(layout));
        for invalid in [
            "1,2,3;0,0,2",
            "1,2,3;0,1,3",
            "1,2;0,1",
            "-1,2,3;0,1,2",
            "999999,2,3;0,1,2",
            "a;0",
            "1,2,3",
        ] {
            assert!(ColumnLayout::decode(invalid, 3).is_none(), "{invalid}");
        }
    }

    #[test]
    fn dpi_changes_preserve_logical_widths() {
        assert_eq!(rescale(320, 96, 144), 480);
        assert_eq!(rescale(480, 144, 96), 320);
        assert_eq!(rescale(320, 96, 192), 640);
    }

    #[test]
    fn wide_columns_do_not_overflow_native_widths_on_high_dpi_monitors() {
        assert!(ColumnLayout::decode("32767;0", 1).is_some());
        assert!(ColumnLayout::decode("32768;0", 1).is_none());
        assert_eq!(native_width(16_384, 192), 32_767);
        assert_eq!(native_width(32_767, 384), 32_767);
        assert_eq!(native_width(320, 192), 640);
    }
}

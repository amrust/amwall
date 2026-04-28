// simplewall-rs — toolbar icon image list.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// At toolbar-create time we build a 32-bit ARGB ImageList from
// PNGs embedded via `include_bytes!`. The PNGs are the FamFamFam
// Silk icons we vendored in `assets/icons/silk/` (CC-BY 2.5,
// attributed in NOTICE).
//
// Pipeline per icon:
//   1. include_bytes!  — PNG bytes baked into the .exe at build
//                       time, no runtime file I/O.
//   2. image::load_from_memory + .to_rgba8() — decode + 8-bit
//      RGBA pixel buffer.
//   3. (optional) image::imageops::resize — DPI-scale 16->target.
//   4. RGBA -> BGRA pre-multiplied alpha — Win32 DIBs are BGRA
//      and the alpha-blending path in the toolbar wants
//      pre-multiplied.
//   5. CreateDIBSection(BITMAPINFOHEADER, top-down) — gets us
//      a 32bpp HBITMAP backed by raw bytes we memcpy in.
//   6. ImageList_Add — add the bitmap to the toolbar's list.
//
// `IconSet` owns the HIMAGELIST + the const mapping from each
// supported IDM_* command to its image-list index. Exposed
// publicly so `toolbar` can call `attach_to_toolbar` after the
// buttons are inserted.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIB_RGB_COLORS, GetDC, HBITMAP,
    ReleaseDC,
};
use windows::Win32::UI::Controls::{
    HIMAGELIST, ILC_COLOR32, ImageList_Add, ImageList_Create, TB_SETIMAGELIST,
};
use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

use super::ids::{
    IDM_OPENRULESEDITOR, IDM_REFRESH, IDM_RELEASES, IDM_SETTINGS, IDM_TRAY_ENABLELOG_CHK,
    IDM_TRAY_ENABLENOTIFICATIONS_CHK, IDM_TRAY_ENABLEUILOG_CHK, IDM_TRAY_LOGCLEAR,
    IDM_TRAY_LOGSHOW, IDM_TRAY_START,
};

/// Embedded PNG bytes, one per supported toolbar button. Kept in
/// the same order they're added to the image list — index in this
/// array is the iBitmap value to put on the corresponding TBBUTTON.
const SILK_PNGS: &[(u16, &[u8])] = &[
    // 0: Enable filters     -> tick_shield (green tick over a shield)
    (
        IDM_TRAY_START,
        include_bytes!("../../assets/icons/silk/tick_shield.png"),
    ),
    // 1: Create rule        -> plus
    (
        IDM_OPENRULESEDITOR,
        include_bytes!("../../assets/icons/silk/plus.png"),
    ),
    // 2: Notifications      -> note
    (
        IDM_TRAY_ENABLENOTIFICATIONS_CHK,
        include_bytes!("../../assets/icons/silk/note.png"),
    ),
    // 3: Log to file        -> page_white_magnify (file with a search glyph)
    (
        IDM_TRAY_ENABLELOG_CHK,
        include_bytes!("../../assets/icons/silk/page_white_magnify.png"),
    ),
    // 4: Log UI             -> eye
    (
        IDM_TRAY_ENABLEUILOG_CHK,
        include_bytes!("../../assets/icons/silk/eye.png"),
    ),
    // 5: Refresh            -> arrow_refresh
    (
        IDM_REFRESH,
        include_bytes!("../../assets/icons/silk/arrow_refresh.png"),
    ),
    // 6: Settings           -> cog_edit
    (
        IDM_SETTINGS,
        include_bytes!("../../assets/icons/silk/cog_edit.png"),
    ),
    // 7: Show log           -> accept_button (green tick — "view confirmed log")
    (
        IDM_TRAY_LOGSHOW,
        include_bytes!("../../assets/icons/silk/accept_button.png"),
    ),
    // 8: Clear log          -> page_white_delete (file with a red x)
    (
        IDM_TRAY_LOGCLEAR,
        include_bytes!("../../assets/icons/silk/page_white_delete.png"),
    ),
    // 9: Releases           -> resultset_next (forward arrow)
    (
        IDM_RELEASES,
        include_bytes!("../../assets/icons/silk/resultset_next.png"),
    ),
];

pub struct IconSet {
    pub himagelist: HIMAGELIST,
    /// `(command_id, image_list_index)` pairs in the same order as
    /// SILK_PNGS. Used by `toolbar::populate_toolbar` to assign
    /// each TBBUTTON's `iBitmap`.
    pub mapping: Vec<(u16, i32)>,
}

/// Build the toolbar image list. Each PNG is decoded, optionally
/// resized to the DPI-scaled icon size, converted to BGRA
/// pre-multiplied alpha, and stuffed into a new HBITMAP via
/// CreateDIBSection. Failures inside the loop log a warning and
/// skip the icon — the toolbar falls back to text-only for that
/// button rather than refusing to render.
pub fn build(dpi: u32) -> IconSet {
    let logical = 16i32;
    let target = (logical as i64 * dpi as i64 / 96).max(1) as i32;

    let himagelist = unsafe {
        ImageList_Create(target, target, ILC_COLOR32, SILK_PNGS.len() as i32, 1)
    };

    let mut mapping = Vec::with_capacity(SILK_PNGS.len());
    if himagelist.is_invalid() {
        eprintln!("simplewall-rs: ImageList_Create failed");
        return IconSet { himagelist, mapping };
    }

    for (id, bytes) in SILK_PNGS {
        match decode_to_hbitmap(bytes, target) {
            Ok(hbm) => {
                let idx = unsafe { ImageList_Add(himagelist, hbm, HBITMAP::default()) };
                if idx < 0 {
                    eprintln!("simplewall-rs: ImageList_Add failed for IDM {id}");
                } else {
                    mapping.push((*id, idx));
                }
                // ImageList_Add copies the bitmap; release ours.
                unsafe {
                    let _ = windows::Win32::Graphics::Gdi::DeleteObject(hbm);
                }
            }
            Err(e) => {
                eprintln!("simplewall-rs: PNG decode failed for IDM {id}: {e}");
            }
        }
    }

    IconSet { himagelist, mapping }
}

/// Hand the image list to the toolbar so iBitmap indices on the
/// TBBUTTON entries actually resolve to graphics.
pub fn attach_to_toolbar(toolbar: HWND, himl: HIMAGELIST) {
    if himl.is_invalid() {
        return;
    }
    unsafe {
        let _ = SendMessageW(toolbar, TB_SETIMAGELIST, WPARAM(0), LPARAM(himl.0));
    }
}

/// Look up the image-list index matching this command ID, or
/// `I_IMAGENONE` (-2) if we don't have an icon for it (e.g. the
/// imagelist failed to load).
pub fn index_for(set: &IconSet, id: u16) -> i32 {
    set.mapping
        .iter()
        .find_map(|(cmd, idx)| if *cmd == id { Some(*idx) } else { None })
        .unwrap_or(-2) // I_IMAGENONE
}

fn decode_to_hbitmap(png_bytes: &[u8], target: i32) -> Result<HBITMAP, String> {
    let img = image::load_from_memory(png_bytes)
        .map_err(|e| format!("png decode: {e}"))?
        .to_rgba8();
    // Silk icons are 16x16. If the target DPI scaling needs a
    // different size, resize using a quality-reasonable filter.
    let img = if img.width() as i32 != target || img.height() as i32 != target {
        image::imageops::resize(
            &img,
            target as u32,
            target as u32,
            image::imageops::FilterType::Lanczos3,
        )
    } else {
        img
    };

    let (w, h) = (img.width() as i32, img.height() as i32);
    let pixel_count = (w * h) as usize;

    // RGBA -> BGRA + pre-multiply alpha. Win32 imagelist with
    // ILC_COLOR32 expects pre-multiplied so the alpha blender
    // doesn't darken transparent edges.
    let mut bgra = vec![0u8; pixel_count * 4];
    for (i, px) in img.pixels().enumerate() {
        let [r, g, b, a] = px.0;
        let pma = a as u16;
        let pmr = ((r as u16 * pma) / 255) as u8;
        let pmg = ((g as u16 * pma) / 255) as u8;
        let pmb = ((b as u16 * pma) / 255) as u8;
        let off = i * 4;
        bgra[off] = pmb;
        bgra[off + 1] = pmg;
        bgra[off + 2] = pmr;
        bgra[off + 3] = a;
    }

    // Top-down DIB: negative biHeight tells GDI the rows are
    // ordered from top to bottom (matches `image`'s output).
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            biSizeImage: 0,
            ..Default::default()
        },
        ..Default::default()
    };

    unsafe {
        let hdc = GetDC(HWND::default());
        let mut bits_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0)
            .map_err(|e| format!("CreateDIBSection: {e}"))?;
        if !bits_ptr.is_null() {
            std::ptr::copy_nonoverlapping(bgra.as_ptr(), bits_ptr as *mut u8, bgra.len());
        }
        ReleaseDC(HWND::default(), hdc);
        Ok(hbm)
    }
}

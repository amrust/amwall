// amwall — system font helpers.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Win32 dialog templates auto-bind the dialog font (Segoe UI 9pt
// with ClearType on Windows 10+) via DS_SHELLFONT. Plain
// CreateWindowEx-created controls don't inherit it — they default
// to the legacy bitmap "System" font, which renders without
// anti-aliasing and looks visibly out of place next to dialog
// content. The main window + its toolbar / tab / listviews are
// all CreateWindowEx-built, so they need the font applied
// manually via WM_SETFONT.
//
// Two pieces:
//   - `load_message_font()` calls SystemParametersInfoW with
//     SPI_GETNONCLIENTMETRICS to get the user's currently
//     configured menu/message font, then CreateFontIndirectW
//     to materialise an HFONT.
//   - `apply_recursive(root, font)` walks the entire window
//     tree under `root` and broadcasts WM_SETFONT. Controls
//     that were created before this call inherit the new
//     font; ones that get created after still need their own
//     WM_SETFONT (or they'll render in System font for one
//     paint cycle until the next layout pass).
//
// Caller owns the HFONT and is responsible for DeleteObject on
// teardown — leaking is fine for the process lifetime, but we
// clean up properly in WM_NCDESTROY paths to keep clippy /
// gdileak quiet.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateFontIndirectW, HFONT};
use windows::Win32::UI::WindowsAndMessaging::{
    GW_CHILD, GW_HWNDNEXT, GetWindow, NONCLIENTMETRICSW, SPI_GETNONCLIENTMETRICS,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SendMessageW, SystemParametersInfoW, WM_SETFONT,
};

/// Look up the user's current message font (Segoe UI 9pt on
/// Windows 10/11 default) and create an HFONT for it. Returns
/// a default (invalid) HFONT if the SystemParametersInfo call
/// fails — Win32 treats that as "use the system default font",
/// which is correct fallback behaviour.
pub fn load_message_font() -> HFONT {
    let mut metrics = NONCLIENTMETRICSW {
        cbSize: std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
        ..Default::default()
    };
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
            Some(&mut metrics as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    if ok.is_err() {
        return HFONT::default();
    }
    unsafe { CreateFontIndirectW(&metrics.lfMessageFont) }
}

/// Toggle Windows 10/11's "immersive dark mode" on the title bar
/// of `hwnd`. Effects:
///   - Title bar + caption buttons render dark.
///   - Default text color flips to light.
///
/// On older Windows or when DWM doesn't expose the attribute the
/// call returns Err — we silently ignore.
pub fn set_dark_mode(hwnd: HWND, on: bool) {
    use windows::Win32::Graphics::Dwm::{
        DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute,
    };
    let value: i32 = if on { 1 } else { 0 };
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &value as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        );
    }
}

/// Build an HFONT from a stored face name + height (LOGFONT
/// convention — negative for character height, positive for cell
/// height). Returns `None` if the face name is empty so the
/// caller can fall back to `load_message_font`.
pub fn load_named_font(face: &str, height: i32) -> Option<HFONT> {
    use windows::Win32::Graphics::Gdi::LOGFONTW;
    if face.is_empty() {
        return None;
    }
    let mut lf = LOGFONTW {
        lfHeight: height,
        lfWeight: 400, // FW_NORMAL — the picker writes the user's choice in directly
        ..Default::default()
    };
    let face_w: Vec<u16> = face.encode_utf16().chain(std::iter::once(0)).collect();
    let n = face_w.len().min(lf.lfFaceName.len());
    lf.lfFaceName[..n].copy_from_slice(&face_w[..n]);
    let hf = unsafe { CreateFontIndirectW(&lf) };
    if hf.is_invalid() { None } else { Some(hf) }
}

/// Show the system Choose Font dialog seeded with the current
/// `(face, height)` and return the user's selection on OK, or
/// `None` if they cancelled. The returned LOGFONT face / height
/// are what the caller persists into `Settings.font_*`.
pub fn pick_font(
    parent: HWND,
    initial_face: &str,
    initial_height: i32,
) -> Option<(String, i32)> {
    use windows::Win32::Graphics::Gdi::LOGFONTW;
    use windows::Win32::UI::Controls::Dialogs::{
        CF_EFFECTS, CF_INITTOLOGFONTSTRUCT, CF_SCREENFONTS, CHOOSEFONTW, ChooseFontW,
    };

    // Seed LOGFONT with the current font (if any). When the
    // settings face is empty we leave the LOGFONT zero — the
    // picker just shows whatever default it picks.
    let mut lf = LOGFONTW {
        lfHeight: if initial_height != 0 { initial_height } else { -12 },
        lfWeight: 400,
        ..Default::default()
    };
    if !initial_face.is_empty() {
        let face_w: Vec<u16> =
            initial_face.encode_utf16().chain(std::iter::once(0)).collect();
        let n = face_w.len().min(lf.lfFaceName.len());
        lf.lfFaceName[..n].copy_from_slice(&face_w[..n]);
    }

    let mut cf = CHOOSEFONTW {
        lStructSize: std::mem::size_of::<CHOOSEFONTW>() as u32,
        hwndOwner: parent,
        lpLogFont: &mut lf,
        Flags: CF_SCREENFONTS | CF_EFFECTS | CF_INITTOLOGFONTSTRUCT,
        ..Default::default()
    };
    let ok = unsafe { ChooseFontW(&mut cf) }.as_bool();
    if !ok {
        return None;
    }
    // Marshal the face out. lfFaceName is a null-terminated
    // wide-char array of length 32 (LF_FACESIZE).
    let face_len = lf
        .lfFaceName
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(lf.lfFaceName.len());
    let face = String::from_utf16_lossy(&lf.lfFaceName[..face_len]);
    Some((face, lf.lfHeight))
}

/// Walk every descendant of `root` and broadcast WM_SETFONT.
/// `font` is HFONT cast to wparam; lparam = TRUE asks for an
/// immediate repaint. Recurses depth-first via GW_CHILD /
/// GW_HWNDNEXT.
pub fn apply_recursive(root: HWND, font: HFONT) {
    if font.is_invalid() {
        return;
    }
    unsafe {
        SendMessageW(root, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }
    let mut current = unsafe { GetWindow(root, GW_CHILD) };
    while current.0 != 0 {
        apply_recursive(current, font);
        current = unsafe { GetWindow(current, GW_HWNDNEXT) };
    }
}

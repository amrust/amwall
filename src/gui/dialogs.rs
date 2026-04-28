// simplewall-rs — file Open / Save dialogs.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Wraps Win32's modern IFileDialog COM interfaces (Vista+) for the
// File menu's Import / Export entries. Two reasons to prefer
// IFileOpenDialog / IFileSaveDialog over the older GetOpenFileNameW
// API:
//
//   1. Modern look + correct DPI/theming on Windows 10+. The legacy
//      common dialogs render with a Win9x feel even with a v6
//      manifest.
//
//   2. Larger / saner code surface — no MAX_PATH ceiling, proper
//      Unicode handling, and a structured options bitmask vs. the
//      legacy flag soup.
//
// Trade-off: COM lifetime + HRESULT-error handling is verbose. The
// helpers here hide that behind plain `Option<PathBuf>` returns —
// `None` covers both "user cancelled" and "dialog failed", since
// callers don't care which.

#![cfg(windows)]

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FOS_FORCEFILESYSTEM, FOS_OVERWRITEPROMPT, FileOpenDialog, FileSaveDialog,
    IFileOpenDialog, IFileSaveDialog, SIGDN_FILESYSPATH,
};
use windows::core::PCWSTR;

/// Show the standard "Open profile…" dialog. Returns the chosen
/// path on success, or `None` if the user cancelled or the dialog
/// failed to construct (rare — usually means COM wasn't
/// initialised, or shell32 is broken).
pub fn open_profile(parent: HWND) -> Option<PathBuf> {
    unsafe {
        let dialog: IFileOpenDialog =
            CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;

        // FOS_FORCEFILESYSTEM: refuse virtual / shell-namespace
        // items so SIGDN_FILESYSPATH always returns a real path.
        let opts = dialog.GetOptions().ok()?;
        let _ = dialog.SetOptions(opts | FOS_FORCEFILESYSTEM);

        // *.xml profiles only by default. Two filter rows so users
        // can fall back to All files when they want to inspect a
        // weirdly-named profile.
        let xml_name = wide_static("XML profile (*.xml)");
        let xml_spec = wide_static("*.xml");
        let any_name = wide_static("All files (*.*)");
        let any_spec = wide_static("*.*");
        let filters = [
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(xml_name.as_ptr()),
                pszSpec: PCWSTR(xml_spec.as_ptr()),
            },
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(any_name.as_ptr()),
                pszSpec: PCWSTR(any_spec.as_ptr()),
            },
        ];
        let _ = dialog.SetFileTypes(&filters);
        let _ = dialog.SetFileTypeIndex(1);

        // Show modal-relative-to-parent so it docks onto the main
        // window correctly under DWM. Cancellation comes back as
        // HRESULT(0x800704C7); both that and other failures hit the
        // `?` and short-circuit to None.
        dialog.Show(parent).ok()?;
        let item = dialog.GetResult().ok()?;
        let pwstr = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;

        let path = pwstr_to_pathbuf(pwstr.0);
        CoTaskMemFree(Some(pwstr.0 as *const _));
        Some(path)
    }
}

/// Show the standard "Save profile…" dialog. `default_name` is
/// pre-filled in the filename field; pass `Some("profile.xml")`
/// for the typical export flow.
pub fn save_profile(parent: HWND, default_name: Option<&str>) -> Option<PathBuf> {
    unsafe {
        let dialog: IFileSaveDialog =
            CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER).ok()?;

        let opts = dialog.GetOptions().ok()?;
        let _ = dialog.SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT);

        let xml_name = wide_static("XML profile (*.xml)");
        let xml_spec = wide_static("*.xml");
        let any_name = wide_static("All files (*.*)");
        let any_spec = wide_static("*.*");
        let filters = [
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(xml_name.as_ptr()),
                pszSpec: PCWSTR(xml_spec.as_ptr()),
            },
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(any_name.as_ptr()),
                pszSpec: PCWSTR(any_spec.as_ptr()),
            },
        ];
        let _ = dialog.SetFileTypes(&filters);
        let _ = dialog.SetFileTypeIndex(1);

        let xml_ext = wide_static("xml");
        let _ = dialog.SetDefaultExtension(PCWSTR(xml_ext.as_ptr()));

        if let Some(name) = default_name {
            let buf = wide_static(name);
            let _ = dialog.SetFileName(PCWSTR(buf.as_ptr()));
        }

        dialog.Show(parent).ok()?;
        let item = dialog.GetResult().ok()?;
        let pwstr = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;

        let path = pwstr_to_pathbuf(pwstr.0);
        CoTaskMemFree(Some(pwstr.0 as *const _));
        Some(path)
    }
}

/// UTF-16 + NUL-terminated buffer. Caller stores the returned
/// `Vec<u16>` somewhere stable until the dialog is dismissed —
/// PCWSTR pointers borrow from this buffer.
fn wide_static(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert a NUL-terminated UTF-16 pointer (as returned by
/// IShellItem::GetDisplayName) into a `PathBuf`. Lossy on the rare
/// invalid-UTF-16 case; PathBuf wraps OsString which is happy with
/// arbitrary u16 sequences on Windows.
unsafe fn pwstr_to_pathbuf(ptr: *mut u16) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    if ptr.is_null() {
        return PathBuf::new();
    }
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    PathBuf::from(OsString::from_wide(slice))
}

/// Trivial wrapper so handlers reading from disk can keep their
/// own `&Path` parameter style without re-implementing the
/// dialog -> PathBuf adapter.
#[allow(dead_code)]
pub fn open_profile_or<P: AsRef<Path>>(parent: HWND, _fallback: P) -> Option<PathBuf> {
    open_profile(parent)
}

/// Open a "pick an executable" file dialog. Used by
/// IDM_ADD_FILE → adds the picked .exe path to `profile.apps`.
pub fn open_executable(parent: HWND) -> Option<PathBuf> {
    unsafe {
        let dialog: IFileOpenDialog =
            CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let opts = dialog.GetOptions().ok()?;
        let _ = dialog.SetOptions(opts | FOS_FORCEFILESYSTEM);

        let exe_name = wide_static("Executable (*.exe)");
        let exe_spec = wide_static("*.exe");
        let any_name = wide_static("All files (*.*)");
        let any_spec = wide_static("*.*");
        let filters = [
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(exe_name.as_ptr()),
                pszSpec: PCWSTR(exe_spec.as_ptr()),
            },
            COMDLG_FILTERSPEC {
                pszName: PCWSTR(any_name.as_ptr()),
                pszSpec: PCWSTR(any_spec.as_ptr()),
            },
        ];
        let _ = dialog.SetFileTypes(&filters);
        let _ = dialog.SetFileTypeIndex(1);

        dialog.Show(parent).ok()?;
        let item = dialog.GetResult().ok()?;
        let pwstr = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;

        let path = pwstr_to_pathbuf(pwstr.0);
        CoTaskMemFree(Some(pwstr.0 as *const _));
        Some(path)
    }
}

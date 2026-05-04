// amwall — per-app icon lookup for the Apps / Services / UWP
// listviews. Mirrors upstream simplewall's icons.c — for each
// row, ask the shell what icon to render and feed it to the
// listview through the system small-icon imagelist.
//
// We don't manage our own imagelist. `SHGetFileInfoW` with
// `SHGFI_SYSICONINDEX` returns a handle to the global system
// imagelist (the same one Explorer uses) and an index inside it.
// The listview just needs that imagelist attached as its
// LVSIL_SMALL once at create time, then per-row LVITEMW.iImage
// is the index. No HICON ownership, no DestroyIcon, no leaks.
//
// Some rows won't get an icon — paths that don't exist on disk
// resolve through extension defaults (so .exe still gets the
// generic exe icon), but UNC / NT-form / driver-only paths can
// fail outright. `index_for` returns `-1` in that case and the
// listview renders a blank slot — same fallback simplewall has.

#![cfg(windows)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows::Win32::UI::Controls::HIMAGELIST;
use windows::Win32::UI::Shell::{
    SHFILEINFOW, SHGFI_LARGEICON, SHGFI_SMALLICON, SHGFI_SYSICONINDEX, SHGFI_USEFILEATTRIBUTES,
    SHGetFileInfoW, SHGetImageList, SHIL_EXTRALARGE,
};
use windows::core::PCWSTR;

use super::wide;

/// Look up the small-icon index for `path` in the system
/// imagelist. Returns `(imagelist_handle, icon_index)`. The
/// imagelist handle is the same global one for every call —
/// callers can grab it once at listview-create time and
/// discard it afterwards. `icon_index` is `-1` on failure
/// (path the shell can't resolve), which the listview renders
/// as no icon.
///
/// Hits the disk to extract per-exe icons. For paths that
/// don't exist, the shell falls back to the generic
/// extension icon (.exe → blank exe). For paths the shell
/// can't classify at all, returns `-1`.
pub fn lookup(path: &Path) -> (HIMAGELIST, i32) {
    let s = path.display().to_string();
    let wpath = wide(&s);
    let mut sfi = SHFILEINFOW::default();
    let il = unsafe {
        SHGetFileInfoW(
            PCWSTR(wpath.as_ptr()),
            FILE_ATTRIBUTE_NORMAL,
            Some(&mut sfi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_SYSICONINDEX | SHGFI_SMALLICON,
        )
    };
    if il == 0 {
        return (HIMAGELIST::default(), -1);
    }
    (HIMAGELIST(il as isize), sfi.iIcon)
}

/// Return the system small-icon imagelist handle without
/// hitting the disk. We only need the handle, so we pass
/// SHGFI_USEFILEATTRIBUTES + FILE_ATTRIBUTE_NORMAL to make
/// SHGetFileInfo skip the file lookup and just hand back the
/// global imagelist + the generic .exe icon index (we
/// throw both pieces away — only the imagelist matters here).
/// Without USEFILEATTRIBUTES the call would stat "amwall.exe"
/// against the cwd and frequently come back empty when the
/// elevated process landed in System32.
pub fn system_small_imagelist() -> HIMAGELIST {
    let wpath = wide("dummy.exe");
    let mut sfi = SHFILEINFOW::default();
    let il = unsafe {
        SHGetFileInfoW(
            PCWSTR(wpath.as_ptr()),
            FILE_ATTRIBUTE_NORMAL,
            Some(&mut sfi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES,
        )
    };
    if il == 0 {
        eprintln!("amwall: SHGetFileInfo(SHGFI_SYSICONINDEX) returned 0");
        return HIMAGELIST::default();
    }
    HIMAGELIST(il as isize)
}

/// Same as `system_small_imagelist` but for the 32×32 system
/// imagelist (LV_VIEW_ICON / LV_VIEW_TILE default size). Returns
/// the global system large-icon imagelist; cache the handle the
/// caller's listview attaches as LVSIL_NORMAL.
pub fn system_large_imagelist() -> HIMAGELIST {
    let wpath = wide("dummy.exe");
    let mut sfi = SHFILEINFOW::default();
    let il = unsafe {
        SHGetFileInfoW(
            PCWSTR(wpath.as_ptr()),
            FILE_ATTRIBUTE_NORMAL,
            Some(&mut sfi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_SYSICONINDEX | SHGFI_LARGEICON | SHGFI_USEFILEATTRIBUTES,
        )
    };
    if il == 0 {
        eprintln!("amwall: SHGetFileInfo(LARGE SYSICONINDEX) returned 0");
        return HIMAGELIST::default();
    }
    HIMAGELIST(il as isize)
}

/// 48×48 ("extralarge") system imagelist. Win10's HiDPI display
/// settings ramp this to 64×64+ on high-DPI screens, which is
/// what upstream's Extra-large view uses. `SHGetImageList`
/// returns an `IImageList` COM handle that wraps the same
/// underlying HIMAGELIST; we transmute through the COM pointer
/// to get the raw handle the listview needs.
pub fn system_extralarge_imagelist() -> HIMAGELIST {
    let result: windows::core::Result<windows::Win32::UI::Controls::IImageList> =
        unsafe { SHGetImageList(SHIL_EXTRALARGE as i32) };
    match result {
        Ok(list) => {
            // IImageList is a COM newtype around the underlying
            // HIMAGELIST handle. Cast through usize so we extract
            // the raw pointer the listview wants.
            let raw: *mut std::ffi::c_void =
                unsafe { std::mem::transmute_copy(&list) };
            std::mem::forget(list); // shell owns the imagelist; don't AddRef/Release it
            HIMAGELIST(raw as isize)
        }
        Err(_) => {
            eprintln!("amwall: SHGetImageList(SHIL_EXTRALARGE) failed");
            HIMAGELIST::default()
        }
    }
}

/// Cache of resolved per-path icon indices. Lookups go through
/// the cache to avoid hitting the shell repeatedly for the same
/// path on every repaint of the Apps listview. Negative results
/// (-1) are cached too, so a path that the shell can't resolve
/// doesn't keep retrying.
pub struct IconCache {
    inner: RefCell<HashMap<PathBuf, i32>>,
}

impl IconCache {
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(HashMap::new()),
        }
    }

    pub fn index_for(&self, path: &Path) -> i32 {
        if let Some(&idx) = self.inner.borrow().get(path) {
            return idx;
        }
        let (_, idx) = lookup(path);
        self.inner.borrow_mut().insert(path.to_path_buf(), idx);
        idx
    }
}

impl Default for IconCache {
    fn default() -> Self {
        Self::new()
    }
}

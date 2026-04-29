// amwall — UWP / packaged-app enumeration for the Apps → UWP tab.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Walks the per-user packaged-app repository registry hive, the same
// store the AppX deployment runtime writes to:
//
//   HKEY_CURRENT_USER\Software\Classes\Local Settings\
//     Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages
//
// Each subkey is a "package full name" (e.g.
// `Microsoft.WindowsCalculator_11.2210.0.0_x64__8wekyb3d8bbwe`) and
// has values:
//
//   DisplayName        - REG_SZ friendly name (often a resource id
//                        like "@{...}", which we resolve at display
//                        time via SHLoadIndirectString — for now we
//                        fall back to the package's "name part" if
//                        DisplayName is unresolvable).
//   PackageRootFolder  - REG_SZ install directory.
//   Publisher          - REG_SZ X.500 publisher string.
//
// Why registry instead of the WinRT `PackageManager`:
//
//   - WinRT `Windows::Management::Deployment::PackageManager` is the
//     "right" API but lives behind windows-rs's WinRT module which
//     would require adding the `Windows_Management_Deployment` Cargo
//     feature (and pulls in the entire WinRT side of the crate).
//     Registry walk is a few hundred bytes of Win32 code with no
//     extra deps, sufficient for "list installed packages so the
//     user can author a rule against one".
//   - The display names we get from the registry are sometimes the
//     unresolved indirect form (`@{Microsoft.WindowsCalculator_...?
//     ms-resource://...}`); falling back to the "name part" of the
//     package full name (`Microsoft.WindowsCalculator`) gives a
//     stable readable identifier without an MRT round-trip.

#![cfg(windows)]

use std::path::PathBuf;

use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, REG_SAM_FLAGS,
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::PCWSTR;

const REPOSITORY_KEY: &str = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

/// One row in the UWP listview. `display_name` is the human-
/// readable label (preferred for display), `package_full_name` is
/// the registry-key form a firewall rule needs as an identifier,
/// and `install_path` is where the package's binaries live (used by
/// future rule-creation flows that need an AppPath).
#[derive(Debug, Clone)]
pub struct PackageEntry {
    pub display_name: String,
    pub package_full_name: String,
    pub install_path: PathBuf,
}

/// Enumerate every UWP package registered for the current user.
/// Errors at any layer (key not found, individual subkey read fail)
/// degrade silently — the UWP tab "missing some entries" is better
/// than crashing the GUI on a partially-corrupt Repository hive.
pub fn enumerate() -> Vec<PackageEntry> {
    let key = match open_subkey(
        HKEY_CURRENT_USER,
        REPOSITORY_KEY,
        KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
    ) {
        Some(k) => k,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();
    let mut idx: u32 = 0;
    loop {
        let name = match enum_subkey_name(key, idx) {
            EnumResult::Name(n) => n,
            EnumResult::End => break,
            EnumResult::Error => break,
        };
        idx += 1;

        let entry = read_package_entry(key, &name);
        if let Some(e) = entry {
            entries.push(e);
        } else {
            // Even if the subkey lookups failed, surface the package
            // full name so the user sees something rather than a
            // silently-shorter list. Install path stays empty.
            entries.push(PackageEntry {
                display_name: derive_name_part(&name).to_string(),
                package_full_name: name,
                install_path: PathBuf::new(),
            });
        }
    }

    unsafe {
        let _ = RegCloseKey(key);
    }

    entries.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
    });
    entries
}

fn read_package_entry(parent: HKEY, full_name: &str) -> Option<PackageEntry> {
    let sub = open_subkey(parent, full_name, KEY_QUERY_VALUE)?;

    let raw_display = read_string_value(sub, "DisplayName").unwrap_or_default();
    let install = read_string_value(sub, "PackageRootFolder").unwrap_or_default();

    unsafe {
        let _ = RegCloseKey(sub);
    }

    let display_name = if raw_display.is_empty() || raw_display.starts_with("@{") {
        // `@{...}` is an unresolved indirect-string reference. We
        // could resolve via SHLoadIndirectString but that requires
        // a per-package SxS context activation; not worth the
        // complexity for the M5.4 scope. Fall back to the readable
        // name part of the full name.
        derive_name_part(full_name).to_string()
    } else {
        raw_display
    };

    Some(PackageEntry {
        display_name,
        package_full_name: full_name.to_string(),
        install_path: PathBuf::from(install),
    })
}

/// Extract the "name" portion of a package full name. The format is
/// `<name>_<version>_<arch>__<publisherid>`, so the substring up to
/// the first `_` is the family-grouped readable identifier, e.g.
/// `Microsoft.WindowsCalculator`.
fn derive_name_part(full_name: &str) -> &str {
    full_name.split_once('_').map(|(n, _)| n).unwrap_or(full_name)
}

fn open_subkey(parent: HKEY, path: &str, sam: REG_SAM_FLAGS) -> Option<HKEY> {
    let wpath: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut out = HKEY::default();
    let res = unsafe {
        RegOpenKeyExW(parent, PCWSTR(wpath.as_ptr()), 0, sam, &mut out)
    };
    if res == ERROR_SUCCESS { Some(out) } else { None }
}

enum EnumResult {
    Name(String),
    End,
    Error,
}

fn enum_subkey_name(parent: HKEY, idx: u32) -> EnumResult {
    // 256 char names cover every legal package full name (256 wide
    // chars with a NUL = 514 bytes). Allocate 512 to be safe.
    let mut buf = vec![0u16; 512];
    let mut len: u32 = buf.len() as u32;
    let res = unsafe {
        RegEnumKeyExW(
            parent,
            idx,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
            None,
            windows::core::PWSTR::null(),
            None,
            None,
        )
    };
    if res == ERROR_NO_MORE_ITEMS {
        return EnumResult::End;
    }
    if res != ERROR_SUCCESS {
        return EnumResult::Error;
    }
    let s = String::from_utf16_lossy(&buf[..len as usize]);
    EnumResult::Name(s)
}

fn read_string_value(key: HKEY, name: &str) -> Option<String> {
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut size: u32 = 0;
    // First call: probe for size. Pass null buffer + zero size; the
    // API writes the required byte count to `size`.
    let probe = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(wname.as_ptr()),
            None,
            None,
            None,
            Some(&mut size),
        )
    };
    if probe != ERROR_SUCCESS || size == 0 {
        return None;
    }
    // size is bytes; we want u16 words.
    let u16_count = (size as usize).div_ceil(2);
    let mut buf = vec![0u16; u16_count];
    let buf_bytes = buf.as_mut_ptr() as *mut u8;
    let res = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(wname.as_ptr()),
            None,
            None,
            Some(buf_bytes),
            Some(&mut size),
        )
    };
    if res != ERROR_SUCCESS {
        return None;
    }
    // Trim trailing NUL(s) — REG_SZ values are stored with a
    // terminator, sometimes two.
    while let Some(&0) = buf.last() {
        buf.pop();
    }
    Some(String::from_utf16_lossy(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_part_strips_version_arch_publisher() {
        assert_eq!(
            derive_name_part("Microsoft.WindowsCalculator_11.2210.0.0_x64__8wekyb3d8bbwe"),
            "Microsoft.WindowsCalculator"
        );
        assert_eq!(
            derive_name_part("Microsoft.UI.Xaml.2.7_7.2208.15002.0_x64__8wekyb3d8bbwe"),
            "Microsoft.UI.Xaml.2.7"
        );
    }

    #[test]
    fn name_part_handles_no_underscore() {
        assert_eq!(derive_name_part("Plain"), "Plain");
        assert_eq!(derive_name_part(""), "");
    }

    /// Live registry walk. Every Windows install ships with at least
    /// a few inbox UWP packages (Settings, Photos, Calculator) — a
    /// non-empty result is the bar. If this fails, either the
    /// registry path moved (Windows version drift) or the user's
    /// hive is broken.
    #[test]
    fn enumerate_returns_some_packages() {
        let entries = enumerate();
        assert!(
            !entries.is_empty(),
            "registry walk produced zero packages — Repository\\Packages key missing or empty"
        );
        for e in &entries {
            assert!(
                !e.package_full_name.is_empty(),
                "package_full_name empty in {e:?}"
            );
            assert!(!e.display_name.is_empty(), "display_name empty in {e:?}");
        }
    }
}

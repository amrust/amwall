// amwall — portable / installed path resolution (M9.1).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Two layouts:
//
//   Portable: `amwall.ini` exists next to `amwall.exe`. All
//             persistent state (profile, settings, log, locale)
//             lives in the same directory as the exe. Lets users
//             carry a configured copy on a USB drive or sync it
//             to a different machine without leaking into
//             `%APPDATA%`. Mirrors upstream simplewall's portable
//             mode (where the marker is `simplewall.ini`).
//
//   Installed: marker absent. State lives under
//              `%APPDATA%\amwall\`, the default since v0.0.1.
//
// The marker file (`amwall.ini`) doubles as the settings file in
// portable mode — its content is the same line-oriented `key=value`
// store the installed-mode `settings.txt` uses, just under a
// different name. Detection only looks at file existence, so
// creating an empty `amwall.ini` next to the exe is enough to
// flip into portable mode on next launch.

use std::path::{Path, PathBuf};

/// Filename that gates portable mode. Presence next to the exe →
/// portable layout. Content can be empty or a settings-format
/// `key=value` file.
pub const PORTABLE_MARKER: &str = "amwall.ini";

/// `true` when `amwall.ini` is next to the exe. Drives `data_dir`,
/// `settings_path`, `profile_path`, etc. Cheap (one stat per call)
/// — callers that hot-path it can wrap in a `OnceLock`, but for
/// startup-only path resolution the bare syscall is fine.
pub fn is_portable() -> bool {
    exe_dir()
        .map(|d| d.join(PORTABLE_MARKER).is_file())
        .unwrap_or(false)
}

/// Where amwall reads / writes per-user state. `<exe_dir>` in
/// portable mode, `%APPDATA%\amwall\` otherwise. Falls back to the
/// current directory if neither resolves (e.g. running as SYSTEM
/// with no APPDATA in the environment) — the I/O calls downstream
/// will then surface a permission error rather than silently
/// landing files in an unexpected location.
pub fn data_dir() -> PathBuf {
    if is_portable() {
        return exe_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    appdata_amwall_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Settings file path. Portable mode reuses `amwall.ini` (the
/// marker) since its on-disk format is already line-oriented
/// key=value; installed mode keeps the historical `settings.txt`.
pub fn settings_path() -> PathBuf {
    if is_portable() {
        data_dir().join(PORTABLE_MARKER)
    } else {
        data_dir().join("settings.txt")
    }
}

/// User profile (`profile.xml`) path. Same filename in both modes.
pub fn profile_path() -> PathBuf {
    data_dir().join("profile.xml")
}

/// Default packet-log path used by `event_log` when
/// `Settings.log_path` is empty. Lives under `data_dir()` so
/// portable mode keeps logs alongside the exe.
pub fn default_log_path() -> PathBuf {
    data_dir().join("amwall.log")
}

/// Directory containing the exe, or `None` if `current_exe`
/// fails (rare — sandboxes that block `GetModuleFileNameW`).
pub fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
}

fn appdata_amwall_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("amwall"))
}

// ---- Path-containment policy (security audit finding D) -------------
//
// When amwall runs elevated it must not act on paths taken from the
// user-writable settings file (log_path, log_viewer) without checking
// them, or a Medium-integrity user gains a High-integrity file-write /
// code-execution primitive. These pure helpers implement the policy;
// the elevation-gated call sites live in event_log.rs / main_window.rs.

/// Fold `.` and `..` components lexically (NO filesystem access) so a
/// containment check can't be fooled by a `..`-laden path that
/// textually sits inside `base` but escapes it. Lexical only: a
/// directory junction inside `base` pointing out of the tree is not
/// resolved here — callers that need that must canonicalize first.
pub fn normalize_lexically(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop a preceding Normal segment; keep the prefix/root
                // anchored, and preserve a leading `..` that can't pop.
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn os_eq_ci(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    // Windows path components compare case-insensitively.
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

fn components_eq_ci(a: std::path::Component<'_>, b: std::path::Component<'_>) -> bool {
    use std::path::Component::*;
    match (a, b) {
        (RootDir, RootDir) | (CurDir, CurDir) | (ParentDir, ParentDir) => true,
        (Prefix(x), Prefix(y)) => os_eq_ci(x.as_os_str(), y.as_os_str()),
        (Normal(x), Normal(y)) => os_eq_ci(x, y),
        _ => false,
    }
}

/// True when `candidate` is `base` itself or a descendant of it, after
/// lexical normalization, compared case-insensitively (Windows path
/// semantics) and by WHOLE component (so `C:\a\bevil` is NOT inside
/// `C:\a\b`). A candidate that still bears an escaping `..` after
/// normalization is rejected. Pure — no I/O.
pub fn path_is_contained(base: &Path, candidate: &Path) -> bool {
    let base = normalize_lexically(base);
    let cand = normalize_lexically(candidate);
    // An empty base would vacuously "contain" everything; never allow
    // that (data_dir is always absolute, but be defensive).
    if base.components().next().is_none() {
        return false;
    }
    let mut b = base.components();
    let mut c = cand.components();
    loop {
        match (b.next(), c.next()) {
            (None, _) => return true,        // matched all of base -> inside
            (Some(_), None) => return false, // candidate shorter than base
            (Some(bc), Some(cc)) => {
                if !components_eq_ci(bc, cc) {
                    return false;
                }
            }
        }
    }
}

/// The admin-only-writable system roots (Windows / Program Files),
/// canonicalized, built from the environment so a non-`C:` system
/// drive still resolves. A Medium-integrity user cannot plant a file
/// under these, so an elevated amwall may safely execute a program
/// found here.
fn admin_only_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in [
        "SystemRoot",
        "windir",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
    ] {
        if let Some(v) = std::env::var_os(var) {
            if let Ok(canon) = PathBuf::from(v).canonicalize() {
                if !roots.contains(&canon) {
                    roots.push(canon);
                }
            }
        }
    }
    roots
}

/// True when `path` resolves inside an admin-only-writable system root.
/// Canonicalizes `path` first (proving it exists and defeating 8.3 /
/// symlink / `..` tricks) before the containment check; a path that
/// can't be canonicalized (missing / unreadable) fails closed to
/// `false`. Used to decide whether an elevated amwall may run a
/// user-configured external program. Security audit finding D.
pub fn is_admin_only_location(path: &Path) -> bool {
    let Ok(canon) = path.canonicalize() else {
        return false;
    };
    admin_only_roots()
        .iter()
        .any(|root| path_is_contained(root, &canon))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn normalize_lexically_resolves_dot_and_dotdot() {
        assert_eq!(
            normalize_lexically(Path::new(r"C:\a\b\..\c")),
            PathBuf::from(r"C:\a\c")
        );
        assert_eq!(
            normalize_lexically(Path::new(r"C:\a\.\b")),
            PathBuf::from(r"C:\a\b")
        );
    }

    #[cfg(windows)]
    #[test]
    fn path_is_contained_basic_and_case_insensitive() {
        let base = Path::new(r"C:\Users\me\AppData\Roaming\amwall");
        assert!(path_is_contained(base, base)); // base itself is contained
        assert!(path_is_contained(
            base,
            Path::new(r"C:\Users\me\AppData\Roaming\amwall\amwall.log")
        ));
        // case-insensitive (Windows path semantics)
        assert!(path_is_contained(
            base,
            Path::new(r"c:\users\ME\appdata\roaming\AMWALL\sub\x.log")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn path_is_contained_rejects_outside_siblings_and_unnormalized() {
        let base = Path::new(r"C:\data\amwall");
        // sibling-prefix must NOT count as inside (whole-component match)
        assert!(!path_is_contained(base, Path::new(r"C:\data\amwall-evil\x")));
        // out of tree
        assert!(!path_is_contained(base, Path::new(r"C:\Windows\System32\x")));
        // shorter than base
        assert!(!path_is_contained(base, Path::new(r"C:\data")));
        // a `..` that escapes base after normalization is rejected
        assert!(!path_is_contained(
            base,
            Path::new(r"C:\data\amwall\..\Windows\x")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn is_admin_only_location_matches_only_system_roots() {
        // SystemRoot exists on any Windows host / CI runner and is
        // admin-only-writable. A path under the user-writable data dir
        // is not (and a non-existent path fails closed to false).
        if let Some(sysroot) = std::env::var_os("SystemRoot") {
            assert!(
                is_admin_only_location(Path::new(&sysroot)),
                "SystemRoot must be treated as admin-only"
            );
        }
        let user_path = data_dir().join("definitely-not-admin-xyz.log");
        assert!(!is_admin_only_location(&user_path));
    }

    #[test]
    fn portable_marker_is_amwall_ini() {
        // Sanity: future renames need to update the comment block
        // at the top of the file too — this test catches accidental
        // changes that diverge from the contract.
        assert_eq!(PORTABLE_MARKER, "amwall.ini");
    }

    #[test]
    fn paths_share_a_common_data_dir() {
        // Whatever data_dir resolves to, the per-file helpers
        // should hang every artifact off it. Catches regressions
        // where one helper hardcodes %APPDATA% and the other
        // doesn't, splitting state across two locations.
        let dir = data_dir();
        assert!(profile_path().starts_with(&dir));
        assert!(default_log_path().starts_with(&dir));
        // Settings can be either `<dir>/amwall.ini` (portable) or
        // `<dir>/settings.txt` (installed) — both still under `dir`.
        assert!(settings_path().starts_with(&dir));
    }
}

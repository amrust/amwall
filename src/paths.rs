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

/// Dev-capture `swaplog.txt` path — the file a VS Code build task / the
/// run-elevated script redirect stderr into with `2> swaplog.txt`
/// (portable: beside the exe; installed: `%APPDATA%\amwall\`). NOTE: a
/// running GUI process does NOT write here — `logging::init_debug_log`
/// SetStdHandle-redirects stderr to `logs\amwall-<ts>.log` instead. This
/// is only the FALLBACK for the tray "Errors log" feature; the real
/// runtime sink is `logging::current_log_path()`. See error_log_target
/// in main_window.
pub fn error_log_path() -> PathBuf {
    data_dir().join("swaplog.txt")
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

// ---- Environment-variable expansion (issue #12) ----------------------
//
// simplewall profiles routinely store app paths in variable form
// (`%ProgramFiles%\…`, `%SystemRoot%\…`, `%USERPROFILE%\…`). The stored
// string is kept verbatim so a load→save round-trip never rewrites the
// user's profile into absolute, machine-specific paths; instead every
// consumer that needs a *real* file resolves it here at the point of
// use. That mirrors upstream's split between `ITEM_APP.original_path`
// and `ITEM_APP.real_path` (helper.c:645-650).
//
// This lives in `paths` rather than `install` because both the
// enforcement path (app-id blobs) and the GUI (existence highlight,
// purge, hashing, signatures) need the same answer, and they must never
// disagree about whether a given entry exists.

/// Expand `%VAR%` placeholders against `std::env`. Unknown variables
/// are emitted literally (`%FOO%`) rather than dropped, matching
/// Win32 `ExpandEnvironmentStringsW` semantics for unmatched names.
pub fn expand_env(s: &str) -> String {
    expand_env_with(s, |k| std::env::var(k).ok())
}

/// Testable core of [`expand_env`] — `lookup` stands in for the process
/// environment so the expansion rules can be pinned without touching
/// real variables.
pub(crate) fn expand_env_with<F: Fn(&str) -> Option<String>>(s: &str, lookup: F) -> String {
    // Fast path: the overwhelming majority of paths have no `%` at all.
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // Collect chars until the closing `%`. If no closing `%`
        // appears, emit the buffered text literally (with the
        // leading `%`).
        let mut name = String::new();
        let mut closed = false;
        while let Some(&peek) = chars.peek() {
            chars.next();
            if peek == '%' {
                closed = true;
                break;
            }
            name.push(peek);
        }
        if closed {
            match lookup(&name) {
                Some(v) => out.push_str(&v),
                None => {
                    // Unknown var: emit `%NAME%` literally.
                    out.push('%');
                    out.push_str(&name);
                    out.push('%');
                }
            }
        } else {
            // Unmatched `%`: emit `%NAME` literally.
            out.push('%');
            out.push_str(&name);
        }
    }
    out
}

/// Resolve a stored app path to the file the OS will actually open.
///
/// Only `%VAR%` expansion today; the input is returned unchanged when
/// it contains no variables, so the common case allocates nothing new
/// beyond the borrow. Callers must pass a *file* path — service short
/// names and UWP package SIDs are not filesystem paths and are handled
/// by [`crate::profile::App::resolved_path`], which checks the kind
/// first.
pub fn resolve_app_path(raw: &Path) -> std::borrow::Cow<'_, Path> {
    let s = raw.to_string_lossy();
    if !s.contains('%') {
        return std::borrow::Cow::Borrowed(raw);
    }
    std::borrow::Cow::Owned(PathBuf::from(expand_env(&s)))
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

/// The Windows directory (e.g. `C:\Windows`) from the OS, NOT from the
/// overridable `%SystemRoot%` / `%windir%` environment.
/// `GetSystemWindowsDirectoryW` is preferred over `GetWindowsDirectoryW`
/// (which can return a per-user directory under Terminal Services).
#[cfg(windows)]
fn system_windows_dir() -> Option<PathBuf> {
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 260];
    // Returns the length in chars (excluding the NUL) on success, the
    // required size if the buffer was too small, or 0 on failure.
    let len = unsafe { GetSystemWindowsDirectoryW(Some(&mut buf)) } as usize;
    if len == 0 || len > buf.len() {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..len])))
}

/// Resolve a KNOWNFOLDERID to a path via the shell (reads HKLM, not the
/// process environment). The returned `PWSTR` is owned by the shell and
/// freed with `CoTaskMemFree`.
#[cfg(windows)]
fn known_folder(id: &windows::core::GUID) -> Option<PathBuf> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    unsafe {
        let pwstr = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, HANDLE::default()).ok()?;
        if pwstr.is_null() {
            return None;
        }
        let s = pwstr.to_string().ok();
        CoTaskMemFree(Some(pwstr.0 as *const std::ffi::c_void));
        s.map(PathBuf::from)
    }
}

/// The admin-only-writable system roots (Windows / Program Files),
/// canonicalized, resolved from AUTHORITATIVE OS APIs rather than the
/// process environment. A same-user process can shadow `%ProgramFiles%`
/// / `%SystemRoot%` in its own environment, so trusting those for a
/// privilege boundary (the skip-UAC target check) is unsound. A
/// Medium-integrity user cannot plant a file under these, so an elevated
/// amwall may safely execute a program found here. Fable sweep finding
/// #15 (hardens audit finding E's guard).
#[cfg(windows)]
fn admin_only_roots() -> Vec<PathBuf> {
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86};
    let mut roots = Vec::new();
    for p in [
        system_windows_dir(),
        known_folder(&FOLDERID_ProgramFiles),
        known_folder(&FOLDERID_ProgramFilesX86),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(canon) = p.canonicalize() {
            if !roots.contains(&canon) {
                roots.push(canon);
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

/// Like `path_is_contained`, but resolves directory junctions and
/// symlinks: it canonicalizes the deepest EXISTING ancestor of
/// `candidate` (the target file usually doesn't exist yet) and
/// re-appends the not-yet-existing tail before comparing against a
/// canonicalized `base`. This defeats a junction/symlink planted inside
/// `base` that points out of the tree — which the purely lexical
/// `path_is_contained` cannot see. Fails closed (`false`) if `base` or
/// every ancestor of `candidate` fails to canonicalize. Touches the
/// filesystem, unlike `path_is_contained`.
pub fn real_path_contained(base: &Path, candidate: &Path) -> bool {
    let Ok(canon_base) = base.canonicalize() else {
        return false;
    };
    // Walk up from the candidate until an ancestor canonicalizes,
    // stacking the not-yet-existing tail components to re-append.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = candidate.to_path_buf();
    loop {
        if let Ok(canon) = cur.canonicalize() {
            let mut real = canon;
            for part in tail.iter().rev() {
                real.push(part);
            }
            return path_is_contained(&canon_base, &real);
        }
        let name = match cur.file_name() {
            Some(n) => n.to_owned(),
            None => return false, // reached a root that won't canonicalize
        };
        if !cur.pop() {
            return false;
        }
        tail.push(name);
    }
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
    fn real_path_contained_resolves_ancestors_and_rejects_outside() {
        // A not-yet-existing file whose deepest EXISTING ancestor is
        // inside `base` is contained.
        let base = std::env::temp_dir().join("amwall-rpc-test");
        let _ = std::fs::create_dir_all(&base);
        assert!(real_path_contained(
            &base,
            &base.join("sub").join("amwall.log")
        ));
        // A path whose real ancestor is outside `base` is not.
        assert!(!real_path_contained(
            &base,
            Path::new(r"C:\Windows\System32\amwall-nope.log")
        ));
        // A base that can't be canonicalized fails closed.
        assert!(!real_path_contained(
            Path::new(r"C:\amwall-does-not-exist-xyz-987"),
            &base.join("x.log")
        ));
        let _ = std::fs::remove_dir_all(&base);
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

    // ---- environment-variable expansion (issue #12) ----------------
    //
    // Moved here from `install` when the GUI began needing the same
    // answer as the enforcement path.

    #[test]
    fn expand_env_with_known_var() {
        let out = expand_env_with(r"%FOO%\bar", |k| {
            if k == "FOO" {
                Some(r"C:\baz".to_string())
            } else {
                None
            }
        });
        assert_eq!(out, r"C:\baz\bar");
    }

    #[test]
    fn expand_env_with_unknown_var_keeps_literal() {
        let out = expand_env_with("%missing%/end", |_| None);
        assert_eq!(out, "%missing%/end");
    }

    #[test]
    fn expand_env_with_unmatched_percent_keeps_literal() {
        let out = expand_env_with("prefix %unmatched", |_| Some("X".into()));
        assert_eq!(out, "prefix %unmatched");
    }

    #[test]
    fn expand_env_with_no_percent_passes_through() {
        let out = expand_env_with(r"C:\Windows\System32", |_| None);
        assert_eq!(out, r"C:\Windows\System32");
    }

    #[test]
    fn expand_env_handles_the_forms_reported_in_issue_12() {
        // The exact variable forms from the migration report.
        let lookup = |k: &str| match k {
            "SystemDrive" => Some(r"C:".to_string()),
            "ProgramFiles" => Some(r"C:\Program Files".to_string()),
            "AppData" => Some(r"C:\Users\u\AppData\Roaming".to_string()),
            "SystemRoot" => Some(r"C:\Windows".to_string()),
            "USERPROFILE" => Some(r"C:\Users\u".to_string()),
            _ => None,
        };
        let cases = [
            (r"%SystemDrive%\tools\t.exe", r"C:\tools\t.exe"),
            (r"%ProgramFiles%\App\app.exe", r"C:\Program Files\App\app.exe"),
            (r"%AppData%\App\app.exe", r"C:\Users\u\AppData\Roaming\App\app.exe"),
            (r"%SystemRoot%\System32\svchost.exe", r"C:\Windows\System32\svchost.exe"),
            (r"%USERPROFILE%\bin\b.exe", r"C:\Users\u\bin\b.exe"),
        ];
        for (raw, want) in cases {
            assert_eq!(expand_env_with(raw, lookup), want, "input {raw}");
        }
    }

    #[test]
    fn expand_env_var_names_are_case_insensitive_via_the_os() {
        // simplewall profiles use `%systemroot%` lowercase as often as
        // `%SystemRoot%`. Windows env lookups are case-insensitive, so
        // the real `expand_env` handles both; pin that the expander
        // itself passes the name through verbatim and does not, say,
        // upper-case or trim it before lookup.
        let seen = std::cell::RefCell::new(Vec::new());
        let _ = expand_env_with(r"%systemroot%\x", |k| {
            seen.borrow_mut().push(k.to_string());
            None
        });
        assert_eq!(seen.into_inner(), vec!["systemroot".to_string()]);
    }

    #[test]
    fn resolve_app_path_borrows_when_there_is_nothing_to_expand() {
        let raw = Path::new(r"C:\Program Files\App\app.exe");
        let resolved = resolve_app_path(raw);
        assert!(matches!(resolved, std::borrow::Cow::Borrowed(_)));
        assert_eq!(resolved.as_ref(), raw);
    }

    #[test]
    fn resolve_app_path_expands_a_real_variable() {
        // SystemRoot is guaranteed present on any Windows host.
        let raw = PathBuf::from(r"%SystemRoot%\System32\svchost.exe");
        let resolved = resolve_app_path(&raw);
        assert!(
            !resolved.to_string_lossy().contains('%'),
            "expected expansion, got {}",
            resolved.display()
        );
        assert!(resolved.to_string_lossy().ends_with(r"System32\svchost.exe"));
    }

    #[test]
    fn resolve_app_path_keeps_an_unknown_variable_literal() {
        // Never silently turn an unresolvable entry into a different
        // path — leaving it literal keeps it failing visibly.
        let raw = PathBuf::from(r"%AMWALL_NO_SUCH_VAR_5d9aa%\x.exe");
        let resolved = resolve_app_path(&raw);
        assert_eq!(resolved.as_ref(), raw.as_path());
    }
}

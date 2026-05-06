// amwall — session debug log (stderr/stdout capture for installed mode).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Problem: amwall is built with `windows_subsystem = "windows"`, so an
// MSI-installed copy launched from Explorer / Start Menu has no
// console attached. Every `eprintln!` / `println!` in the codebase
// goes to a closed handle — useful debug info during development
// (we capture it to swaplog.txt via a VS Code build task) is lost
// in production.
//
// Solution: at GUI entry, open a timestamped log file under
// `%APPDATA%\amwall\logs\amwall-<YYYY-MM-DD_HH-MM-SS>.log`, then
// `SetStdHandle(STD_ERROR_HANDLE / STD_OUTPUT_HANDLE)` to point
// at it. Every existing `eprintln!` in the codebase now writes
// to disk without per-call-site changes. Rust's default panic
// handler also writes to stderr, so panics get captured too.
//
// File rotation: each launch creates a new file. Old files are
// pruned to keep the most recent `MAX_LOG_FILES` (lexicographic
// sort on the timestamped filename). Bounded disk use; the user
// can grab the latest few when reporting issues.

#![cfg(windows)]

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::System::SystemInformation::{
    GetLocalTime, GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows::core::PCWSTR;

/// How many session log files to keep around. Older files (by
/// lexicographic sort on the timestamp embedded in the filename)
/// get deleted at startup. 10 covers a typical debug session
/// without ballooning disk use even if the user opens / closes
/// amwall many times.
const MAX_LOG_FILES: usize = 10;

/// Filename prefix. `prune_old_logs` keys off this so it doesn't
/// touch unrelated files a user might drop in the logs folder.
const LOG_PREFIX: &str = "amwall-";
const LOG_EXTENSION: &str = ".log";

/// `<data_dir>\logs\` — folder holding the session-log files.
/// Lives under `data_dir()` so portable mode keeps logs alongside
/// the exe and installed mode keeps them under `%APPDATA%\amwall\`.
pub fn log_dir() -> PathBuf {
    crate::paths::data_dir().join("logs")
}

/// Open a fresh timestamped log file, redirect this process's
/// stdout + stderr to it, and prune older logs so we keep the
/// most recent `MAX_LOG_FILES`. Best-effort: any I/O failure
/// (no APPDATA, no write permission, full disk) silently
/// degrades to "no debug log this session" rather than crashing
/// the GUI launch.
///
/// Call exactly once at the start of GUI mode, BEFORE any code
/// that might `eprintln!`. CLI subcommands shouldn't call this
/// — they want their stderr to go to the parent shell, not a
/// file (the existing `attach_to_parent_console` handles that).
pub fn init_debug_log() {
    let dir = log_dir();
    if create_dir_all(&dir).is_err() {
        return;
    }

    let timestamp = current_timestamp();
    let filename = format!("{LOG_PREFIX}{timestamp}{LOG_EXTENSION}");
    let path = dir.join(&filename);

    let mut file = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return,
    };

    // Header so a log file picked up cold is self-describing.
    // Each piece is best-effort — a Windows version that doesn't
    // expose one of these registry keys / APIs falls through to
    // "<unknown>" rather than crashing the GUI launch.
    let _ = writeln!(
        file,
        "=== amwall {} session log ===",
        env!("CARGO_PKG_VERSION"),
    );
    let _ = writeln!(file, "started: {timestamp} (local time)");
    let _ = writeln!(
        file,
        "exe: {}",
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
    );
    let _ = writeln!(file, "os:  {}", os_version_string());
    let _ = writeln!(file, "cpu: {}", cpu_info_string());
    let _ = writeln!(file, "ram: {}", ram_string());
    let _ = writeln!(file);
    let _ = file.flush();

    // SetStdHandle with the file's raw HANDLE so subsequent
    // `eprintln!` / `println!` lands here. The `_file` value is
    // intentionally `mem::forget`-ed below — closing it would
    // invalidate the handle Win32 now thinks is stderr.
    let raw = file.as_raw_handle() as isize;
    let handle = HANDLE(raw);
    unsafe {
        let _ = SetStdHandle(STD_ERROR_HANDLE, handle);
        let _ = SetStdHandle(STD_OUTPUT_HANDLE, handle);
    }

    // The file handle now lives inside Win32's per-process std
    // handle table; dropping our `File` would close it and
    // turn future eprintln! into a noop or worse. Forget the
    // owning value so its drop never runs. The OS reclaims the
    // handle when the process exits.
    std::mem::forget(file);

    prune_old_logs(&dir);
}

/// Local time formatted as `YYYY-MM-DD_HH-MM-SS`. The dashes
/// (vs the typical `:` for time) keep the result safe to use
/// as a filename on Windows. Lexicographic sort matches
/// chronological order.
fn current_timestamp() -> String {
    let st = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02}_{:02}-{:02}-{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
    )
}

/// "Windows 10 Pro (build 19045.1234, x64)" or similar. Reads
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` for the
/// product display name + build numbers; appends architecture
/// from `GetSystemInfo`. Falls back to "<unknown>" pieces if any
/// of the reads fail.
fn os_version_string() -> String {
    let hive = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = read_reg_string(HKEY_LOCAL_MACHINE, hive, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let build = read_reg_string(HKEY_LOCAL_MACHINE, hive, "CurrentBuild")
        .unwrap_or_else(|| "<unknown>".to_string());
    let ubr = read_reg_dword(HKEY_LOCAL_MACHINE, hive, "UBR");
    let display_version = read_reg_string(HKEY_LOCAL_MACHINE, hive, "DisplayVersion");
    let arch = match cpu_arch_string() {
        Some(s) => s,
        None => "<unknown arch>".to_string(),
    };
    let build_full = match ubr {
        Some(u) => format!("{build}.{u}"),
        None => build,
    };
    match display_version {
        Some(dv) => format!("{product} {dv} (build {build_full}, {arch})"),
        None => format!("{product} (build {build_full}, {arch})"),
    }
}

/// "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz, 8 cores" or
/// similar. Name comes from `HKLM\HARDWARE\DESCRIPTION\System\
/// CentralProcessor\0\ProcessorNameString`; core count from
/// `GetSystemInfo::dwNumberOfProcessors`.
fn cpu_info_string() -> String {
    let name = read_reg_string(
        HKEY_LOCAL_MACHINE,
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    )
    .unwrap_or_else(|| "<unknown>".to_string());
    // Trim trailing whitespace some CPUs report (Intel ships
    // names padded with spaces in this registry value).
    let name = name.trim().to_string();

    let mut sysinfo: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut sysinfo) };
    let cores = sysinfo.dwNumberOfProcessors;
    format!("{name}, {cores} cores")
}

/// "16.0 GiB" — total physical RAM via `GlobalMemoryStatusEx`.
/// We report the binary GiB the OS sees, not the marketing-GB
/// figure on the box.
fn ram_string() -> String {
    let mut info = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut info) }.is_err() {
        return "<unknown>".to_string();
    }
    let bytes = info.ullTotalPhys as f64;
    let gib = bytes / (1024.0 * 1024.0 * 1024.0);
    format!("{gib:.1} GiB")
}

/// CPU architecture name from `GetSystemInfo`. ARM64 / x64 / x86
/// are the realistic values; other PROCESSOR_ARCHITECTURE_*
/// codes fall through to a numeric formatting.
fn cpu_arch_string() -> Option<String> {
    let mut sysinfo: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut sysinfo) };
    // wProcessorArchitecture lives inside an anonymous union; access
    // through `Anonymous.Anonymous`. Constants: 0=x86, 9=x64, 12=arm64.
    let arch = unsafe { sysinfo.Anonymous.Anonymous.wProcessorArchitecture };
    let s = match arch.0 {
        0 => "x86".to_string(),
        5 => "ARM".to_string(),
        9 => "x64".to_string(),
        12 => "ARM64".to_string(),
        other => format!("arch={other}"),
    };
    Some(s)
}

/// Read a `REG_SZ` value into a `String`. Trims a trailing NUL
/// if the registry stored one.
fn read_reg_string(hive: HKEY, subkey: &str, value: &str) -> Option<String> {
    let mut wpath: Vec<u16> =
        subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut wname: Vec<u16> =
        value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    let res = unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(wpath.as_mut_ptr()),
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        )
    };
    if res.is_err() {
        return None;
    }
    let mut size: u32 = 0;
    let probe = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(wname.as_mut_ptr()),
            None,
            None,
            None,
            Some(&mut size),
        )
    };
    if probe.is_err() || size == 0 {
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        return None;
    }
    let u16_count = (size as usize).div_ceil(2);
    let mut buf = vec![0u16; u16_count];
    let mut size_io = size;
    let buf_bytes = buf.as_mut_ptr() as *mut u8;
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(wname.as_mut_ptr()),
            None,
            None,
            Some(buf_bytes),
            Some(&mut size_io),
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if res.is_err() {
        return None;
    }
    while let Some(&0) = buf.last() {
        buf.pop();
    }
    Some(String::from_utf16_lossy(&buf))
}

/// Read a `REG_DWORD` value as `u32`.
fn read_reg_dword(hive: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let mut wpath: Vec<u16> =
        subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut wname: Vec<u16> =
        value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    let res = unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(wpath.as_mut_ptr()),
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        )
    };
    if res.is_err() {
        return None;
    }
    let mut data: u32 = 0;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(wname.as_mut_ptr()),
            None,
            None,
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if res.is_err() { None } else { Some(data) }
}

/// Walk `dir`, find log files matching our prefix/extension,
/// sort by name (= chronological), delete everything except the
/// most recent `MAX_LOG_FILES`. Anything else in the folder is
/// untouched — if the user drops in a `notes.txt` it stays.
fn prune_old_logs(dir: &Path) {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut files: Vec<_> = read
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.starts_with(LOG_PREFIX) && s.ends_with(LOG_EXTENSION)
        })
        .collect();
    if files.len() <= MAX_LOG_FILES {
        return;
    }
    files.sort_by_key(|e| e.file_name());
    let to_remove = files.len() - MAX_LOG_FILES;
    for entry in files.iter().take(to_remove) {
        let _ = std::fs::remove_file(entry.path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_filename_safe() {
        let s = current_timestamp();
        // No characters Win32 disallows in filenames.
        for c in s.chars() {
            assert!(
                c.is_ascii_digit() || c == '-' || c == '_',
                "timestamp contains filename-unsafe char: {c:?}"
            );
        }
        // Roughly 19 chars (YYYY-MM-DD_HH-MM-SS).
        assert_eq!(s.len(), 19);
    }

    #[test]
    fn timestamp_lexicographic_matches_chronological() {
        // Two synthetic timestamps: a datapoint from Jan and one
        // from Feb of the same year. Lexicographic ordering must
        // place Jan before Feb (i.e. preserve chronology).
        let jan = "2026-01-15_10-00-00".to_string();
        let feb = "2026-02-15_10-00-00".to_string();
        assert!(jan < feb);
        // And same month different days.
        let day1 = "2026-01-01_10-00-00".to_string();
        let day2 = "2026-01-02_10-00-00".to_string();
        assert!(day1 < day2);
    }
}

// amwall — net-event log file writer.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// One plaintext line per WFP net event, appended to a single
// rotating log file. Format mirrors what an end-user firewall log
// is expected to look like — date+time, action (BLOCK / ALLOW),
// direction, protocol, app, 5-tuple, filter id — and is greppable
// without a viewer.
//
// Path comes from `Settings.log_path`; empty falls back to
// `%APPDATA%\amwall\amwall.log`. The writer re-resolves on every
// `append` so a settings change (toggling `enable_log`, changing
// `log_path`, flipping `exclude_classify_allow`) takes effect on
// the very next event without an explicit reload step.
//
// Rotation: when the current file's size + the new line would
// exceed `log_size_limit` KB, the current file is renamed to
// `<path>.bak` (overwriting any prior `.bak`) and a fresh file
// opened. One backup = bounded disk usage at ~2× the limit.
//
// Thread model: called from `main_window::drain_events` on the GUI
// thread; the writer holds `BufWriter<File>` non-`Sync`, but that's
// fine — there's only ever one caller.

#![cfg(windows)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::wfp::events::{NetDirection, NetEvent, NetEventDetails};

use super::settings::Settings;

pub struct EventLogWriter {
    /// Open append-mode handle, if logging is enabled and the file
    /// has been opened. `None` whenever logging is disabled or the
    /// last open attempt failed (we don't retry on every event —
    /// errors are logged once via `eprintln!` and the writer goes
    /// quiet until settings change).
    ///
    /// No `BufWriter` wrapper, deliberately — buffered output stays
    /// invisible to a `tail -f` watcher until the buffer fills (8 KB
    /// default) or the process exits, which defeats the point of a
    /// live log. Event rates are low enough (a handful per second on
    /// a typical desktop) that going straight through the OS page
    /// cache is fine.
    writer: Option<File>,
    /// Path the current `writer` is bound to. Compared against the
    /// freshly resolved path on every `append` so config changes
    /// trigger a transparent reopen.
    current_path: Option<PathBuf>,
    /// Bytes already written to the current file (including any
    /// pre-existing content from a previous run, captured at open
    /// time via `metadata().len()`). Tracked locally to avoid an
    /// extra syscall on every line.
    current_size: u64,
}

impl EventLogWriter {
    pub fn new() -> Self {
        Self {
            writer: None,
            current_path: None,
            current_size: 0,
        }
    }

    /// Append `event` to the log file if logging is enabled and the
    /// event passes the configured filters. Errors (path resolution,
    /// open, write) are reported once to stderr and then suppressed
    /// until the failing condition changes — we never bubble I/O
    /// errors into the GUI thread.
    pub fn append(&mut self, event: &NetEvent, settings: &Settings) {
        if !settings.enable_log {
            self.close();
            return;
        }

        if matches!(event, NetEvent::Allow(_)) && settings.exclude_classify_allow {
            return;
        }

        let details = match event {
            NetEvent::Drop(d) | NetEvent::Allow(d) => d,
            // CLASSIFY_OTHER and friends don't carry the per-packet
            // info that makes the log useful — skip them rather
            // than write rows full of "?" placeholders.
            NetEvent::Other(_) => return,
        };
        let action = match event {
            NetEvent::Drop(_) => "BLOCK",
            NetEvent::Allow(_) => "ALLOW",
            NetEvent::Other(_) => unreachable!(),
        };

        let path = resolve_path(&settings.log_path);
        let limit_bytes = (settings.log_size_limit as u64).saturating_mul(1024);

        // Reopen if the resolved path changed (settings edited) or
        // we don't have a writer yet.
        if self.current_path.as_deref() != Some(path.as_path()) {
            self.close();
            if let Err(e) = self.open(&path) {
                eprintln!(
                    "amwall: log: failed to open {}: {e}",
                    path.display()
                );
                return;
            }
        }

        let line = format_line(action, details);
        let line_bytes = line.len() as u64 + 1; // +1 for '\n'

        // Rotate if appending this line would push us past the cap.
        // limit_bytes == 0 disables rotation (treat as unlimited),
        // matching upstream's "0 = no cap" convention.
        if limit_bytes > 0 && self.current_size + line_bytes > limit_bytes {
            if let Err(e) = self.rotate(&path) {
                eprintln!(
                    "amwall: log: rotation failed for {}: {e}",
                    path.display()
                );
                // Stop trying to write to the current file — the
                // next settings change will reopen via `current_path`
                // mismatch.
                self.close();
                return;
            }
        }

        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => return,
        };
        if let Err(e) = writeln!(writer, "{line}") {
            eprintln!("amwall: log: write failed: {e}");
            self.close();
            return;
        }
        self.current_size += line_bytes;
    }

    /// Close the current handle. Call at shutdown or whenever the
    /// resolved path changes. Subsequent `append` calls reopen lazily.
    pub fn close(&mut self) {
        self.writer = None;
        self.current_path = None;
        self.current_size = 0;
    }

    fn open(&mut self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        self.writer = Some(file);
        self.current_path = Some(path.to_path_buf());
        self.current_size = size;
        Ok(())
    }

    fn rotate(&mut self, path: &Path) -> std::io::Result<()> {
        // Drop the current handle so the rename can proceed on
        // Windows (which won't rename an open file).
        self.writer = None;
        let bak = bak_path(path);
        // Best-effort: remove an existing .bak first (rename on
        // Windows fails if the destination exists).
        let _ = std::fs::remove_file(&bak);
        std::fs::rename(path, &bak)?;
        self.open(path)
    }
}

impl Default for EventLogWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EventLogWriter {
    fn drop(&mut self) {
        self.close();
    }
}

fn resolve_path(configured: &str) -> PathBuf {
    let trimmed = configured.trim();
    if !trimmed.is_empty() {
        return PathBuf::from(trimmed);
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        PathBuf::from(appdata).join("amwall").join("amwall.log")
    } else {
        PathBuf::from("amwall.log")
    }
}

fn bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

fn format_line(action: &str, d: &NetEventDetails) -> String {
    let ts = format_local_time(d.timestamp);
    let dir = match d.direction {
        Some(NetDirection::Outbound) => "outbound",
        Some(NetDirection::Inbound) => "inbound",
        None => "-",
    };
    let proto = match d.protocol {
        Some(1) => "ICMPv4",
        Some(6) => "TCP",
        Some(17) => "UDP",
        Some(58) => "ICMPv6",
        Some(n) => return format_line_raw(action, &ts, dir, &format!("proto{n}"), d),
        None => "-",
    };
    format_line_raw(action, &ts, dir, proto, d)
}

fn format_line_raw(
    action: &str,
    ts: &str,
    dir: &str,
    proto: &str,
    d: &NetEventDetails,
) -> String {
    let app = d.app_path.as_deref().unwrap_or("-");
    let local = format_endpoint(d.local_addr, d.local_port);
    let remote = format_endpoint(d.remote_addr, d.remote_port);
    let filter = d
        .filter_id
        .map(|f| f.to_string())
        .unwrap_or_else(|| "-".into());
    format!("{ts} {action} {dir} {proto} app={app} {local} -> {remote} filter={filter}")
}

fn format_endpoint(addr: Option<std::net::IpAddr>, port: Option<u16>) -> String {
    use std::net::IpAddr;
    match (addr, port) {
        // IPv6 + port needs `[addr]:port` bracketing — otherwise the
        // colon between address and port collides with the colons
        // inside the address itself, and `2603::1:53` is ambiguous
        // (host port 53? terminal address group 53?).
        (Some(IpAddr::V6(a)), Some(p)) => format!("[{a}]:{p}"),
        (Some(a), Some(p)) => format!("{a}:{p}"),
        (Some(a), None) => a.to_string(),
        (None, Some(p)) => format!(":{p}"),
        (None, None) => "-".into(),
    }
}

/// `YYYY-MM-DD HH:MM:SS` in the user's local timezone via the
/// standard Win32 conversion chain (FILETIME → UTC SYSTEMTIME →
/// local SYSTEMTIME). Falls back to `(invalid)` if the kernel
/// timestamp can't be converted, which shouldn't happen for live
/// events.
fn format_local_time(t: std::time::SystemTime) -> String {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::Time::{
        FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime,
    };

    let dur = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let intervals: u64 = (dur.as_secs() + 11_644_473_600) * 10_000_000
        + (dur.subsec_nanos() as u64) / 100;
    let ft = FILETIME {
        dwLowDateTime: (intervals & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (intervals >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    if unsafe { FileTimeToSystemTime(&ft, &mut utc) }.is_err() {
        return "(invalid)".into();
    }
    let mut local = SYSTEMTIME::default();
    let st = if unsafe { SystemTimeToTzSpecificLocalTime(None, &utc, &mut local) }.is_ok() {
        &local
    } else {
        &utc
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, UNIX_EPOCH};

    fn sample_details() -> NetEventDetails {
        NetEventDetails {
            timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            local_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            local_port: Some(54321),
            remote_addr: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            remote_port: Some(443),
            protocol: Some(6),
            app_path: Some(r"\device\harddiskvolume3\test\app.exe".into()),
            direction: Some(NetDirection::Outbound),
            filter_id: Some(12345),
        }
    }

    #[test]
    fn format_line_contains_all_fields() {
        let line = format_line("BLOCK", &sample_details());
        assert!(line.contains("BLOCK"));
        assert!(line.contains("outbound"));
        assert!(line.contains("TCP"));
        assert!(line.contains("192.168.1.10:54321"));
        assert!(line.contains("1.2.3.4:443"));
        assert!(line.contains("filter=12345"));
        assert!(line.contains(r"app=\device\harddiskvolume3\test\app.exe"));
    }

    #[test]
    fn ipv6_endpoint_brackets_address_when_port_present() {
        use std::net::Ipv6Addr;
        let mut d = sample_details();
        d.local_addr = Some(IpAddr::V6(Ipv6Addr::new(
            0x2603, 0x9001, 0x7cf0, 0x8db0, 0x558f, 0xf8d1, 0xae54, 0x0343,
        )));
        d.local_port = Some(61598);
        d.remote_addr = Some(IpAddr::V6(Ipv6Addr::new(
            0x2603, 0x9001, 0x7cf0, 0x8db0, 0, 0, 0, 1,
        )));
        d.remote_port = Some(53);
        let line = format_line("BLOCK", &d);
        assert!(
            line.contains("[2603:9001:7cf0:8db0:558f:f8d1:ae54:343]:61598"),
            "v6 local endpoint not bracketed: {line}"
        );
        assert!(
            line.contains("[2603:9001:7cf0:8db0::1]:53"),
            "v6 remote endpoint not bracketed: {line}"
        );
    }

    #[test]
    fn unknown_protocol_falls_back_to_proto_n() {
        let mut d = sample_details();
        d.protocol = Some(99);
        let line = format_line("ALLOW", &d);
        assert!(line.contains("proto99"));
    }

    #[test]
    fn missing_fields_emit_dashes() {
        let mut d = sample_details();
        d.local_addr = None;
        d.local_port = None;
        d.remote_addr = None;
        d.remote_port = None;
        d.protocol = None;
        d.direction = None;
        d.filter_id = None;
        d.app_path = None;
        let line = format_line("BLOCK", &d);
        assert!(line.contains("- - app=- - -> -"));
        assert!(line.contains("filter=-"));
    }

    #[test]
    fn resolve_path_uses_explicit_when_set() {
        let p = resolve_path(r"C:\custom\amwall.log");
        assert_eq!(p, PathBuf::from(r"C:\custom\amwall.log"));
    }

    #[test]
    fn resolve_path_trims_whitespace() {
        let p = resolve_path("  C:\\custom\\amwall.log  ");
        assert_eq!(p, PathBuf::from(r"C:\custom\amwall.log"));
    }

    #[test]
    fn bak_path_appends_bak_extension() {
        assert_eq!(
            bak_path(Path::new(r"C:\amwall.log")),
            PathBuf::from(r"C:\amwall.log.bak")
        );
    }

    #[test]
    fn append_disabled_is_noop() {
        let mut w = EventLogWriter::new();
        let s = Settings {
            enable_log: false,
            ..Settings::default()
        };
        w.append(&NetEvent::Allow(sample_details()), &s);
        assert!(w.writer.is_none());
        assert!(w.current_path.is_none());
    }

    #[test]
    fn append_writes_and_rotates() {
        let dir = std::env::temp_dir().join("amwall-event-log-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("rotate.log");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(bak_path(&path));

        let s = Settings {
            enable_log: true,
            log_path: path.to_string_lossy().into_owned(),
            // 1 KB cap — guarantees rotation after a couple of events.
            log_size_limit: 1,
            ..Settings::default()
        };

        let mut w = EventLogWriter::new();
        for _ in 0..50 {
            w.append(&NetEvent::Drop(sample_details()), &s);
        }
        w.close();

        // After 50 lines at ~150 bytes each (~7.5 KB) and a 1 KB
        // cap, the .bak must exist and the live file must be
        // smaller than it would be without rotation.
        assert!(bak_path(&path).exists(), "expected rotated .bak file");
        let live = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        assert!(live > 0, "expected live log to have content");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(bak_path(&path));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn append_skips_allow_when_excluded() {
        let dir = std::env::temp_dir().join("amwall-event-log-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("exclude.log");
        let _ = std::fs::remove_file(&path);

        let s = Settings {
            enable_log: true,
            log_path: path.to_string_lossy().into_owned(),
            exclude_classify_allow: true,
            log_size_limit: 0, // unlimited
            ..Settings::default()
        };

        let mut w = EventLogWriter::new();
        w.append(&NetEvent::Allow(sample_details()), &s);
        w.append(&NetEvent::Drop(sample_details()), &s);
        w.close();

        let body = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(body.contains("BLOCK"), "drop event must be logged");
        assert!(!body.contains("ALLOW"), "allow event must be skipped");

        let _ = std::fs::remove_file(&path);
    }
}

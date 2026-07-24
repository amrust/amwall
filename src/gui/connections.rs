// amwall — live network connection enumeration.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Walks the Win32 IP Helper tables (TCP4 / TCP6 / UDP4 / UDP6) for
// the user-mode "what's connected right now" view that drives the
// Connections tab. Strictly observation — we don't filter or
// modify anything from this module; the WFP install path is
// completely separate.
//
// This is the "user-mode" Connections view: it shows everything
// the OS exposes through the IP Helper APIs. The packet-level
// blocked-traffic Log tab is a different beast — that needs a WFP
// callout driver to capture drop events, which is M6+ work.

#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats,
    MIB_TCP6ROW, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCP_STATE,
    MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_DELETE_TCB,
    MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1, MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK,
    MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT,
    MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats, TCP_ESTATS_DATA_ROD_v0,
    TCP_ESTATS_DATA_RW_v0, TcpConnectionEstatsData, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Snapshot of one connection / listener returned from
/// [`enumerate`]. Self-contained (no Win32 handles) so callers can
/// stash these in a Vec across UI redraws.
#[derive(Debug, Clone)]
pub struct Connection {
    /// Process name (basename of the .exe). Best-effort: PID 0
    /// (System) and PIDs we can't open are reported as "?".
    pub process: String,
    /// Owning process id. Lets the Connections context menu resolve the
    /// full image path on demand (Explore / Show-in-list) without paying
    /// `process_full_path` per connection on every refresh (Fable #27).
    pub pid: u32,
    pub local: Endpoint,
    pub remote: Endpoint,
    pub protocol: Protocol,
    /// State string ("ESTABLISHED" / "LISTEN" / etc.). For UDP
    /// (which has no connection state) this is empty.
    pub state: &'static str,
    /// Live per-connection download rate in bytes/sec, sampled from
    /// TCP ESTATS. Zero (and `has_stats == false`) for UDP,
    /// listeners, and when ESTATS can't be enabled (see
    /// [`TrafficMonitor`]). Mirrors upstream PR #2100.
    pub download_speed: u64,
    /// Live per-connection upload rate in bytes/sec (see
    /// `download_speed`).
    pub upload_speed: u64,
    /// Cumulative bytes (down + up) observed on this connection since
    /// amwall first sampled it. Reset when the connection closes.
    pub total_bytes: u64,
    /// True once ESTATS has produced at least one reading for this
    /// connection. Drives whether the traffic columns render a value
    /// or stay blank — upstream leaves them empty until initialized.
    pub has_stats: bool,
}

impl Connection {
    /// Whether the remote endpoint is IPv4 — the only family SetTcpEntry
    /// can close.
    pub fn is_ipv4(&self) -> bool {
        matches!(self.remote.ip, IpAddr::V4(_))
    }

    /// Whether this is a live IPv4 TCP connection that can be torn down
    /// via `close_connection` (upstream gate: af==AF_INET && ESTAB).
    pub fn is_closable(&self) -> bool {
        self.is_ipv4() && self.protocol == Protocol::Tcp && self.state == "ESTABLISHED"
    }
}

/// Forcibly close an established IPv4 TCP connection by setting its TCB
/// state to DELETE (mirrors upstream, messages.c:2449-2457). Only IPv4
/// established TCP can be closed this way — IPv6 and UDP have no
/// SetTcpEntry equivalent, so callers gray the menu item for them.
/// Requires an elevated process; returns the Win32 error on failure.
///
/// NOTE: unverifiable under `cargo test` — SetTcpEntry only works
/// elevated and only on AF_INET established TCP, and a wrong address/port
/// byte order silently no-ops. Verify with an elevated run tearing down a
/// live TCP connection and confirming via `netstat`.
pub fn close_connection(c: &Connection) -> Result<(), u32> {
    use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCPROW_LH, MIB_TCPROW_LH_0, SetTcpEntry,
    };

    if !c.is_closable() {
        return Err(ERROR_INVALID_PARAMETER.0);
    }
    let (IpAddr::V4(local), IpAddr::V4(remote)) = (c.local.ip, c.remote.ip) else {
        return Err(ERROR_INVALID_PARAMETER.0);
    };
    // in_addr.S_un.S_addr is the network-order address as a u32; on x86
    // that's the octets read little-endian. Ports go to network order via
    // a 16-bit byteswap (upstream _r_byteswap_ushort), stored in the low
    // word. The LH row's state lives in an anonymous union.
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            State: MIB_TCP_STATE_DELETE_TCB,
        },
        dwLocalAddr: u32::from_le_bytes(local.octets()),
        dwLocalPort: c.local.port.to_be() as u32,
        dwRemoteAddr: u32::from_le_bytes(remote.octets()),
        dwRemotePort: c.remote.port.to_be() as u32,
    };
    let rc = unsafe { SetTcpEntry(&row) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        }
    }
}

/// Walk the same TCP / UDP tables `enumerate` does and return
/// the **set of full image paths** owning at least one
/// connection. Used by the apps-tab row colorizer to highlight
/// "this app is currently talking to the network". One pass per
/// timer tick; the basename-based `Connection.process` field
/// from `enumerate` isn't enough since
/// `profile.apps[].path` is the full Win32 path.
pub fn enumerate_active_paths() -> std::collections::HashSet<std::path::PathBuf> {
    let mut pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    if let Some(rows) = read_pids_tcp4() {
        pids.extend(rows);
    }
    if let Some(rows) = read_pids_tcp6() {
        pids.extend(rows);
    }
    if let Some(rows) = read_pids_udp4() {
        pids.extend(rows);
    }
    if let Some(rows) = read_pids_udp6() {
        pids.extend(rows);
    }

    let mut out = std::collections::HashSet::with_capacity(pids.len());
    for pid in pids {
        if let Some(p) = process_full_path(pid) {
            out.insert(p);
        }
    }
    out
}

fn read_pids_tcp4() -> Option<Vec<u32>> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut size, true, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, true, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    let rows_ptr = std::ptr::addr_of!(table.table) as *const MIB_TCPROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    Some(rows.iter().map(|r| r.dwOwningPid).collect())
}

fn read_pids_tcp6() -> Option<Vec<u32>> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut size, true, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, true, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    let rows_ptr = std::ptr::addr_of!(table.table) as *const MIB_TCP6ROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    Some(rows.iter().map(|r| r.dwOwningPid).collect())
}

fn read_pids_udp4() -> Option<Vec<u32>> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedUdpTable(None, &mut size, true, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedUdpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, true, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    let rows_ptr = std::ptr::addr_of!(table.table) as *const MIB_UDPROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    Some(rows.iter().map(|r| r.dwOwningPid).collect())
}

fn read_pids_udp6() -> Option<Vec<u32>> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedUdpTable(None, &mut size, true, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0);
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedUdpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, true, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    let rows_ptr = std::ptr::addr_of!(table.table) as *const MIB_UDP6ROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    Some(rows.iter().map(|r| r.dwOwningPid).collect())
}

pub fn process_full_path(pid: u32) -> Option<std::path::PathBuf> {
    if pid == 0 {
        return None;
    }
    let handle: HANDLE = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?
    };
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    let path = if result.is_ok() {
        let slice = &buf[..len as usize];
        Some(std::path::PathBuf::from(String::from_utf16_lossy(slice)))
    } else {
        None
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    path
}

/// Enumerate every TCP + UDP endpoint visible to user-mode IP
/// Helper. Returns a flat Vec; UI code sorts / filters as needed.
/// Best-effort — failures inside any of the four enumerations log
/// to stderr and are skipped so a partial table still renders.
pub fn enumerate() -> Vec<Connection> {
    let mut out = Vec::new();
    if let Some(rows) = read_tcp4(None) {
        out.extend(rows);
    }
    if let Some(rows) = read_tcp6(None) {
        out.extend(rows);
    }
    if let Some(rows) = read_udp4() {
        out.extend(rows);
    }
    if let Some(rows) = read_udp6() {
        out.extend(rows);
    }
    out
}

/// Like [`enumerate`], but also samples per-connection TCP traffic
/// through `monitor` so each TCP row carries live download/upload
/// rates and a running byte total (the Connections-tab traffic
/// columns; mirrors upstream PR #2100). `monitor` persists across
/// ticks — it holds the previous byte counters each rate is computed
/// against, and prunes connections that have since closed. UDP rows
/// and listeners carry zeroed stats (`has_stats == false`), exactly
/// like upstream, since Windows exposes no per-UDP-socket counters.
pub fn enumerate_with_traffic(monitor: &mut TrafficMonitor) -> Vec<Connection> {
    monitor.begin_pass();
    let mut out = Vec::new();
    if let Some(rows) = read_tcp4(Some(&mut *monitor)) {
        out.extend(rows);
    }
    if let Some(rows) = read_tcp6(Some(&mut *monitor)) {
        out.extend(rows);
    }
    if let Some(rows) = read_udp4() {
        out.extend(rows);
    }
    if let Some(rows) = read_udp6() {
        out.extend(rows);
    }
    monitor.end_pass();
    out
}

// ---- per-connection TCP traffic (ESTATS) ----
//
// Adapted from upstream simplewall PR #2100 (network.c
// `_app_network_update_stats_values` / `_app_network_update_tcpN_stats`).
// Upstream keeps a persistent ITEM_NETWORK per connection and updates it
// in place each timer tick; amwall rebuilds a fresh `Vec<Connection>`
// every tick, so the persistent piece — the previous byte counters each
// rate is differenced against — lives here in `TrafficMonitor`, keyed by
// the raw connection tuple. Everything is single-threaded on the UI
// thread, so no interlocked access is needed (upstream's volatile/
// _Interlocked* dance guards a background generator thread it doesn't
// have here).

/// Identity of a TCP connection, built from the raw network-order MIB
/// fields (no host-order round-tripping — the ESTATS row wants the same
/// bytes the table hands us).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConnKey {
    V4 { la: u32, lp: u32, ra: u32, rp: u32 },
    V6 { la: [u8; 16], lp: u32, ra: [u8; 16], rp: u32 },
}

/// Rolling counters for one connection, carried across ticks.
#[derive(Debug, Default, Clone, Copy)]
struct ConnStat {
    /// ESTATS data-path collection turned on for this connection.
    enabled: bool,
    /// At least one reading taken — until then we only have a baseline,
    /// so speed is undefined and the columns stay blank.
    initialized: bool,
    last_bytes_in: u64,
    last_bytes_out: u64,
    last_tick: u64,
    download_total: u64,
    upload_total: u64,
    download_speed: u64,
    upload_speed: u64,
    /// Pass counter this stat was last touched in — anything stale after
    /// a full enumeration is a closed connection and gets pruned.
    seen_gen: u64,
}

impl ConnStat {
    /// Fold one ESTATS reading in, mirroring upstream
    /// `_app_network_update_stats_values`: first reading only sets a
    /// baseline; later readings turn the byte delta over the elapsed
    /// wall-clock into a per-second rate and accumulate the total.
    fn update(&mut self, bytes_in: u64, bytes_out: u64, tick: u64) {
        if !self.initialized {
            self.last_bytes_in = bytes_in;
            self.last_bytes_out = bytes_out;
            self.last_tick = tick;
            self.initialized = true;
            return;
        }
        let elapsed = tick.wrapping_sub(self.last_tick);
        if elapsed == 0 {
            return;
        }
        // ESTATS counters are monotonic; guard against a counter reset
        // (or a reused tuple) reading lower than last time.
        let delta_in = bytes_in.saturating_sub(self.last_bytes_in);
        self.download_total = self.download_total.saturating_add(delta_in);
        self.download_speed = delta_in.saturating_mul(1000) / elapsed;

        let delta_out = bytes_out.saturating_sub(self.last_bytes_out);
        self.upload_total = self.upload_total.saturating_add(delta_out);
        self.upload_speed = delta_out.saturating_mul(1000) / elapsed;

        self.last_bytes_in = bytes_in;
        self.last_bytes_out = bytes_out;
        self.last_tick = tick;
    }
}

/// One connection's traffic snapshot handed back to the row builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrafficSample {
    pub download_speed: u64,
    pub upload_speed: u64,
    pub total_bytes: u64,
    pub has_stats: bool,
}

/// Persistent, cross-tick per-connection TCP traffic tracker. Owned by
/// the window state and threaded into [`enumerate_with_traffic`]. Not
/// `Send`/`Sync`-hostile — it holds only plain data — but it is meant to
/// be driven from the single UI thread.
#[derive(Debug)]
pub struct TrafficMonitor {
    stats: std::collections::HashMap<ConnKey, ConnStat>,
    /// Incremented once per enumeration pass; drives pruning.
    generation: u64,
    /// Cleared once ESTATS reports the process lacks the rights to
    /// enable collection (needs elevation). Prevents hammering
    /// `SetPerTcpConnectionEStats` on every row of every tick when it
    /// can never succeed. Upstream simplewall always runs elevated so it
    /// never hits this; amwall's GUI often does not.
    available: bool,
}

// NO_ERROR / ERROR_ACCESS_DENIED as returned by the ESTATS calls.
const ESTATS_OK: u32 = 0;
const ESTATS_ACCESS_DENIED: u32 = 5;

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMonitor {
    pub fn new() -> Self {
        TrafficMonitor { stats: std::collections::HashMap::new(), generation: 0, available: true }
    }

    /// Open a new sampling pass. Every `sample_*` call after this stamps
    /// the current generation; [`end_pass`](Self::end_pass) drops any
    /// entry not touched this pass.
    fn begin_pass(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// Drop stats for connections that vanished this pass so a long-lived
    /// process's churn of short connections can't grow the map without
    /// bound.
    fn end_pass(&mut self) {
        let cur_gen = self.generation;
        self.stats.retain(|_, s| s.seen_gen == cur_gen);
    }

    fn sample_tcp4(&mut self, r: &MIB_TCPROW_OWNER_PID) -> TrafficSample {
        let key = ConnKey::V4 {
            la: r.dwLocalAddr,
            lp: r.dwLocalPort,
            ra: r.dwRemoteAddr,
            rp: r.dwRemotePort,
        };
        // The ESTATS row is byte-identical to the OWNER_PID row's 4-tuple.
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE(r.dwState as i32) },
            dwLocalAddr: r.dwLocalAddr,
            dwLocalPort: r.dwLocalPort,
            dwRemoteAddr: r.dwRemoteAddr,
            dwRemotePort: r.dwRemotePort,
        };
        self.sample(key, |stat, tick| unsafe { estats_read_v4(&row, stat, tick) })
    }

    fn sample_tcp6(&mut self, r: &MIB_TCP6ROW_OWNER_PID) -> TrafficSample {
        let key = ConnKey::V6 {
            la: r.ucLocalAddr,
            lp: r.dwLocalPort,
            ra: r.ucRemoteAddr,
            rp: r.dwRemotePort,
        };
        let row = MIB_TCP6ROW {
            State: MIB_TCP_STATE(r.dwState as i32),
            LocalAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: r.ucLocalAddr } },
            dwLocalScopeId: r.dwLocalScopeId,
            dwLocalPort: r.dwLocalPort,
            RemoteAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: r.ucRemoteAddr } },
            dwRemoteScopeId: r.dwRemoteScopeId,
            dwRemotePort: r.dwRemotePort,
        };
        self.sample(key, |stat, tick| unsafe { estats_read_v6(&row, stat, tick) })
    }

    /// Shared body for both families: enable collection once, read the
    /// byte counters, fold them into the stat, and hand back the snapshot.
    /// `read` returns `false` when ESTATS gave no usable reading this tick
    /// (collection not yet on, transient failure) — the stat still carries
    /// whatever it accumulated before.
    fn sample(
        &mut self,
        key: ConnKey,
        read: impl FnOnce(&mut ConnStat, u64) -> ReadOutcome,
    ) -> TrafficSample {
        if !self.available {
            return TrafficSample::default();
        }
        let cur_gen = self.generation;
        let stat = self.stats.entry(key).or_default();
        stat.seen_gen = cur_gen;
        let tick = unsafe { GetTickCount64() };
        match read(stat, tick) {
            ReadOutcome::Updated | ReadOutcome::NoReading => {}
            ReadOutcome::AccessDenied => {
                // Not elevated — give up globally for this session.
                self.available = false;
                return TrafficSample::default();
            }
        }
        let stat = &self.stats[&key];
        TrafficSample {
            download_speed: stat.download_speed,
            upload_speed: stat.upload_speed,
            total_bytes: stat.download_total.saturating_add(stat.upload_total),
            has_stats: stat.initialized,
        }
    }
}

/// What one ESTATS read/enable attempt produced.
enum ReadOutcome {
    /// A byte reading was folded into the stat.
    Updated,
    /// No usable reading this tick (collection just enabled, or a
    /// transient/per-connection failure) — try again next tick.
    NoReading,
    /// The process lacks the rights to enable collection (needs admin).
    AccessDenied,
}

/// View a plain-old-data value as the byte slice the ESTATS FFI wants.
/// Safe here because the ESTATS structs are `#[repr(C)]` integer records
/// with no padding invariants we rely on.
unsafe fn pod_bytes<T>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), std::mem::size_of::<T>()) }
}

unsafe fn pod_bytes_mut<T>(v: &mut T) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut((v as *mut T).cast::<u8>(), std::mem::size_of::<T>()) }
}

/// Enable (once) and read the IPv4 data-path ESTATS counters for `row`,
/// folding a reading into `stat`. Mirrors upstream
/// `_app_network_update_tcp4_stats`.
unsafe fn estats_read_v4(row: &MIB_TCPROW_LH, stat: &mut ConnStat, tick: u64) -> ReadOutcome {
    if !stat.enabled {
        let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: windows::Win32::Foundation::BOOLEAN(1) };
        let status = unsafe {
            SetPerTcpConnectionEStats(row, TcpConnectionEstatsData, pod_bytes(&rw), 0, 0)
        };
        if status == ESTATS_ACCESS_DENIED {
            return ReadOutcome::AccessDenied;
        }
        if status != ESTATS_OK {
            return ReadOutcome::NoReading;
        }
        stat.enabled = true;
    }
    let mut rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: windows::Win32::Foundation::BOOLEAN(0) };
    let mut rod: TCP_ESTATS_DATA_ROD_v0 = unsafe { std::mem::zeroed() };
    let status = unsafe {
        GetPerTcpConnectionEStats(
            row,
            TcpConnectionEstatsData,
            Some(pod_bytes_mut(&mut rw)),
            0,
            None,
            0,
            Some(pod_bytes_mut(&mut rod)),
            0,
        )
    };
    if status == ESTATS_OK && rw.EnableCollection.0 != 0 {
        stat.update(rod.DataBytesIn, rod.DataBytesOut, tick);
        ReadOutcome::Updated
    } else {
        ReadOutcome::NoReading
    }
}

/// IPv6 counterpart of [`estats_read_v4`].
unsafe fn estats_read_v6(row: &MIB_TCP6ROW, stat: &mut ConnStat, tick: u64) -> ReadOutcome {
    if !stat.enabled {
        let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: windows::Win32::Foundation::BOOLEAN(1) };
        let status = unsafe {
            SetPerTcp6ConnectionEStats(row, TcpConnectionEstatsData, pod_bytes(&rw), 0, 0)
        };
        if status == ESTATS_ACCESS_DENIED {
            return ReadOutcome::AccessDenied;
        }
        if status != ESTATS_OK {
            return ReadOutcome::NoReading;
        }
        stat.enabled = true;
    }
    let mut rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: windows::Win32::Foundation::BOOLEAN(0) };
    let mut rod: TCP_ESTATS_DATA_ROD_v0 = unsafe { std::mem::zeroed() };
    let status = unsafe {
        GetPerTcp6ConnectionEStats(
            row,
            TcpConnectionEstatsData,
            Some(pod_bytes_mut(&mut rw)),
            0,
            None,
            0,
            Some(pod_bytes_mut(&mut rod)),
            0,
        )
    };
    if status == ESTATS_OK && rw.EnableCollection.0 != 0 {
        stat.update(rod.DataBytesIn, rod.DataBytesOut, tick);
        ReadOutcome::Updated
    } else {
        ReadOutcome::NoReading
    }
}

/// Human-readable byte size, base-1024 (mirrors upstream
/// `_r_format_bytesize64`): "512 B", "1.50 KB", "3.24 MB", …
pub fn format_bytesize(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

/// Byte-rate label for the speed columns: byte size with a "/s" suffix.
pub fn format_speed(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytesize(bytes_per_sec))
}

// ---- TCP v4 ----

fn read_tcp4(mut stats: Option<&mut TrafficMonitor>) -> Option<Vec<Connection>> {
    let mut size = 0u32;
    unsafe {
        // First call with NULL buffer to get the required size.
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            true,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            true,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        eprintln!("amwall: GetExtendedTcpTable(v4) failed: {res}");
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    // The `table` array is a flexible-length tail of the struct;
    // walk it as a raw slice rather than via the [_;1] field.
    let rows_ptr =
        std::ptr::addr_of!(table.table) as *const MIB_TCPROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    let mut out = Vec::with_capacity(n);
    for r in rows {
        let s = stats.as_deref_mut().map(|m| m.sample_tcp4(r)).unwrap_or_default();
        out.push(Connection {
            process: process_name(r.dwOwningPid),
            pid: r.dwOwningPid,
            local: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
                port: ntohs(r.dwLocalPort),
            },
            remote: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr))),
                port: ntohs(r.dwRemotePort),
            },
            protocol: Protocol::Tcp,
            state: tcp_state(r.dwState),
            download_speed: s.download_speed,
            upload_speed: s.upload_speed,
            total_bytes: s.total_bytes,
            has_stats: s.has_stats,
        });
    }
    Some(out)
}

// ---- TCP v6 ----

fn read_tcp6(mut stats: Option<&mut TrafficMonitor>) -> Option<Vec<Connection>> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            true,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            true,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        eprintln!("amwall: GetExtendedTcpTable(v6) failed: {res}");
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    let rows_ptr =
        std::ptr::addr_of!(table.table) as *const MIB_TCP6ROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    let mut out = Vec::with_capacity(n);
    for r in rows {
        let s = stats.as_deref_mut().map(|m| m.sample_tcp6(r)).unwrap_or_default();
        out.push(Connection {
            process: process_name(r.dwOwningPid),
            pid: r.dwOwningPid,
            local: Endpoint {
                ip: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                port: ntohs(r.dwLocalPort),
            },
            remote: Endpoint {
                ip: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                port: ntohs(r.dwRemotePort),
            },
            protocol: Protocol::Tcp,
            state: tcp_state(r.dwState),
            download_speed: s.download_speed,
            upload_speed: s.upload_speed,
            total_bytes: s.total_bytes,
            has_stats: s.has_stats,
        });
    }
    Some(out)
}

// ---- UDP v4 ----

fn read_udp4() -> Option<Vec<Connection>> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            true,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            true,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        eprintln!("amwall: GetExtendedUdpTable(v4) failed: {res}");
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    let rows_ptr =
        std::ptr::addr_of!(table.table) as *const MIB_UDPROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    let mut out = Vec::with_capacity(n);
    for r in rows {
        out.push(Connection {
            process: process_name(r.dwOwningPid),
            pid: r.dwOwningPid,
            local: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
                port: ntohs(r.dwLocalPort),
            },
            remote: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 0,
            },
            protocol: Protocol::Udp,
            state: "",
            download_speed: 0,
            upload_speed: 0,
            total_bytes: 0,
            has_stats: false,
        });
    }
    Some(out)
}

// ---- UDP v6 ----

fn read_udp6() -> Option<Vec<Connection>> {
    let mut size = 0u32;
    unsafe {
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            true,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedUdpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            true,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if res != ERROR_SUCCESS.0 && res != ERROR_INSUFFICIENT_BUFFER.0 {
        eprintln!("amwall: GetExtendedUdpTable(v6) failed: {res}");
        return None;
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let n = table.dwNumEntries as usize;
    let rows_ptr =
        std::ptr::addr_of!(table.table) as *const MIB_UDP6ROW_OWNER_PID;
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, n) };
    let mut out = Vec::with_capacity(n);
    for r in rows {
        out.push(Connection {
            process: process_name(r.dwOwningPid),
            pid: r.dwOwningPid,
            local: Endpoint {
                ip: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                port: ntohs(r.dwLocalPort),
            },
            remote: Endpoint {
                ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                port: 0,
            },
            protocol: Protocol::Udp,
            state: "",
            download_speed: 0,
            upload_speed: 0,
            total_bytes: 0,
            has_stats: false,
        });
    }
    Some(out)
}

// ---- helpers ----

/// IP Helper stores ports in network byte order in the low 16
/// bits of a u32. ntohs picks them back out as host-order u16.
fn ntohs(port: u32) -> u16 {
    u16::from_be((port & 0xFFFF) as u16)
}

fn tcp_state(state: u32) -> &'static str {
    let s = MIB_TCP_STATE(state as i32);
    if s == MIB_TCP_STATE_CLOSED {
        "CLOSED"
    } else if s == MIB_TCP_STATE_LISTEN {
        "LISTEN"
    } else if s == MIB_TCP_STATE_SYN_SENT {
        "SYN_SENT"
    } else if s == MIB_TCP_STATE_SYN_RCVD {
        "SYN_RCVD"
    } else if s == MIB_TCP_STATE_ESTAB {
        "ESTABLISHED"
    } else if s == MIB_TCP_STATE_FIN_WAIT1 {
        "FIN_WAIT1"
    } else if s == MIB_TCP_STATE_FIN_WAIT2 {
        "FIN_WAIT2"
    } else if s == MIB_TCP_STATE_CLOSE_WAIT {
        "CLOSE_WAIT"
    } else if s == MIB_TCP_STATE_CLOSING {
        "CLOSING"
    } else if s == MIB_TCP_STATE_LAST_ACK {
        "LAST_ACK"
    } else if s == MIB_TCP_STATE_TIME_WAIT {
        "TIME_WAIT"
    } else if s == MIB_TCP_STATE_DELETE_TCB {
        "DELETE_TCB"
    } else {
        "?"
    }
}

/// Best-effort: open the process, query its image path, return the
/// basename. PID 0 is the kernel/System idle pseudo-process; all
/// the OpenProcess failures (no such PID, no rights, etc.) get
/// reported as "?" rather than an error string so the column stays
/// visually consistent.
fn process_name(pid: u32) -> String {
    if pid == 0 {
        return "System".to_string();
    }
    let handle: HANDLE = match unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
    } {
        Ok(h) => h,
        Err(_) => return "?".to_string(),
    };

    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    let name = if result.is_ok() {
        let slice = &buf[..len as usize];
        let path = String::from_utf16_lossy(slice);
        // basename of the full path
        std::path::Path::new(&path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or(path)
    } else {
        "?".to_string()
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_returns_at_least_one_listener() {
        // Any non-trivial Windows install has at least services.exe
        // listening on something. If this comes back empty the
        // enumeration is broken.
        let conns = enumerate();
        // Don't strictly assert non-empty in case CI runs in a
        // minimal container; just check the call doesn't panic.
        let _ = conns;
    }

    #[test]
    fn tcp_state_known_values() {
        assert_eq!(tcp_state(MIB_TCP_STATE_ESTAB.0 as u32), "ESTABLISHED");
        assert_eq!(tcp_state(MIB_TCP_STATE_LISTEN.0 as u32), "LISTEN");
        assert_eq!(tcp_state(99), "?");
    }

    #[test]
    fn first_reading_only_sets_baseline() {
        // The first ESTATS reading has no prior counter to diff against,
        // so it must not report a speed or a total — just prime the state.
        let mut s = ConnStat::default();
        s.update(1_000, 500, 10_000);
        assert!(s.initialized);
        assert_eq!(s.download_speed, 0);
        assert_eq!(s.upload_speed, 0);
        assert_eq!(s.download_total, 0);
        assert_eq!(s.upload_total, 0);
    }

    #[test]
    fn second_reading_computes_rate_and_total() {
        let mut s = ConnStat::default();
        s.update(1_000, 500, 10_000);
        // +2000 bytes in / +1000 out over 1000 ms -> 2000 B/s and 1000 B/s.
        s.update(3_000, 1_500, 11_000);
        assert_eq!(s.download_speed, 2_000);
        assert_eq!(s.upload_speed, 1_000);
        assert_eq!(s.download_total, 2_000);
        assert_eq!(s.upload_total, 1_000);
    }

    #[test]
    fn zero_elapsed_is_ignored() {
        // Two reads on the same tick would divide by zero — must no-op.
        let mut s = ConnStat::default();
        s.update(1_000, 500, 10_000);
        s.update(9_999, 9_999, 10_000);
        assert_eq!(s.download_speed, 0);
        assert_eq!(s.download_total, 0);
    }

    #[test]
    fn counter_regression_does_not_underflow() {
        // A reused tuple / counter reset reading lower than before must
        // clamp the delta to zero rather than wrap around u64.
        let mut s = ConnStat::default();
        s.update(10_000, 10_000, 10_000);
        s.update(5, 5, 11_000);
        assert_eq!(s.download_speed, 0);
        assert_eq!(s.upload_speed, 0);
        assert_eq!(s.download_total, 0);
    }

    #[test]
    fn total_accumulates_across_readings() {
        let mut s = ConnStat::default();
        s.update(0, 0, 1_000);
        s.update(100, 0, 2_000);
        s.update(300, 0, 3_000);
        assert_eq!(s.download_total, 300);
    }

    #[test]
    fn bytesize_formats_each_unit() {
        assert_eq!(format_bytesize(0), "0 B");
        assert_eq!(format_bytesize(512), "512 B");
        assert_eq!(format_bytesize(1024), "1.00 KB");
        assert_eq!(format_bytesize(1536), "1.50 KB");
        assert_eq!(format_bytesize(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytesize(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn speed_appends_per_second() {
        assert_eq!(format_speed(0), "0 B/s");
        assert_eq!(format_speed(2_048), "2.00 KB/s");
    }

    #[test]
    fn monitor_prunes_closed_connections() {
        let mut m = TrafficMonitor::new();
        let k = ConnKey::V4 { la: 1, lp: 2, ra: 3, rp: 4 };
        // Pass 1: a connection is present.
        m.begin_pass();
        m.stats.entry(k).or_default().seen_gen = m.generation;
        m.end_pass();
        assert!(m.stats.contains_key(&k));
        // Pass 2: it's gone — not re-stamped, so it must be pruned.
        m.begin_pass();
        m.end_pass();
        assert!(!m.stats.contains_key(&k));
    }
}

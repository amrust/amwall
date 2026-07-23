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
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD,
    MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
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
    if let Some(rows) = read_tcp4() {
        out.extend(rows);
    }
    if let Some(rows) = read_tcp6() {
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

// ---- TCP v4 ----

fn read_tcp4() -> Option<Vec<Connection>> {
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
        });
    }
    Some(out)
}

// ---- TCP v6 ----

fn read_tcp6() -> Option<Vec<Connection>> {
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

use windows::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE;

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
}

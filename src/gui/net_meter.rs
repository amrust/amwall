// amwall — per-process network throughput meter (ETW).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// TCP ESTATS (see `connections.rs`) only exposes per-connection TCP byte
// counters — so it misses UDP entirely, and a µTP/UDP torrent reads far
// below its real speed. This meter closes that gap the only way Windows
// allows: a real-time ETW trace of the `Microsoft-Windows-Kernel-Network`
// provider, which reports EVERY TCP and UDP datagram with the owning PID
// and byte count (the same source Task Manager / Resource Monitor use for
// their per-process network figures).
//
// This is net-new relative to upstream simplewall (whose meter is
// TCP-ESTATS-only, verified against its current source). It only drives
// the Apps tab's per-app Speed columns; the Connections tab keeps its
// per-connection ESTATS view.
//
// Requires elevation (a real-time trace session needs admin). When the
// session can't start, `start` returns `None` and callers fall back to
// blank speeds — exactly the ESTATS graceful-degradation path.

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW, TRACE_LEVEL_VERBOSE,
    WNODE_FLAG_TRACED_GUID, CONTROLTRACE_HANDLE,
};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::core::{GUID, PCWSTR, PWSTR};

/// `Microsoft-Windows-Kernel-Network` provider.
const PROVIDER_GUID: GUID = GUID::from_u128(0x7dd4_2a49_5329_4832_8dfd_43d9_7915_3a88);

/// Private real-time session name.
const SESSION_NAME: &str = "amwall-netmeter";

// Kernel-Network data-event ids. Payload begins `{u32 pid, u32 size}`,
// then for IPv4 `{u32 daddr, u32 saddr, u16 dport, u16 sport}` and for
// IPv6 `{u8[16] daddr, u8[16] saddr, u16 dport, u16 sport}` — all in
// network byte order.
/// Received a datagram (download): TCP v4/v6 recv, UDP v4/v6 recv.
const RECV_IDS: [u16; 4] = [11, 27, 43, 59];
/// Sent a datagram (upload): TCP v4/v6 send, UDP v4/v6 send.
const SEND_IDS: [u16; 4] = [10, 26, 42, 58];
/// UDP (rather than TCP) data events.
const UDP_IDS: [u16; 4] = [42, 43, 58, 59];
/// IPv6 (rather than IPv4) data events — their addresses are 16 bytes,
/// so the port fields sit at a larger offset.
const V6_IDS: [u16; 4] = [26, 27, 58, 59];

/// Key identifying one connection/socket for per-endpoint metering:
/// `(is_udp, local_port)`. The local (ephemeral) port uniquely identifies
/// an outbound TCP connection, and cleanly aggregates a UDP socket's
/// datagrams across all its peers (UDP is connectionless, so the OS
/// connection table only lists the local bind anyway). `is_udp`
/// separates a TCP and a UDP socket that happen to share a port number.
pub type EndpointKey = (bool, u16);

/// Per-endpoint throughput handed to the Connections tab.
#[derive(Debug, Default, Clone, Copy)]
pub struct EndpointTraffic {
    pub download: u64,
    pub upload: u64,
    pub total: u64,
}

/// Cumulative byte counters, shared between the ETW consumer thread
/// (which adds to them from the callback) and the UI thread (which
/// snapshots them via [`NetMeter::rates`] / [`NetMeter::conn_rates`]).
#[derive(Default)]
struct Counters {
    /// pid -> (bytes received, bytes sent) since session start. Drives
    /// the Apps tab's per-process Speed columns.
    pids: Mutex<HashMap<u32, (u64, u64)>>,
    /// (is_udp, local_port) -> (bytes received, bytes sent). Drives the
    /// Connections tab's per-connection Speed columns (TCP + UDP).
    endpoints: Mutex<HashMap<EndpointKey, (u64, u64)>>,
}

/// A running per-process network meter. Owns the trace session and the
/// consumer thread; stops both on drop.
pub struct NetMeter {
    counters: Arc<Counters>,
    /// Session handle from `StartTraceW`, as a raw u64 (the handle
    /// newtype isn't `Send`; we re-wrap it for the STOP call).
    session: u64,
    consumer: Option<std::thread::JoinHandle<()>>,
    /// Previous per-PID snapshot + tick, for turning deltas into rates.
    last_pids: HashMap<u32, (u64, u64)>,
    last_pids_tick: u64,
    /// Previous per-endpoint snapshot + tick (separate baseline: the two
    /// rate readers run on different tabs at different times).
    last_endpoints: HashMap<EndpointKey, (u64, u64)>,
    last_endpoints_tick: u64,
}

/// What a Kernel-Network data-event id tells us, derived purely from the
/// id. Pulled out of the callback so the fragile bits — which ids we
/// meter, send-vs-recv, TCP-vs-UDP, and the payload offset of the LOCAL
/// port — are unit-testable (`classify_event_table`); a wrong offset here
/// would silently mis-key every UDP row and the gate triad couldn't see
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventKind {
    /// True = a received datagram (download); false = sent (upload).
    is_recv: bool,
    /// True = UDP, false = TCP.
    is_udp: bool,
    /// Byte offset of the LOCAL port in the payload: the source port on a
    /// send, the destination port on a receive. IPv6's 16-byte addresses
    /// push it back vs IPv4. (Network byte order at that offset.)
    local_port_offset: usize,
}

/// Classify a data-event id, or `None` for ids we don't meter
/// (connect/disconnect/retransmit/... and everything non-network).
fn classify_event(id: u16) -> Option<EventKind> {
    let is_recv = RECV_IDS.contains(&id);
    let is_send = SEND_IDS.contains(&id);
    if !is_recv && !is_send {
        return None;
    }
    let is_v6 = V6_IDS.contains(&id);
    let local_port_offset = match (is_send, is_v6) {
        (true, false) => 18,  // sport, IPv4
        (true, true) => 42,   // sport, IPv6
        (false, false) => 16, // dport, IPv4
        (false, true) => 40,  // dport, IPv6
    };
    Some(EventKind { is_recv, is_udp: UDP_IDS.contains(&id), local_port_offset })
}

/// The ETW real-time callback. Runs on the consumer thread for every
/// event the enabled provider emits. Adds the datagram's byte count to
/// its owning PID's and local endpoint's running totals. The owning PID
/// comes from the event PAYLOAD (`UserData[0..4]`), not
/// `EventHeader.ProcessId` — kernel network events are logged in
/// arbitrary thread context, so the header PID is unreliable; the payload
/// PID is the socket owner.
unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = unsafe { &*record };
    let Some(kind) = classify_event(rec.EventHeader.EventDescriptor.Id) else {
        return;
    };
    if rec.UserData.is_null() || rec.UserDataLength < 8 {
        return;
    }
    if rec.UserContext.is_null() {
        return;
    }
    let data =
        unsafe { std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize) };
    let pid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
    // System-idle / kernel PID 0 is noise for a per-app view.
    if pid == 0 {
        return;
    }
    let counters = unsafe { &*(rec.UserContext as *const Counters) };

    // Per-process totals (Apps tab).
    if let Ok(mut map) = counters.pids.lock() {
        let entry = map.entry(pid).or_insert((0, 0));
        if kind.is_recv {
            entry.0 = entry.0.saturating_add(size);
        } else {
            entry.1 = entry.1.saturating_add(size);
        }
    }

    // Per-endpoint totals (Connections tab), keyed by (is_udp, local port).
    let port_off = kind.local_port_offset;
    if data.len() >= port_off + 2 {
        let local_port = u16::from_be_bytes([data[port_off], data[port_off + 1]]);
        if local_port != 0 {
            let key = (kind.is_udp, local_port);
            if let Ok(mut map) = counters.endpoints.lock() {
                let entry = map.entry(key).or_insert((0, 0));
                if kind.is_recv {
                    entry.0 = entry.0.saturating_add(size);
                } else {
                    entry.1 = entry.1.saturating_add(size);
                }
            }
        }
    }
}

/// Build a heap buffer holding an `EVENT_TRACE_PROPERTIES` followed by
/// space for the trailing logger-name string (which `StartTraceW` /
/// `ControlTraceW` copy in at `LoggerNameOffset`). Returns the buffer;
/// the caller sets the mode-specific fields.
fn make_properties_buffer() -> Vec<u8> {
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    // Room for the session name (and a would-be log-file name) as WCHARs.
    let total = props_size + 2 * (SESSION_NAME.len() + 1) * 2 + 16;
    let mut buf = vec![0u8; total];
    // SAFETY: buf is zeroed and large enough for the header.
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1; // QPC timestamps
        (*props).LoggerNameOffset = props_size as u32;
    }
    buf
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

impl NetMeter {
    /// Start the trace session, enable the provider, and spawn the
    /// consumer thread. Returns `None` (with a note on stderr) if any
    /// step fails — most commonly because the process isn't elevated.
    pub fn start() -> Option<NetMeter> {
        let counters = Arc::new(Counters::default());
        let name_w = wide(SESSION_NAME);

        // Start (retrying once past a leftover session from a prior crash).
        let mut props = make_properties_buffer();
        set_realtime_mode(&mut props);
        let mut session = CONTROLTRACE_HANDLE::default();
        let mut rc = unsafe {
            StartTraceW(&mut session, PCWSTR(name_w.as_ptr()), props.as_mut_ptr() as *mut _)
        };
        if rc == ERROR_ALREADY_EXISTS {
            let mut stop = make_properties_buffer();
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(name_w.as_ptr()),
                    stop.as_mut_ptr() as *mut _,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            props = make_properties_buffer();
            set_realtime_mode(&mut props);
            session = CONTROLTRACE_HANDLE::default();
            rc = unsafe {
                StartTraceW(&mut session, PCWSTR(name_w.as_ptr()), props.as_mut_ptr() as *mut _)
            };
        }
        if rc != ERROR_SUCCESS {
            eprintln!("amwall: net meter StartTrace failed: {} (needs elevation)", rc.0);
            return None;
        }

        // Enable the Kernel-Network provider on the session (all keywords;
        // the callback filters by event id).
        let rc = unsafe {
            EnableTraceEx2(
                session,
                &PROVIDER_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                u64::MAX,
                0,
                0,
                None,
            )
        };
        if rc != ERROR_SUCCESS {
            eprintln!("amwall: net meter EnableTraceEx2 failed: {}", rc.0);
            stop_session(session.Value, &name_w);
            return None;
        }

        // Consumer thread: OpenTrace + the blocking ProcessTrace loop.
        let acc = counters.clone();
        let consumer = match std::thread::Builder::new()
            .name("amwall-netmeter".into())
            .spawn(move || run_consumer(acc))
        {
            Ok(h) => h,
            Err(_) => {
                stop_session(session.Value, &name_w);
                return None;
            }
        };

        let now = unsafe { GetTickCount64() };
        Some(NetMeter {
            counters,
            session: session.Value,
            consumer: Some(consumer),
            last_pids: HashMap::new(),
            last_pids_tick: now,
            last_endpoints: HashMap::new(),
            last_endpoints_tick: now,
        })
    }

    /// Snapshot the cumulative counters and return each PID's throughput
    /// in bytes/sec (received, sent) since the previous call. The first
    /// call only primes the baseline and returns empty.
    pub fn rates(&mut self) -> HashMap<u32, (u64, u64)> {
        let now = unsafe { GetTickCount64() };
        let snapshot: HashMap<u32, (u64, u64)> = match self.counters.pids.lock() {
            Ok(map) => map.clone(),
            Err(_) => return HashMap::new(),
        };
        let elapsed = now.wrapping_sub(self.last_pids_tick);
        let mut out = HashMap::new();
        if elapsed > 0 && !self.last_pids.is_empty() {
            for (&pid, &(recv, sent)) in &snapshot {
                let (prev_recv, prev_sent) = self.last_pids.get(&pid).copied().unwrap_or((0, 0));
                let d_recv = recv.saturating_sub(prev_recv);
                let d_sent = sent.saturating_sub(prev_sent);
                if d_recv == 0 && d_sent == 0 {
                    continue;
                }
                out.insert(
                    pid,
                    (d_recv.saturating_mul(1000) / elapsed, d_sent.saturating_mul(1000) / elapsed),
                );
            }
        }
        self.last_pids = snapshot;
        self.last_pids_tick = now;
        out
    }

    /// Per-endpoint throughput (download/upload rate + cumulative total)
    /// keyed by `(is_udp, local_port)`, since the previous call. Covers
    /// both TCP and UDP — this is what lets the Connections tab show UDP
    /// speed that ESTATS could never provide. First call primes only.
    pub fn conn_rates(&mut self) -> HashMap<EndpointKey, EndpointTraffic> {
        let now = unsafe { GetTickCount64() };
        let snapshot: HashMap<EndpointKey, (u64, u64)> = match self.counters.endpoints.lock() {
            Ok(map) => map.clone(),
            Err(_) => return HashMap::new(),
        };
        let elapsed = now.wrapping_sub(self.last_endpoints_tick);
        let mut out = HashMap::new();
        if elapsed > 0 && !self.last_endpoints.is_empty() {
            for (&key, &(recv, sent)) in &snapshot {
                let (prev_recv, prev_sent) = self.last_endpoints.get(&key).copied().unwrap_or((0, 0));
                let d_recv = recv.saturating_sub(prev_recv);
                let d_sent = sent.saturating_sub(prev_sent);
                out.insert(
                    key,
                    EndpointTraffic {
                        download: d_recv.saturating_mul(1000) / elapsed,
                        upload: d_sent.saturating_mul(1000) / elapsed,
                        total: recv.saturating_add(sent),
                    },
                );
            }
        }
        self.last_endpoints = snapshot;
        self.last_endpoints_tick = now;
        out
    }
}

/// Set the real-time-logging fields on a freshly-built properties buffer.
fn set_realtime_mode(buf: &mut [u8]) {
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    }
}

/// Stop a session by handle + name. Idempotent enough for teardown.
fn stop_session(session_value: u64, name_w: &[u16]) {
    let mut stop = make_properties_buffer();
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE { Value: session_value },
            PCWSTR(name_w.as_ptr()),
            stop.as_mut_ptr() as *mut _,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Consumer thread body: open the real-time trace and pump events until
/// the session is stopped (which makes `ProcessTrace` return). Holds the
/// `Arc<Counters>` alive for the whole pump so the callback's
/// `UserContext` pointer stays valid.
fn run_consumer(acc: Arc<Counters>) {
    let mut name_w = wide(SESSION_NAME);
    // SAFETY: zeroed EVENT_TRACE_LOGFILEW is a valid "empty" consumer.
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    logfile.LoggerName = PWSTR(name_w.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(on_event);
    // The callback reads this back as EVENT_RECORD.UserContext.
    logfile.Context = Arc::as_ptr(&acc) as *mut c_void;

    let handle = unsafe { OpenTraceW(&mut logfile) };
    // INVALID_PROCESSTRACE_HANDLE is all-ones on 64-bit (and the low-32
    // all-ones form on 32-bit); either means OpenTrace failed.
    if handle.Value == u64::MAX || handle.Value == 0x0000_0000_ffff_ffff {
        eprintln!("amwall: net meter OpenTrace failed");
        return;
    }
    // Blocks until the session stops; return value is best-effort.
    unsafe {
        let _ = ProcessTrace(&[handle], None, None);
        let _ = CloseTrace(handle);
    }
    // Keep the accumulator alive until the pump (and thus the callback)
    // has definitely stopped.
    drop(acc);
}

impl Drop for NetMeter {
    fn drop(&mut self) {
        // Stopping the session makes the consumer's ProcessTrace return.
        let name_w = wide(SESSION_NAME);
        stop_session(self.session, &name_w);
        if let Some(h) = self.consumer.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_event, EventKind};

    /// Pin the full id → (direction, protocol, local-port offset) table.
    /// These offsets are read straight out of raw ETW payloads, so a
    /// silent drift would mis-key every row with no compile-time warning.
    #[test]
    fn classify_event_table() {
        // (id, is_recv, is_udp, local_port_offset)
        let cases = [
            (10u16, false, false, 18), // TCP v4 send  -> sport @18
            (11, true, false, 16),     // TCP v4 recv  -> dport @16
            (26, false, false, 42),    // TCP v6 send  -> sport @42
            (27, true, false, 40),     // TCP v6 recv  -> dport @40
            (42, false, true, 18),     // UDP v4 send  -> sport @18
            (43, true, true, 16),      // UDP v4 recv  -> dport @16
            (58, false, true, 42),     // UDP v6 send  -> sport @42
            (59, true, true, 40),      // UDP v6 recv  -> dport @40
        ];
        for (id, is_recv, is_udp, off) in cases {
            assert_eq!(
                classify_event(id),
                Some(EventKind { is_recv, is_udp, local_port_offset: off }),
                "id {id}"
            );
        }
    }

    #[test]
    fn classify_event_ignores_non_data_events() {
        // connect(12)/disconnect(13)/retransmit(14)/accept(15) and any
        // unrelated id carry no metered payload -> None.
        for id in [0u16, 12, 13, 14, 15, 28, 99, 1000] {
            assert_eq!(classify_event(id), None, "id {id} should not be metered");
        }
    }

    #[test]
    fn recv_and_send_ids_are_disjoint() {
        // An id is never both a send and a receive, so direction is
        // unambiguous.
        for id in super::RECV_IDS {
            assert!(!super::SEND_IDS.contains(&id));
        }
    }
}

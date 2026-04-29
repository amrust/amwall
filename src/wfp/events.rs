// amwall — WFP net-event subscription.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Wraps `FwpmNetEventSubscribe0` / `FwpmNetEventUnsubscribe0`. The
// kernel emits `FWPM_NET_EVENT1` records when a filter classifies
// a packet (drop, allow, or other engine event); we marshal the
// useful subset of the C struct into a `NetEvent` enum and push
// one per event through an `mpsc::channel` to a consumer thread.
//
// The callback runs on a Win32 worker thread that the system owns,
// so anything inside it must be `Send`. The channel `Sender` is
// `Send`; the `Receiver` is held by the consumer (typically the
// GUI thread) and gets owned events via `recv` / `try_recv`.
//
// Lifetime: `EventSubscription` owns a `Box<CallbackContext>`. The
// raw pointer we hand to WFP points into that heap allocation,
// which stays put as long as the subscription is alive. Drop
// unsubscribes synchronously (per MSDN, `FwpmNetEventUnsubscribe0`
// blocks until any in-flight callback returns), so it's safe to
// drop the context after that.
//
// `subscribe` also calls `FwpmEngineSetOption0` with
// `FWPM_ENGINE_COLLECT_NET_EVENTS = 1` so the kernel actually emits
// events. Without that, the callback never fires.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, SystemTime};

use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB, FWP_IP_VERSION, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWP_UINT32, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_NET_EVENT1, FWPM_NET_EVENT_FLAG_APP_ID_SET,
    FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET, FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
    FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, FWPM_NET_EVENT_HEADER1, FWPM_NET_EVENT_HEADER1_0,
    FWPM_NET_EVENT_HEADER1_1, FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE,
    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FwpmEngineSetOption0,
    FwpmNetEventSubscribe0, FwpmNetEventUnsubscribe0,
};

use super::WfpEngine;

/// Decoded WFP net event. Drop/Allow carry per-event detail; other
/// kernel event types (IKE failures, IPsec drops, capability
/// events, …) are preserved as `Other(type_code)` without payload
/// decoding — they're rare and not relevant for an end-user
/// firewall log.
#[derive(Debug, Clone)]
pub enum NetEvent {
    /// `FWPM_NET_EVENT_TYPE_CLASSIFY_DROP` — a filter blocked traffic.
    Drop(NetEventDetails),
    /// `FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW` — a filter permitted
    /// traffic and the filter had `FWPM_FILTER_FLAG_PERMIT |
    /// FWPM_FILTER_FLAG_LOG_PERMITS` set so the engine logged it.
    Allow(NetEventDetails),
    /// Any other event type (IKE / IPsec / capability / …). Contains
    /// the raw `FWPM_NET_EVENT_TYPE` value for debugging.
    Other(u32),
}

/// Common per-event data lifted out of `FWPM_NET_EVENT_HEADER1`.
/// Optional fields reflect the header's `flags` bitmap — fields the
/// kernel didn't populate land as `None`.
#[derive(Debug, Clone)]
pub struct NetEventDetails {
    pub timestamp: SystemTime,
    pub local_addr: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub protocol: Option<u8>,
    /// NT-form path of the application whose traffic triggered the
    /// event (`\device\harddiskvolume3\…`). Empty / absent on system
    /// traffic that isn't tied to a specific image.
    pub app_path: Option<String>,
}

/// RAII subscription handle. Drop unsubscribes synchronously.
pub struct EventSubscription {
    handle: HANDLE,
    engine: HANDLE,
    // Holds the channel `Sender` that the WFP callback writes to.
    // Boxed so its address is stable across moves of the
    // `EventSubscription`.
    _context: Box<CallbackContext>,
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        // `FwpmNetEventUnsubscribe0` blocks until any in-flight
        // callback completes, so after this returns the kernel
        // won't touch our context again — safe to drop the Box.
        unsafe {
            let _ = FwpmNetEventUnsubscribe0(self.engine, self.handle);
        }
    }
}

struct CallbackContext {
    tx: Sender<NetEvent>,
}

/// Subscribe to drop / allow / other net events. Returns the
/// subscription RAII handle plus a `Receiver` that the consumer
/// drains via `recv` / `try_recv`.
///
/// Side effect: enables `FWPM_ENGINE_COLLECT_NET_EVENTS` on the
/// engine so the kernel actually emits events. This is a global
/// engine setting, not per-subscription — leaving it on after
/// unsubscribe is harmless (events just queue with no listener).
pub fn subscribe(
    engine: &WfpEngine,
) -> Result<(EventSubscription, Receiver<NetEvent>), String> {
    enable_event_collection(engine)?;

    let (tx, rx) = mpsc::channel();
    let context = Box::new(CallbackContext { tx });
    let context_ptr = &*context as *const CallbackContext as *mut c_void;

    // Default-initialised subscription matches all event types and
    // doesn't filter on conditions. Tighter filtering (only drops,
    // only specific layer, …) lands later if needed.
    let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();

    let mut handle = HANDLE::default();
    let res = unsafe {
        FwpmNetEventSubscribe0(
            engine.raw(),
            &subscription,
            Some(raw_callback),
            Some(context_ptr),
            &mut handle,
        )
    };
    if res != 0 {
        return Err(format!("FwpmNetEventSubscribe0 failed: {res:#010x}"));
    }

    Ok((
        EventSubscription {
            handle,
            engine: engine.raw(),
            _context: context,
        },
        rx,
    ))
}

fn enable_event_collection(engine: &WfpEngine) -> Result<(), String> {
    // FWP_VALUE0 carrying a UINT32 = 1. The engine accepts UINT32
    // for COLLECT_NET_EVENTS even though the docs sometimes show
    // BOOL — both interpretations work and UINT32 sidesteps any
    // BOOL definition mismatch.
    let val = FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: 1 },
    };
    let res = unsafe {
        FwpmEngineSetOption0(engine.raw(), FWPM_ENGINE_COLLECT_NET_EVENTS, &val)
    };
    if res != 0 {
        return Err(format!(
            "FwpmEngineSetOption0(COLLECT_NET_EVENTS) failed: {res:#010x}"
        ));
    }
    Ok(())
}

unsafe extern "system" fn raw_callback(
    context: *mut c_void,
    event: *const FWPM_NET_EVENT1,
) {
    if event.is_null() || context.is_null() {
        return;
    }
    let ctx = unsafe { &*(context as *const CallbackContext) };
    let event_ref = unsafe { &*event };
    let parsed = parse_event(event_ref);
    // Send is best-effort. If the consumer dropped the Receiver
    // (e.g. they're shutting down), the send fails — drop the
    // event silently rather than panic on the worker thread.
    let _ = ctx.tx.send(parsed);
}

fn parse_event(event: &FWPM_NET_EVENT1) -> NetEvent {
    let details = parse_header(&event.header);
    match event.r#type {
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP => NetEvent::Drop(details),
        FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW => NetEvent::Allow(details),
        FWPM_NET_EVENT_TYPE(other) => NetEvent::Other(other as u32),
    }
}

fn parse_header(h: &FWPM_NET_EVENT_HEADER1) -> NetEventDetails {
    let timestamp = filetime_to_systime(h.timeStamp);

    let local_addr = if (h.flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET) != 0 {
        extract_local_addr(h.ipVersion, &h.Anonymous1)
    } else {
        None
    };
    let remote_addr = if (h.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) != 0 {
        extract_remote_addr(h.ipVersion, &h.Anonymous2)
    } else {
        None
    };
    let local_port = if (h.flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) != 0 {
        Some(h.localPort)
    } else {
        None
    };
    let remote_port = if (h.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) != 0 {
        Some(h.remotePort)
    } else {
        None
    };
    let protocol = if (h.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) != 0 {
        Some(h.ipProtocol)
    } else {
        None
    };
    let app_path = if (h.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) != 0 {
        decode_app_id(&h.appId)
    } else {
        None
    };

    NetEventDetails {
        timestamp,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        protocol,
        app_path,
    }
}

/// IPv4 addresses in WFP are stored as `u32` host-order. Convert
/// directly: `Ipv4Addr::from(u32)` is big-endian, matching the
/// kernel's representation.
fn extract_local_addr(
    version: FWP_IP_VERSION,
    addr: &FWPM_NET_EVENT_HEADER1_0,
) -> Option<IpAddr> {
    match version {
        FWP_IP_VERSION_V4 => Some(IpAddr::V4(Ipv4Addr::from(unsafe { addr.localAddrV4 }))),
        FWP_IP_VERSION_V6 => Some(IpAddr::V6(Ipv6Addr::from(
            unsafe { addr.localAddrV6 }.byteArray16,
        ))),
        _ => None,
    }
}

fn extract_remote_addr(
    version: FWP_IP_VERSION,
    addr: &FWPM_NET_EVENT_HEADER1_1,
) -> Option<IpAddr> {
    match version {
        FWP_IP_VERSION_V4 => Some(IpAddr::V4(Ipv4Addr::from(unsafe { addr.remoteAddrV4 }))),
        FWP_IP_VERSION_V6 => Some(IpAddr::V6(Ipv6Addr::from(
            unsafe { addr.remoteAddrV6 }.byteArray16,
        ))),
        _ => None,
    }
}

/// FILETIME (100-nanosecond intervals since 1601-01-01 UTC) →
/// `SystemTime`. Saturates to UNIX epoch for pre-1970 timestamps,
/// which shouldn't happen for live events but guards against junk
/// data.
fn filetime_to_systime(ft: FILETIME) -> SystemTime {
    let intervals = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
    let secs_since_1601 = intervals / 10_000_000;
    let sub_intervals = intervals % 10_000_000;
    let nanos = (sub_intervals * 100) as u32;
    // 1601-01-01 → 1970-01-01 = 11_644_473_600 seconds.
    let secs_since_unix = secs_since_1601.saturating_sub(11_644_473_600);
    SystemTime::UNIX_EPOCH + Duration::new(secs_since_unix, nanos)
}

fn decode_app_id(blob: &FWP_BYTE_BLOB) -> Option<String> {
    if blob.size == 0 || blob.data.is_null() {
        return None;
    }
    // App id is a wide string (with terminator) packed into the
    // byte blob. Treat it as `[u16]` and decode lossily.
    let byte_len = blob.size as usize;
    let u16_len = byte_len / 2;
    let slice = unsafe { std::slice::from_raw_parts(blob.data as *const u16, u16_len) };
    // Trim trailing NULs so the displayed path doesn't end with
    // garbage characters.
    let trimmed: Vec<u16> = slice.iter().take_while(|&&c| c != 0).copied().collect();
    Some(String::from_utf16_lossy(&trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_zero_maps_before_unix_epoch() {
        // FILETIME(0) is 1601-01-01. Saturates to UNIX_EPOCH.
        let ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        assert_eq!(filetime_to_systime(ft), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn filetime_at_unix_epoch_round_trips() {
        // 1970-01-01 in FILETIME = 11_644_473_600 seconds × 10^7
        // intervals.
        let intervals: u64 = 11_644_473_600 * 10_000_000;
        let ft = FILETIME {
            dwLowDateTime: (intervals & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (intervals >> 32) as u32,
        };
        assert_eq!(filetime_to_systime(ft), SystemTime::UNIX_EPOCH);
    }

    /// Live exercise of the subscribe / unsubscribe lifecycle.
    /// Doesn't try to trigger a specific event — that's flaky on
    /// systems with active firewalls — just verifies the API
    /// doesn't error and that the RAII drop unsubscribes cleanly.
    /// Run with `cargo test -- --ignored` from an elevated shell.
    #[test]
    #[ignore = "requires elevated shell to call FwpmEngineSetOption0 / FwpmNetEventSubscribe0"]
    fn subscribe_unsubscribe_admin_smoke() {
        let engine = WfpEngine::open().expect("engine open failed");
        let (sub, rx) = subscribe(&engine).expect("subscribe failed");

        // Give the kernel a brief window to fire something. On a
        // live machine with active filters this will usually
        // produce at least one event, but we don't assert that —
        // just drain any that arrive without blocking.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            match rx.try_recv() {
                Ok(_event) => {} // silently drained
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }

        // Drop unsubscribes synchronously — no panic, no UAF.
        drop(sub);
    }
}

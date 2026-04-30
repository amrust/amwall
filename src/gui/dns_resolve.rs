// amwall — async reverse-DNS pump.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Hostname resolution off the GUI thread. Reverse DNS is slow
// (50–500 ms per address even with the cache warm; a multi-second
// timeout when the resolver gives up) — populating the
// Connections / Log tab on the message-pump thread would freeze
// the window for the duration. Solution: a worker thread plus
// cache.
//
// Lifecycle:
//   - WM_CREATE spawns one worker via `spawn_worker`, hands the
//     main HWND in so `PostMessageW(WM_USER_DNS_REFRESH)` can
//     punt repaints back. Returned `Sender<IpAddr>` lives on
//     `WndState.dns_tx`.
//   - Connections / Log populator looks each IP up in the
//     `Arc<Mutex<HashMap>>` cache. Hit → render hostname in the
//     Host column. Miss → enqueue and render the numeric address
//     for now.
//   - Worker calls `GetNameInfoW` with `NI_NAMEREQD` (so it
//     fails-fast for IPs with no PTR record rather than echoing
//     the address). Each successful lookup goes into the cache;
//     after every BATCH_FOR_REFRESH resolutions (or on idle
//     drain) the worker posts WM_USER_DNS_REFRESH so the visible
//     tab repaints.
//   - Cache stores Option<String>: None means "queried, no PTR
//     record", which lets the populator skip re-enqueuing dead
//     IPs.
//
// Thread-safety: `Sender<IpAddr>` is the wakeup channel; `cache`
// is shared via `Arc<Mutex<...>>` since the worker writes from
// another thread. HWND isn't Send, so we cast to usize for the
// thread move and re-wrap on the worker side. PostMessageW is
// thread-safe by Win32 contract.
//
// Resolution gating: the populator should only enqueue lookups
// when `Settings.use_network_resolution` is true. The worker
// itself is unconditional — costs nothing while idle.

#![cfg(windows)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Receiver, Sender, channel};

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, NI_MAXHOST, NI_NAMEREQD,
    SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, WSADATA, WSACleanup, WSAStartup,
    GetNameInfoW, socklen_t,
};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_USER};

/// Posted from the DNS worker after a batch of lookups. The main
/// wndproc treats it as "if the Connections tab is visible,
/// repopulate so newly-resolved hostnames render."
pub const WM_USER_DNS_REFRESH: u32 = WM_USER + 0x104;

/// `None` cached value means "we queried this IP and it has no
/// PTR record" (or an error short of network failure). The
/// populator uses presence-of-key not Some-ness to skip
/// re-enqueuing.
pub type DnsCacheMap = HashMap<IpAddr, Option<String>>;

/// Spawn the reverse-DNS worker. Returns the `Sender` the GUI
/// drops new IPs into. Worker shuts down when the sender is
/// dropped (channel closed).
pub fn spawn_worker(
    main_hwnd: HWND,
    cache: Arc<Mutex<DnsCacheMap>>,
) -> Sender<IpAddr> {
    let (tx, rx): (Sender<IpAddr>, Receiver<IpAddr>) = channel();
    let hwnd_raw = main_hwnd.0 as usize;
    std::thread::spawn(move || {
        // WSAStartup is required before the first ws2_32 call on
        // a thread that hasn't already run one. Cheap (refcount
        // bump if the GUI's IP-helper code beat us to it). 0x0202
        // = Winsock 2.2.
        let mut wsa: WSADATA = unsafe { std::mem::zeroed() };
        let started = unsafe { WSAStartup(0x0202, &mut wsa) } == 0;

        const BATCH_FOR_REFRESH: u32 = 8;
        let mut since_last_post = 0u32;
        while let Ok(ip) = rx.recv() {
            // Skip if cached.
            if let Ok(g) = cache.lock() {
                if g.contains_key(&ip) {
                    continue;
                }
            }
            let result = reverse_lookup(ip);
            if let Ok(mut g) = cache.lock() {
                g.insert(ip, result);
            }
            since_last_post += 1;
            if since_last_post >= BATCH_FOR_REFRESH {
                since_last_post = 0;
                post_refresh(hwnd_raw);
            }
        }
        if since_last_post > 0 {
            post_refresh(hwnd_raw);
        }
        if started {
            unsafe {
                let _ = WSACleanup();
            }
        }
    });
    tx
}

fn post_refresh(hwnd_raw: usize) {
    let h = HWND(hwnd_raw as isize);
    unsafe {
        let _ = PostMessageW(h, WM_USER_DNS_REFRESH, WPARAM(0), LPARAM(0));
    }
}

/// Wrap an IpAddr in the right SOCKADDR_IN / SOCKADDR_IN6 and
/// hand it to `GetNameInfoW(NI_NAMEREQD)`. Returns `Some(host)`
/// when a PTR record came back, `None` for "no name" / errors —
/// the cache stores the negative result so the GUI doesn't keep
/// re-enqueuing dead IPs.
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let mut name = vec![0u16; NI_MAXHOST as usize];
    let result = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let s_addr = u32::from_be_bytes(octets);
            let sa = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: s_addr.to_be() },
                },
                sin_zero: [0; 8],
            };
            unsafe {
                GetNameInfoW(
                    &sa as *const _ as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
                    Some(&mut name),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let sa = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: octets },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            };
            unsafe {
                GetNameInfoW(
                    &sa as *const _ as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN6>() as i32),
                    Some(&mut name),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
    };
    if result != 0 {
        return None;
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&name[..len]))
}

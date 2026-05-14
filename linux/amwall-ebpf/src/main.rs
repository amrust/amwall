//! amwall-ebpf — BPF LSM enforcement.
//!
//! Phase 6.3.1: when the `task_walk` feature is enabled (toggled by
//! linux-build.sh after aya-tool successfully emits src/vmlinux.rs from
//! /sys/kernel/btf/vmlinux), the program reads the comm of the thread-group
//! leader instead of the current thread. That collapses Firefox's per-thread
//! "DNS Resolver #N" worker names back to "firefox", so the userspace prompt
//! dedup actually works on multi-thread apps. Without the feature, we fall
//! back to bpf_get_current_comm() (per-thread name) — same as pre-6.3.1.

#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};

#[cfg(feature = "task_walk")]
use aya_ebpf::helpers::bpf_get_current_task;

#[cfg(feature = "task_walk")]
#[allow(non_camel_case_types, non_snake_case, dead_code, unused_imports,
        non_upper_case_globals, deref_nullptr, unnecessary_transmutes,
        improper_ctypes_definitions, clippy::all)]
mod vmlinux;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const ACT_DENY: u8 = 0;
const ACT_ALLOW: u8 = 1;

const VERDICT_ALLOW: i32 = 0;
const VERDICT_DENY: i32 = -1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub family: u16,
    pub dest_port: u16,
    pub dest_ip4: u32,
    pub dest_ip6: [u8; 16],
    pub action: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKey {
    pub comm: [u8; 16],
    pub dest_ip4: u32,
    pub dest_port: u16,
    pub _pad: u16,
}

// Phase 6.4.1: parallel map for IPv6 lookups. dest_ip6 is the raw
// 16-byte address (network byte order, same as in_addr6). Wildcard
// slot is dest_ip6=[0; 16] + dest_port=0 — populated by the daemon
// whenever the user sets a rule with ip="any" so that wildcard
// allows/denies cover both IPv4 and IPv6 destinations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKeyV6 {
    pub comm: [u8; 16],
    pub dest_ip6: [u8; 16],
    pub dest_port: u16,
    pub _pad: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 7],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(1024, 0);

#[map]
static RULES_V6: HashMap<RuleKeyV6, RuleValue> = HashMap::with_max_entries(1024, 0);

// Phase 6.9 blocklist maps. Checked BEFORE per-comm rules, so a hit
// here is a hard deny regardless of which process is connecting and
// regardless of whether the user has an explicit allow rule for that
// process — that's the simplewall blocklist semantic ("system block
// list", IDC_RULES_BLOCKLIST). Capacity is 65k entries each which
// covers a typical telemetry+ads merge with headroom; bump if a
// future list needs more.
//
// Value is just a presence marker (u8), since the only signal is
// "is this destination in the blocklist or not". The BPF program
// doesn't care which list it came from — that mapping lives in the
// daemon's blocklist.toml metadata.
#[map]
static BLOCKLIST_V4: HashMap<u32, u8> = HashMap::with_max_entries(65536, 0);

#[map]
static BLOCKLIST_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(65536, 0);

// Master enforcement toggle. 1-element Array (key=0) holding a u32:
//   1 = filters ENABLED (default — every connect goes through the
//       blocklist + per-comm rule lookup)
//   0 = filters DISABLED (decide() short-circuits to ACT_ALLOW
//       before any lookup; useful when the user wants to temporarily
//       lift enforcement without stopping the daemon — same shape as
//       simplewall's "Disable filters" toggle)
//
// The daemon writes to this map from its SetEnabled D-Bus method
// (polkit-gated) and persists the chosen value to /etc/amwall/enabled
// so the state survives daemon restarts. Default on missing file = 1
// (enforce) — fail-closed.
#[map]
static ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[inline(always)]
fn is_enforcement_enabled() -> bool {
    // Default to enabled if the daemon hasn't initialized the map
    // yet (between BPF program load and the daemon's first write,
    // a connect could fire and we want fail-closed semantics).
    match ENABLED.get(0) {
        Some(&v) => v != 0,
        None => true,
    }
}

#[repr(C)]
struct SockAddrFamily { family: u16 }

#[repr(C)]
struct SockAddrIn { family: u16, port: u16, addr: u32 }

#[repr(C)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[lsm(hook = "socket_connect")]
pub fn amwall_socket_connect(ctx: LsmContext) -> i32 {
    match decide(&ctx) {
        ACT_ALLOW => VERDICT_ALLOW,
        _         => VERDICT_DENY,
    }
}

// Returns the comm of the thread-group leader when task_walk is enabled,
// else the per-thread comm. Any error walking the task_struct falls back
// to the per-thread name — that's a UX regression (extra prompts), not a
// security one, since the comm only feeds the rule lookup.
fn current_comm() -> [u8; 16] {
    #[cfg(feature = "task_walk")]
    unsafe {
        use vmlinux::task_struct;
        let task_addr = bpf_get_current_task();
        if task_addr == 0 {
            return bpf_get_current_comm().unwrap_or([0; 16]);
        }
        let task = task_addr as *const task_struct;
        // &(*task).group_leader is constant-offset pointer arithmetic
        // (the verifier accepts this on a task_struct kernel ptr).
        // bpf_probe_read_kernel does the actual safe deref.
        let leader_field = &(*task).group_leader as *const _ as *const u64;
        let leader_addr: u64 = match bpf_probe_read_kernel::<u64>(leader_field) {
            Ok(p) => p,
            Err(_) => return bpf_get_current_comm().unwrap_or([0; 16]),
        };
        if leader_addr == 0 {
            return bpf_get_current_comm().unwrap_or([0; 16]);
        }
        let leader = leader_addr as *const task_struct;
        let comm_field = &(*leader).comm as *const _ as *const [i8; 16];
        match bpf_probe_read_kernel::<[i8; 16]>(comm_field) {
            Ok(c) => core::mem::transmute::<[i8; 16], [u8; 16]>(c),
            Err(_) => bpf_get_current_comm().unwrap_or([0; 16]),
        }
    }
    #[cfg(not(feature = "task_walk"))]
    bpf_get_current_comm().unwrap_or([0; 16])
}

fn decide(ctx: &LsmContext) -> u8 {
    // Master toggle — when filters are disabled at the daemon level,
    // bypass every check and allow everything. We deliberately skip
    // the ringbuf event submission too: the GUI's Packets log would
    // otherwise fill with "allowed" entries that aren't really
    // policy decisions, just bypass passthroughs.
    if !is_enforcement_enabled() {
        return ACT_ALLOW;
    }

    let addr_ptr: *const c_void = unsafe { ctx.arg(1) };

    let family = match unsafe {
        bpf_probe_read_kernel::<SockAddrFamily>(addr_ptr as *const SockAddrFamily)
    } {
        Ok(f) => f.family,
        Err(_) => return ACT_ALLOW,
    };

    let comm = current_comm();
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut entry = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(e) => e,
        None => return ACT_ALLOW,
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = pid;
        (*event).comm = comm;
        (*event).family = family;
        (*event).dest_port = 0;
        (*event).dest_ip4 = 0;
        (*event).dest_ip6 = [0; 16];
        (*event).action = ACT_ALLOW;
        (*event)._pad = [0; 3];
    }

    let action = match family {
        AF_INET => {
            match unsafe {
                bpf_probe_read_kernel::<SockAddrIn>(addr_ptr as *const SockAddrIn)
            } {
                Ok(a) => {
                    let port_host = u16::from_be(a.port);
                    unsafe {
                        (*event).dest_port = port_host;
                        (*event).dest_ip4 = a.addr;
                    }
                    // Blocklist hit overrides any per-comm allow rule.
                    if unsafe { BLOCKLIST_V4.get(&a.addr).is_some() } {
                        ACT_DENY
                    } else {
                        lookup(comm, a.addr, port_host)
                    }
                }
                Err(_) => ACT_ALLOW,
            }
        }
        AF_INET6 => {
            // Phase 6.4.1: IPv6 is now subject to the same default-deny
            // policy as IPv4. lookup_v6 does the parallel 4-way wildcard
            // search against RULES_V6; the daemon mirrors "any" rules
            // into both maps so a single user click covers v4 + v6.
            match unsafe {
                bpf_probe_read_kernel::<SockAddrIn6>(addr_ptr as *const SockAddrIn6)
            } {
                Ok(a) => {
                    let port_host = u16::from_be(a.port);
                    unsafe {
                        (*event).dest_port = port_host;
                        (*event).dest_ip6 = a.addr;
                    }
                    if unsafe { BLOCKLIST_V6.get(&a.addr).is_some() } {
                        ACT_DENY
                    } else {
                        lookup_v6(comm, a.addr, port_host)
                    }
                }
                Err(_) => ACT_ALLOW,
            }
        }
        _ => ACT_ALLOW,
    };

    unsafe { (*event).action = action; }
    entry.submit(0);
    action
}

fn lookup(comm: [u8; 16], ip: u32, port: u16) -> u8 {
    let k1 = RuleKey { comm, dest_ip4: ip, dest_port: port, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k1) } { return v.action; }

    let k2 = RuleKey { comm, dest_ip4: ip, dest_port: 0, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k2) } { return v.action; }

    let k3 = RuleKey { comm, dest_ip4: 0, dest_port: port, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k3) } { return v.action; }

    let k4 = RuleKey { comm, dest_ip4: 0, dest_port: 0, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k4) } { return v.action; }

    ACT_DENY
}

fn lookup_v6(comm: [u8; 16], ip6: [u8; 16], port: u16) -> u8 {
    // 4-way wildcard, mirroring `lookup` for IPv4.
    let k1 = RuleKeyV6 { comm, dest_ip6: ip6, dest_port: port, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k1) } { return v.action; }

    let k2 = RuleKeyV6 { comm, dest_ip6: ip6, dest_port: 0, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k2) } { return v.action; }

    let k3 = RuleKeyV6 { comm, dest_ip6: [0; 16], dest_port: port, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k3) } { return v.action; }

    let k4 = RuleKeyV6 { comm, dest_ip6: [0; 16], dest_port: 0, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k4) } { return v.action; }

    ACT_DENY
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

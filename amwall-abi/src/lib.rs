//! amwall-abi — the byte-exact struct layouts shared by the BPF program
//! and the userspace daemon.
//!
//! These `#[repr(C)]` types define the wire format of the BPF maps
//! (`RULES`, `RULES_V6`) and the `EVENTS` ring buffer. They were
//! previously hand-copied into both `amwall-ebpf` (kernel, no_std) and
//! `amwall-daemon` (userspace, std); a silent field/pad drift between
//! the two copies would mis-key the map or mis-read events with no
//! compile error. Defining them once here removes that risk
//! (docs/linux-logic-atlas.md gap #14).
//!
//! The crate is `no_std` so the `bpfel-unknown-none` BPF build can
//! depend on it. The daemon enables the `aya-pod` feature to get the
//! `aya::Pod` impls needed to read/write the maps over aya's FFI; the
//! BPF crate leaves the feature off and never links aya.

#![no_std]

/// Per-comm IPv4 rule key. `comm` is the 16-byte process name; `dest_ip4`
/// is the destination address in NETWORK byte order (0 = wildcard);
/// `dest_port` is host byte order (0 = wildcard). Byte layout MUST match
/// the BPF `RULES` map exactly.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleKey {
    pub comm: [u8; 16],
    pub dest_ip4: u32,
    pub dest_port: u16,
    pub _pad: u16,
}

/// Per-comm IPv6 rule key. `dest_ip6` is the raw 16-byte address in
/// network byte order ([0; 16] = wildcard). Byte layout MUST match the
/// BPF `RULES_V6` map exactly.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleKeyV6 {
    pub comm: [u8; 16],
    pub dest_ip6: [u8; 16],
    pub dest_port: u16,
    pub _pad: [u8; 6],
}

/// Rule map value. `action`: 0 = deny, 1 = allow.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 7],
}

/// One connect-attempt notification pushed from the BPF program to the
/// daemon over the `EVENTS` ring buffer. `action` records the verdict
/// the kernel returned (0 = deny, 1 = allow). Byte layout MUST match
/// what the BPF program writes.
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

// Only the map key/value types cross aya's map FFI and need `Pod`.
// `ConnectEvent` is read from the ring buffer via `read_unaligned`, not
// through a typed aya map, so it needs no `Pod` impl.
#[cfg(feature = "aya-pod")]
mod pod_impls {
    use super::{RuleKey, RuleKeyV6, RuleValue};

    unsafe impl aya::Pod for RuleKey {}
    unsafe impl aya::Pod for RuleKeyV6 {}
    unsafe impl aya::Pod for RuleValue {}
}

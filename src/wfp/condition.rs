// simplewall-rs — WFP filter conditions.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// `FilterCondition` is the high-level user-facing description of a
// match clause on a WFP filter. The mapping to native
// `FWPM_FILTER_CONDITION0` arrays + their backing pointer storage
// happens in `filter::add` via `compile_into`. The intermediate
// `CompiledConditions` value owns all the heap-allocated auxiliary
// structs (FWP_V4_ADDR_AND_MASK, FWP_V6_ADDR_AND_MASK) so the raw
// pointers in `FWPM_FILTER_CONDITION0::conditionValue` stay valid for
// the duration of `FwpmFilterAdd0`.
//
// M1.5a covers network-only conditions: protocol, ports, IPs (v4/v6
// with optional CIDR mask), direction. App-path conditions land in
// M1.5b — that needs `FwpmGetAppIdFromFileName0` plus a separate
// post-call cleanup with `FwpmFreeMemory0`.

use std::net::{Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_ARRAY16, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DIRECTION,
    FWP_DIRECTION_INBOUND, FWP_DIRECTION_OUTBOUND, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16,
    FWP_UINT32, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    FWPM_CONDITION_DIRECTION, FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
};
use windows::core::GUID;

/// IP protocol number (the `IPPROTO_*` family). Upstream simplewall
/// rules can match TCP, UDP, ICMP and a few others by number.
#[derive(Debug, Clone, Copy)]
pub enum IpProto {
    /// `IPPROTO_ICMP` (1).
    Icmp,
    /// `IPPROTO_TCP` (6).
    Tcp,
    /// `IPPROTO_UDP` (17).
    Udp,
    /// `IPPROTO_ICMPV6` (58).
    IcmpV6,
    /// Any other protocol number.
    Other(u8),
}

impl IpProto {
    fn as_u8(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::IcmpV6 => 58,
            Self::Other(n) => n,
        }
    }
}

/// Traffic direction at layers that handle both directions
/// (e.g. transport-layer filters). For most ALE layers the layer
/// itself encodes direction (`ALE_AUTH_CONNECT_V4` = outbound,
/// `ALE_AUTH_RECV_ACCEPT_V4` = inbound) and an explicit Direction
/// condition is redundant.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    fn as_fwp(self) -> FWP_DIRECTION {
        match self {
            Self::Inbound => FWP_DIRECTION_INBOUND,
            Self::Outbound => FWP_DIRECTION_OUTBOUND,
        }
    }
}

/// One match clause on a filter. A filter passes only when ALL of its
/// conditions match (AND semantics).
///
/// IP-address conditions accept an optional CIDR prefix length. When
/// `None`, the filter matches a single host address (compiled to
/// `FWP_UINT32`/`FWP_BYTE_ARRAY16`); when `Some`, it compiles to
/// `FWP_V4_ADDR_MASK` / `FWP_V6_ADDR_MASK` with the prefix expanded
/// to a full 32-bit / 128-bit mask.
#[derive(Debug, Clone, Copy)]
pub enum FilterCondition {
    Protocol(IpProto),
    LocalPort(u16),
    RemotePort(u16),
    LocalAddrV4 { addr: Ipv4Addr, prefix: Option<u8> },
    RemoteAddrV4 { addr: Ipv4Addr, prefix: Option<u8> },
    LocalAddrV6 { addr: Ipv6Addr, prefix: Option<u8> },
    RemoteAddrV6 { addr: Ipv6Addr, prefix: Option<u8> },
    Direction(Direction),
}

/// Compile a slice of `FilterCondition` into a parallel array of
/// native `FWPM_FILTER_CONDITION0` plus the backing storage their
/// pointer fields reference into.
///
/// Returned value owns the storage; the caller passes
/// `compiled.as_native_slice()` to `FwpmFilterAdd0` and drops the
/// `CompiledConditions` AFTER the call returns. The kernel copies
/// pointed-to data into its own storage during the call so the
/// auxiliary backing can be freed at end of the caller's scope.
pub(super) fn compile(conditions: &[FilterCondition]) -> CompiledConditions {
    let mut storage = CompiledConditions {
        v4_masks: Vec::with_capacity(conditions.len()),
        v6_masks: Vec::with_capacity(conditions.len()),
        v6_addrs: Vec::with_capacity(conditions.len()),
        natives: Vec::with_capacity(conditions.len()),
    };

    for cond in conditions {
        let native = match *cond {
            FilterCondition::Protocol(proto) => fc_uint8(FWPM_CONDITION_IP_PROTOCOL, proto.as_u8()),

            FilterCondition::LocalPort(port) => fc_uint16(FWPM_CONDITION_IP_LOCAL_PORT, port),
            FilterCondition::RemotePort(port) => fc_uint16(FWPM_CONDITION_IP_REMOTE_PORT, port),

            FilterCondition::LocalAddrV4 { addr, prefix: None } => {
                fc_uint32(FWPM_CONDITION_IP_LOCAL_ADDRESS, u32::from(addr))
            }
            FilterCondition::RemoteAddrV4 { addr, prefix: None } => {
                fc_uint32(FWPM_CONDITION_IP_REMOTE_ADDRESS, u32::from(addr))
            }

            FilterCondition::LocalAddrV4 { addr, prefix: Some(p) } => storage.fc_v4_mask(
                FWPM_CONDITION_IP_LOCAL_ADDRESS,
                addr,
                p,
            ),
            FilterCondition::RemoteAddrV4 { addr, prefix: Some(p) } => storage.fc_v4_mask(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                addr,
                p,
            ),

            FilterCondition::LocalAddrV6 { addr, prefix: None } => {
                storage.fc_v6_addr(FWPM_CONDITION_IP_LOCAL_ADDRESS, addr)
            }
            FilterCondition::RemoteAddrV6 { addr, prefix: None } => {
                storage.fc_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, addr)
            }

            FilterCondition::LocalAddrV6 { addr, prefix: Some(p) } => storage.fc_v6_mask(
                FWPM_CONDITION_IP_LOCAL_ADDRESS,
                addr,
                p,
            ),
            FilterCondition::RemoteAddrV6 { addr, prefix: Some(p) } => storage.fc_v6_mask(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                addr,
                p,
            ),

            FilterCondition::Direction(d) => {
                fc_uint32(FWPM_CONDITION_DIRECTION, d.as_fwp().0 as u32)
            }
        };
        storage.natives.push(native);
    }

    storage
}

/// Owning storage for compiled conditions. Drop only AFTER
/// `FwpmFilterAdd0` returns.
///
/// The three pointer-storage vecs are `Vec<Box<T>>`, **not** `Vec<T>`,
/// because we hand out raw pointers into individual elements while
/// also pushing more elements. `Vec<T>` reallocates the underlying
/// heap buffer when its capacity is exceeded, which would invalidate
/// any `&[i]`-derived pointer; `Box<T>` owns its own heap allocation
/// so its address is stable regardless of how the `Vec` containing
/// the boxes grows. This is what `clippy::vec_box` warns against,
/// but the lint doesn't model raw-pointer aliasing — the box is
/// load-bearing here.
#[allow(clippy::vec_box)]
pub(super) struct CompiledConditions {
    /// Heap-allocated v4 mask structs referenced by `v4AddrMask`
    /// pointers in compiled conditions.
    v4_masks: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    /// Heap-allocated v6 mask structs referenced by `v6AddrMask`
    /// pointers in compiled conditions.
    v6_masks: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    /// Heap-allocated v6 raw addresses for the no-mask path
    /// (referenced by `byteArray16` pointers).
    v6_addrs: Vec<Box<FWP_BYTE_ARRAY16>>,
    /// The compiled native conditions, in the same order as the
    /// input slice. Pointers within these reference into the three
    /// `Box` vecs above.
    natives: Vec<FWPM_FILTER_CONDITION0>,
}

impl CompiledConditions {
    /// Slice of `FWPM_FILTER_CONDITION0` ready to feed to
    /// `FwpmFilterAdd0` via `FWPM_FILTER0::filterCondition` +
    /// `FWPM_FILTER0::numFilterConditions`.
    pub(super) fn as_native_slice(&self) -> &[FWPM_FILTER_CONDITION0] {
        &self.natives
    }

    fn fc_v4_mask(
        &mut self,
        field: GUID,
        addr: Ipv4Addr,
        prefix: u8,
    ) -> FWPM_FILTER_CONDITION0 {
        let mask_struct = Box::new(FWP_V4_ADDR_AND_MASK {
            addr: u32::from(addr),
            mask: prefix_to_mask_v4(prefix),
        });
        let raw_ptr: *mut FWP_V4_ADDR_AND_MASK =
            mask_struct.as_ref() as *const _ as *mut _;
        self.v4_masks.push(mask_struct);

        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: raw_ptr },
            },
        }
    }

    fn fc_v6_mask(
        &mut self,
        field: GUID,
        addr: Ipv6Addr,
        prefix: u8,
    ) -> FWPM_FILTER_CONDITION0 {
        let mask_struct = Box::new(FWP_V6_ADDR_AND_MASK {
            addr: addr.octets(),
            prefixLength: prefix,
        });
        let raw_ptr: *mut FWP_V6_ADDR_AND_MASK =
            mask_struct.as_ref() as *const _ as *mut _;
        self.v6_masks.push(mask_struct);

        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: raw_ptr },
            },
        }
    }

    fn fc_v6_addr(&mut self, field: GUID, addr: Ipv6Addr) -> FWPM_FILTER_CONDITION0 {
        let arr = Box::new(FWP_BYTE_ARRAY16 {
            byteArray16: addr.octets(),
        });
        let raw_ptr: *mut FWP_BYTE_ARRAY16 = arr.as_ref() as *const _ as *mut _;
        self.v6_addrs.push(arr);

        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type:
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: raw_ptr },
            },
        }
    }
}

/// Inline `FWP_UINT8` condition — value lives in the union directly,
/// no auxiliary storage needed.
fn fc_uint8(field: GUID, value: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: value },
        },
    }
}

/// Inline `FWP_UINT16` condition.
fn fc_uint16(field: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
        },
    }
}

/// Inline `FWP_UINT32` condition.
fn fc_uint32(field: GUID, value: u32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint32: value },
        },
    }
}

/// Convert a CIDR prefix length (0..=32) into a 32-bit mask in host
/// byte order. WFP wants the mask as a regular `u32` numeric value
/// (not network byte order — see MSDN sample for IP filter
/// conditions, which writes `ntohl(inet_addr(...))`).
///
/// Out-of-range prefixes saturate at /32 (all-ones).
fn prefix_to_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_to_mask_v4_known_values() {
        assert_eq!(prefix_to_mask_v4(0), 0);
        assert_eq!(prefix_to_mask_v4(8), 0xFF000000);
        assert_eq!(prefix_to_mask_v4(16), 0xFFFF0000);
        assert_eq!(prefix_to_mask_v4(24), 0xFFFFFF00);
        assert_eq!(prefix_to_mask_v4(32), 0xFFFFFFFF);
        // Out-of-range saturates.
        assert_eq!(prefix_to_mask_v4(33), 0xFFFFFFFF);
        assert_eq!(prefix_to_mask_v4(255), 0xFFFFFFFF);
    }

    #[test]
    fn ip_proto_numbers() {
        assert_eq!(IpProto::Icmp.as_u8(), 1);
        assert_eq!(IpProto::Tcp.as_u8(), 6);
        assert_eq!(IpProto::Udp.as_u8(), 17);
        assert_eq!(IpProto::IcmpV6.as_u8(), 58);
        assert_eq!(IpProto::Other(99).as_u8(), 99);
    }

    /// Compilation produces one native condition per input.
    #[test]
    fn compile_yields_one_native_per_input() {
        let conds = [
            FilterCondition::Protocol(IpProto::Tcp),
            FilterCondition::RemotePort(443),
            FilterCondition::RemoteAddrV4 {
                addr: Ipv4Addr::new(192, 168, 0, 1),
                prefix: None,
            },
            FilterCondition::RemoteAddrV4 {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix: Some(8),
            },
        ];
        let compiled = compile(&conds);
        assert_eq!(compiled.as_native_slice().len(), 4);
    }

    /// CIDR-form v4 conditions allocate exactly one
    /// FWP_V4_ADDR_AND_MASK box per condition.
    #[test]
    fn compile_v4_mask_storage_count() {
        let conds = [
            FilterCondition::RemoteAddrV4 {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix: Some(8),
            },
            FilterCondition::LocalAddrV4 {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                prefix: Some(16),
            },
        ];
        let compiled = compile(&conds);
        assert_eq!(compiled.v4_masks.len(), 2);
        assert_eq!(compiled.v6_masks.len(), 0);
    }
}

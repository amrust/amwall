// simplewall-rs — WFP filter conditions.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// `FilterCondition` is the high-level user-facing description of a
// match clause on a WFP filter. The mapping to native
// `FWPM_FILTER_CONDITION0` arrays + their backing pointer storage
// happens via `compile()`, called from `filter::add`. The intermediate
// `CompiledConditions` value owns all the heap-allocated auxiliary
// structs (FWP_V4_ADDR_AND_MASK, FWP_V6_ADDR_AND_MASK,
// FWP_BYTE_ARRAY16) AND any WFP-heap-allocated app-id blobs, so the
// raw pointers in `FWPM_FILTER_CONDITION0::conditionValue` stay valid
// for the duration of `FwpmFilterAdd0`. Drop releases the WFP blobs
// via `FwpmFreeMemory0` and lets Rust's allocator reclaim the rest.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_ARRAY16, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_DIRECTION, FWP_DIRECTION_INBOUND, FWP_DIRECTION_OUTBOUND,
    FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE0, FWP_RANGE_TYPE, FWP_UINT8, FWP_UINT16,
    FWP_UINT32, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    FWP_VALUE0, FWP_VALUE0_0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_DIRECTION,
    FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
};
use windows::core::{GUID, PCWSTR};

use super::WfpError;

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
///
/// `AppPath` matches the originating application by full Win32 path
/// (e.g. `C:\Windows\System32\svchost.exe`). The path is resolved to
/// an "app id" `FWP_BYTE_BLOB` via `FwpmGetAppIdFromFileName0` at
/// compile time, which means the file must exist and be readable
/// when `filter::add` runs.
#[derive(Debug, Clone)]
pub enum FilterCondition {
    Protocol(IpProto),
    LocalPort(u16),
    RemotePort(u16),
    /// Inclusive port range, compiled to `FWP_RANGE0` over
    /// `FWP_UINT16` values with `FWP_MATCH_RANGE`.
    LocalPortRange(u16, u16),
    RemotePortRange(u16, u16),
    LocalAddrV4 { addr: Ipv4Addr, prefix: Option<u8> },
    RemoteAddrV4 { addr: Ipv4Addr, prefix: Option<u8> },
    /// Inclusive IPv4 address range, compiled to `FWP_RANGE0` over
    /// `FWP_UINT32` values (host byte order) with `FWP_MATCH_RANGE`.
    LocalAddrV4Range(Ipv4Addr, Ipv4Addr),
    RemoteAddrV4Range(Ipv4Addr, Ipv4Addr),
    LocalAddrV6 { addr: Ipv6Addr, prefix: Option<u8> },
    RemoteAddrV6 { addr: Ipv6Addr, prefix: Option<u8> },
    Direction(Direction),
    AppPath(PathBuf),
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
///
/// Fails when an `AppPath` condition references a missing or
/// unreadable file (returns `WfpError::AppIdFromFileName`). When that
/// happens any app-id blobs already obtained for earlier conditions
/// are released through `CompiledConditions`'s `Drop` impl as the
/// partial value goes out of scope.
pub(super) fn compile(
    conditions: &[FilterCondition],
) -> Result<CompiledConditions, WfpError> {
    let mut storage = CompiledConditions {
        v4_masks: Vec::with_capacity(conditions.len()),
        v6_masks: Vec::with_capacity(conditions.len()),
        v6_addrs: Vec::with_capacity(conditions.len()),
        app_id_blobs: Vec::new(),
        ranges: Vec::new(),
        natives: Vec::with_capacity(conditions.len()),
    };

    for cond in conditions {
        let native = match cond {
            FilterCondition::Protocol(proto) => {
                fc_uint8(FWPM_CONDITION_IP_PROTOCOL, proto.as_u8())
            }

            FilterCondition::LocalPort(port) => fc_uint16(FWPM_CONDITION_IP_LOCAL_PORT, *port),
            FilterCondition::RemotePort(port) => fc_uint16(FWPM_CONDITION_IP_REMOTE_PORT, *port),

            FilterCondition::LocalPortRange(lo, hi) => {
                storage.fc_port_range(FWPM_CONDITION_IP_LOCAL_PORT, *lo, *hi)
            }
            FilterCondition::RemotePortRange(lo, hi) => {
                storage.fc_port_range(FWPM_CONDITION_IP_REMOTE_PORT, *lo, *hi)
            }

            FilterCondition::LocalAddrV4Range(lo, hi) => {
                storage.fc_v4_range(FWPM_CONDITION_IP_LOCAL_ADDRESS, *lo, *hi)
            }
            FilterCondition::RemoteAddrV4Range(lo, hi) => {
                storage.fc_v4_range(FWPM_CONDITION_IP_REMOTE_ADDRESS, *lo, *hi)
            }

            FilterCondition::LocalAddrV4 { addr, prefix: None } => {
                fc_uint32(FWPM_CONDITION_IP_LOCAL_ADDRESS, u32::from(*addr))
            }
            FilterCondition::RemoteAddrV4 { addr, prefix: None } => {
                fc_uint32(FWPM_CONDITION_IP_REMOTE_ADDRESS, u32::from(*addr))
            }

            FilterCondition::LocalAddrV4 { addr, prefix: Some(p) } => {
                storage.fc_v4_mask(FWPM_CONDITION_IP_LOCAL_ADDRESS, *addr, *p)
            }
            FilterCondition::RemoteAddrV4 { addr, prefix: Some(p) } => {
                storage.fc_v4_mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, *addr, *p)
            }

            FilterCondition::LocalAddrV6 { addr, prefix: None } => {
                storage.fc_v6_addr(FWPM_CONDITION_IP_LOCAL_ADDRESS, *addr)
            }
            FilterCondition::RemoteAddrV6 { addr, prefix: None } => {
                storage.fc_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, *addr)
            }

            FilterCondition::LocalAddrV6 { addr, prefix: Some(p) } => {
                storage.fc_v6_mask(FWPM_CONDITION_IP_LOCAL_ADDRESS, *addr, *p)
            }
            FilterCondition::RemoteAddrV6 { addr, prefix: Some(p) } => {
                storage.fc_v6_mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, *addr, *p)
            }

            FilterCondition::Direction(d) => {
                fc_uint32(FWPM_CONDITION_DIRECTION, d.as_fwp().0 as u32)
            }

            FilterCondition::AppPath(path) => storage.fc_app_id(path)?,
        };
        storage.natives.push(native);
    }

    Ok(storage)
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
    /// `FWP_BYTE_BLOB*` pointers returned by
    /// `FwpmGetAppIdFromFileName0`. These point at the **WFP heap**
    /// (NOT Rust's heap) and must be released via `FwpmFreeMemory0`
    /// in `Drop`.
    app_id_blobs: Vec<*mut FWP_BYTE_BLOB>,
    /// Heap-allocated `FWP_RANGE0` structs (each holds
    /// `valueLow`/`valueHigh` of `FWP_VALUE0`) referenced by
    /// `rangeValue` pointers in compiled range conditions.
    ranges: Vec<Box<FWP_RANGE0>>,
    /// The compiled native conditions, in the same order as the
    /// input slice. Pointers within these reference into the three
    /// `Box` vecs above and into the WFP-heap blobs.
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

    /// Build a `FWP_RANGE0`-backed port range condition.
    /// `valueLow` / `valueHigh` are `FWP_UINT16` (inline u16, no
    /// pointer indirection).
    fn fc_port_range(
        &mut self,
        field: GUID,
        lo: u16,
        hi: u16,
    ) -> FWPM_FILTER_CONDITION0 {
        let range = Box::new(FWP_RANGE0 {
            valueLow: FWP_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_VALUE0_0 { uint16: lo },
            },
            valueHigh: FWP_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_VALUE0_0 { uint16: hi },
            },
        });
        let raw_ptr: *mut FWP_RANGE0 = range.as_ref() as *const _ as *mut _;
        self.ranges.push(range);
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { rangeValue: raw_ptr },
            },
        }
    }

    /// Build a `FWP_RANGE0`-backed IPv4 address range condition.
    /// `valueLow` / `valueHigh` are `FWP_UINT32` carrying the
    /// addresses in **host byte order** (matching the same
    /// convention used by `fc_v4_mask` and the upstream MSDN
    /// IP-filter sample).
    fn fc_v4_range(
        &mut self,
        field: GUID,
        lo: Ipv4Addr,
        hi: Ipv4Addr,
    ) -> FWPM_FILTER_CONDITION0 {
        let range = Box::new(FWP_RANGE0 {
            valueLow: FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: u32::from(lo) },
            },
            valueHigh: FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: u32::from(hi) },
            },
        });
        let raw_ptr: *mut FWP_RANGE0 = range.as_ref() as *const _ as *mut _;
        self.ranges.push(range);
        FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { rangeValue: raw_ptr },
            },
        }
    }

    /// Resolve `path` to an "app id" `FWP_BYTE_BLOB` via
    /// `FwpmGetAppIdFromFileName0`, store the WFP-heap pointer for
    /// later release in `Drop`, and build the matching
    /// `FWPM_CONDITION_ALE_APP_ID` condition.
    fn fc_app_id(&mut self, path: &Path) -> Result<FWPM_FILTER_CONDITION0, WfpError> {
        // Encode the OsStr as UTF-16 + NUL — handles any Windows path
        // including those that aren't valid UTF-8.
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut blob_ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob_ptr) };
        if status != 0 {
            return Err(WfpError::AppIdFromFileName(status));
        }
        // Track for release. Safety: blob_ptr is a WFP-heap pointer
        // owned by us; no aliasing with anything else.
        self.app_id_blobs.push(blob_ptr);

        Ok(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob_ptr },
            },
        })
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

impl Drop for CompiledConditions {
    fn drop(&mut self) {
        // Release every WFP-heap `FWP_BYTE_BLOB` we obtained from
        // `FwpmGetAppIdFromFileName0`. The Vec<Box<T>> fields above
        // free themselves through their normal Drop impls; only the
        // app-id blobs need an explicit Win32 free.
        for blob_ptr in self.app_id_blobs.drain(..) {
            if !blob_ptr.is_null() {
                // FwpmFreeMemory0 takes `*mut *mut c_void` — it null-
                // patches the caller's pointer after freeing. We
                // keep a local copy so the cast is to a stack slot
                // rather than to a Vec element pointer that could
                // theoretically be re-borrowed elsewhere in the loop.
                let mut local = blob_ptr as *mut std::ffi::c_void;
                unsafe { FwpmFreeMemory0(&mut local) };
            }
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
        let compiled = compile(&conds).expect("compile failed");
        assert_eq!(compiled.as_native_slice().len(), 4);
    }

    /// Range conditions allocate exactly one `FWP_RANGE0` box per
    /// range — both port-range and v4-addr-range live in the same
    /// `ranges` storage Vec.
    #[test]
    fn compile_range_storage_count() {
        let conds = [
            FilterCondition::RemotePortRange(20, 21),
            FilterCondition::RemoteAddrV4Range(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 10),
            ),
        ];
        let compiled = compile(&conds).expect("compile failed");
        assert_eq!(compiled.ranges.len(), 2);
        // Each range condition emits one native FWPM_FILTER_CONDITION0,
        // not two — the range struct holds both endpoints.
        assert_eq!(compiled.as_native_slice().len(), 2);
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
        let compiled = compile(&conds).expect("compile failed");
        assert_eq!(compiled.v4_masks.len(), 2);
        assert_eq!(compiled.v6_masks.len(), 0);
    }

    /// AppPath against a real always-present file resolves to a
    /// non-null FWP_BYTE_BLOB pointer, and Drop releases it cleanly
    /// without panicking. `FwpmGetAppIdFromFileName0` is documented
    /// as not requiring admin (only path-resolution rights), so this
    /// runs in the default `cargo test` profile.
    #[test]
    fn compile_app_path_resolves_blob() {
        let conds = [FilterCondition::AppPath(PathBuf::from(
            r"C:\Windows\System32\cmd.exe",
        ))];
        let compiled = compile(&conds).expect("compile against cmd.exe failed");
        assert_eq!(compiled.app_id_blobs.len(), 1);
        assert!(
            !compiled.app_id_blobs[0].is_null(),
            "FwpmGetAppIdFromFileName0 returned a null blob pointer"
        );
        // Compiled drops here — Drop calls FwpmFreeMemory0 on the
        // blob. No panic == release path is sound.
    }

    /// Compilation against a missing path surfaces the
    /// `FwpmGetAppIdFromFileName0` error instead of panicking. Uses
    /// a path that cannot exist on any Windows install (drive letter
    /// `Z:` is conventionally unmapped on default installs; the
    /// filename is also a sentinel).
    #[test]
    fn compile_app_path_missing_file_returns_error() {
        let conds = [FilterCondition::AppPath(PathBuf::from(
            r"Z:\simplewall_rs_does_not_exist_53b8b2d8.exe",
        ))];
        match compile(&conds) {
            Err(WfpError::AppIdFromFileName(_)) => {} // expected
            Err(e) => panic!("expected AppIdFromFileName, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}

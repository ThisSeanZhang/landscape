use std::net::{Ipv4Addr, Ipv6Addr};

use libbpf_rs::{MapCore, MapFlags};

use crate::bpf_error::LdEbpfResult;

use super::{apply_raw_map_diff, diff_raw_map, snapshot_raw_map, RawEbpfMapEntries};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NatMappingKeyV4 {
    pub gress: u8,
    pub l4proto: u8,
    pub from_port: u16,
    pub from_addr: u32,
}

unsafe impl plain::Plain for NatMappingKeyV4 {}

#[derive(Debug, Clone, Copy)]
pub struct StaticNatMappingV4Item {
    pub wan_port: u16,
    pub lan_port: u16,
    pub lan_ip: Ipv4Addr,
    pub l4_protocol: u8,
}

#[derive(Debug)]
pub struct StaticNatMappingV6Item {
    pub wan_port: u16,
    pub lan_port: u16,
    pub lan_ip: Ipv6Addr,
    pub l4_protocol: u8,
}

fn reconcile_raw_map<M: MapCore>(map: &M, desired: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let current = snapshot_raw_map(map)?;
    let diff = diff_raw_map(&current, &desired);
    apply_raw_map_diff(map, diff)
}

fn update_raw_entries<M: MapCore>(map: &M, entries: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let entry_count = entries.len() as u32;
    let key_len: usize = entries.keys().map(Vec::len).sum();
    let value_len: usize = entries.values().map(Vec::len).sum();
    let mut keys = Vec::with_capacity(key_len);
    let mut values = Vec::with_capacity(value_len);
    for (key, value) in entries {
        keys.extend_from_slice(&key);
        values.extend_from_slice(&value);
    }
    map.update_batch(&keys, &values, entry_count, MapFlags::ANY, MapFlags::ANY)?;
    Ok(())
}

pub mod v4;
pub mod v6;

pub use v4::{
    add_static_nat4_mapping_v3, build_static_nat4_entries, reconcile_static_nat4_entries,
    reconcile_static_nat4_map,
};
pub use v6::{
    add_static_nat6_mapping, build_static_nat6_entries, reconcile_static_nat6_entries,
    reconcile_static_nat6_map,
};

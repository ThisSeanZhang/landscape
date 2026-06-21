use std::net::{Ipv4Addr, Ipv6Addr};

use landscape_common::iface::nat::{
    RuntimeStaticNatMappingV4Config, RuntimeStaticNatMappingV6Config,
};
use libbpf_rs::{MapCore, MapFlags};

use crate::bpf_error::LdEbpfResult;
use crate::{
    map_setting::share_map::types::{
        nat4_mapping_value_v3, static_nat_mapping_key_v6, static_nat_mapping_value_v6,
    },
    LANDSCAPE_IPV6_TYPE, MAP_PATHS, NAT_MAPPING_EGRESS, NAT_MAPPING_INGRESS,
};

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

pub fn build_static_nat4_entries(configs: &[RuntimeStaticNatMappingV4Config]) -> RawEbpfMapEntries {
    let mut entries = RawEbpfMapEntries::new();
    for config in configs {
        let lan_ip = config.lan_ipv4;
        for l4_protocol in &config.l4_protocols {
            for pair in &config.mapping_pair_ports {
                insert_static_nat4_item_entries(
                    &mut entries,
                    StaticNatMappingV4Item {
                        wan_port: pair.wan_port,
                        lan_port: pair.lan_port,
                        lan_ip,
                        l4_protocol: *l4_protocol,
                    },
                );
            }
        }
    }
    entries
}

pub fn build_static_nat6_entries(configs: &[RuntimeStaticNatMappingV6Config]) -> RawEbpfMapEntries {
    let mut entries = RawEbpfMapEntries::new();
    for config in configs {
        let lan_ip = config.lan_ipv6;
        for l4_protocol in &config.l4_protocols {
            for pair in &config.mapping_pair_ports {
                insert_static_nat6_item_entries(
                    &mut entries,
                    StaticNatMappingV6Item {
                        wan_port: pair.wan_port,
                        lan_port: pair.lan_port,
                        lan_ip,
                        l4_protocol: *l4_protocol,
                    },
                );
            }
        }
    }
    entries
}

pub fn reconcile_static_nat4_entries(desired: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let nat4_st_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat4_st_map)?;
    reconcile_raw_map(&nat4_st_map, desired)
}

pub fn reconcile_static_nat6_entries(desired: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let static_nat_mappings =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat6_static_mappings)?;
    reconcile_raw_map(&static_nat_mappings, desired)
}

pub fn reconcile_static_nat4_map(configs: &[RuntimeStaticNatMappingV4Config]) -> LdEbpfResult<()> {
    reconcile_static_nat4_entries(build_static_nat4_entries(configs))
}

pub fn reconcile_static_nat6_map(configs: &[RuntimeStaticNatMappingV6Config]) -> LdEbpfResult<()> {
    reconcile_static_nat6_entries(build_static_nat6_entries(configs))
}

fn reconcile_raw_map<M: MapCore>(map: &M, desired: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let current = snapshot_raw_map(map)?;
    let diff = diff_raw_map(&current, &desired);
    apply_raw_map_diff(map, diff)
}

fn insert_static_nat4_item_entries(
    entries: &mut RawEbpfMapEntries,
    static_mapping: StaticNatMappingV4Item,
) {
    let ingress_mapping_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto: static_mapping.l4_protocol,
        from_port: static_mapping.wan_port.to_be(),
        from_addr: 0,
    };

    let egress_mapping_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_EGRESS,
        l4proto: static_mapping.l4_protocol,
        from_port: static_mapping.lan_port.to_be(),
        from_addr: static_mapping.lan_ip.to_bits().to_be(),
    };

    let mut ingress_mapping_value = nat4_mapping_value_v3::default();
    let mut egress_mapping_value = nat4_mapping_value_v3::default();

    ingress_mapping_value.port = static_mapping.lan_port.to_be();
    ingress_mapping_value.addr = static_mapping.lan_ip.to_bits().to_be();
    ingress_mapping_value.is_static = 1;

    egress_mapping_value.port = static_mapping.wan_port.to_be();
    egress_mapping_value.is_static = 1;

    entries.insert(
        unsafe { plain::as_bytes(&ingress_mapping_key) }.to_vec(),
        unsafe { plain::as_bytes(&ingress_mapping_value) }.to_vec(),
    );
    entries.insert(
        unsafe { plain::as_bytes(&egress_mapping_key) }.to_vec(),
        unsafe { plain::as_bytes(&egress_mapping_value) }.to_vec(),
    );
}

fn insert_static_nat6_item_entries(
    entries: &mut RawEbpfMapEntries,
    static_mapping: StaticNatMappingV6Item,
) {
    let mut ingress_mapping_key = static_nat_mapping_key_v6 {
        prefixlen: 64,
        port: static_mapping.wan_port.to_be(),
        gress: NAT_MAPPING_INGRESS,
        l4_protocol: static_mapping.l4_protocol,
        ..Default::default()
    };

    let mut egress_mapping_key = static_nat_mapping_key_v6 {
        prefixlen: 192,
        port: static_mapping.lan_port.to_be(),
        gress: NAT_MAPPING_EGRESS,
        l4_protocol: static_mapping.l4_protocol,
        ..Default::default()
    };

    let mut ingress_mapping_value = static_nat_mapping_value_v6::default();
    let mut egress_mapping_value = static_nat_mapping_value_v6::default();

    ingress_mapping_value.port = static_mapping.lan_port.to_be();
    egress_mapping_value.port = static_mapping.wan_port.to_be();
    ingress_mapping_value.is_static = 1;
    egress_mapping_value.is_static = 1;

    let ipv6_addr = static_mapping.lan_ip;
    ingress_mapping_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    egress_mapping_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    egress_mapping_key.addr.bytes = ipv6_addr.to_bits().to_be_bytes();
    ingress_mapping_value.addr.bytes = ipv6_addr.to_bits().to_be_bytes();

    entries.insert(
        unsafe { plain::as_bytes(&ingress_mapping_key) }.to_vec(),
        unsafe { plain::as_bytes(&ingress_mapping_value) }.to_vec(),
    );
    entries.insert(
        unsafe { plain::as_bytes(&egress_mapping_key) }.to_vec(),
        unsafe { plain::as_bytes(&egress_mapping_value) }.to_vec(),
    );
}

pub(crate) fn add_static_nat4_mapping<'obj, T, I>(nat4_st_map: &T, mappings: I)
where
    T: MapCore,
    I: IntoIterator<Item = StaticNatMappingV4Item>,
    I::IntoIter: ExactSizeIterator,
{
    let desired = raw_static_nat4_entries_from_items(mappings);
    if desired.is_empty() {
        return;
    }
    if let Err(e) = update_raw_entries(nat4_st_map, desired) {
        tracing::error!("update nat4_st_map error:{e:?}");
    }
}

pub fn add_static_nat4_mapping_v3<'obj, T, I>(nat4_st_map: &T, mappings: I)
where
    T: MapCore,
    I: IntoIterator<Item = StaticNatMappingV4Item>,
    I::IntoIter: ExactSizeIterator,
{
    add_static_nat4_mapping(nat4_st_map, mappings)
}

pub fn add_static_nat6_mapping<'obj, T, I>(static_nat_mappings: &T, mappings: I)
where
    T: MapCore,
    I: IntoIterator<Item = StaticNatMappingV6Item>,
    I::IntoIter: ExactSizeIterator,
{
    let desired = raw_static_nat6_entries_from_items(mappings);
    if desired.is_empty() {
        return;
    }
    if let Err(e) = update_raw_entries(static_nat_mappings, desired) {
        tracing::error!("update static_nat_mappings error:{e:?}");
    }
}

fn raw_static_nat4_entries_from_items<I>(mappings: I) -> RawEbpfMapEntries
where
    I: IntoIterator<Item = StaticNatMappingV4Item>,
{
    let mut entries = RawEbpfMapEntries::new();
    for mapping in mappings {
        insert_static_nat4_item_entries(&mut entries, mapping);
    }
    entries
}

fn raw_static_nat6_entries_from_items<I>(mappings: I) -> RawEbpfMapEntries
where
    I: IntoIterator<Item = StaticNatMappingV6Item>,
{
    let mut entries = RawEbpfMapEntries::new();
    for mapping in mappings {
        insert_static_nat6_item_entries(&mut entries, mapping);
    }
    entries
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

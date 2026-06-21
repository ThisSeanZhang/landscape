use landscape_common::iface::nat::RuntimeStaticNatMappingV4Config;
use libbpf_rs::MapCore;

use crate::bpf_error::LdEbpfResult;
use crate::map_setting::share_map::types::nat4_mapping_value_v3;
use crate::{MAP_PATHS, NAT_MAPPING_EGRESS, NAT_MAPPING_INGRESS};

use super::super::RawEbpfMapEntries;
use super::{reconcile_raw_map, update_raw_entries, NatMappingKeyV4, StaticNatMappingV4Item};

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

pub fn reconcile_static_nat4_entries(desired: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let nat4_st_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat4_st_map)?;
    reconcile_raw_map(&nat4_st_map, desired)
}

pub fn reconcile_static_nat4_map(configs: &[RuntimeStaticNatMappingV4Config]) -> LdEbpfResult<()> {
    reconcile_static_nat4_entries(build_static_nat4_entries(configs))
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

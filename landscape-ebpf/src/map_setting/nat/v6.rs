use landscape_common::iface::nat::{RuntimeStaticNatMappingV6Config, StaticNatV6PortConfig};
use libbpf_rs::MapCore;

use crate::bpf_error::LdEbpfResult;
use crate::map_setting::share_map::types::{static_nat6_mapping_key, static_nat6_mapping_value};
use crate::{LANDSCAPE_IPV6_TYPE, MAP_PATHS, NAT_MAPPING_EGRESS, NAT_MAPPING_INGRESS};

use super::super::RawEbpfMapEntries;
use super::{reconcile_raw_map, update_raw_entries, StaticNatMappingV6Item};

pub fn build_static_nat6_entries(configs: &[RuntimeStaticNatMappingV6Config]) -> RawEbpfMapEntries {
    let mut entries = RawEbpfMapEntries::new();
    for config in configs {
        let lan_ip = config.lan_ipv6;
        for l4_protocol in &config.l4_protocols {
            match &config.port_config {
                StaticNatV6PortConfig::All => {
                    insert_static_nat6_item_entries(
                        &mut entries,
                        StaticNatMappingV6Item {
                            wan_port: 0,
                            lan_port: 0,
                            lan_ip,
                            l4_protocol: *l4_protocol,
                        },
                    );
                }
                StaticNatV6PortConfig::Ports { ports } => {
                    for port in ports {
                        insert_static_nat6_item_entries(
                            &mut entries,
                            StaticNatMappingV6Item {
                                wan_port: *port,
                                lan_port: *port,
                                lan_ip,
                                l4_protocol: *l4_protocol,
                            },
                        );
                    }
                }
            }
        }
    }
    entries
}

pub fn reconcile_static_nat6_entries(desired: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let static_nat_mappings =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat6_static_mappings)?;
    reconcile_raw_map(&static_nat_mappings, desired)
}

pub fn reconcile_static_nat6_map(configs: &[RuntimeStaticNatMappingV6Config]) -> LdEbpfResult<()> {
    reconcile_static_nat6_entries(build_static_nat6_entries(configs))
}

fn insert_static_nat6_item_entries(
    entries: &mut RawEbpfMapEntries,
    static_mapping: StaticNatMappingV6Item,
) {
    let mut ingress_mapping_key = static_nat6_mapping_key {
        prefixlen: 64,
        port: static_mapping.wan_port.to_be(),
        gress: NAT_MAPPING_INGRESS,
        l4_protocol: static_mapping.l4_protocol,
        ..Default::default()
    };

    let mut egress_mapping_key = static_nat6_mapping_key {
        prefixlen: 192,
        port: static_mapping.lan_port.to_be(),
        gress: NAT_MAPPING_EGRESS,
        l4_protocol: static_mapping.l4_protocol,
        ..Default::default()
    };

    let mut ingress_mapping_value = static_nat6_mapping_value::default();
    let mut egress_mapping_value = static_nat6_mapping_value::default();

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

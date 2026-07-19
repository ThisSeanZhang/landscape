use landscape_common::config_service::static_nat::config6::{
    RuntimeStaticNatMappingV6Config, StaticNatV6PortConfig,
};
use libbpf_rs::MapCore;

use crate::bpf_error::LdEbpfResult;
use crate::map_setting::share_map::types::{static_nat6_mapping_key, static_nat6_mapping_value};
use crate::MAP_PATHS;

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
                        StaticNatMappingV6Item { port: 0, lan_ip, l4_protocol: *l4_protocol },
                    );
                }
                StaticNatV6PortConfig::Ports { ports } => {
                    for port in ports {
                        insert_static_nat6_item_entries(
                            &mut entries,
                            StaticNatMappingV6Item {
                                port: *port,
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
    let static_nat_mappings = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat6_static_map)?;
    reconcile_raw_map(&static_nat_mappings, desired)
}

pub fn reconcile_static_nat6_map(configs: &[RuntimeStaticNatMappingV6Config]) -> LdEbpfResult<()> {
    reconcile_static_nat6_entries(build_static_nat6_entries(configs))
}

fn insert_static_nat6_item_entries(
    entries: &mut RawEbpfMapEntries,
    static_mapping: StaticNatMappingV6Item,
) {
    let ipv6_addr = static_mapping.lan_ip;
    let ip_bytes = ipv6_addr.to_bits().to_be_bytes();

    let mut key = static_nat6_mapping_key {
        port: static_mapping.port.to_be(),
        l4_protocol: static_mapping.l4_protocol,
        ..Default::default()
    };
    key.ip_suffix.copy_from_slice(&ip_bytes[8..16]);

    let mut value = static_nat6_mapping_value::default();
    value.lan_prefix.copy_from_slice(&ip_bytes[0..8]);

    entries.insert(
        unsafe { plain::as_bytes(&key) }.to_vec(),
        unsafe { plain::as_bytes(&value) }.to_vec(),
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

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn decode_single_entry(
        config: RuntimeStaticNatMappingV6Config,
    ) -> (static_nat6_mapping_key, static_nat6_mapping_value) {
        let entries = build_static_nat6_entries(&[config]);
        assert_eq!(entries.len(), 1);
        let (key, value) = entries.into_iter().next().unwrap();
        (unsafe { std::ptr::read_unaligned(key.as_ptr().cast()) }, unsafe {
            std::ptr::read_unaligned(value.as_ptr().cast())
        })
    }

    #[test]
    fn suffix_only_target_uses_exact_suffix_and_zero_prefix() {
        let target = "::1234:5678".parse::<Ipv6Addr>().unwrap();
        let (key, value) = decode_single_entry(RuntimeStaticNatMappingV6Config {
            port_config: StaticNatV6PortConfig::Ports { ports: vec![53] },
            lan_ipv6: target,
            l4_protocols: vec![17],
        });

        assert_eq!(key.port, 53u16.to_be());
        assert_eq!(key.l4_protocol, 17);
        assert_eq!(&key.ip_suffix, &target.octets()[8..]);
        assert_eq!(value.lan_prefix, [0; 8]);
    }

    #[test]
    fn full_target_splits_prefix_and_suffix() {
        let target = "fd00:1234:5678:abcd::42".parse::<Ipv6Addr>().unwrap();
        let (key, value) = decode_single_entry(RuntimeStaticNatMappingV6Config {
            port_config: StaticNatV6PortConfig::All,
            lan_ipv6: target,
            l4_protocols: vec![6],
        });

        assert_eq!(key.port, 0);
        assert_eq!(key.l4_protocol, 6);
        assert_eq!(&key.ip_suffix, &target.octets()[8..]);
        assert_eq!(&value.lan_prefix, &target.octets()[..8]);
    }
}

use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use landscape_common::firewall::{FirewallRuleItem, FirewallRuleMark, LandscapeIpType};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags,
};

mod share_map {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/share_map.skel.rs"));
}

use share_map::*;

use crate::{
    map_setting::share_map::types::{u_inet_addr, wan_ip_info_key, wan_ip_info_value},
    LandscapeMapPath, LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE, MAP_PATHS,
};

pub mod dns;
pub mod flow;
pub mod flow_dns;
pub mod flow_target;
pub mod flow_wanip;
pub mod metric;
pub mod nat;
pub mod route;

pub(crate) fn init_path(paths: LandscapeMapPath) {
    let landscape_builder = ShareMapSkelBuilder::default();
    // landscape_builder.obj_builder.debug(true);
    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = landscape_builder.open(&mut open_object).unwrap();

    landscape_open.maps.wan_ipv4_binding.set_pin_path(&paths.wan_ip).unwrap();
    landscape_open.maps.static_nat_mappings.set_pin_path(&paths.static_nat_mappings).unwrap();

    // firewall
    landscape_open.maps.firewall_block_ip4_map.set_pin_path(&paths.firewall_ipv4_block).unwrap();
    landscape_open.maps.firewall_block_ip6_map.set_pin_path(&paths.firewall_ipv6_block).unwrap();
    landscape_open
        .maps
        .firewall_allow_rules_map
        .set_pin_path(&paths.firewall_allow_rules_map)
        .unwrap();
    // flow verdict map
    landscape_open.maps.flow_v_dns_map.set_pin_path(&paths.flow_verdict_dns_map).unwrap();
    landscape_open.maps.flow_v_ip_map.set_pin_path(&paths.flow_verdict_ip_map).unwrap();
    landscape_open.maps.flow_match_map.set_pin_path(&paths.flow_match_map).unwrap();
    landscape_open.maps.flow_target_map.set_pin_path(&paths.flow_target_map).unwrap();
    landscape_open.maps.dns_flow_socks.set_pin_path(&paths.dns_flow_socks).unwrap();

    // metric
    landscape_open.maps.metric_bucket_map.set_pin_path(&paths.metric_map).unwrap();
    landscape_open.maps.nat_conn_events.set_pin_path(&paths.nat_conn_events).unwrap();

    landscape_open.maps.firewall_conn_events.set_pin_path(&paths.firewall_conn_events).unwrap();
    landscape_open
        .maps
        .firewall_conn_metric_events
        .set_pin_path(&paths.firewall_conn_metric_events)
        .unwrap();

    landscape_open.maps.rt_lan_map.set_pin_path(&paths.rt_lan_map).unwrap();
    landscape_open.maps.rt_target_map.set_pin_path(&paths.rt_target_map).unwrap();

    // route ip mac cache table
    landscape_open.maps.ip_mac_tab.set_pin_path(&paths.ip_mac_tab).unwrap();

    let _landscape_skel = landscape_open.load().unwrap();
}

pub fn add_ipv6_wan_ip(ifindex: u32, addr: Ipv6Addr, mask: u8) {
    add_wan_ip(ifindex, IpAddr::V6(addr), mask, LANDSCAPE_IPV6_TYPE);
}

pub fn add_ipv4_wan_ip(ifindex: u32, addr: Ipv4Addr, mask: u8) {
    add_wan_ip(ifindex, IpAddr::V4(addr), mask, LANDSCAPE_IPV4_TYPE);
}

fn add_wan_ip(ifindex: u32, addr: IpAddr, mask: u8, l3_protocol: u8) {
    tracing::debug!("add wan index - 1: {ifindex:?}");
    let wan_ipv4_binding = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wan_ip).unwrap();

    let mut key = wan_ip_info_key::default();
    let mut value = wan_ip_info_value::default();
    key.ifindex = ifindex;
    key.l3_protocol = l3_protocol;
    value.mask = mask;

    match addr {
        std::net::IpAddr::V4(ipv4_addr) => {
            value.addr.ip = ipv4_addr.to_bits().to_be();
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            value.addr = u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() };
        }
    };

    let key = unsafe { plain::as_bytes(&key) };
    let value = unsafe { plain::as_bytes(&value) };

    // let addr_num: u32 = .clone().into();
    if let Err(e) = wan_ipv4_binding.update(key, value, MapFlags::ANY) {
        tracing::error!("setting wan ip error:{e:?}");
    } else {
        tracing::info!("setting wan index: {ifindex:?} addr:{addr:?}");
    }

    // if LAND_ARGS.export_manager {
    //     let static_nat_mappings =
    //         libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.static_nat_mappings).unwrap();
    //     crate::nat::set_nat_static_mapping(
    //         (addr.clone(), LAND_ARGS.port, addr, LAND_ARGS.port),
    //         &static_nat_mappings,
    //     );
    // }
}

pub fn del_ipv6_wan_ip(ifindex: u32) {
    del_wan_ip(ifindex, LANDSCAPE_IPV6_TYPE);
}

pub fn del_ipv4_wan_ip(ifindex: u32) {
    del_wan_ip(ifindex, LANDSCAPE_IPV4_TYPE);
}

fn del_wan_ip(ifindex: u32, l3_protocol: u8) {
    tracing::debug!("del wan index - 1: {ifindex:?}");
    let wan_ipv4_binding = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wan_ip).unwrap();
    let mut key = wan_ip_info_key::default();
    key.ifindex = ifindex;
    key.l3_protocol = l3_protocol;

    let key = unsafe { plain::as_bytes(&key) };
    if let Err(e) = wan_ipv4_binding.delete(key) {
        tracing::error!("delete wan ip error:{e:?}");
    } else {
        tracing::info!("delete wan index: {ifindex:?}");
    }
}

pub fn add_firewall_rule(rules: Vec<FirewallRuleMark>) {
    let firewall_allow_rules_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.firewall_allow_rules_map).unwrap();

    if let Err(e) = add_firewall_rules(&firewall_allow_rules_map, rules) {
        tracing::error!("add_lan_ip_mark:{e:?}");
    }
}

pub fn del_firewall_rule(rule_items: Vec<FirewallRuleItem>) {
    let firewall_allow_rules_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.firewall_allow_rules_map).unwrap();

    if let Err(e) = del_firewall_rules(&firewall_allow_rules_map, rule_items) {
        tracing::error!("del_lan_ip_mark:{e:?}");
    }
}

fn add_firewall_rules<'obj, T>(map: &T, rules: Vec<FirewallRuleMark>) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    use crate::map_setting::types::firewall_static_ct_action;
    if rules.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];

    let count = rules.len() as u32;
    for FirewallRuleMark { item, mark } in rules.into_iter() {
        let item = conver_rule(item);
        let value = firewall_static_ct_action { mark: mark.into() };
        keys.extend_from_slice(unsafe { plain::as_bytes(&item) });
        values.extend_from_slice(unsafe { plain::as_bytes(&value) });
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

fn del_firewall_rules<'obj, T>(map: &T, rules: Vec<FirewallRuleItem>) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if rules.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];

    let count = rules.len() as u32;
    for rule in rules.into_iter() {
        let rule = conver_rule(rule);
        keys.extend_from_slice(unsafe { plain::as_bytes(&rule) });
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

fn conver_rule(rule: FirewallRuleItem) -> crate::map_setting::types::firewall_static_rule_key {
    use crate::map_setting::types::u_inet_addr;

    let mut prefixlen = 8;
    let (ip_type, remote_address) = match rule.address {
        std::net::IpAddr::V4(ipv4_addr) => {
            let mut ip = u_inet_addr::default();
            ip.ip = ipv4_addr.to_bits().to_be();
            (LandscapeIpType::Ipv4, ip)
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            (LandscapeIpType::Ipv6, u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() })
        }
    };
    let mut rule_port = 0;
    let mut ip_protocol = 0;

    if let Some(proto) = rule.ip_protocol {
        ip_protocol = proto as u8;
        prefixlen += 8;
        if let Some(port) = rule.local_port {
            prefixlen += 16;
            rule_port = port;
        }
    }

    crate::map_setting::types::firewall_static_rule_key {
        prefixlen: rule.ip_prefixlen as u32 + prefixlen,
        ip_type: ip_type as u8,
        ip_protocol,
        local_port: rule_port.to_be(),
        remote_address,
    }
}

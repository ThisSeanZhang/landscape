use std::{mem::MaybeUninit, net::Ipv4Addr};

use landscape_common::{
    firewall::{FirewallRuleItem, FirewallRuleMark, LandscapeIpType},
    ip_mark::{IpConfig, IpMarkInfo},
};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags,
};

mod share_map {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/share_map.skel.rs"));
}

use share_map::*;
use types::{ipv4_lpm_key, ipv4_mark_action};

use crate::{LandscapeMapPath, MAP_PATHS};

pub(crate) fn init_path(paths: LandscapeMapPath) {
    let landscape_builder = ShareMapSkelBuilder::default();
    // landscape_builder.obj_builder.debug(true);
    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = landscape_builder.open(&mut open_object).unwrap();

    landscape_open.maps.wan_ipv4_binding.set_pin_path(&paths.wan_ip).unwrap();
    landscape_open.maps.static_nat_mappings.set_pin_path(&paths.static_nat_mappings).unwrap();
    landscape_open.maps.nat_expose_ports.set_pin_path(&paths.nat_expose_ports).unwrap();
    landscape_open.maps.packet_mark_map.set_pin_path(&paths.packet_mark).unwrap();
    landscape_open.maps.lanip_mark_map.set_pin_path(&paths.lanip_mark).unwrap();
    landscape_open.maps.wanip_mark_map.set_pin_path(&paths.wanip_mark).unwrap();
    landscape_open.maps.redirect_index_map.set_pin_path(&paths.redirect_index).unwrap();

    // firewall
    landscape_open.maps.firewall_block_ip4_map.set_pin_path(&paths.firewall_ipv4_block).unwrap();
    landscape_open.maps.firewall_block_ip6_map.set_pin_path(&paths.firewall_ipv6_block).unwrap();
    landscape_open
        .maps
        .firewall_allow_rules_map
        .set_pin_path(&paths.firewall_allow_rules_map)
        .unwrap();
    let _landscape_skel = landscape_open.load().unwrap();
}

pub fn add_wan_ip(ifindex: u32, addr: Ipv4Addr) {
    tracing::debug!("add wan index - 1: {ifindex:?}");
    let wan_ipv4_binding = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wan_ip).unwrap();

    let addr_num: u32 = addr.clone().into();
    if let Err(e) =
        wan_ipv4_binding.update(&ifindex.to_le_bytes(), &addr_num.to_be_bytes(), MapFlags::ANY)
    {
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

pub fn del_wan_ip(ifindex: u32) {
    tracing::debug!("del wan index - 1: {ifindex:?}");
    let wan_ipv4_binding = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wan_ip).unwrap();
    if let Err(e) = wan_ipv4_binding.delete(&ifindex.to_le_bytes()) {
        tracing::error!("delete wan ip error:{e:?}");
    } else {
        tracing::info!("delete wan index: {ifindex:?}");
    }
}

pub fn add_expose_ports(ports: Vec<u16>) {
    let nat_expose_ports = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat_expose_ports)
    {
        Ok(nat_expose_ports) => nat_expose_ports,
        Err(e) => {
            tracing::error!("reuse map nat_expose_ports error: {e:?}");
            return;
        }
    };

    let mut keys = vec![];
    let mut values = vec![];
    let count = ports.len() as u32;
    for port in ports.iter() {
        keys.extend_from_slice(&port.to_be_bytes());
        values.push(0);
    }
    if let Err(e) =
        nat_expose_ports.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("add_expose_port:{e:?}");
    }
}
pub fn add_expose_port(port: u16) {
    add_expose_ports(vec![port]);
}

pub fn del_expose_port(port: u16) {
    let nat_expose_ports =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.nat_expose_ports).unwrap();
    let key = port.to_be_bytes();
    if let Err(e) = nat_expose_ports.delete(&key) {
        tracing::error!("del_expose_port:{e:?}");
    }
}

pub fn add_wan_ip_mark(ips: Vec<IpMarkInfo>) {
    let wanip_mark_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wanip_mark).unwrap();

    if let Err(e) = add_mark_ip_rules(&wanip_mark_map, ips) {
        tracing::error!("add_wan_ip_mark:{e:?}");
    }
}

pub fn del_wan_ip_mark(ips: Vec<IpConfig>) {
    let wanip_mark_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wanip_mark).unwrap();

    if let Err(e) = del_mark_ip_rules(&wanip_mark_map, ips) {
        tracing::error!("del_wan_ip_mark:{e:?}");
    }
}

pub fn add_lan_ip_mark(ips: Vec<IpMarkInfo>) {
    let lanip_mark_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.lanip_mark).unwrap();

    if let Err(e) = add_mark_ip_rules(&lanip_mark_map, ips) {
        tracing::error!("add_lan_ip_mark:{e:?}");
    }
}

pub fn del_lan_ip_mark(ips: Vec<IpConfig>) {
    let lanip_mark_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.lanip_mark).unwrap();

    if let Err(e) = del_mark_ip_rules(&lanip_mark_map, ips) {
        tracing::error!("del_lan_ip_mark:{e:?}");
    }
}

fn del_mark_ip_rules<'obj, T>(map: &T, ips: Vec<IpConfig>) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }
    let mut keys = vec![];

    let count = ips.len() as u32;
    for cidr in ips.into_iter() {
        let addr: u32 = match cidr.ip {
            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.into(),
            std::net::IpAddr::V6(_) => continue,
        };
        let prefixlen = cidr.prefix;
        let data = ipv4_lpm_key { prefixlen, addr: addr.to_be() };
        keys.extend_from_slice(unsafe { plain::as_bytes(&data) });
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

fn add_mark_ip_rules<'obj, T>(map: &T, ips: Vec<IpMarkInfo>) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];

    let count = ips.len() as u32;
    for IpMarkInfo { mark, cidr } in ips.into_iter() {
        let mark: u32 = mark.into();
        let mark_action = ipv4_mark_action { mark };

        let addr: u32 = match cidr.ip {
            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.into(),
            std::net::IpAddr::V6(_) => continue,
        };
        let prefixlen = cidr.prefix;
        let data = ipv4_lpm_key { prefixlen, addr: addr.to_be() };

        keys.extend_from_slice(unsafe { plain::as_bytes(&data) });
        values.extend_from_slice(unsafe { plain::as_bytes(&mark_action) });
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

pub fn add_dns_marks(ip_marks: Vec<IpMarkInfo>) {
    if ip_marks.is_empty() {
        return;
    }
    let packet_mark_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.packet_mark).unwrap();
    let mut keys = vec![];
    let mut values = vec![];
    let counts = ip_marks.len() as u32;

    for IpMarkInfo { mark, cidr } in ip_marks.into_iter() {
        let mark: u32 = mark.into();
        let mark_action = ipv4_mark_action { mark };

        let addr: u32 = match cidr.ip {
            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.into(),
            std::net::IpAddr::V6(_) => continue,
        };
        let prefixlen = cidr.prefix;
        let data = ipv4_lpm_key { prefixlen, addr: addr.to_be() };

        keys.extend_from_slice(unsafe { plain::as_bytes(&data) });
        values.extend_from_slice(unsafe { plain::as_bytes(&mark_action) });
    }
    if let Err(e) =
        packet_mark_map.update_batch(&keys, &values, counts, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("add_dns_marks error:{e:?}");
    }
}

pub fn del_dns_marks(ip_marks: Vec<IpConfig>) {
    if ip_marks.is_empty() {
        return;
    }

    let packet_mark_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.packet_mark).unwrap();
    let mut keys = vec![];
    let counts = ip_marks.len() as u32;

    for cidr in ip_marks.into_iter() {
        let addr: u32 = match cidr.ip {
            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr.into(),
            std::net::IpAddr::V6(_) => continue,
        };
        let prefixlen = cidr.prefix;
        let data = ipv4_lpm_key { prefixlen, addr: addr.to_be() };
        keys.extend_from_slice(unsafe { plain::as_bytes(&data) });
    }

    if let Err(e) = packet_mark_map.delete_batch(&keys, counts, MapFlags::ANY, MapFlags::ANY) {
        tracing::error!("add_dns_marks error:{e:?}");
    }
}

pub fn add_redirect_iface_pair(redirect_index: u8, ifindex: u32) {
    let redirect_index_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.redirect_index).unwrap();
    let key = [redirect_index];
    let value = ifindex.to_le_bytes();
    if let Err(e) = redirect_index_map.update(&key, &value, MapFlags::ANY) {
        tracing::error!("add block ip error:{e:?}");
    }
}

pub fn del_redirect_iface_pair(redirect_index: u8) {
    let redirect_index_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.redirect_index).unwrap();

    let key = [redirect_index];
    if let Err(e) = redirect_index_map.delete(&key) {
        tracing::error!("add block ip error:{e:?}");
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
    if rule.ip_protocol != 0 {
        prefixlen += 8;
        if let Some(port) = rule.local_port {
            prefixlen += 16;
            rule_port = port;
        }
    }
    crate::map_setting::types::firewall_static_rule_key {
        prefixlen: rule.ip_prefixlen as u32 + prefixlen,
        ip_type: ip_type as u8,
        ip_protocol: rule.ip_protocol,
        local_port: rule_port.to_be(),
        remote_address,
    }
}

use std::os::fd::{AsFd, AsRawFd};

use landscape_common::flow::{FlowMathPair, PacketMatchMark};
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};

use crate::{LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE, MAP_PATHS};

use super::{share_map::types::flow_ip_match_key, types::ipv4_lpm_key};

// const DNS_MATCH_MAX_ENTRIES: u32 = 2048;

pub fn create_inner_flow_match_map() {
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        ..Default::default()
    };

    let key_size = size_of::<ipv4_lpm_key>() as u32;
    let value_size = size_of::<u32>() as u32;

    let map =
        MapHandle::create(MapType::LpmTrie, Option::<&str>::None, key_size, value_size, 8, &opts)
            .expect("failed to create map");

    let map_fd = map.as_fd().as_raw_fd();
    let flow_dns_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_ip_map).unwrap();

    let key = 0_u32;
    let key_value = unsafe { plain::as_bytes(&key) };

    let value_value = unsafe { plain::as_bytes(&map_fd) };

    flow_dns_match_map.update(key_value, value_value, MapFlags::ANY).unwrap();
}

// pub fn create_flow_dns_inner_map(flow_id: u32, data: Vec<FlowDnsMarkInfo>) {
//     #[allow(clippy::needless_update)]
//     let opts = libbpf_sys::bpf_map_create_opts {
//         sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
//         map_flags: libbpf_sys::BPF_F_NO_COMMON_LRU,
//         ..Default::default()
//     };

//     let key_size = 16 as u32;
//     let value_size = size_of::<u32>() as u32;

//     let map = MapHandle::create(
//         MapType::LruHash,
//         Some(&format!("flow_dns_{}", flow_id)),
//         key_size,
//         value_size,
//         DNS_MATCH_MAX_ENTRIES,
//         &opts,
//     )
//     .unwrap();

//     update_flow_dns_rules(&map, data).unwrap();

//     let map_fd = map.as_fd().as_raw_fd();
//     let flow_dns_match_map =
//         libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

//     let key_value = unsafe { plain::as_bytes(&flow_id) };

//     let value_value = unsafe { plain::as_bytes(&map_fd) };

//     flow_dns_match_map.update(key_value, value_value, MapFlags::ANY).unwrap();
// }

// pub fn update_flow_dns_rule(flow_id: u32, data: Vec<FlowDnsMarkInfo>) {
//     let flow_dns_match_map =
//         libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

//     let key_value = unsafe { plain::as_bytes(&flow_id) };
//     if let Ok(Some(fd_id_arr)) = flow_dns_match_map.lookup(key_value, MapFlags::ANY) {
//         if let Ok(fd) = plain::from_bytes::<i32>(&fd_id_arr) {
//             let map = libbpf_rs::MapHandle::from_map_id(*fd as u32).unwrap();
//             update_flow_dns_rules(&map, data).unwrap();
//         }
//     }
// }

// pub fn update_flow_dns_rules<'obj, T>(map: &T, ips: Vec<FlowDnsMarkInfo>) -> libbpf_rs::Result<()>
// where
//     T: MapCore,
// {
//     if ips.is_empty() {
//         return Ok(());
//     }

//     let mut keys = vec![];
//     let mut values = vec![];
//     let count = ips.len() as u32;

//     for FlowDnsMarkInfo { ip, mark } in ips.into_iter() {
//         let mark: u32 = mark.into();

//         let addr = match ip {
//             std::net::IpAddr::V4(ipv4_addr) => {
//                 let mut ip = u_inet_addr::default();
//                 ip.ip = ipv4_addr.to_bits().to_be();
//                 ip
//             }
//             std::net::IpAddr::V6(ipv6_addr) => {
//                 u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() }
//             }
//         };

//         // let key = flow_dns_match_key { addr };

//         keys.extend_from_slice(unsafe { plain::as_bytes(&addr) });
//         values.extend_from_slice(unsafe { plain::as_bytes(&mark) });
//     }

//     map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
// }

pub fn update_flow_match_rule(rules: Vec<FlowMathPair>) {
    if rules.is_empty() {
        return;
    }

    let flow_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_match_map).unwrap();
    let mut keys = vec![];
    let mut values = vec![];
    let counts = rules.len() as u32;

    for FlowMathPair { match_rule, flow_id } in rules.into_iter() {
        let mut match_key = flow_ip_match_key {
            vlan_tci: match_rule.vlan_id.unwrap_or(0),
            tos: match_rule.qos.unwrap_or(0),
            l4_protocol: 6,
            ..Default::default()
        };

        match match_rule.ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
                match_key.src_addr.ip = ipv4_addr.to_bits().to_be();
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
                match_key.src_addr.bits = ipv6_addr.to_bits().to_be_bytes()
            }
        }
        keys.extend_from_slice(unsafe { plain::as_bytes(&match_key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&flow_id) });
    }
    if let Err(e) =
        flow_match_map.update_batch(&keys, &values, counts, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("update_flow_match_rule error:{e:?}");
    }
}

pub fn del_flow_match_rule(rules: Vec<PacketMatchMark>) {
    if rules.is_empty() {
        return;
    }

    let flow_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_match_map).unwrap();
    let mut keys = vec![];
    let counts = rules.len() as u32;

    for match_rule in rules.into_iter() {
        let mut match_key = flow_ip_match_key {
            vlan_tci: match_rule.vlan_id.unwrap_or(0),
            tos: match_rule.qos.unwrap_or(0),
            ..Default::default()
        };

        match match_rule.ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
                match_key.src_addr.ip = ipv4_addr.to_bits().to_be();
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
                match_key.src_addr.bits = ipv6_addr.to_bits().to_be_bytes()
            }
        }

        keys.extend_from_slice(unsafe { plain::as_bytes(&match_key) });
    }
    if let Err(e) = flow_match_map.delete_batch(&keys, counts, MapFlags::ANY, MapFlags::ANY) {
        tracing::error!("del_flow_match_rule error:{e:?}");
    }
}

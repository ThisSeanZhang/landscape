use std::os::fd::{AsFd, AsRawFd};

use landscape_common::flow::FlowDnsMarkInfo;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};

use crate::{
    map_setting::share_map::types::flow_dns_match_key, LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE,
    MAP_PATHS,
};

use super::share_map::types::u_inet_addr;

const DNS_MATCH_MAX_ENTRIES: u32 = 2048;

/// 相当于刷新现有的所有记录
pub fn create_flow_dns_inner_map(flow_id: u32, data: Vec<FlowDnsMarkInfo>) {
    tracing::debug!("{:?}", MAP_PATHS.flow_verdict_dns_map);
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let key_size = size_of::<flow_dns_match_key>() as u32;
    let value_size = size_of::<u32>() as u32;

    let map = MapHandle::create(
        MapType::LruHash,
        Some(format!("flow_dns_{}", flow_id)),
        key_size,
        value_size,
        DNS_MATCH_MAX_ENTRIES,
        &opts,
    )
    .unwrap();

    update_flow_dns_rules(&map, data).unwrap();
    tracing::debug!("put data in map");

    let map_fd = map.as_fd().as_raw_fd();
    let flow_dns_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

    let key = flow_id;
    let key_value = unsafe { plain::as_bytes(&key) };

    let value_value = unsafe { plain::as_bytes(&map_fd) };

    if let Err(e) = flow_dns_match_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        println!("Last OS error: {:?}", last_os_error);
        println!("Last OS error: {e:?}");
    }
}

/// 只更新部分 DNS 指定的规则
pub fn update_flow_dns_rule(flow_id: u32, data: Vec<FlowDnsMarkInfo>) {
    let flow_dns_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

    let key_value = unsafe { plain::as_bytes(&flow_id) };
    if let Ok(Some(fd_id_arr)) = flow_dns_match_map.lookup(key_value, MapFlags::ANY) {
        if let Ok(fd) = plain::from_bytes::<i32>(&fd_id_arr) {
            let map = libbpf_rs::MapHandle::from_map_id(*fd as u32).unwrap();
            update_flow_dns_rules(&map, data).unwrap();
        }
    } else {
        create_flow_dns_inner_map(flow_id, data);
    }
}

fn update_flow_dns_rules<'obj, T>(map: &T, ips: Vec<FlowDnsMarkInfo>) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let count = ips.len() as u32;

    for FlowDnsMarkInfo { ip, mark } in ips.into_iter() {
        let mark: u32 = mark.into();
        let mut key = flow_dns_match_key::default();
        match ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                key.addr.ip = ipv4_addr.to_bits().to_be();
                key.l3_protocol = LANDSCAPE_IPV4_TYPE;
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                key.addr = u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() };
                key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            }
        };

        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&mark) });
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

// pub fn update_flow_dns_mark_rules(flow_id: u32, marks: Vec<FlowDnsMarkInfo>) {
//     let flow_verdict_dns_map =
//         libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

//     if let Err(e) = update_flow_dns_mark_rules_inner(&flow_verdict_dns_map, flow_id, marks) {
//         tracing::error!("update_flow_dns_mark_rules: {e:?}");
//     }
// }

// fn update_flow_dns_mark_rules_inner<'obj, T>(
//     map: &T,
//     flow_id: u32,
//     data: Vec<FlowDnsMarkInfo>,
// ) -> libbpf_rs::Result<()>
// where
//     T: MapCore,
// {
//     if data.is_empty() {
//         return Ok(());
//     }
//     let mut keys = vec![];
//     let mut values = vec![];

//     let counts = data.len() as u32;
//     for FlowDnsMarkInfo { ip, mark } in data.into_iter() {
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

//         let key = flow_dns_match_key { flow_id, addr };
//         let mark: u32 = mark.into();
//         keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
//         values.extend_from_slice(unsafe { plain::as_bytes(&mark) });
//     }

//     map.update_batch(&keys, &values, counts, MapFlags::ANY, MapFlags::ANY)
// }

// pub fn del_flow_dns_mark_rules(flow_id: u32, marks: Vec<FlowDnsMarkInfo>) {
//     let flow_verdict_dns_map =
//         libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

//     if let Err(e) = del_flow_dns_mark_rules_inner(&flow_verdict_dns_map, flow_id, marks) {
//         tracing::error!("del_flow_dns_mark_rules: {e:?}");
//     }
// }

// fn del_flow_dns_mark_rules_inner<'obj, T>(
//     map: &T,
//     flow_id: u32,
//     data: Vec<FlowDnsMarkInfo>,
// ) -> libbpf_rs::Result<()>
// where
//     T: MapCore,
// {
//     if data.is_empty() {
//         return Ok(());
//     }
//     let mut keys = vec![];

//     let counts = data.len() as u32;
//     for FlowDnsMarkInfo { ip, .. } in data.into_iter() {
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

//         let key = flow_dns_match_key { flow_id, addr };
//         keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
//     }

//     map.delete_batch(&keys, counts, MapFlags::ANY, MapFlags::ANY)
// }

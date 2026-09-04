use std::os::fd::{AsFd, AsRawFd};

use landscape_common::flow::FlowMarkInfo;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    maps::{FlowDnsMatchKeyV4, FlowDnsMatchKeyV6, FlowDnsMatchValueV4, FlowDnsMatchValueV6},
    MAP_PATHS,
};

const DNS_MATCH_MAX_ENTRIES: u32 = 10240;

/// 相当于刷新现有的所有记录
pub fn refreash_flow_dns_inner_map(flow_id: u32, data: Vec<FlowMarkInfo>) {
    let flow_dns_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow4_dns_map).unwrap();

    create_flow_dns_inner_map_v4(&flow_dns_match_map, flow_id, &data);

    let flow_dns_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow6_dns_map).unwrap();

    create_flow_dns_inner_map_v6(&flow_dns_match_map, flow_id, &data);
}

// ==================
// IPv4
//

pub(crate) fn create_flow_dns_inner_map_v4<T>(
    flow_dns_outer_map: &T,
    flow_id: u32,
    data: &[FlowMarkInfo],
) where
    T: MapCore,
{
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let key_size = size_of::<FlowDnsMatchKeyV4>() as u32;
    let value_size = size_of::<FlowDnsMatchValueV4>() as u32;

    let map = MapHandle::create(
        MapType::LruHash,
        Some(format!("flow4_dns_{}", flow_id)),
        key_size,
        value_size,
        DNS_MATCH_MAX_ENTRIES,
        &opts,
    )
    .unwrap();

    update_flow_dns_rules_v4(&map, data).unwrap();
    tracing::debug!("put data in map");

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    if let Err(e) = flow_dns_outer_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Last OS error: {:?}", last_os_error);
        tracing::error!("Last OS error: {e:?}");
    }
}

#[allow(clippy::field_reassign_with_default)]
fn update_flow_dns_rules_v4<T>(map: &T, ips: &[FlowMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let mut count = 0;

    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        let mut key = FlowDnsMatchKeyV4::default();
        let mut value = FlowDnsMatchValueV4::default();
        value.mark = *mark;
        value.priority = *priority;
        match ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                key.addr = ipv4_addr.to_bits().to_be();
            }
            std::net::IpAddr::V6(_) => {
                continue;
            }
        };

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY).unwrap();
    }
    Ok(())
}

// ==================
// IPv6
//

pub(crate) fn create_flow_dns_inner_map_v6<T>(
    flow_dns_outer_map: &T,
    flow_id: u32,
    data: &[FlowMarkInfo],
) where
    T: MapCore,
{
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let key_size = size_of::<FlowDnsMatchKeyV6>() as u32;
    let value_size = size_of::<FlowDnsMatchValueV6>() as u32;

    let map = MapHandle::create(
        MapType::LruHash,
        Some(format!("flow6_dns_{}", flow_id)),
        key_size,
        value_size,
        DNS_MATCH_MAX_ENTRIES,
        &opts,
    )
    .unwrap();

    update_flow_dns_rules_v6(&map, data).unwrap();
    tracing::debug!("put data in map");

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    if let Err(e) = flow_dns_outer_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Last OS error: {:?}", last_os_error);
        tracing::error!("Last OS error: {e:?}");
    }
}

#[allow(clippy::field_reassign_with_default)]
fn update_flow_dns_rules_v6<T>(map: &T, ips: &[FlowMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let mut count = 0;

    for FlowMarkInfo { ip, mark, priority } in ips.iter() {
        let mut key = FlowDnsMatchKeyV6::default();
        let mut value = FlowDnsMatchValueV6::default();
        value.mark = *mark;
        value.priority = *priority;
        match ip {
            std::net::IpAddr::V4(_) => {
                continue;
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                key.addr = ipv6_addr.to_bits().to_be_bytes();
            }
        };

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }
    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY).unwrap();
    }
    Ok(())
}

/// 只更新部分 DNS 指定的规则
pub fn update_flow_dns_rule(flow_id: u32, data: Vec<FlowMarkInfo>) {
    let flow_dns_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow4_dns_map).unwrap();

    let key_value = flow_id.as_bytes();
    if let Ok(Some(fd_id_arr)) = flow_dns_match_map.lookup(key_value, MapFlags::ANY) {
        if let Ok(fd) = i32::read_from_bytes(&fd_id_arr) {
            // Note: Sometimes it crashes
            let map = libbpf_rs::MapHandle::from_map_id(fd as u32).unwrap();
            update_flow_dns_rules_v4(&map, &data).unwrap();
        }
    } else {
        create_flow_dns_inner_map_v4(&flow_dns_match_map, flow_id, &data);
    }

    let flow_dns_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow6_dns_map).unwrap();

    let key_value = flow_id.as_bytes();
    if let Ok(Some(fd_id_arr)) = flow_dns_match_map.lookup(key_value, MapFlags::ANY) {
        if let Ok(fd) = i32::read_from_bytes(&fd_id_arr) {
            // Note: Sometimes it crashes
            let map = libbpf_rs::MapHandle::from_map_id(fd as u32).unwrap();
            update_flow_dns_rules_v6(&map, &data).unwrap();
        }
    } else {
        create_flow_dns_inner_map_v6(&flow_dns_match_map, flow_id, &data);
    }
}

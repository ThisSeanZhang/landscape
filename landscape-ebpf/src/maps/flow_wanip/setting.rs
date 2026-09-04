use std::os::fd::{AsFd, AsRawFd};

use landscape_common::flow::ip_mark::IpMarkInfo;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use zerocopy::IntoBytes;

use crate::{
    bpf_error::LdEbpfResult,
    maps::{FlowIpTrieKeyV4, FlowIpTrieKeyV6, FlowIpTrieValueV4, FlowIpTrieValueV6},
    MAP_PATHS,
};

const IP_MATCH_MAX_ENTRIES: u32 = 20840;

pub(crate) fn create_inner_flow_match_map_v4<T>(
    outer_map: &T,
    flow_id: u32,
    ips: &[IpMarkInfo],
) -> LdEbpfResult<()>
where
    T: MapCore,
{
    let sz = size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t;
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        ..Default::default()
    };

    let key_size = size_of::<FlowIpTrieKeyV4>() as u32;
    let value_size = size_of::<FlowIpTrieValueV4>() as u32;

    let map = MapHandle::create(
        MapType::LpmTrie,
        Some(format!("flow4_ip_{}", flow_id)),
        key_size,
        value_size,
        IP_MATCH_MAX_ENTRIES,
        &opts,
    )?;

    add_mark_ip_rules_v4(&map, ips)?;

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    outer_map.update(key_value, value_value, MapFlags::ANY)?;
    Ok(())
}

#[allow(clippy::field_reassign_with_default)]
fn add_mark_ip_rules_v4<T>(map: &T, ips: &[IpMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];

    let mut count = 0;
    for IpMarkInfo { mark, cidr, priority } in ips.iter() {
        let ipv4_addr = match cidr.ip {
            std::net::IpAddr::V4(addr) => addr,
            std::net::IpAddr::V6(_) => continue,
        };

        let mark: u32 = (*mark).into();
        let mut value = FlowIpTrieValueV4::default();
        value.mark = mark;
        value.priority = *priority;

        let mut key = FlowIpTrieKeyV4::default();
        key.addr = ipv4_addr.to_bits().to_be();
        key.prefixlen = cidr.prefix;

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }

    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY).unwrap();
    }
    Ok(())
}

pub fn add_wan_ip_mark(flow_id: u32, ips: Vec<IpMarkInfo>) {
    if let Err(e) = add_wan_ip_mark_inner(flow_id, ips) {
        tracing::error!("{e:?}");
    }
}

pub(crate) fn create_inner_flow_match_map_v6<T>(
    outer_map: &T,
    flow_id: u32,
    ips: &[IpMarkInfo],
) -> LdEbpfResult<()>
where
    T: MapCore,
{
    let sz = size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t;
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        ..Default::default()
    };

    let key_size = size_of::<FlowIpTrieKeyV6>() as u32;
    let value_size = size_of::<FlowIpTrieValueV6>() as u32;

    let map = MapHandle::create(
        MapType::LpmTrie,
        Some(format!("flow_ip_{}", flow_id)),
        key_size,
        value_size,
        IP_MATCH_MAX_ENTRIES,
        &opts,
    )?;

    add_mark_ip_rules_v6(&map, ips)?;

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = flow_id.as_bytes();
    let value_value = map_fd.as_bytes();

    outer_map.update(key_value, value_value, MapFlags::ANY)?;
    Ok(())
}

#[allow(clippy::field_reassign_with_default)]
fn add_mark_ip_rules_v6<T>(map: &T, ips: &[IpMarkInfo]) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];

    let mut count = 0;
    for IpMarkInfo { mark, cidr, priority } in ips.iter() {
        let ipv6_addr = match cidr.ip {
            std::net::IpAddr::V4(_) => continue,
            std::net::IpAddr::V6(addr) => addr,
        };

        let mark: u32 = (*mark).into();
        let mut value = FlowIpTrieValueV6::default();
        value.mark = mark;
        value.priority = *priority;

        let mut key = FlowIpTrieKeyV6::default();
        key.addr.copy_from_slice(&ipv6_addr.to_bits().to_be_bytes());
        key.prefixlen = cidr.prefix;

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
        count += 1;
    }

    if count > 0 {
        map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY).unwrap();
    }
    Ok(())
}

fn add_wan_ip_mark_inner(flow_id: u32, ips: Vec<IpMarkInfo>) -> LdEbpfResult<()> {
    let flow_ip_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow4_ip_map)?;
    create_inner_flow_match_map_v4(&flow_ip_match_map, flow_id, &ips)?;

    let flow_ip_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow6_ip_map)?;
    create_inner_flow_match_map_v6(&flow_ip_match_map, flow_id, &ips)?;
    Ok(())
}

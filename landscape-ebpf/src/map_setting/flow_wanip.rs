use std::os::fd::{AsFd, AsRawFd};

use landscape_common::ip_mark::IpMarkInfo;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};

use crate::{
    bpf_error::LdEbpfResult,
    map_setting::share_map::types::{
        flow_ip_trie_key_v4, flow_ip_trie_key_v6, flow_ip_trie_value_v4, flow_ip_trie_value_v6,
    },
    MAP_PATHS,
};

const IP_MATCH_MAX_ENTRIES: u32 = 20840;

pub(crate) fn create_inner_flow_match_map_v4<'obj, T>(
    outer_map: &T,
    flow_id: u32,
    ips: &Vec<IpMarkInfo>,
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

    let key_size = size_of::<flow_ip_trie_key_v4>() as u32;
    let value_size = size_of::<flow_ip_trie_value_v4>() as u32;

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

    let key = flow_id;
    let key_value = unsafe { plain::as_bytes(&key) };

    let value_value = unsafe { plain::as_bytes(&map_fd) };

    outer_map.update(key_value, value_value, MapFlags::ANY)?;
    Ok(())
}

fn add_mark_ip_rules_v4<'obj, T>(map: &T, ips: &Vec<IpMarkInfo>) -> libbpf_rs::Result<()>
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

        let mark: u32 = mark.clone().into();
        let mut value = flow_ip_trie_value_v4::default();
        value.mark = mark;
        value.priority = *priority;

        let mut key = flow_ip_trie_key_v4::default();
        key.addr = ipv4_addr.to_bits().to_be();
        key.prefixlen = cidr.prefix;

        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&value) });
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

pub(crate) fn create_inner_flow_match_map_v6<'obj, T>(
    outer_map: &T,
    flow_id: u32,
    ips: &Vec<IpMarkInfo>,
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

    let key_size = size_of::<flow_ip_trie_key_v6>() as u32;
    let value_size = size_of::<flow_ip_trie_value_v6>() as u32;

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

    let key = flow_id;
    let key_value = unsafe { plain::as_bytes(&key) };

    let value_value = unsafe { plain::as_bytes(&map_fd) };

    outer_map.update(key_value, value_value, MapFlags::ANY)?;
    Ok(())
}

fn add_mark_ip_rules_v6<'obj, T>(map: &T, ips: &Vec<IpMarkInfo>) -> libbpf_rs::Result<()>
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

        let mark: u32 = mark.clone().into();
        let mut value = flow_ip_trie_value_v6::default();
        value.mark = mark;
        value.priority = *priority;

        let mut key = flow_ip_trie_key_v6::default();
        key.addr.bytes = ipv6_addr.to_bits().to_be_bytes();
        key.prefixlen = cidr.prefix;

        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&value) });
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

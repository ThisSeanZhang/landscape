use std::os::fd::{AsFd, AsRawFd};

use landscape_common::ip_mark::{IpConfig, IpMarkInfo};
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};

use crate::{
    bpf_error::{LandscapeEbpfError, LdEbpfResult},
    LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE, MAP_PATHS,
};

use super::share_map::types::{flow_ip_trie_key, flow_ip_trie_value, u_inet_addr};

const DNS_MATCH_MAX_ENTRIES: u32 = 2048;

fn create_inner_flow_match_map(flow_id: u32, ips: Vec<IpMarkInfo>) -> LdEbpfResult<()> {
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        ..Default::default()
    };

    let key_size = size_of::<flow_ip_trie_key>() as u32;
    let value_size = size_of::<flow_ip_trie_value>() as u32;

    let map = MapHandle::create(
        MapType::LpmTrie,
        Some(format!("flow_ip_{}", flow_id)),
        key_size,
        value_size,
        DNS_MATCH_MAX_ENTRIES,
        &opts,
    )?;

    add_mark_ip_rules(&map, ips)?;

    let map_fd = map.as_fd().as_raw_fd();
    let flow_ip_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_ip_map)?;

    let key = flow_id;
    let key_value = unsafe { plain::as_bytes(&key) };

    let value_value = unsafe { plain::as_bytes(&map_fd) };

    flow_ip_match_map.update(key_value, value_value, MapFlags::ANY)?;
    Ok(())
}

pub fn add_wan_ip_mark(flow_id: u32, ips: Vec<IpMarkInfo>) {
    if let Err(e) = add_wan_ip_mark_inner(flow_id, ips) {
        tracing::debug!("{e:?}");
    }
}

fn add_wan_ip_mark_inner(flow_id: u32, ips: Vec<IpMarkInfo>) -> LdEbpfResult<()> {
    // let flow_ip_match_map =
    //     libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_ip_map).unwrap();
    // let key_bytes = unsafe { plain::as_bytes(&flow_id) };
    // let map_fd = flow_ip_match_map.lookup(key_bytes, MapFlags::ANY)?;

    create_inner_flow_match_map(flow_id, ips)?;
    // if let Some(map) = map_fd {
    //     let inner_map_id = vec_u8_to_u32(&map)?;
    //     let inner_map = libbpf_rs::MapHandle::from_map_id(inner_map_id)?;
    //     add_mark_ip_rules(&inner_map, ips)?;
    // } else {
    //     let inner_map = create_inner_flow_match_map(flow_id)?;

    //     add_mark_ip_rules(&inner_map, ips)?;
    // }
    Ok(())
}

fn vec_u8_to_u32(bytes: &[u8]) -> LdEbpfResult<u32> {
    if bytes.len() == 4 {
        let array: [u8; 4] = bytes.try_into()?;
        Ok(u32::from_le_bytes(array))
    } else {
        Err(LandscapeEbpfError::ParseIdErr)
    }
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
    for IpMarkInfo { mark, cidr, override_dns } in ips.into_iter() {
        let mark: u32 = mark.into();
        let value = flow_ip_trie_value {
            mark,
            override_dns: if override_dns { 1 } else { 0 },
        };

        // TODO: 抽取转换逻辑
        let mut key = flow_ip_trie_key::default();
        match cidr.ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                key.addr.ip = ipv4_addr.to_bits().to_be();
                key.l3_protocol = LANDSCAPE_IPV4_TYPE;
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                key.addr = u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() };
                key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            }
        };
        key.prefixlen = cidr.prefix + 32;

        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&value) });
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

pub fn del_wan_ip_mark(flow_id: u32, ips: Vec<IpConfig>) {
    if let Err(e) = del_wan_ip_mark_inner(flow_id, ips) {
        tracing::debug!("{e:?}");
    }
}

fn del_wan_ip_mark_inner(flow_id: u32, ips: Vec<IpConfig>) -> LdEbpfResult<()> {
    let flow_ip_match_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_ip_map).unwrap();
    let key_bytes = unsafe { plain::as_bytes(&flow_id) };
    let map_fd = flow_ip_match_map.lookup(key_bytes, MapFlags::ANY)?;

    if let Some(map) = map_fd {
        let inner_map_id = vec_u8_to_u32(&map)?;
        let inner_map = libbpf_rs::MapHandle::from_map_id(inner_map_id)?;
        del_mark_ip_rules(&inner_map, ips)?;
    } else {
        // 没找到对应的 map 不用进行删除
    }
    Ok(())
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
        let mut key = flow_ip_trie_key::default();
        match cidr.ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                key.addr.ip = ipv4_addr.to_bits().to_be();
                key.l3_protocol = LANDSCAPE_IPV4_TYPE;
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                key.addr = u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() };
                key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            }
        };
        key.prefixlen = cidr.prefix + 32;
        // let key = flow_ip_trie_key { prefixlen, addr, ..Default::default() };
        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

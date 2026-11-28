use std::os::fd::{AsFd, AsRawFd};

use landscape_common::flow::ip_mark::{IpMarkInfo, PortMarkInfo};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, libbpf_sys};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    bpf_error::LdEbpfResult,
    maps::{
        FlowIpTrieKeyV4, FlowIpTrieKeyV6, FlowIpTrieValueV4, FlowIpTrieValueV6, LandscapeMapPath,
        flow_wanip::types::{
            FLOW_L4_MAX_RULES_PER_FLOW, FlowL4Meta, FlowL4RuleEntry, FlowL4RuleSet,
        },
    },
};

const IP_MATCH_MAX_ENTRIES: u32 = 20840;

static FLOW_L4_META_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

pub fn add_wan_ip_mark(paths: &LandscapeMapPath, flow_id: u32, ips: Vec<IpMarkInfo>) {
    if let Err(e) = add_wan_ip_mark_inner(paths, flow_id, ips) {
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

fn add_wan_ip_mark_inner(
    paths: &LandscapeMapPath,
    flow_id: u32,
    ips: Vec<IpMarkInfo>,
) -> LdEbpfResult<()> {
    let flow_ip_match_map = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_ip_map)?;
    create_inner_flow_match_map_v4(&flow_ip_match_map, flow_id, &ips)?;

    let flow_ip_match_map = libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_ip_map)?;
    create_inner_flow_match_map_v6(&flow_ip_match_map, flow_id, &ips)?;
    Ok(())
}

pub(crate) fn set_flow_l4_rules_with_maps<R, M>(
    rule_map: &R,
    meta_map: &M,
    flow_id: u32,
    ports: &[PortMarkInfo],
) -> LdEbpfResult<()>
where
    R: MapCore,
    M: MapCore,
{
    if flow_id >= 256 {
        return Ok(());
    }

    let mut sorted = ports.to_vec();
    sorted
        .sort_unstable_by_key(|p| (p.priority, p.start_port, p.end_port, p.protocol.to_ipproto()));

    if sorted.len() > FLOW_L4_MAX_RULES_PER_FLOW {
        tracing::warn!(
            "flow {flow_id} has {} L4 port rules; truncating to {FLOW_L4_MAX_RULES_PER_FLOW}",
            sorted.len()
        );
    }

    let count = sorted.len().min(FLOW_L4_MAX_RULES_PER_FLOW);
    let mut rule_set = FlowL4RuleSet { count: count as u32, ..Default::default() };
    for (dst, src) in rule_set.entries.iter_mut().zip(sorted.iter().take(count)) {
        *dst = FlowL4RuleEntry {
            mark: u32::from(src.mark),
            start_port: src.start_port,
            end_port: src.end_port,
            priority: src.priority,
            l4_proto: src.protocol.to_ipproto(),
            ..Default::default()
        };
    }

    let _guard = FLOW_L4_META_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    rule_map.update(flow_id.as_bytes(), rule_set.as_bytes(), MapFlags::ANY)?;

    let zero = 0u32;
    let mut meta = match meta_map.lookup(zero.as_bytes(), MapFlags::ANY)? {
        Some(raw) => FlowL4Meta::read_from_bytes(&raw).unwrap_or_default(),
        None => FlowL4Meta::default(),
    };
    let word_idx = ((flow_id >> 5) & 7) as usize;
    let bit = 1u32 << (flow_id & 31);
    if count > 0 {
        meta.active_mask_words[word_idx] |= bit;
    } else {
        meta.active_mask_words[word_idx] &= !bit;
    }
    meta_map.update(zero.as_bytes(), meta.as_bytes(), MapFlags::ANY)?;

    Ok(())
}

pub fn set_dst_port_marks(paths: &LandscapeMapPath, flow_id: u32, ports: Vec<PortMarkInfo>) {
    if let Err(e) = set_dst_port_marks_inner(paths, flow_id, &ports) {
        tracing::error!("set_dst_port_marks(flow_id={flow_id}) error: {e:?}");
    }
}

fn set_dst_port_marks_inner(
    paths: &LandscapeMapPath,
    flow_id: u32,
    ports: &[PortMarkInfo],
) -> LdEbpfResult<()> {
    let rule_map = MapHandle::from_pinned_path(&paths.flow_l4_rule_map)?;
    let meta_map = MapHandle::from_pinned_path(&paths.flow_l4_meta_map)?;
    set_flow_l4_rules_with_maps(&rule_map, &meta_map, flow_id, ports)
}

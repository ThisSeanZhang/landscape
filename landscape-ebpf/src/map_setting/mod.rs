use std::{
    collections::HashMap,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use landscape_common::{ip_mark::IpConfig, net::MacAddr};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    AsRawLibbpf, MapCore, MapFlags, OpenMapMut,
};

use crate::bpf_error::LdEbpfResult;

pub type RawEbpfMapEntries = HashMap<Vec<u8>, Vec<u8>>;

pub(crate) struct RawEbpfMapDiff {
    pub delete_keys: Vec<Vec<u8>>,
    pub upsert_entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl RawEbpfMapDiff {
    pub fn is_empty(&self) -> bool {
        self.delete_keys.is_empty() && self.upsert_entries.is_empty()
    }
}

pub(crate) fn snapshot_raw_map<M: MapCore>(map: &M) -> LdEbpfResult<RawEbpfMapEntries> {
    let mut result = RawEbpfMapEntries::new();
    for key in map.keys() {
        if let Some(value) = map.lookup(&key, MapFlags::ANY)? {
            result.insert(key, value);
        }
    }
    Ok(result)
}

pub(crate) fn diff_raw_map(
    current: &RawEbpfMapEntries,
    desired: &RawEbpfMapEntries,
) -> RawEbpfMapDiff {
    let delete_keys = current.keys().filter(|key| !desired.contains_key(*key)).cloned().collect();

    let upsert_entries = desired
        .iter()
        .filter(|(key, value)| current.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    RawEbpfMapDiff { delete_keys, upsert_entries }
}

pub(crate) fn apply_raw_map_diff<M: MapCore>(map: &M, diff: RawEbpfMapDiff) -> LdEbpfResult<()> {
    if !diff.delete_keys.is_empty() {
        let key_count = diff.delete_keys.len() as u32;
        let mut keys = Vec::with_capacity(diff.delete_keys.iter().map(Vec::len).sum());
        for key in diff.delete_keys {
            keys.extend_from_slice(&key);
        }
        map.delete_batch(&keys, key_count, MapFlags::ANY, MapFlags::ANY)?;
    }

    if !diff.upsert_entries.is_empty() {
        let entry_count = diff.upsert_entries.len() as u32;
        let key_len: usize = diff.upsert_entries.iter().map(|(key, _)| key.len()).sum();
        let value_len: usize = diff.upsert_entries.iter().map(|(_, value)| value.len()).sum();
        let mut keys = Vec::with_capacity(key_len);
        let mut values = Vec::with_capacity(value_len);
        for (key, value) in diff.upsert_entries {
            keys.extend_from_slice(&key);
            values.extend_from_slice(&value);
        }
        map.update_batch(&keys, &values, entry_count, MapFlags::ANY, MapFlags::ANY)?;
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedMapReuseStatus {
    Compatible,
    Missing,
    Incompatible,
}

pub fn probe_pinned_map_reuse(
    map: &mut OpenMapMut,
    path: &(impl AsRef<Path> + ?Sized),
) -> PinnedMapReuseStatus {
    let ptr = map.as_libbpf_object().as_ptr();
    let expected_ty = unsafe { libbpf_rs::libbpf_sys::bpf_map__type(ptr) };
    let expected_ks = unsafe { libbpf_rs::libbpf_sys::bpf_map__key_size(ptr) };
    let expected_vs = unsafe { libbpf_rs::libbpf_sys::bpf_map__value_size(ptr) };
    let expected_me = unsafe { libbpf_rs::libbpf_sys::bpf_map__max_entries(ptr) };
    let expected_flags = unsafe { libbpf_rs::libbpf_sys::bpf_map__map_flags(ptr) };
    map.set_pin_path(path).unwrap();
    if !path.as_ref().exists() {
        return PinnedMapReuseStatus::Missing;
    }
    let pinned = match libbpf_rs::MapHandle::from_pinned_path(path) {
        Ok(pinned) => pinned,
        Err(e) => {
            tracing::warn!(
                "Cannot inspect pinned map {}: {e}, will recreate",
                path.as_ref().display(),
            );
            return PinnedMapReuseStatus::Incompatible;
        }
    };
    let pinned_info = match pinned.info() {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(
                "Cannot inspect pinned map {} info: {e}, will recreate",
                path.as_ref().display(),
            );
            return PinnedMapReuseStatus::Incompatible;
        }
    };
    let actual_ty = pinned.map_type() as u32;
    let actual_ks = pinned.key_size();
    let actual_vs = pinned.value_size();
    let actual_me = pinned.max_entries();
    let actual_flags = pinned_info.info.map_flags;

    if actual_ty != expected_ty
        || actual_ks != expected_ks
        || actual_vs != expected_vs
        || actual_me != expected_me
        || actual_flags != expected_flags
    {
        tracing::warn!(
            "Pinned map {} layout changed (type {}->{}, ks {}->{}, vs {}->{}, max_entries {}->{}, flags {:#x}->{:#x}), will recreate",
            path.as_ref().display(),
            actual_ty,
            expected_ty,
            actual_ks,
            expected_ks,
            actual_vs,
            expected_vs,
            actual_me,
            expected_me,
            actual_flags,
            expected_flags,
        );
        return PinnedMapReuseStatus::Incompatible;
    }

    PinnedMapReuseStatus::Compatible
}

/// Try to reuse a pinned map. If the pinned map is incompatible (e.g. struct
/// layout changed), remove the stale pin file so `load()` creates a fresh one.
///
/// NOTE: libbpf's `bpf_map__reuse_fd` silently overwrites the map definition
/// with the reused fd's sizes, so we must check key/value sizes explicitly
/// before calling `reuse_pinned_map`.
pub fn reuse_pinned_map_or_recreate(map: &mut OpenMapMut, path: &(impl AsRef<Path> + ?Sized)) {
    match probe_pinned_map_reuse(map, path) {
        PinnedMapReuseStatus::Compatible => {
            if let Err(e) = map.reuse_pinned_map(path) {
                tracing::warn!(
                    "Pinned map {} reuse failed: {e}, will recreate",
                    path.as_ref().display(),
                );
                let _ = std::fs::remove_file(path);
            }
        }
        PinnedMapReuseStatus::Missing => {}
        PinnedMapReuseStatus::Incompatible => {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(crate) mod share_map {
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
pub mod flow_wanip;
pub mod metric;
pub mod nat;
pub mod route;

pub mod event;
pub mod redirect_able;

pub(crate) fn init_path(paths: &LandscapeMapPath) {
    let landscape_builder = ShareMapSkelBuilder::default();
    // landscape_builder.obj_builder.debug(true);
    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = crate::bpf_ctx!(
        landscape_builder.open(&mut open_object),
        "map_setting open shared maps skeleton failed"
    )
    .unwrap();

    reuse_pinned_map_or_recreate(&mut landscape_open.maps.wan_ip_binding, &paths.wan_ip);
    // NAT
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.nat6_static_mappings,
        &paths.nat6_static_mappings,
    );
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.nat4_st_map, &paths.nat4_st_map);

    // firewall
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.firewall_block_ip4_map,
        &paths.firewall_ipv4_block,
    );
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.firewall_block_ip6_map,
        &paths.firewall_ipv6_block,
    );
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.flow_match_map, &paths.flow_match_map);
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.dns_flow_socks, &paths.dns_flow_socks);

    // metric
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.metric_bucket_map, &paths.metric_map);
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.nat_conn_metric_events,
        &paths.nat_conn_metric_events,
    );
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.firewall_conn_metric_events,
        &paths.firewall_conn_metric_events,
    );

    let _ = std::fs::remove_file(&paths.rt4_lan_map);
    let _ = std::fs::remove_file(&paths.rt6_lan_map);
    let _ = std::fs::remove_file(&paths.rt4_target_slot_map);
    let _ = std::fs::remove_file(&paths.rt6_target_slot_map);

    // flow verdict and forward
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.rt4_lan_map, &paths.rt4_lan_map);
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.rt4_target_slot_map,
        &paths.rt4_target_slot_map,
    );
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.flow4_dns_map, &paths.flow4_dns_map);
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.flow4_ip_map, &paths.flow4_ip_map);

    reuse_pinned_map_or_recreate(&mut landscape_open.maps.rt6_lan_map, &paths.rt6_lan_map);
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.rt6_target_slot_map,
        &paths.rt6_target_slot_map,
    );
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.flow6_dns_map, &paths.flow6_dns_map);
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.flow6_ip_map, &paths.flow6_ip_map);

    // 每次启动重建 cache 外层 map（含内层 map），避免结构体变更后大小不匹配。
    let _ = std::fs::remove_file(&paths.rt4_cache_map);
    let _ = std::fs::remove_file(&paths.rt6_cache_map);

    reuse_pinned_map_or_recreate(&mut landscape_open.maps.rt4_cache_map, &paths.rt4_cache_map);
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.rt6_cache_map, &paths.rt6_cache_map);

    reuse_pinned_map_or_recreate(&mut landscape_open.maps.ip_mac_v4, &paths.ip_mac_v4);
    reuse_pinned_map_or_recreate(&mut landscape_open.maps.ip_mac_v6, &paths.ip_mac_v6);
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.xdp_redirect_able,
        &paths.xdp_redirect_able,
    );

    let _landscape_skel =
        crate::bpf_ctx!(landscape_open.load(), "map_setting load shared maps skeleton failed")
            .unwrap();
    route::cache::init_route_wan_cache_inner_map(paths);
    route::cache::init_route_lan_cache_inner_map(paths);
}

/// Unpin shared maps during full app shutdown so the kernel can free them.
///
/// Must be called after all services have stopped.
pub fn cleanup_pinned_maps() {
    let maps_to_unpin: [&std::path::Path; 0] = [];
    for path in maps_to_unpin {
        match std::fs::remove_file(path) {
            Ok(()) => tracing::info!("Unpinned map: {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("Failed to unpin {}: {e}", path.display()),
        }
    }
}

pub fn add_ipv6_wan_ip(
    ifindex: u32,
    addr: Ipv6Addr,
    gateway: Option<Ipv6Addr>,
    mask: u8,
    mac: Option<MacAddr>,
) {
    let wan_ip_binding = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wan_ip).unwrap();
    add_wan_ip(&wan_ip_binding, ifindex, IpAddr::V6(addr), gateway.map(IpAddr::V6), mask, mac);
}

pub fn add_ipv4_wan_ip(
    ifindex: u32,
    addr: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    mask: u8,
    mac: Option<MacAddr>,
) {
    let wan_ip_binding = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wan_ip).unwrap();
    add_wan_ip(&wan_ip_binding, ifindex, IpAddr::V4(addr), gateway.map(IpAddr::V4), mask, mac);
}

/// Compute the NPT (Network Prefix Translation) mask for IPv6 prefix translation.
///
/// For a given prefix length N (0..64), the mask covers the bits between the
/// prefix and the 64-bit interface-ID boundary. These are the bits that should
/// be preserved from the LAN-side address during NPT translation.
///
/// The result is a little-endian u64 where each byte corresponds to bytes 0..7
/// of the IPv6 address (in network order). Bits *inside* the prefix are 0
/// (replaced by the WAN prefix) and bits *outside* the prefix (up to bit 63)
/// are 1 (kept from the LAN address).
fn compute_npt_mask(prefix_len: u8) -> u64 {
    if prefix_len >= 64 {
        return 0;
    }
    let mut mask: u64 = 0;
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;
    for i in 0..8usize {
        let byte_mask: u8 = if i < full_bytes {
            0x00
        } else if i == full_bytes && remaining_bits > 0 {
            (1u8 << (8 - remaining_bits)) - 1
        } else {
            0xFF
        };
        mask |= (byte_mask as u64) << (i * 8);
    }
    mask
}

pub(crate) fn add_wan_ip<'obj, T>(
    wan_ip_binding: &T,
    ifindex: u32,
    addr: IpAddr,
    gateway: Option<IpAddr>,
    mask: u8,
    mac: Option<MacAddr>,
) where
    T: MapCore,
{
    tracing::debug!("add wan index - 1: {ifindex:?}");
    let mut key = wan_ip_info_key::default();
    let mut value = wan_ip_info_value::default();
    key.ifindex = ifindex;
    value.mask = mask;

    match addr {
        std::net::IpAddr::V4(ipv4_addr) => {
            value.addr.ip = ipv4_addr.to_bits().to_be();
            key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            value.addr = u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() };
            key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            value.npt_mask = compute_npt_mask(mask);
        }
    };

    match gateway {
        Some(std::net::IpAddr::V4(ipv4_addr)) => {
            value.gateway.ip = ipv4_addr.to_bits().to_be();
        }
        Some(std::net::IpAddr::V6(ipv6_addr)) => {
            value.gateway = u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() };
        }
        None => {}
    };

    match mac {
        Some(mac) => {
            value.mac = mac.octets();
            value.has_mac = 1;
        }
        None => {
            value.has_mac = 0;
        }
    }

    let key = unsafe { plain::as_bytes(&key) };
    let value = unsafe { plain::as_bytes(&value) };

    if let Err(e) = wan_ip_binding.update(key, value, MapFlags::ANY) {
        tracing::error!("setting wan ip error:{e:?}");
    } else {
        tracing::info!("setting wan index: {ifindex:?} addr:{addr:?}");
    }
}

pub fn del_ipv6_wan_ip(ifindex: u32) {
    del_wan_ip(ifindex, LANDSCAPE_IPV6_TYPE);
}

pub fn del_ipv4_wan_ip(ifindex: u32) {
    del_wan_ip(ifindex, LANDSCAPE_IPV4_TYPE);
}

fn del_wan_ip(ifindex: u32, l3_protocol: u8) {
    tracing::debug!("del wan index - 1: {ifindex:?}");
    let wan_ip_binding = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.wan_ip).unwrap();
    let mut key = wan_ip_info_key::default();
    key.ifindex = ifindex;
    key.l3_protocol = l3_protocol;

    let key = unsafe { plain::as_bytes(&key) };
    if let Err(e) = wan_ip_binding.delete(key) {
        tracing::error!("delete wan ip error:{e:?}");
    } else {
        tracing::info!("delete wan index: {ifindex:?}");
    }
}

pub fn sync_firewall_blacklist(new_ips: Vec<IpConfig>, old_ips: Vec<IpConfig>) {
    use std::collections::HashSet;

    let new_set: HashSet<IpConfig> = new_ips.into_iter().collect();
    let old_set: HashSet<IpConfig> = old_ips.into_iter().collect();

    let to_add: Vec<&IpConfig> = new_set.difference(&old_set).collect();
    let to_del: Vec<&IpConfig> = old_set.difference(&new_set).collect();

    // Split into IPv4 and IPv6
    let (add_v4, add_v6): (Vec<&IpConfig>, Vec<&IpConfig>) =
        to_add.into_iter().partition(|ip| ip.ip.is_ipv4());
    let (del_v4, del_v6): (Vec<&IpConfig>, Vec<&IpConfig>) =
        to_del.into_iter().partition(|ip| ip.ip.is_ipv4());

    // IPv4 block map
    if !add_v4.is_empty() || !del_v4.is_empty() {
        let map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.firewall_ipv4_block).unwrap();
        if !del_v4.is_empty() {
            if let Err(e) = delete_blacklist_ipv4(&map, &del_v4) {
                tracing::error!("del firewall blacklist ipv4: {e:?}");
            }
        }
        if !add_v4.is_empty() {
            if let Err(e) = add_blacklist_ipv4(&map, &add_v4) {
                tracing::error!("add firewall blacklist ipv4: {e:?}");
            }
        }
    }

    // IPv6 block map
    if !add_v6.is_empty() || !del_v6.is_empty() {
        let map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.firewall_ipv6_block).unwrap();
        if !del_v6.is_empty() {
            if let Err(e) = delete_blacklist_ipv6(&map, &del_v6) {
                tracing::error!("del firewall blacklist ipv6: {e:?}");
            }
        }
        if !add_v6.is_empty() {
            if let Err(e) = add_blacklist_ipv6(&map, &add_v6) {
                tracing::error!("add firewall blacklist ipv6: {e:?}");
            }
        }
    }
}

fn add_blacklist_ipv4<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    use crate::map_setting::types::{firewall_action, ipv4_lpm_key};

    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V4(addr) = ip.ip {
            let key = ipv4_lpm_key { prefixlen: ip.prefix, addr: addr.to_bits().to_be() };
            let value = firewall_action { mark: 0 };
            keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
            values.extend_from_slice(unsafe { plain::as_bytes(&value) });
        }
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

fn delete_blacklist_ipv4<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    use crate::map_setting::types::ipv4_lpm_key;

    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V4(addr) = ip.ip {
            let key = ipv4_lpm_key { prefixlen: ip.prefix, addr: addr.to_bits().to_be() };
            keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        }
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

fn add_blacklist_ipv6<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    use crate::map_setting::types::{__anon_in6_addr_1, firewall_action, in6_addr, ipv6_lpm_key};

    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V6(addr) = ip.ip {
            let key = ipv6_lpm_key {
                prefixlen: ip.prefix,
                addr: in6_addr {
                    in6_u: __anon_in6_addr_1 { u6_addr8: addr.octets() },
                },
            };
            let value = firewall_action { mark: 0 };
            keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
            values.extend_from_slice(unsafe { plain::as_bytes(&value) });
        }
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

fn delete_blacklist_ipv6<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    use crate::map_setting::types::{__anon_in6_addr_1, in6_addr, ipv6_lpm_key};

    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V6(addr) = ip.ip {
            let key = ipv6_lpm_key {
                prefixlen: ip.prefix,
                addr: in6_addr {
                    in6_u: __anon_in6_addr_1 { u6_addr8: addr.octets() },
                },
            };
            keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        }
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

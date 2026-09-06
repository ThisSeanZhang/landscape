use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use landscape_common::net::MacAddr;
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::maps::{
    flow::types::FlowMatchKey, route::cache::create_inner_map_generic_with_outer, MacKeyV4,
    MacKeyV6, MacValueV4, MacValueV6, Route4CacheKey, Route4CacheValue, Route4LanInfo,
    Route4LanKey, Route6CacheKey, Route6CacheValue, Route6LanInfo, Route6LanKey,
};

pub(crate) use crate::maps::route::cache::{LAN_CACHE, WAN_CACHE};

pub(crate) const TARGET_IFINDEX: u32 = 11;
pub(crate) const WAN_IFINDEX: u32 = 6;

// Mirrors ROUTE_TYPE_* in maps/route/lan.rs and bpf route headers.
pub(crate) const LAN_ROUTE_TYPE: u8 = 0;
pub(crate) const ROUTE_TYPE_NEXTHOP: u8 = 1;
pub(crate) const WAN_ROUTE_TYPE: u8 = 2;

pub(crate) fn local_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00::10").unwrap()
}

pub(crate) fn remote_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:2::20").unwrap()
}

pub(crate) fn gateway_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:ffff::1").unwrap()
}

pub(crate) fn wan_addr() -> IpAddr {
    IpAddr::V6(Ipv6Addr::from_str("2001:db8:ffff::10").unwrap())
}

pub(crate) fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

pub(crate) fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

pub(crate) fn lookup_inner_map<T: MapCore>(outer_map: &T, cache_index: u32) -> MapHandle {
    let inner_id = lookup_inner_map_id(outer_map, cache_index);
    MapHandle::from_map_id(inner_id as u32).expect("open route cache inner map")
}

pub(crate) fn lookup_inner_map_id<T: MapCore>(outer_map: &T, cache_index: u32) -> i32 {
    let value = outer_map
        .lookup(as_bytes(&cache_index), MapFlags::ANY)
        .expect("lookup route cache outer map")
        .expect("missing route cache inner map id");
    read_unaligned::<i32>(&value)
}

pub(crate) fn create_route4_cache_inner_map<T: MapCore>(outer_map: &T, cache_index: u32) {
    create_inner_map_generic_with_outer::<_, Route4CacheKey, Route4CacheValue>(
        outer_map,
        format!("route_test_rt4_cache_{cache_index}"),
        cache_index,
    );
    lookup_inner_map_id(outer_map, cache_index);
}

pub(crate) fn create_route6_cache_inner_map<T: MapCore>(outer_map: &T, cache_index: u32) {
    create_inner_map_generic_with_outer::<_, Route6CacheKey, Route6CacheValue>(
        outer_map,
        format!("route_test_rt6_cache_{cache_index}"),
        cache_index,
    );
    lookup_inner_map_id(outer_map, cache_index);
}

pub(crate) fn make_rt6_cache_key(local: Ipv6Addr, remote: Ipv6Addr) -> Route6CacheKey {
    Route6CacheKey {
        local_addr: local.to_bits().to_be_bytes(),
        remote_addr: remote.to_bits().to_be_bytes(),
    }
}

pub(crate) fn make_rt4_cache_key(local: Ipv4Addr, remote: Ipv4Addr) -> Route4CacheKey {
    Route4CacheKey {
        local_addr: local.to_bits().to_be(),
        remote_addr: remote.to_bits().to_be(),
    }
}

/// v4 twin of `put_rt6_cache_ifindex` (see `route4_cache_value` C layout).
/// Full-control v4 cache insert (docker flag, gate addr, cached mac).
/// `gate_addr`/`mac` back `route4_redirect_by_cached_target`'s rewrite branches.
#[allow(clippy::too_many_arguments)]
pub(crate) fn put_rt4_cache_full<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    ifindex: u32,
    has_mac: bool,
    mark_value: u32,
    is_docker: bool,
    gate_addr: Ipv4Addr,
    mac: [u8; 6],
) {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt4_cache_key(local, remote);
    let value = Route4CacheValue {
        mark_value,
        ifindex,
        has_mac: has_mac as u8,
        is_docker: is_docker as u8,
        gate_addr: gate_addr.to_bits().to_be(),
        mac,
        ..Default::default()
    };
    inner
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert route v4 cache value");
}

pub(crate) fn put_rt4_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    ifindex: u32,
    has_mac: bool,
    mark_value: u32,
) {
    put_rt4_cache_full(
        outer_map,
        cache_index,
        local,
        remote,
        ifindex,
        has_mac,
        mark_value,
        false,
        Ipv4Addr::UNSPECIFIED,
        [0; 6],
    );
}

pub(crate) fn put_rt4_cache_ifindex<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    ifindex: u32,
    has_mac: bool,
) {
    put_rt4_cache_value(outer_map, cache_index, local, remote, ifindex, has_mac, 0);
}

pub(crate) fn put_rt6_cache_ifindex<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ifindex: u32,
    has_mac: bool,
) {
    put_rt6_cache_value(outer_map, cache_index, local, remote, ifindex, has_mac, 0);
}

/// Full-control v6 cache insert (mark / docker / gate addr / cached mac),
/// v6 twin of `put_rt4_cache_full`.
pub(crate) fn put_rt6_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ifindex: u32,
    has_mac: bool,
    mark_value: u32,
) {
    put_rt6_cache_full(
        outer_map,
        cache_index,
        local,
        remote,
        ifindex,
        has_mac,
        mark_value,
        false,
        Ipv6Addr::UNSPECIFIED,
        [0; 6],
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn put_rt6_cache_full<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ifindex: u32,
    has_mac: bool,
    mark_value: u32,
    is_docker: bool,
    gate_addr: Ipv6Addr,
    mac: [u8; 6],
) {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt6_cache_key(local, remote);
    let value = Route6CacheValue {
        mark_value,
        ifindex,
        has_mac: has_mac as u8,
        is_docker: is_docker as u8,
        gate_addr: gate_addr.octets(),
        mac,
        ..Default::default()
    };
    inner
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert route v6 cache value");
}

pub(crate) fn lookup_rt6_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
) -> Option<Route6CacheValue> {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt6_cache_key(local, remote);
    inner
        .lookup(as_bytes(&key), MapFlags::ANY)
        .expect("lookup route v6 cache value")
        .map(|bytes| read_unaligned::<Route6CacheValue>(&bytes))
}

pub(crate) fn lookup_rt4_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv4Addr,
    remote: Ipv4Addr,
) -> Option<Route4CacheValue> {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = Route4CacheKey {
        local_addr: local.to_bits().to_be(),
        remote_addr: remote.to_bits().to_be(),
    };
    inner
        .lookup(as_bytes(&key), MapFlags::ANY)
        .expect("lookup route v4 cache value")
        .map(|bytes| read_unaligned::<Route4CacheValue>(&bytes))
}

/// v4 twin of `insert_ip_mac_v6` (see `mac_value_v4` C layout).
pub(crate) fn insert_ip_mac_v4<T: MapCore>(
    map: &T,
    addr: Ipv4Addr,
    mac: MacAddr,
    dev_mac: MacAddr,
    ifindex: u32,
) {
    let key = MacKeyV4 { addr: addr.to_bits().to_be() };

    let value = MacValueV4 {
        ifindex,
        mac: mac.octets(),
        dev_mac: dev_mac.octets(),
        proto: 0x0800_u16.to_be(),
        ..Default::default()
    };

    map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).expect("insert ip_mac_v4 entry");
}

pub(crate) fn insert_ip_mac_v6<T: MapCore>(
    map: &T,
    addr: Ipv6Addr,
    mac: MacAddr,
    dev_mac: MacAddr,
    ifindex: u32,
) {
    let key = MacKeyV6 { addr: addr.to_bits().to_be_bytes() };

    let value = MacValueV6 {
        ifindex,
        mac: mac.octets(),
        dev_mac: dev_mac.octets(),
        proto: 0xdd86,
        sourced: 0,
        ..Default::default()
    };

    map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).expect("insert ip_mac_v6 entry");
}

/// Lookup an `ip_mac_v6` binding: returns `(mac, dev_mac, ifindex)`.
pub(crate) fn lookup_ip_mac_v6<T: MapCore>(
    map: &T,
    addr: Ipv6Addr,
) -> Option<([u8; 6], [u8; 6], u32)> {
    let key = MacKeyV6 { addr: addr.to_bits().to_be_bytes() };
    map.lookup(as_bytes(&key), MapFlags::ANY).expect("lookup ip_mac_v6").map(|bytes| {
        let v: MacValueV6 = read_unaligned(&bytes);
        (v.mac, v.dev_mac, v.ifindex)
    })
}

/// Lookup an `ip_mac_v4` binding: returns `(mac, dev_mac, ifindex)`.
pub(crate) fn lookup_ip_mac_v4<T: MapCore>(
    map: &T,
    addr: Ipv4Addr,
) -> Option<([u8; 6], [u8; 6], u32)> {
    let key = MacKeyV4 { addr: addr.to_bits().to_be() };
    map.lookup(as_bytes(&key), MapFlags::ANY).expect("lookup ip_mac_v4").map(|bytes| {
        let v: MacValueV4 = read_unaligned(&bytes);
        (v.mac, v.dev_mac, v.ifindex)
    })
}

/// Insert a `rt6_lan_map` entry. `key_addr` is the LPM key address, `value_addr`
/// the `addr` field of the value (route_type / ifindex / mac owned by the entry).
#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_route6_lan_entry<T: MapCore>(
    map: &T,
    prefix: u8,
    key_addr: Ipv6Addr,
    value_addr: Ipv6Addr,
    route_type: u8,
    ifindex: u32,
    has_mac: bool,
    mac_addr: [u8; 6],
) {
    let key = Route6LanKey {
        prefixlen: prefix as u32,
        addr: key_addr.to_bits().to_be_bytes(),
    };
    let value = Route6LanInfo {
        has_mac,
        mac_addr,
        route_type,
        ifindex,
        addr: value_addr.to_bits().to_be_bytes(),
    };
    map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).expect("insert route6 lan entry");
}

/// v4 twin of `insert_route6_lan_entry` (see `route4_lan_info` C layout).
#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_route4_lan_entry<T: MapCore>(
    map: &T,
    prefix: u8,
    key_addr: Ipv4Addr,
    value_addr: Ipv4Addr,
    route_type: u8,
    ifindex: u32,
    has_mac: bool,
    mac_addr: [u8; 6],
) {
    let key = Route4LanKey {
        prefixlen: prefix as u32,
        addr: key_addr.to_bits().to_be(),
    };
    let value = Route4LanInfo {
        has_mac,
        mac_addr,
        route_type,
        ifindex,
        addr: value_addr.to_bits().to_be(),
    };
    map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).expect("insert route4 lan entry");
}

/// `flow_match_map` entry matching the eth src mac (FLOW_ENTRY_MODE_MAC,
/// FLOW_MAC_MATCH_LEN).
#[allow(clippy::field_reassign_with_default)]
pub(crate) fn seed_flow_match_mac<T: MapCore>(map: &T, mac: [u8; 6], flow_id: u32) {
    let mut key = FlowMatchKey::default();
    key.prefixlen = 80; // FLOW_MAC_MATCH_LEN
    key.is_match_ip = 0; // FLOW_ENTRY_MODE_MAC
    key.set_src_mac(mac);
    map.update(as_bytes(&key), as_bytes(&flow_id), MapFlags::ANY)
        .expect("insert flow_match mac entry");
}

/// `flow_match_map` entry matching the IPv4 src address (FLOW_ENTRY_MODE_IP,
/// FLOW_IP_IPV4_MATCH_LEN).
///
/// Mirrors the BPF key construction (flow_match.h match_flow_id_v4): the IP
/// branch reuses the MAC-branch `match_key`, so the 4-byte `src_addr.ip`
/// write leaves `mac[4..6]` in the union tail. Those bytes sit beyond the
/// 64-bit LPM comparison (8 key header bytes + 4 address bytes), so they do
/// NOT affect which entries match — the leak is cosmetic, not behavioural.
/// The helper still carries them so the key is byte-identical to the BPF
/// lookup key.
#[allow(clippy::field_reassign_with_default)]
pub(crate) fn seed_flow_match_ip_v4<T: MapCore>(
    map: &T,
    addr: Ipv4Addr,
    mac: [u8; 6],
    flow_id: u32,
) {
    let mut key = FlowMatchKey::default();
    key.prefixlen = 64; // FLOW_IP_IPV4_MATCH_LEN
    key.l3_protocol = 0; // LANDSCAPE_IPV4_TYPE
    key.is_match_ip = 1; // FLOW_ENTRY_MODE_IP
    key.set_src_mac(mac); // mac[4..6] leak into the key tail (see note above)
    key.set_src_ipv4_be(addr.to_bits());
    map.update(as_bytes(&key), as_bytes(&flow_id), MapFlags::ANY)
        .expect("insert flow_match ip entry");
}

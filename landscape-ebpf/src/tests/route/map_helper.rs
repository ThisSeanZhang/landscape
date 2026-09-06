use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use landscape_common::net::MacAddr;
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::maps::{
    route::cache::create_inner_map_generic_with_outer, MacKeyV6, MacValueV6, Route4CacheKey,
    Route4CacheValue, Route4LanInfo, Route4LanKey, Route6CacheKey, Route6CacheValue, Route6LanInfo,
    Route6LanKey,
};

pub(crate) use crate::maps::route::cache::{LAN_CACHE, WAN_CACHE};

pub(crate) const TARGET_IFINDEX: u32 = 11;
pub(crate) const WAN_IFINDEX: u32 = 6;

// Mirrors ROUTE_TYPE_* in maps/route/lan.rs and bpf route headers.
pub(crate) const LAN_ROUTE_TYPE: u8 = 0;
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

pub(crate) fn put_rt6_cache_ifindex<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ifindex: u32,
    has_mac: bool,
) {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt6_cache_key(local, remote);
    let value = Route6CacheValue {
        ifindex,
        has_mac: has_mac as u8,
        ..Default::default()
    };
    inner
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert route v6 cache ifindex value");
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

/// Insert a `rt6_lan_map` entry. `key_addr` is the LPM key address, `value_addr`
/// the `addr` field of the value (route_type / ifindex / mac owned by the entry).
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

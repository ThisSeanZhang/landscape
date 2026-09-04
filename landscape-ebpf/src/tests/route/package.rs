use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::PacketBuilder;
use landscape_common::net::MacAddr;
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::maps::{
    route::cache::create_inner_map_generic_with_outer, MacKeyV6, MacValueV6, RtCacheKeyV4,
    RtCacheKeyV6, RtCacheValueV4, RtCacheValueV6,
};

pub(crate) use crate::maps::route::cache::{LAN_CACHE, WAN_CACHE};

pub fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

pub fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

pub fn lookup_inner_map<T: MapCore>(outer_map: &T, cache_index: u32) -> MapHandle {
    let inner_id = lookup_inner_map_id(outer_map, cache_index);
    MapHandle::from_map_id(inner_id as u32).expect("open route cache inner map")
}

pub fn lookup_inner_map_id<T: MapCore>(outer_map: &T, cache_index: u32) -> i32 {
    let value = outer_map
        .lookup(as_bytes(&cache_index), MapFlags::ANY)
        .expect("lookup route cache outer map")
        .expect("missing route cache inner map id");
    read_unaligned::<i32>(&value)
}

pub fn create_route_cache_inner_map_v4<T: MapCore>(outer_map: &T, cache_index: u32) {
    create_inner_map_generic_with_outer::<_, RtCacheKeyV4, RtCacheValueV4>(
        outer_map,
        format!("route_test_rt4_cache_{cache_index}"),
        cache_index,
    );
    lookup_inner_map_id(outer_map, cache_index);
}

pub fn create_route_cache_inner_map_v6<T: MapCore>(outer_map: &T, cache_index: u32) {
    create_inner_map_generic_with_outer::<_, RtCacheKeyV6, RtCacheValueV6>(
        outer_map,
        format!("route_test_rt6_cache_{cache_index}"),
        cache_index,
    );
    lookup_inner_map_id(outer_map, cache_index);
}

pub fn make_rt6_cache_key(local: Ipv6Addr, remote: Ipv6Addr) -> RtCacheKeyV6 {
    RtCacheKeyV6 {
        local_addr: local.to_bits().to_be_bytes(),
        remote_addr: remote.to_bits().to_be_bytes(),
    }
}

pub fn put_rt6_cache_ifindex<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ifindex: u32,
    has_mac: bool,
) {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt6_cache_key(local, remote);
    let value = RtCacheValueV6 {
        ifindex,
        has_mac: has_mac as u8,
        ..Default::default()
    };
    inner
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert route v6 cache ifindex value");
}

pub fn lookup_rt6_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
) -> Option<RtCacheValueV6> {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt6_cache_key(local, remote);
    inner
        .lookup(as_bytes(&key), MapFlags::ANY)
        .expect("lookup route v6 cache value")
        .map(|bytes| read_unaligned::<RtCacheValueV6>(&bytes))
}

pub fn lookup_rt4_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv4Addr,
    remote: Ipv4Addr,
) -> Option<RtCacheValueV4> {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = RtCacheKeyV4 {
        local_addr: local.to_bits().to_be(),
        remote_addr: remote.to_bits().to_be(),
    };
    inner
        .lookup(as_bytes(&key), MapFlags::ANY)
        .expect("lookup route v4 cache value")
        .map(|bytes| read_unaligned::<RtCacheValueV4>(&bytes))
}

pub fn insert_ip_mac_v6<T: MapCore>(
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

pub fn simple_ipv6_tcp_syn(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .tcp(12345, 443, 0x1020_3040, 4096);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv6 tcp packet");
    packet
}

pub fn simple_ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .tcp(12345, 443, 0x1020_3040, 4096);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv4 tcp packet");
    packet
}

pub fn simple_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .udp(10000, 53);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv4 udp packet");
    packet
}

pub fn simple_ipv6_udp(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .udp(10000, 53);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv6 udp packet");
    packet
}

/// Solicited-node multicast address ff02::1:ffXX:XXXX for `addr`.
fn solicited_node_multicast(addr: Ipv6Addr) -> Ipv6Addr {
    let bits = addr.to_bits();
    let snma = 0xff02_0000_0000_0000_0000_0001_ff00_0000_u128 | (bits & 0xffffff);
    Ipv6Addr::from_bits(snma)
}

/// Ethernet multicast MAC (33:33:ff:XX:XX:XX) for a solicited-node multicast.
fn solicited_node_mac(addr: Ipv6Addr) -> [u8; 6] {
    let bits = addr.to_bits();
    [0x33, 0x33, 0xff, ((bits >> 16) & 0xff) as u8, ((bits >> 8) & 0xff) as u8, (bits & 0xff) as u8]
}

/// DAD Neighbor Solicitation: ethernet + IPv6 (nexthdr=ICMPv6) + NS header
/// (type 135, code 0, cksum, reserved) + 16-byte Target Address, sent to the
/// solicited-node multicast of `target`. The IPv6 source is unspecified
/// (`::`) as required by DAD (RFC 4862).
pub fn simple_ipv6_ns_dad(src_mac: [u8; 6], target: Ipv6Addr) -> Vec<u8> {
    let snma = solicited_node_multicast(target);
    let ns_len = 8 + 16;
    let mut packet = Vec::with_capacity(14 + 40 + ns_len);
    packet.extend_from_slice(&solicited_node_mac(target));
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&0x86DD_u16.to_be_bytes());
    // IPv6 header
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&(ns_len as u16).to_be_bytes());
    packet.push(58); // nexthdr = ICMPv6
    packet.push(255); // hop limit
    packet.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
    packet.extend_from_slice(&snma.octets());
    // ICMPv6 Neighbor Solicitation
    packet.extend_from_slice(&[135, 0, 0, 0, 0, 0, 0, 0]); // type, code, cksum, reserved
    packet.extend_from_slice(&target.octets());
    packet
}

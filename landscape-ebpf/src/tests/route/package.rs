use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use etherparse::PacketBuilder;
use landscape_common::net::MacAddr;
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};

use crate::map_setting::share_map::types::{
    mac_key_v6, mac_value_v6, rt_cache_key_v4, rt_cache_key_v6, rt_cache_value_v4,
    rt_cache_value_v6,
};

static ROUTE_TEST_PIN_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub const WAN_CACHE: u32 = 0;
pub const LAN_CACHE: u32 = 1;

pub fn isolated_pin_root(prefix: &str) -> PathBuf {
    let unique = ROUTE_TEST_PIN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/{prefix}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create isolated bpf pin root");
    path
}

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
    let unique = ROUTE_TEST_PIN_COUNTER.fetch_add(1, Ordering::Relaxed);
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let map = MapHandle::create(
        MapType::LruHash,
        Some(format!("route_test_rt4_cache_{cache_index}_{unique}")),
        std::mem::size_of::<rt_cache_key_v4>() as u32,
        std::mem::size_of::<rt_cache_value_v4>() as u32,
        65_536,
        &opts,
    )
    .expect("create route v4 cache inner map");

    let map_fd = map.as_fd().as_raw_fd();
    outer_map
        .update(as_bytes(&cache_index), as_bytes(&map_fd), MapFlags::ANY)
        .expect("attach route v4 cache inner map");
}

pub fn create_route_cache_inner_map_v6<T: MapCore>(outer_map: &T, cache_index: u32) {
    let unique = ROUTE_TEST_PIN_COUNTER.fetch_add(1, Ordering::Relaxed);
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let map = MapHandle::create(
        MapType::LruHash,
        Some(format!("route_test_rt6_cache_{cache_index}_{unique}")),
        std::mem::size_of::<rt_cache_key_v6>() as u32,
        std::mem::size_of::<rt_cache_value_v6>() as u32,
        65_536,
        &opts,
    )
    .expect("create route v6 cache inner map");

    let map_fd = map.as_fd().as_raw_fd();
    outer_map
        .update(as_bytes(&cache_index), as_bytes(&map_fd), MapFlags::ANY)
        .expect("attach route v6 cache inner map");
}

pub fn make_rt6_cache_key(local: Ipv6Addr, remote: Ipv6Addr) -> rt_cache_key_v6 {
    let mut key = rt_cache_key_v6::default();
    key.local_addr.bytes = local.to_bits().to_be_bytes();
    key.remote_addr.bytes = remote.to_bits().to_be_bytes();
    key
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
    let mut value = rt_cache_value_v6::default();
    value.ifindex = ifindex;
    value.has_mac = has_mac as u8;
    inner
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert route v6 cache ifindex value");
}

pub fn lookup_rt6_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
) -> Option<rt_cache_value_v6> {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt6_cache_key(local, remote);
    inner
        .lookup(as_bytes(&key), MapFlags::ANY)
        .expect("lookup route v6 cache value")
        .map(|bytes| read_unaligned::<rt_cache_value_v6>(&bytes))
}

pub fn lookup_rt4_cache_value<T: MapCore>(
    outer_map: &T,
    cache_index: u32,
    local: Ipv4Addr,
    remote: Ipv4Addr,
) -> Option<rt_cache_value_v4> {
    let inner = lookup_inner_map(outer_map, cache_index);
    let mut key = rt_cache_key_v4::default();
    key.local_addr = local.to_bits().to_be();
    key.remote_addr = remote.to_bits().to_be();
    inner
        .lookup(as_bytes(&key), MapFlags::ANY)
        .expect("lookup route v4 cache value")
        .map(|bytes| read_unaligned::<rt_cache_value_v4>(&bytes))
}

pub fn insert_ip_mac_v6<T: MapCore>(
    map: &T,
    addr: Ipv6Addr,
    mac: MacAddr,
    dev_mac: MacAddr,
    ifindex: u32,
) {
    let mut key = mac_key_v6::default();
    key.addr.bytes = addr.to_bits().to_be_bytes();

    let mut value = mac_value_v6::default();
    value.ifindex = ifindex;
    value.mac = mac.octets();
    value.dev_mac = dev_mac.octets();
    value.proto = 0xdd86;

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

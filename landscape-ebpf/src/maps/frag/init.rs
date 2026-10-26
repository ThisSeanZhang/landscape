use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, recreate_pinned_map};

const FRAG_CACHE_MAX_ENTRIES: u32 = 65536;

pub(crate) const FRAG4_CACHE_LAN_PIN: &str = "frag4_cache_lan";
pub(crate) const FRAG4_CACHE_WAN_PIN: &str = "frag4_cache_wan";
pub(crate) const FRAG6_CACHE_LAN_PIN: &str = "frag6_cache_lan";
pub(crate) const FRAG6_CACHE_WAN_PIN: &str = "frag6_cache_wan";

#[allow(dead_code)]
#[repr(C)]
struct Frag4CacheKey {
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    ip_id: [u8; 2],
    proto: u8,
    pad: [u8; 1],
}

#[allow(dead_code)]
#[repr(C)]
struct Frag4CacheValue {
    src_port: [u8; 2],
    dst_port: [u8; 2],
}

#[allow(dead_code)]
#[repr(C)]
struct Frag6CacheKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    frag_id: [u8; 4],
}

#[allow(dead_code)]
#[repr(C)]
struct Frag6CacheValue {
    src_port: [u8; 2],
    dst_port: [u8; 2],
    proto: u8,
    frag_next_header: u8,
    flags: u8,
    pad: [u8; 1],
}

pub(crate) const FRAG4_CACHE_LAN_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FRAG4_CACHE_LAN_PIN,
    key_size: size_of::<Frag4CacheKey>() as u32,
    value_size: size_of::<Frag4CacheValue>() as u32,
    max_entries: FRAG_CACHE_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

pub(crate) const FRAG4_CACHE_WAN_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FRAG4_CACHE_WAN_PIN,
    key_size: size_of::<Frag4CacheKey>() as u32,
    value_size: size_of::<Frag4CacheValue>() as u32,
    max_entries: FRAG_CACHE_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

pub(crate) const FRAG6_CACHE_LAN_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FRAG6_CACHE_LAN_PIN,
    key_size: size_of::<Frag6CacheKey>() as u32,
    value_size: size_of::<Frag6CacheValue>() as u32,
    max_entries: FRAG_CACHE_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

pub(crate) const FRAG6_CACHE_WAN_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: FRAG6_CACHE_WAN_PIN,
    key_size: size_of::<Frag6CacheKey>() as u32,
    value_size: size_of::<Frag6CacheValue>() as u32,
    max_entries: FRAG_CACHE_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

pub fn init_frag4_cache_lan_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&FRAG4_CACHE_LAN_SPEC, path)
}

pub fn init_frag4_cache_wan_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&FRAG4_CACHE_WAN_SPEC, path)
}

pub fn init_frag6_cache_lan_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&FRAG6_CACHE_LAN_SPEC, path)
}

pub fn init_frag6_cache_wan_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&FRAG6_CACHE_WAN_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skel::tc_nat4_v4::TcNat4V4SkelBuilder;
    use crate::skel::tc_nat6::TcNat6SkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn frag_cache_map_params_match_skel() {
        let mut obj4 = std::mem::MaybeUninit::uninit();
        let open4 = TcNat4V4SkelBuilder::default().open(&mut obj4).expect("open tc_nat4_v4");
        crate::maps::assert_skel_map_matches(&open4.maps.frag4_cache_lan, &FRAG4_CACHE_LAN_SPEC);
        crate::maps::assert_skel_map_matches(&open4.maps.frag4_cache_wan, &FRAG4_CACHE_WAN_SPEC);

        let mut obj6 = std::mem::MaybeUninit::uninit();
        let open6 = TcNat6SkelBuilder::default().open(&mut obj6).expect("open tc_nat6");
        crate::maps::assert_skel_map_matches(&open6.maps.frag6_cache_lan, &FRAG6_CACHE_LAN_SPEC);
        crate::maps::assert_skel_map_matches(&open6.maps.frag6_cache_wan, &FRAG6_CACHE_WAN_SPEC);
    }
}

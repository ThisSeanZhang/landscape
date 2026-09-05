//! Startup creation/pinning of the route-domain maps and their verdict
//! caches.
//!
//! Creation parameters mirror the C `SEC(".maps")` definitions in
//! `src/bpf/route/route4_lan.h`, `route6_lan.h`, `route4_slot.h`,
//! `route6_slot.h`, `route4_cache.h` and `route6_cache.h`. The LAN route
//! maps / target slots / cache outers are
//! rebuilt on every boot (their entries are re-synced from user space), while
//! the per-flow rule outers (`flow4/6_dns_map`, `flow4/6_ip_map`) live in the
//! `flow_dns` / `flow_wanip` init modules. Passing the pin paths explicitly
//! lets tests create the maps under an isolated (temporary) bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{libbpf_sys, MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{recreate_pinned_map, InnerMapSpec, MapCreateSpec};

use super::cache;
use super::types::{
    Route4CacheKey, Route4CacheValue, Route4LanInfo, Route4LanKey, Route4SlotKey, Route4TargetInfo,
    Route6CacheKey, Route6CacheValue, Route6LanInfo, Route6LanKey, Route6SlotKey, Route6TargetInfo,
};

const LAN_ROUTE_MAX_ENTRIES: u32 = 1024;
const TARGET_SLOT_MAX_ENTRIES: u32 = 4096;
const ROUTE_CACHE_MAX_ENTRIES: u32 = 65536;
/// Outer ARRAY_OF_MAPS capacity (indexed by cache type WAN/LAN).
const ROUTE_CACHE_OUTER_ENTRIES: u32 = 4;

/// Pin 文件名 = C map 符号名（见 `route4_lan.h` / `route4_slot.h` 等）。
pub(crate) const RT4_LAN_MAP_PIN: &str = "rt4_lan_map";
pub(crate) const RT6_LAN_MAP_PIN: &str = "rt6_lan_map";
pub(crate) const RT4_SLOT_MAP_PIN: &str = "rt4_slot_map";
pub(crate) const RT6_SLOT_MAP_PIN: &str = "rt6_slot_map";
pub(crate) const RT4_CACHE_MAP_PIN: &str = "rt4_cache_map";
pub(crate) const RT6_CACHE_MAP_PIN: &str = "rt6_cache_map";

/// `rt4_lan_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `route4_lan_key` (8), value
/// `route4_lan_info` (16), 1024 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const RT4_LAN_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: RT4_LAN_MAP_PIN,
    key_size: size_of::<Route4LanKey>() as u32,
    value_size: size_of::<Route4LanInfo>() as u32,
    max_entries: LAN_ROUTE_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `rt6_lan_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `route6_lan_key` (20), value
/// `route6_lan_info` (32), 1024 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const RT6_LAN_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: RT6_LAN_MAP_PIN,
    key_size: size_of::<Route6LanKey>() as u32,
    value_size: size_of::<Route6LanInfo>() as u32,
    max_entries: LAN_ROUTE_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `rt4_slot_map`: `BPF_MAP_TYPE_HASH`, key
/// `route4_slot_key` (8), value `route4_target_info` (16), 4096
/// entries, `BPF_F_NO_PREALLOC`.
pub(crate) const RT4_SLOT_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: RT4_SLOT_MAP_PIN,
    key_size: size_of::<Route4SlotKey>() as u32,
    value_size: size_of::<Route4TargetInfo>() as u32,
    max_entries: TARGET_SLOT_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `rt6_slot_map`: `BPF_MAP_TYPE_HASH`, key
/// `route6_slot_key` (8), value `route6_target_info` (28), 4096
/// entries, `BPF_F_NO_PREALLOC`.
pub(crate) const RT6_SLOT_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: RT6_SLOT_MAP_PIN,
    key_size: size_of::<Route6SlotKey>() as u32,
    value_size: size_of::<Route6TargetInfo>() as u32,
    max_entries: TARGET_SLOT_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// Inner template `rt4_each_cache`: `BPF_MAP_TYPE_LRU_HASH`, 65536 entries.
pub(crate) const EACH_V4_CACHE: InnerMapSpec = InnerMapSpec {
    map_type: MapType::LruHash,
    name: "rt4_each_cache",
    key_size: size_of::<Route4CacheKey>() as u32,
    value_size: size_of::<Route4CacheValue>() as u32,
    max_entries: ROUTE_CACHE_MAX_ENTRIES,
    map_flags: 0,
};

/// Inner template `rt6_each_cache`: `BPF_MAP_TYPE_LRU_HASH`, 65536 entries.
pub(crate) const EACH_V6_CACHE: InnerMapSpec = InnerMapSpec {
    map_type: MapType::LruHash,
    name: "rt6_each_cache",
    key_size: size_of::<Route6CacheKey>() as u32,
    value_size: size_of::<Route6CacheValue>() as u32,
    max_entries: ROUTE_CACHE_MAX_ENTRIES,
    map_flags: 0,
};

/// `rt4_cache_map`: `BPF_MAP_TYPE_ARRAY_OF_MAPS`, key `u32` cache type, 4
/// entries, inner `rt4_each_cache`.
pub(crate) const RT4_CACHE_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::ArrayOfMaps,
    name: RT4_CACHE_MAP_PIN,
    key_size: 4,
    value_size: 4,
    max_entries: ROUTE_CACHE_OUTER_ENTRIES,
    map_flags: 0,
    inner: Some(EACH_V4_CACHE),
};

/// `rt6_cache_map`: `BPF_MAP_TYPE_ARRAY_OF_MAPS`, key `u32` cache type, 4
/// entries, inner `rt6_each_cache`.
pub(crate) const RT6_CACHE_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::ArrayOfMaps,
    name: RT6_CACHE_MAP_PIN,
    key_size: 4,
    value_size: 4,
    max_entries: ROUTE_CACHE_OUTER_ENTRIES,
    map_flags: 0,
    inner: Some(EACH_V6_CACHE),
};

/// Recreate the pinned `rt4_lan_map` at `path` (LAN routes are re-synced on
/// every boot).
pub fn init_rt4_lan_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&RT4_LAN_MAP_SPEC, path)
}

/// Recreate the pinned `rt6_lan_map` at `path` (LAN routes are re-synced on
/// every boot).
pub fn init_rt6_lan_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&RT6_LAN_MAP_SPEC, path)
}

/// Recreate the pinned `rt4_slot_map` at `path` (slots are re-synced
/// on every boot).
pub fn init_rt4_slot_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&RT4_SLOT_MAP_SPEC, path)
}

/// Recreate the pinned `rt6_slot_map` at `path` (slots are re-synced
/// on every boot).
pub fn init_rt6_slot_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&RT6_SLOT_MAP_SPEC, path)
}

/// Recreate the pinned `rt4_cache_map` outer map at `path`, then repopulate
/// its WAN/LAN inner maps (the verdict cache never survives a boot).
pub fn init_rt4_cache_map(
    path: &Path,
    rt6_cache_path: &Path,
) -> LdEbpfResult<(MapHandle, MapHandle)> {
    let rt4 = recreate_pinned_map(&RT4_CACHE_MAP_SPEC, path)?;
    let rt6 = recreate_pinned_map(&RT6_CACHE_MAP_SPEC, rt6_cache_path)?;
    Ok((rt4, rt6))
}

/// Startup population of the WAN verdict-cache inner maps (see `cache.rs`
/// for the recreate-at-runtime helpers).
pub fn init_route_wan_cache_inner_map(rt4_cache_path: &Path, rt6_cache_path: &Path) {
    cache::create_inner_map_generic::<_, Route4CacheKey, Route4CacheValue>(
        rt4_cache_path,
        "rt4_cache_wan".into(),
        cache::WAN_CACHE,
    );
    cache::create_inner_map_generic::<_, Route6CacheKey, Route6CacheValue>(
        rt6_cache_path,
        "rt6_cache_wan".into(),
        cache::WAN_CACHE,
    );
}

/// Startup population of the LAN verdict-cache inner maps (see `cache.rs`
/// for the recreate-at-runtime helpers).
pub fn init_route_lan_cache_inner_map(rt4_cache_path: &Path, rt6_cache_path: &Path) {
    cache::create_inner_map_generic::<_, Route4CacheKey, Route4CacheValue>(
        rt4_cache_path,
        "rt4_cache_lan".into(),
        cache::LAN_CACHE,
    );
    cache::create_inner_map_generic::<_, Route6CacheKey, Route6CacheValue>(
        rt6_cache_path,
        "rt6_cache_lan".into(),
        cache::LAN_CACHE,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xdp_wan_route::xdp_wan_route_skel::XdpWanRouteSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn route_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpWanRouteSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.rt4_lan_map, &RT4_LAN_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_lan_map, &RT6_LAN_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt4_slot_map, &RT4_SLOT_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_slot_map, &RT6_SLOT_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt4_cache_map, &RT4_CACHE_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_cache_map, &RT6_CACHE_MAP_SPEC);
    }
}

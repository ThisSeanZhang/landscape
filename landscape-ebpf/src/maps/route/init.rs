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

use libbpf_rs::{MapHandle, MapType, libbpf_sys};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{InnerMapSpec, MapCreateSpec, recreate_pinned_map};

use super::cache;
use super::types::{
    Route4CacheKey, Route4CacheValue, Route4ConnKey, Route4LanInfo, Route4LanKey, Route4SlotKey,
    Route4TargetInfo, Route6CacheKey, Route6CacheValue, Route6ConnKey, Route6LanInfo, Route6LanKey,
    Route6SlotKey, Route6TargetInfo, RouteConnValue, RouteFlowTargetKey,
};

const LAN_ROUTE_MAX_ENTRIES: u32 = 1024;
const TARGET_SLOT_MAX_ENTRIES: u32 = 65536;
/// Entries 0..255 store per-flow balance mode; entry 256 summarizes whether
/// any flow is currently configured for FiveTuple balancing.
const FLOW_MODE_MAX_ENTRIES: u32 = 257;
const FLOW_TARGETS_MAX_ENTRIES: u32 = 4096;
const ROUTE_CACHE_MAX_ENTRIES: u32 = 65536;
/// Outer ARRAY_OF_MAPS capacity (indexed by cache type WAN/LAN).
const ROUTE_CACHE_OUTER_ENTRIES: u32 = 2;
/// Outer ARRAY_OF_MAPS capacity for `rt4/6_conn_map`:
/// slot 0 (`CONN_PIN_CACHE`) + slot 1 (`L4_VERDICT_CACHE`).
const ROUTE_CONN_OUTER_ENTRIES: u32 = 2;

/// Pin 文件名 = C map 符号名（见 `route4_lan.h` / `route4_slot.h` 等）。
pub(crate) const RT_FLOW_MODE_MAP_PIN: &str = "rt_flow_mode_map";
pub(crate) const RT4_LAN_MAP_PIN: &str = "rt4_lan_map";
pub(crate) const RT6_LAN_MAP_PIN: &str = "rt6_lan_map";
pub(crate) const RT4_SLOT_MAP_PIN: &str = "rt4_slot_map";
pub(crate) const RT6_SLOT_MAP_PIN: &str = "rt6_slot_map";
pub(crate) const RT4_FLOW_TARGETS_PIN: &str = "rt4_flow_targets";
pub(crate) const RT6_FLOW_TARGETS_PIN: &str = "rt6_flow_targets";
pub(crate) const RT4_CACHE_MAP_PIN: &str = "rt4_cache_map";
pub(crate) const RT6_CACHE_MAP_PIN: &str = "rt6_cache_map";
pub(crate) const RT4_CONN_MAP_PIN: &str = "rt4_conn_map";
pub(crate) const RT6_CONN_MAP_PIN: &str = "rt6_conn_map";

/// `rt_flow_mode_map`: `BPF_MAP_TYPE_ARRAY`, key `u32` flow id (0..255) plus
/// summary slot 256 (`any_five_tuple`), value `u8`, 257 entries.
pub(crate) const RT_FLOW_MODE_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Array,
    name: RT_FLOW_MODE_MAP_PIN,
    key_size: 4,
    value_size: 1,
    max_entries: FLOW_MODE_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

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
/// `route4_slot_key` (8), value `route4_target_info` (8), 65536
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
/// `route6_slot_key` (8), value `route6_target_info` (8), 65536
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

/// `rt4_flow_targets`: `BPF_MAP_TYPE_HASH`, key `route_flow_target_key` (8),
/// value `route4_target_info` (8), 4096 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const RT4_FLOW_TARGETS_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: RT4_FLOW_TARGETS_PIN,
    key_size: size_of::<RouteFlowTargetKey>() as u32,
    value_size: size_of::<Route4TargetInfo>() as u32,
    max_entries: FLOW_TARGETS_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `rt6_flow_targets`: `BPF_MAP_TYPE_HASH`, key `route_flow_target_key` (8),
/// value `route6_target_info` (8), 4096 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const RT6_FLOW_TARGETS_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: RT6_FLOW_TARGETS_PIN,
    key_size: size_of::<RouteFlowTargetKey>() as u32,
    value_size: size_of::<Route6TargetInfo>() as u32,
    max_entries: FLOW_TARGETS_MAX_ENTRIES,
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

/// `rt4_cache_map`: `BPF_MAP_TYPE_ARRAY_OF_MAPS`, key `u32` cache type, 2
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

/// `rt6_cache_map`: `BPF_MAP_TYPE_ARRAY_OF_MAPS`, key `u32` cache type, 2
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

/// Inner template `rt4_each_conn`: `BPF_MAP_TYPE_LRU_HASH`, 65536 entries.
pub(crate) const EACH_V4_CONN: InnerMapSpec = InnerMapSpec {
    map_type: MapType::LruHash,
    name: "rt4_each_conn",
    key_size: size_of::<Route4ConnKey>() as u32,
    value_size: size_of::<RouteConnValue>() as u32,
    max_entries: ROUTE_CACHE_MAX_ENTRIES,
    map_flags: 0,
};

/// Inner template `rt6_each_conn`: `BPF_MAP_TYPE_LRU_HASH`, 65536 entries.
pub(crate) const EACH_V6_CONN: InnerMapSpec = InnerMapSpec {
    map_type: MapType::LruHash,
    name: "rt6_each_conn",
    key_size: size_of::<Route6ConnKey>() as u32,
    value_size: size_of::<RouteConnValue>() as u32,
    max_entries: ROUTE_CACHE_MAX_ENTRIES,
    map_flags: 0,
};

/// `rt4_conn_map`: `BPF_MAP_TYPE_ARRAY_OF_MAPS`, key `u32`, 2 entries
/// (`CONN_PIN_CACHE` slot 0, `L4_VERDICT_CACHE` slot 1), inner `rt4_each_conn`.
pub(crate) const RT4_CONN_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::ArrayOfMaps,
    name: RT4_CONN_MAP_PIN,
    key_size: 4,
    value_size: 4,
    max_entries: ROUTE_CONN_OUTER_ENTRIES,
    map_flags: 0,
    inner: Some(EACH_V4_CONN),
};

/// `rt6_conn_map`: `BPF_MAP_TYPE_ARRAY_OF_MAPS`, key `u32`, 2 entries
/// (`CONN_PIN_CACHE` slot 0, `L4_VERDICT_CACHE` slot 1), inner `rt6_each_conn`.
pub(crate) const RT6_CONN_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::ArrayOfMaps,
    name: RT6_CONN_MAP_PIN,
    key_size: 4,
    value_size: 4,
    max_entries: ROUTE_CONN_OUTER_ENTRIES,
    map_flags: 0,
    inner: Some(EACH_V6_CONN),
};

/// Recreate the pinned `rt_flow_mode_map` at `path` (re-synced on every boot).
pub fn init_rt_flow_mode_map(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&RT_FLOW_MODE_MAP_SPEC, path)
}

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

/// Recreate the pinned `rt4_flow_targets` map at `path`.
pub fn init_rt4_flow_targets(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&RT4_FLOW_TARGETS_SPEC, path)
}

/// Recreate the pinned `rt6_flow_targets` map at `path`.
pub fn init_rt6_flow_targets(path: &Path) -> LdEbpfResult<MapHandle> {
    recreate_pinned_map(&RT6_FLOW_TARGETS_SPEC, path)
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

/// Recreate the pinned `rt4/6_conn_map` outer maps at `rt4_conn_path` and
/// `rt6_conn_path`.
pub fn init_rt_conn_maps(
    rt4_conn_path: &Path,
    rt6_conn_path: &Path,
) -> LdEbpfResult<(MapHandle, MapHandle)> {
    let rt4 = recreate_pinned_map(&RT4_CONN_MAP_SPEC, rt4_conn_path)?;
    let rt6 = recreate_pinned_map(&RT6_CONN_MAP_SPEC, rt6_conn_path)?;
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

/// Startup population of the 5-tuple connection-pinning (`CONN_PIN_CACHE`, slot 0)
/// and L4 verdict (`L4_VERDICT_CACHE`, slot 1) inner maps.
pub fn init_route_conn_inner_map(rt4_conn_path: &Path, rt6_conn_path: &Path) {
    cache::create_inner_map_generic::<_, Route4ConnKey, RouteConnValue>(
        rt4_conn_path,
        "rt4_conn_lru".into(),
        cache::CONN_PIN_CACHE,
    );
    cache::create_inner_map_generic::<_, Route6ConnKey, RouteConnValue>(
        rt6_conn_path,
        "rt6_conn_lru".into(),
        cache::CONN_PIN_CACHE,
    );
    cache::create_inner_map_generic::<_, Route4ConnKey, RouteConnValue>(
        rt4_conn_path,
        "rt4_l4_verdict".into(),
        cache::L4_VERDICT_CACHE,
    );
    cache::create_inner_map_generic::<_, Route6ConnKey, RouteConnValue>(
        rt6_conn_path,
        "rt6_l4_verdict".into(),
        cache::L4_VERDICT_CACHE,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skel::xdp_wan_route::XdpWanRouteSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn route_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpWanRouteSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.rt_flow_mode_map, &RT_FLOW_MODE_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt4_lan_map, &RT4_LAN_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_lan_map, &RT6_LAN_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt4_slot_map, &RT4_SLOT_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_slot_map, &RT6_SLOT_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt4_flow_targets, &RT4_FLOW_TARGETS_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_flow_targets, &RT6_FLOW_TARGETS_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt4_cache_map, &RT4_CACHE_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_cache_map, &RT6_CACHE_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt4_conn_map, &RT4_CONN_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.rt6_conn_map, &RT6_CONN_MAP_SPEC);
    }
}

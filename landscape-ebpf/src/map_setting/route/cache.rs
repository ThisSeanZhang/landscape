use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use zerocopy::IntoBytes;

use crate::{
    map_setting::share_map::types::{
        rt_cache_key_v4, rt_cache_key_v6, rt_cache_value_v4, rt_cache_value_v6,
    },
    LandscapeMapPath, MAP_PATHS,
};

const DNS_MATCH_MAX_ENTRIES: u32 = 65536;
const WAN_CACHE: u32 = 0;
const LAN_CACHE: u32 = 1;

fn create_inner_map_generic_with_outer<T, K, V>(outer_map: &T, name: String, cache_type: u32)
where
    T: MapCore,
{
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    let key_size = size_of::<K>() as u32;
    let value_size = size_of::<V>() as u32;

    let map = MapHandle::create(
        MapType::LruHash,
        Some(name),
        key_size,
        value_size,
        DNS_MATCH_MAX_ENTRIES,
        &opts,
    )
    .expect("Failed to create inner LRU map");

    let map_fd = map.as_fd().as_raw_fd();

    let key_value = cache_type.as_bytes();
    let value_value = map_fd.as_bytes();

    if let Err(e) = outer_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Update outer map failed. Last OS error: {:?}", last_os_error);
        tracing::error!("Libbpf error: {e:?}");
    }
}

fn create_inner_map_generic<P, K, V>(path: P, name: String, cache_type: u32)
where
    P: AsRef<std::path::Path>,
{
    tracing::debug!("rt_cache_map at: {:?}, for: {}", path.as_ref().display(), name);

    let outer_map =
        libbpf_rs::MapHandle::from_pinned_path(path).expect("Failed to load pinned outer map");
    create_inner_map_generic_with_outer::<_, K, V>(&outer_map, name, cache_type);
}

fn recreate_route_lan_cache_inner_map_impl<T, U>(rt4_cache_map: &T, rt6_cache_map: &U)
where
    T: MapCore,
    U: MapCore,
{
    create_inner_map_generic_with_outer::<_, rt_cache_key_v4, rt_cache_value_v4>(
        rt4_cache_map,
        "rt4_cache_lan".into(),
        LAN_CACHE,
    );
    create_inner_map_generic_with_outer::<_, rt_cache_key_v6, rt_cache_value_v6>(
        rt6_cache_map,
        "rt6_cache_lan".into(),
        LAN_CACHE,
    );
}

pub(crate) fn init_route_wan_cache_inner_map(path: &LandscapeMapPath) {
    // IPv4
    create_inner_map_generic::<_, rt_cache_key_v4, rt_cache_value_v4>(
        &path.rt4_cache_map,
        "rt4_cache_wan".into(),
        WAN_CACHE,
    );
    // IPv6
    create_inner_map_generic::<_, rt_cache_key_v6, rt_cache_value_v6>(
        &path.rt6_cache_map,
        "rt6_cache_wan".into(),
        WAN_CACHE,
    );
}

pub(crate) fn init_route_lan_cache_inner_map(path: &LandscapeMapPath) {
    // IPv4
    create_inner_map_generic::<_, rt_cache_key_v4, rt_cache_value_v4>(
        &path.rt4_cache_map,
        "rt4_cache_lan".into(),
        LAN_CACHE,
    );
    // IPv6
    create_inner_map_generic::<_, rt_cache_key_v6, rt_cache_value_v6>(
        &path.rt6_cache_map,
        "rt6_cache_lan".into(),
        LAN_CACHE,
    );
}

pub(crate) fn recreate_route_lan_cache_inner_map_with_outer_maps<T, U>(
    rt4_cache_map: &T,
    rt6_cache_map: &U,
) where
    T: MapCore,
    U: MapCore,
{
    recreate_route_lan_cache_inner_map_impl(rt4_cache_map, rt6_cache_map);
}

// 修改了 静态 NAT 需要清理
pub fn recreate_route_wan_cache_inner_map() {
    create_inner_map_generic::<_, rt_cache_key_v4, rt_cache_value_v4>(
        &MAP_PATHS.rt4_cache_map,
        "rt4_cache_wan".into(),
        WAN_CACHE,
    );
    create_inner_map_generic::<_, rt_cache_key_v6, rt_cache_value_v6>(
        &MAP_PATHS.rt6_cache_map,
        "rt6_cache_wan".into(),
        WAN_CACHE,
    );
}

/// 在修改了 DNS 规则， DST IP 规则。 Flow Match 规则后调用
/// 使缓存失效
pub fn recreate_route_lan_cache_inner_map() {
    let rt4_cache_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_cache_map).expect("open rt4_cache");
    let rt6_cache_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_cache_map).expect("open rt6_cache");

    recreate_route_lan_cache_inner_map_impl(&rt4_cache_map, &rt6_cache_map);
}

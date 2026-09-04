//! LAN prefix route maps (`rt4/6_lan_map`): add/del entries in Reachable /
//! NextHop / WanReachable modes, invalidating the LAN verdict cache on change.

use landscape_common::sys_service::route_service::LanRouteInfo;
use libbpf_rs::{MapCore, MapFlags};
use zerocopy::IntoBytes;

use super::cache;
use crate::{
    maps::{LanRouteInfoV4, LanRouteInfoV6, LanRouteKeyV4, LanRouteKeyV6},
    MAP_PATHS,
};
const ROUTE_TYPE_LAN: u8 = 0;
const ROUTE_TYPE_NEXTHOP: u8 = 1;
const ROUTE_TYPE_WAN: u8 = 2;

fn invalidate_lan_route_cache_with_outer_maps<T, U>(rt4_cache_map: &T, rt6_cache_map: &U)
where
    T: MapCore,
    U: MapCore,
{
    cache::recreate_route_lan_cache_inner_map_with_outer_maps(rt4_cache_map, rt6_cache_map);
}
pub fn add_lan_route(lan_info: LanRouteInfo) {
    let rt4_lan_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_lan_map).unwrap();
    let rt6_lan_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_lan_map).unwrap();
    let rt4_cache_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_cache_map).unwrap();
    let rt6_cache_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_cache_map).unwrap();

    let _ = add_lan_route_with_maps(
        &rt4_lan_map,
        &rt6_lan_map,
        &rt4_cache_map,
        &rt6_cache_map,
        &lan_info,
    );
}

pub(crate) fn add_lan_route_with_maps<T, U, V, W>(
    rt4_lan_map: &T,
    rt6_lan_map: &U,
    rt4_cache_map: &V,
    rt6_cache_map: &W,
    lan_info: &LanRouteInfo,
) -> bool
where
    T: MapCore,
    U: MapCore,
    V: MapCore,
    W: MapCore,
{
    let changed_v4 = add_lan_route_inner_v4(rt4_lan_map, lan_info);
    let changed_v6 = add_lan_route_inner_v6(rt6_lan_map, lan_info);

    if changed_v4 || changed_v6 {
        invalidate_lan_route_cache_with_outer_maps(rt4_cache_map, rt6_cache_map);
        return true;
    }

    false
}

pub(crate) fn add_lan_route_inner_v4<T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = LanRouteKeyV4::default();
    let mut value = LanRouteInfoV4::default();

    key.prefixlen = lan_info.prefix as u32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            key.addr = ipv4_addr.to_bits().to_be();
            value.addr = ipv4_addr.to_bits().to_be();
        }
        std::net::IpAddr::V6(_) => {
            return false;
        }
    }
    let key = key.as_bytes();

    value.ifindex = lan_info.ifindex;
    if let Some(mac) = lan_info.mac {
        value.mac_addr = mac.octets();
        value.has_mac = true;
    } else {
        value.has_mac = false;
    }

    match &lan_info.mode {
        landscape_common::sys_service::route_service::LanRouteMode::Reachable => {
            value.route_type = ROUTE_TYPE_LAN;
        }
        landscape_common::sys_service::route_service::LanRouteMode::NextHop { next_hop_ip } => {
            value.route_type = ROUTE_TYPE_NEXTHOP;

            match next_hop_ip {
                std::net::IpAddr::V4(ipv4_addr) => {
                    value.addr = ipv4_addr.to_bits().to_be();
                }
                std::net::IpAddr::V6(_) => {
                    return false;
                }
            }
        }
        landscape_common::sys_service::route_service::LanRouteMode::WanReachable => {
            value.route_type = ROUTE_TYPE_WAN;
        }
    }

    let value = value.as_bytes();

    if let Ok(Some(existing)) = rt_lan_map.lookup(key, MapFlags::ANY) {
        if existing.as_slice() == value {
            return false;
        }
    }

    if let Err(e) = rt_lan_map.update(key, value, MapFlags::ANY) {
        tracing::error!("add lan config error:{e:?}");
        return false;
    }

    true
}

pub(crate) fn add_lan_route_inner_v6<T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = LanRouteKeyV6::default();
    let mut value = LanRouteInfoV6::default();

    key.prefixlen = lan_info.prefix as u32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(_) => {
            return false;
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            key.addr = ipv6_addr.to_bits().to_be_bytes();
            value.addr = ipv6_addr.to_bits().to_be_bytes();
        }
    }
    let key = key.as_bytes();

    value.ifindex = lan_info.ifindex;
    if let Some(mac) = lan_info.mac {
        value.mac_addr = mac.octets();
        value.has_mac = true;
    } else {
        value.has_mac = false;
    }

    match &lan_info.mode {
        landscape_common::sys_service::route_service::LanRouteMode::Reachable => {
            value.route_type = ROUTE_TYPE_LAN;
        }
        landscape_common::sys_service::route_service::LanRouteMode::NextHop { next_hop_ip } => {
            value.route_type = ROUTE_TYPE_NEXTHOP;

            match next_hop_ip {
                std::net::IpAddr::V4(_) => {
                    return false;
                }
                std::net::IpAddr::V6(ipv6_addr) => {
                    value.addr = ipv6_addr.to_bits().to_be_bytes();
                }
            }
        }
        landscape_common::sys_service::route_service::LanRouteMode::WanReachable => {
            value.route_type = ROUTE_TYPE_WAN;
        }
    }

    let value = value.as_bytes();

    if let Ok(Some(existing)) = rt_lan_map.lookup(key, MapFlags::ANY) {
        if existing.as_slice() == value {
            return false;
        }
    }

    if let Err(e) = rt_lan_map.update(key, value, MapFlags::ANY) {
        tracing::error!("add lan config error:{e:?}");
        return false;
    }

    true
}

pub fn del_lan_route(lan_info: LanRouteInfo) {
    let rt4_lan_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_lan_map).unwrap();
    let rt6_lan_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_lan_map).unwrap();

    let _ = del_lan_route_with_maps(&rt4_lan_map, &rt6_lan_map, &lan_info);
}

pub(crate) fn del_lan_route_with_maps<T, U>(
    rt4_lan_map: &T,
    rt6_lan_map: &U,
    lan_info: &LanRouteInfo,
) -> bool
where
    T: MapCore,
    U: MapCore,
{
    let changed_v4 = del_lan_route_inner_v4(rt4_lan_map, lan_info);
    let changed_v6 = del_lan_route_inner_v6(rt6_lan_map, lan_info);

    changed_v4 || changed_v6
}

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn del_lan_route_inner_v4<T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = LanRouteKeyV4::default();
    key.prefixlen = lan_info.prefix as u32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            key.addr = ipv4_addr.to_bits().to_be();
        }
        std::net::IpAddr::V6(_) => {
            return false;
        }
    }
    let key = key.as_bytes();

    match rt_lan_map.lookup(key, MapFlags::ANY) {
        Ok(Some(_)) => {}
        Ok(None) => return false,
        Err(e) => {
            tracing::error!("lookup lan config before delete error:{e:?}");
            return false;
        }
    }

    if let Err(e) = rt_lan_map.delete(key) {
        tracing::error!("del lan config error:{e:?}");
        return false;
    }

    true
}

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn del_lan_route_inner_v6<T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = LanRouteKeyV6::default();
    key.prefixlen = lan_info.prefix as u32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(_) => {
            return false;
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            key.addr = ipv6_addr.to_bits().to_be_bytes();
        }
    }
    let key = key.as_bytes();

    match rt_lan_map.lookup(key, MapFlags::ANY) {
        Ok(Some(_)) => {}
        Ok(None) => return false,
        Err(e) => {
            tracing::error!("lookup lan config before delete error:{e:?}");
            return false;
        }
    }

    if let Err(e) = rt_lan_map.delete(key) {
        tracing::error!("del lan config error:{e:?}");
        return false;
    }

    true
}

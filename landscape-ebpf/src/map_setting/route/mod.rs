use landscape_common::{
    config::FlowId,
    route::{LanRouteInfo, RouteTargetInfo},
};
use libbpf_rs::{MapCore, MapFlags};

use crate::{
    map_setting::share_map::types::{
        lan_route_info, lan_route_key, route_target_info, route_target_key,
    },
    LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE, MAP_PATHS,
};

pub fn add_lan_route(lan_info: LanRouteInfo) {
    let rt_lan_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt_lan_map).unwrap();
    let mut key = lan_route_key::default();
    let mut value = lan_route_info::default();

    key.prefixlen = lan_info.prefix as u32 + 32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            key.l3_protocol = LANDSCAPE_IPV4_TYPE;
            unsafe { key.addr.in6_u.u6_addr32[0] = ipv4_addr.to_bits().to_be() };
            unsafe { value.addr.in6_u.u6_addr32[0] = ipv4_addr.to_bits().to_be() };
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            key.addr.in6_u.u6_addr8 = ipv6_addr.to_bits().to_be_bytes();
            value.addr.in6_u.u6_addr8 = ipv6_addr.to_bits().to_be_bytes();
        }
    }
    let key = unsafe { plain::as_bytes(&key) };

    value.ifindex = lan_info.ifindex;
    if let Some(mac) = lan_info.mac {
        value.mac_addr = mac.octets();
        value.has_mac = std::mem::MaybeUninit::new(true);
    } else {
        value.has_mac = std::mem::MaybeUninit::new(false);
    }
    let value = unsafe { plain::as_bytes(&value) };

    if let Err(e) = rt_lan_map.update(&key, &value, MapFlags::ANY) {
        tracing::error!("add lan config error:{e:?}");
    }
}

pub fn del_lan_route(lan_info: LanRouteInfo) {
    let rt_lan_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt_lan_map).unwrap();
    let mut key = lan_route_key::default();
    key.prefixlen = lan_info.prefix as u32 + 32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            key.l3_protocol = LANDSCAPE_IPV4_TYPE;
            unsafe { key.addr.in6_u.u6_addr32[0] = ipv4_addr.to_bits().to_be() };
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            key.addr.in6_u.u6_addr8 = ipv6_addr.to_bits().to_be_bytes()
        }
    }
    let key = unsafe { plain::as_bytes(&key) };

    if let Err(e) = rt_lan_map.delete(&key) {
        tracing::error!("del lan config error:{e:?}");
    }
}

pub fn add_wan_route(flow_id: FlowId, wan_info: RouteTargetInfo) {
    let rt_target_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt_target_map).unwrap();

    let mut key = route_target_key::default();
    key.flow_id = flow_id;

    let mut value = route_target_info::default();
    value.ifindex = wan_info.ifindex;
    value.has_mac = std::mem::MaybeUninit::new(wan_info.has_mac);
    value.is_docker = std::mem::MaybeUninit::new(wan_info.is_docker);

    match wan_info.gateway_ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            key.l3_protocol = LANDSCAPE_IPV4_TYPE;
            unsafe { value.gate_addr.in6_u.u6_addr32[0] = ipv4_addr.to_bits().to_be() };
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            value.gate_addr.in6_u.u6_addr8 = ipv6_addr.to_bits().to_be_bytes()
        }
    }

    let key = unsafe { plain::as_bytes(&key) };
    let value = unsafe { plain::as_bytes(&value) };

    if let Err(e) = rt_target_map.update(&key, &value, MapFlags::ANY) {
        tracing::error!("add wan config error:{e:?}");
    }
}

pub fn del_ipv6_wan_route(flow_id: FlowId) {
    del_wan_route(flow_id, LANDSCAPE_IPV6_TYPE)
}

pub fn del_ipv4_wan_route(flow_id: FlowId) {
    del_wan_route(flow_id, LANDSCAPE_IPV4_TYPE)
}

fn del_wan_route(flow_id: FlowId, l3_protocol: u8) {
    let rt_target_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt_target_map).unwrap();
    let mut key = route_target_key::default();
    key.flow_id = flow_id;
    key.l3_protocol = l3_protocol;

    let key = unsafe { plain::as_bytes(&key) };

    if let Err(e) = rt_target_map.delete(&key) {
        tracing::error!("del wan config error:{e:?}");
    }
}

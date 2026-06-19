use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use landscape_common::{
    config::FlowId,
    flow::mark::FlowMark,
    route::{
        trace::{
            FlowMatchRequest, FlowMatchResult, FlowMatchSource, FlowRuleMatchResult,
            FlowVerdictRequest, FlowVerdictResult, FlowVerdictSource, SingleVerdictResult,
        },
        LanRouteInfo, RouteTargetInfo,
    },
};
use libbpf_rs::{MapCore, MapFlags};

use crate::{
    map_setting::share_map::types::{
        flow_dns_match_key_v4, flow_dns_match_key_v6, flow_dns_match_value_v4,
        flow_dns_match_value_v6, flow_ip_trie_key_v4, flow_ip_trie_key_v6, flow_ip_trie_value_v4,
        flow_ip_trie_value_v6, flow_match_key, lan_route_info_v4, lan_route_info_v6,
        lan_route_key_v4, lan_route_key_v6, route_target_info_v4, route_target_info_v6,
        rt_cache_key_v4, rt_cache_key_v6, rt_cache_value_v4, rt_cache_value_v6,
    },
    LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE, MAP_PATHS,
};

pub mod cache;

const FLOW_ENTRY_MODE_MAC: u8 = 0;
const FLOW_ENTRY_MODE_IP: u8 = 1;
const FLOW_ID_MASK: u32 = 0x000000FF;
const FLOW_ACTION_MASK: u32 = 0x00007F00;
const LAN_CACHE: u32 = 1;
const FLOW_TARGET_SLOT_COUNT: usize = 16;

const ROUTE_TYPE_LAN: u8 = 0;
const ROUTE_TYPE_NEXTHOP: u8 = 1;
const ROUTE_TYPE_WAN: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct route_target_slot_key_v4 {
    flow_id: u32,
    slot: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct route_target_slot_key_v6 {
    flow_id: u32,
    slot: u32,
}

fn invalidate_lan_route_cache_with_outer_maps<T, U>(rt4_cache_map: &T, rt6_cache_map: &U)
where
    T: MapCore,
    U: MapCore,
{
    cache::recreate_route_lan_cache_inner_map_with_outer_maps(rt4_cache_map, rt6_cache_map);
}

fn pick_effective_flow(
    flow_id_by_mac: Option<u32>,
    flow_id_by_ip: Option<u32>,
    ip_source: FlowMatchSource,
) -> (u32, FlowMatchSource) {
    if let Some(flow_id) = flow_id_by_ip {
        return (flow_id, ip_source);
    }

    if let Some(flow_id) = flow_id_by_mac {
        return (flow_id, FlowMatchSource::Mac);
    }

    (0, FlowMatchSource::Default)
}

/// Step 1: Match source client → flow_id
pub fn trace_flow_match(req: FlowMatchRequest) -> FlowMatchResult {
    let flow_match_map = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_match_map) {
        Ok(map) => map,
        Err(e) => {
            tracing::error!("Failed to open flow_match_map: {e:?}");
            return FlowMatchResult {
                flow_id_by_mac: None,
                flow_id_by_ip: None,
                flow_id_by_ipv4: None,
                flow_id_by_ipv6: None,
                effective_flow_id: 0,
                effective_flow_id_v4: 0,
                effective_flow_id_v6: 0,
                effective_flow_source: FlowMatchSource::Default,
                effective_flow_source_v4: FlowMatchSource::Default,
                effective_flow_source_v6: FlowMatchSource::Default,
            };
        }
    };

    // MAC match
    let flow_id_by_mac = if let Some(mac) = &req.src_mac {
        let mut key = flow_match_key::default();
        key.prefixlen = 80; // FLOW_MAC_MATCH_LEN
        key.l3_protocol = 0;
        key.is_match_ip = FLOW_ENTRY_MODE_MAC;
        key.__anon_flow_match_key_1.mac.mac = mac.octets();

        let key_bytes = unsafe { plain::as_bytes(&key) };
        match flow_match_map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(val)) => plain::from_bytes::<u32>(&val).ok().copied(),
            _ => None,
        }
    } else {
        None
    };

    // IPv4 match
    let flow_id_by_ipv4 = if let Some(ipv4) = &req.src_ipv4 {
        let mut key = flow_match_key::default();
        key.prefixlen = 64; // FLOW_IP_IPV4_MATCH_LEN
        key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        key.is_match_ip = FLOW_ENTRY_MODE_IP;
        key.__anon_flow_match_key_1.src_addr.ip = ipv4.to_bits().to_be();

        let key_bytes = unsafe { plain::as_bytes(&key) };
        match flow_match_map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(val)) => plain::from_bytes::<u32>(&val).ok().copied(),
            _ => None,
        }
    } else {
        None
    };

    // IPv6 match
    let flow_id_by_ipv6 = if let Some(ipv6) = &req.src_ipv6 {
        let mut key = flow_match_key::default();
        key.prefixlen = 160; // FLOW_IP_IPV6_MATCH_LEN
        key.l3_protocol = LANDSCAPE_IPV6_TYPE;
        key.is_match_ip = FLOW_ENTRY_MODE_IP;
        key.__anon_flow_match_key_1.src_addr.bits = ipv6.to_bits().to_be_bytes();

        let key_bytes = unsafe { plain::as_bytes(&key) };
        match flow_match_map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(val)) => plain::from_bytes::<u32>(&val).ok().copied(),
            _ => None,
        }
    } else {
        None
    };

    // IP match: IPv4 takes precedence over IPv6
    let flow_id_by_ip = flow_id_by_ipv4.or(flow_id_by_ipv6);
    let (effective_flow_id_v4, effective_flow_source_v4) =
        pick_effective_flow(flow_id_by_mac, flow_id_by_ipv4, FlowMatchSource::Ipv4);
    let (effective_flow_id_v6, effective_flow_source_v6) =
        pick_effective_flow(flow_id_by_mac, flow_id_by_ipv6, FlowMatchSource::Ipv6);
    let (effective_flow_id, effective_flow_source) = if flow_id_by_ipv4.is_some() {
        (effective_flow_id_v4, FlowMatchSource::Ipv4)
    } else if flow_id_by_ipv6.is_some() {
        (effective_flow_id_v6, FlowMatchSource::Ipv6)
    } else if flow_id_by_mac.is_some() {
        (effective_flow_id_v4, FlowMatchSource::Mac)
    } else {
        (0, FlowMatchSource::Default)
    };

    FlowMatchResult {
        flow_id_by_mac,
        flow_id_by_ip,
        flow_id_by_ipv4,
        flow_id_by_ipv6,
        effective_flow_id,
        effective_flow_id_v4,
        effective_flow_id_v6,
        effective_flow_source,
        effective_flow_source_v4,
        effective_flow_source_v6,
    }
}

/// Step 2: Flow verdict on multiple dst_ips (supports both IPv4 and IPv6)
pub fn trace_flow_verdict(req: FlowVerdictRequest) -> FlowVerdictResult {
    let verdicts = req
        .dst_ips
        .iter()
        .map(|dst_ip| match dst_ip {
            IpAddr::V4(v4) => {
                let (ip_rule_match, dns_rule_match, effective_rule_source, effective_mark) =
                    trace_flow_verdict_single_v4(req.flow_id, *v4);
                let expected_cache_mark = expected_cache_mark_value(req.flow_id, &effective_mark);
                let (has_cache, cached_mark, cache_consistent) = if let Some(src) = req.src_ipv4 {
                    trace_cache_check_v4(src, *v4, expected_cache_mark)
                } else {
                    (false, None, true)
                };

                SingleVerdictResult {
                    dst_ip: *dst_ip,
                    ip_rule_match,
                    dns_rule_match,
                    effective_rule_source,
                    effective_mark,
                    expected_cache_mark,
                    has_cache,
                    cached_mark,
                    cache_consistent,
                }
            }
            IpAddr::V6(v6) => {
                let (ip_rule_match, dns_rule_match, effective_rule_source, effective_mark) =
                    trace_flow_verdict_single_v6(req.flow_id, *v6);
                let expected_cache_mark = expected_cache_mark_value(req.flow_id, &effective_mark);
                let (has_cache, cached_mark, cache_consistent) = if let Some(src) = req.src_ipv6 {
                    trace_cache_check_v6(src, *v6, expected_cache_mark)
                } else {
                    (false, None, true)
                };

                SingleVerdictResult {
                    dst_ip: *dst_ip,
                    ip_rule_match,
                    dns_rule_match,
                    effective_rule_source,
                    effective_mark,
                    expected_cache_mark,
                    has_cache,
                    cached_mark,
                    cache_consistent,
                }
            }
        })
        .collect();

    FlowVerdictResult { verdicts }
}

fn lookup_inner_map(
    outer_map: &libbpf_rs::MapHandle,
    outer_key: &[u8],
) -> Option<libbpf_rs::MapHandle> {
    match outer_map.lookup(outer_key, MapFlags::ANY) {
        Ok(Some(val)) => {
            let id = plain::from_bytes::<i32>(&val).ok()?;
            libbpf_rs::MapHandle::from_map_id(*id as u32).ok()
        }
        _ => None,
    }
}

fn compute_effective_mark(
    ip_rule_match: &Option<FlowRuleMatchResult>,
    dns_rule_match: &Option<FlowRuleMatchResult>,
) -> (FlowVerdictSource, FlowMark) {
    match (ip_rule_match, dns_rule_match) {
        (Some(ip), Some(dns)) => {
            if dns.priority <= ip.priority {
                (FlowVerdictSource::DnsRule, dns.mark)
            } else {
                (FlowVerdictSource::IpRule, ip.mark)
            }
        }
        (Some(ip), None) => (FlowVerdictSource::IpRule, ip.mark),
        (None, Some(dns)) => (FlowVerdictSource::DnsRule, dns.mark),
        (None, None) => (FlowVerdictSource::Default, FlowMark::default()),
    }
}

fn expected_cache_mark_value(flow_id: u32, effective_mark: &FlowMark) -> u32 {
    let mark_value: u32 = (*effective_mark).into();
    let raw_action = ((mark_value & FLOW_ACTION_MASK) >> 8) as u8;

    if raw_action == 0 {
        return (mark_value & !FLOW_ID_MASK) | (flow_id & FLOW_ID_MASK);
    }

    mark_value
}

fn trace_flow_verdict_single_v4(
    flow_id: u32,
    dst_ip: Ipv4Addr,
) -> (Option<FlowRuleMatchResult>, Option<FlowRuleMatchResult>, FlowVerdictSource, FlowMark) {
    let flow_id_key = unsafe { plain::as_bytes(&flow_id) };

    // IP trie lookup
    let ip_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow4_ip_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut trie_key = flow_ip_trie_key_v4::default();
        trie_key.prefixlen = 32;
        trie_key.addr = dst_ip.to_bits().to_be();
        let key_bytes = unsafe { plain::as_bytes(&trie_key) };

        let val_bytes = inner.lookup(key_bytes, MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<flow_ip_trie_value_v4>() {
            return None;
        }
        let val =
            unsafe { std::ptr::read_unaligned(val_bytes.as_ptr() as *const flow_ip_trie_value_v4) };
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    // DNS hash lookup
    let dns_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow4_dns_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut dns_key = flow_dns_match_key_v4::default();
        dns_key.addr = dst_ip.to_bits().to_be();
        let key_bytes = unsafe { plain::as_bytes(&dns_key) };

        let val_bytes = inner.lookup(key_bytes, MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<flow_dns_match_value_v4>() {
            return None;
        }
        let val = unsafe {
            std::ptr::read_unaligned(val_bytes.as_ptr() as *const flow_dns_match_value_v4)
        };
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    let (effective_rule_source, effective_mark) =
        compute_effective_mark(&ip_rule_match, &dns_rule_match);
    (ip_rule_match, dns_rule_match, effective_rule_source, effective_mark)
}

fn trace_flow_verdict_single_v6(
    flow_id: u32,
    dst_ip: Ipv6Addr,
) -> (Option<FlowRuleMatchResult>, Option<FlowRuleMatchResult>, FlowVerdictSource, FlowMark) {
    let flow_id_key = unsafe { plain::as_bytes(&flow_id) };

    // IP trie lookup
    let ip_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow6_ip_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut trie_key = flow_ip_trie_key_v6::default();
        trie_key.prefixlen = 128;
        trie_key.addr.bytes = dst_ip.to_bits().to_be_bytes();
        let key_bytes = unsafe { plain::as_bytes(&trie_key) };

        let val_bytes = inner.lookup(key_bytes, MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<flow_ip_trie_value_v6>() {
            return None;
        }
        let val =
            unsafe { std::ptr::read_unaligned(val_bytes.as_ptr() as *const flow_ip_trie_value_v6) };
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    // DNS hash lookup
    let dns_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow6_dns_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut dns_key = flow_dns_match_key_v6::default();
        dns_key.addr.bytes = dst_ip.to_bits().to_be_bytes();
        let key_bytes = unsafe { plain::as_bytes(&dns_key) };

        let val_bytes = inner.lookup(key_bytes, MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<flow_dns_match_value_v6>() {
            return None;
        }
        let val = unsafe {
            std::ptr::read_unaligned(val_bytes.as_ptr() as *const flow_dns_match_value_v6)
        };
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    let (effective_rule_source, effective_mark) =
        compute_effective_mark(&ip_rule_match, &dns_rule_match);
    (ip_rule_match, dns_rule_match, effective_rule_source, effective_mark)
}

fn trace_cache_check_v4(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    expected_cache_mark: u32,
) -> (bool, Option<u32>, bool) {
    let result = (|| -> Option<(bool, Option<u32>, bool)> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_cache_map).ok()?;

        let cache_index = LAN_CACHE;
        let index_key = unsafe { plain::as_bytes(&cache_index) };
        let inner = lookup_inner_map(&outer, index_key)?;

        let mut cache_key = rt_cache_key_v4::default();
        cache_key.local_addr = src_ip.to_bits().to_be();
        cache_key.remote_addr = dst_ip.to_bits().to_be();
        let key_bytes = unsafe { plain::as_bytes(&cache_key) };

        match inner.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(val_bytes)) => {
                if val_bytes.len() < size_of::<rt_cache_value_v4>() {
                    return Some((false, None, true));
                }
                let val = unsafe {
                    std::ptr::read_unaligned(val_bytes.as_ptr() as *const rt_cache_value_v4)
                };
                let cached_mark_value = val.mark_value;
                let consistent = cached_mark_value == expected_cache_mark;
                Some((true, Some(cached_mark_value), consistent))
            }
            _ => Some((false, None, true)),
        }
    })();

    result.unwrap_or((false, None, true))
}

fn trace_cache_check_v6(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    expected_cache_mark: u32,
) -> (bool, Option<u32>, bool) {
    let result = (|| -> Option<(bool, Option<u32>, bool)> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_cache_map).ok()?;

        let cache_index = LAN_CACHE;
        let index_key = unsafe { plain::as_bytes(&cache_index) };
        let inner = lookup_inner_map(&outer, index_key)?;

        let mut cache_key = rt_cache_key_v6::default();
        cache_key.local_addr.bytes = src_ip.to_bits().to_be_bytes();
        cache_key.remote_addr.bytes = dst_ip.to_bits().to_be_bytes();
        let key_bytes = unsafe { plain::as_bytes(&cache_key) };

        match inner.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(val_bytes)) => {
                if val_bytes.len() < size_of::<rt_cache_value_v6>() {
                    return Some((false, None, true));
                }
                let val = unsafe {
                    std::ptr::read_unaligned(val_bytes.as_ptr() as *const rt_cache_value_v6)
                };
                let cached_mark_value = val.mark_value;
                let consistent = cached_mark_value == expected_cache_mark;
                Some((true, Some(cached_mark_value), consistent))
            }
            _ => Some((false, None, true)),
        }
    })();

    result.unwrap_or((false, None, true))
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

pub(crate) fn add_lan_route_inner_v4<'obj, T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = lan_route_key_v4::default();
    let mut value = lan_route_info_v4::default();

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
    let key = unsafe { plain::as_bytes(&key) };

    value.ifindex = lan_info.ifindex;
    if let Some(mac) = lan_info.mac {
        value.mac_addr = mac.octets();
        value.has_mac = std::mem::MaybeUninit::new(true);
    } else {
        value.has_mac = std::mem::MaybeUninit::new(false);
    }

    match &lan_info.mode {
        landscape_common::route::LanRouteMode::Reachable => {
            value.route_type = ROUTE_TYPE_LAN;
        }
        landscape_common::route::LanRouteMode::NextHop { next_hop_ip } => {
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
        landscape_common::route::LanRouteMode::WanReachable => {
            value.route_type = ROUTE_TYPE_WAN;
        }
    }

    let value = unsafe { plain::as_bytes(&value) };

    if let Ok(Some(existing)) = rt_lan_map.lookup(&key, MapFlags::ANY) {
        if existing.as_slice() == value {
            return false;
        }
    }

    if let Err(e) = rt_lan_map.update(&key, &value, MapFlags::ANY) {
        tracing::error!("add lan config error:{e:?}");
        return false;
    }

    true
}

pub(crate) fn add_lan_route_inner_v6<'obj, T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = lan_route_key_v6::default();
    let mut value = lan_route_info_v6::default();

    key.prefixlen = lan_info.prefix as u32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(_) => {
            return false;
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            key.addr.bytes = ipv6_addr.to_bits().to_be_bytes();
            value.addr.bytes = ipv6_addr.to_bits().to_be_bytes();
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

    match &lan_info.mode {
        landscape_common::route::LanRouteMode::Reachable => {
            value.route_type = ROUTE_TYPE_LAN;
        }
        landscape_common::route::LanRouteMode::NextHop { next_hop_ip } => {
            value.route_type = ROUTE_TYPE_NEXTHOP;

            match next_hop_ip {
                std::net::IpAddr::V4(_) => {
                    return false;
                }
                std::net::IpAddr::V6(ipv6_addr) => {
                    value.addr.bytes = ipv6_addr.to_bits().to_be_bytes();
                }
            }
        }
        landscape_common::route::LanRouteMode::WanReachable => {
            value.route_type = ROUTE_TYPE_WAN;
        }
    }

    let value = unsafe { plain::as_bytes(&value) };

    if let Ok(Some(existing)) = rt_lan_map.lookup(&key, MapFlags::ANY) {
        if existing.as_slice() == value {
            return false;
        }
    }

    if let Err(e) = rt_lan_map.update(&key, &value, MapFlags::ANY) {
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

pub(crate) fn del_lan_route_inner_v4<'obj, T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = lan_route_key_v4::default();
    key.prefixlen = lan_info.prefix as u32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            key.addr = ipv4_addr.to_bits().to_be();
        }
        std::net::IpAddr::V6(_) => {
            return false;
        }
    }
    let key = unsafe { plain::as_bytes(&key) };

    match rt_lan_map.lookup(&key, MapFlags::ANY) {
        Ok(Some(_)) => {}
        Ok(None) => return false,
        Err(e) => {
            tracing::error!("lookup lan config before delete error:{e:?}");
            return false;
        }
    }

    if let Err(e) = rt_lan_map.delete(&key) {
        tracing::error!("del lan config error:{e:?}");
        return false;
    }

    true
}

pub(crate) fn del_lan_route_inner_v6<'obj, T>(rt_lan_map: &T, lan_info: &LanRouteInfo) -> bool
where
    T: MapCore,
{
    let mut key = lan_route_key_v6::default();
    key.prefixlen = lan_info.prefix as u32;
    match lan_info.iface_ip {
        std::net::IpAddr::V4(_) => {
            return false;
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            key.addr.bytes = ipv6_addr.to_bits().to_be_bytes();
        }
    }
    let key = unsafe { plain::as_bytes(&key) };

    match rt_lan_map.lookup(&key, MapFlags::ANY) {
        Ok(Some(_)) => {}
        Ok(None) => return false,
        Err(e) => {
            tracing::error!("lookup lan config before delete error:{e:?}");
            return false;
        }
    }

    if let Err(e) = rt_lan_map.delete(&key) {
        tracing::error!("del lan config error:{e:?}");
        return false;
    }

    true
}

pub fn replace_wan_route_slots_v4(flow_id: FlowId, targets: &[(RouteTargetInfo, u32)]) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_target_slot_map).unwrap();
    replace_wan_route_slots_v4_with_map(&rt_target_map, flow_id, targets);
}

pub fn replace_wan_route_slots_v6(flow_id: FlowId, targets: &[(RouteTargetInfo, u32)]) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_target_slot_map).unwrap();
    replace_wan_route_slots_v6_with_map(&rt_target_map, flow_id, targets);
}

pub fn del_wan_route_slots_v4(flow_id: FlowId) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_target_slot_map).unwrap();
    clear_wan_route_slots_v4(&rt_target_map, flow_id);
}

pub fn del_wan_route_slots_v6(flow_id: FlowId) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_target_slot_map).unwrap();
    clear_wan_route_slots_v6(&rt_target_map, flow_id);
}

fn build_slot_indices(weights: &[u32]) -> Vec<usize> {
    let total_weight: u32 = weights.iter().sum();
    if total_weight == 0 {
        return Vec::new();
    }

    let mut current = vec![0i64; weights.len()];
    let mut slots = Vec::with_capacity(FLOW_TARGET_SLOT_COUNT);
    for _ in 0..FLOW_TARGET_SLOT_COUNT {
        let mut best_idx = None;
        let mut best_score = i64::MIN;
        for (idx, weight) in weights.iter().enumerate() {
            if *weight == 0 {
                continue;
            }
            current[idx] += *weight as i64;
            if current[idx] > best_score {
                best_score = current[idx];
                best_idx = Some(idx);
            }
        }

        let Some(best_idx) = best_idx else {
            break;
        };

        current[best_idx] -= total_weight as i64;
        slots.push(best_idx);
    }
    slots
}

pub(crate) fn replace_wan_route_slots_v4_with_map<T>(
    rt_target_map: &T,
    flow_id: FlowId,
    targets: &[(RouteTargetInfo, u32)],
) where
    T: MapCore,
{
    let filtered: Vec<_> = targets
        .iter()
        .filter(|(target, weight)| *weight > 0 && matches!(target.gateway_ip, IpAddr::V4(_)))
        .collect();
    if filtered.is_empty() {
        clear_wan_route_slots_v4(rt_target_map, flow_id);
        return;
    }

    let weights: Vec<u32> = filtered.iter().map(|(_, weight)| *weight).collect();
    let slots = build_slot_indices(&weights);
    let slot_count = slots.len() as u32;
    let mut keys =
        Vec::with_capacity(slots.len() * std::mem::size_of::<route_target_slot_key_v4>());
    let mut values = Vec::with_capacity(slots.len() * std::mem::size_of::<route_target_info_v4>());

    for (slot, target_index) in slots.into_iter().enumerate() {
        let (target, _) = filtered[target_index];
        let mut key = route_target_slot_key_v4::default();
        key.flow_id = flow_id;
        key.slot = slot as u32;

        let mut value = route_target_info_v4::default();
        value.ifindex = target.ifindex;
        value.is_docker = u8::from(target.is_docker);
        if let IpAddr::V4(ipv4_addr) = target.gateway_ip {
            value.gate_addr = ipv4_addr.to_bits().to_be();
        }
        match target.mac {
            Some(mac) => {
                value.has_mac = 1;
                value.mac = mac.octets();
            }
            None => value.has_mac = 0,
        }

        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&value) });
    }

    if let Err(e) =
        rt_target_map.update_batch(&keys, &values, slot_count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("replace ipv4 wan slot batch error:{e:?}");
    }
}

pub(crate) fn replace_wan_route_slots_v6_with_map<T>(
    rt_target_map: &T,
    flow_id: FlowId,
    targets: &[(RouteTargetInfo, u32)],
) where
    T: MapCore,
{
    let filtered: Vec<_> = targets
        .iter()
        .filter(|(target, weight)| *weight > 0 && matches!(target.gateway_ip, IpAddr::V6(_)))
        .collect();
    if filtered.is_empty() {
        clear_wan_route_slots_v6(rt_target_map, flow_id);
        return;
    }

    let weights: Vec<u32> = filtered.iter().map(|(_, weight)| *weight).collect();
    let slots = build_slot_indices(&weights);
    let slot_count = slots.len() as u32;
    let mut keys =
        Vec::with_capacity(slots.len() * std::mem::size_of::<route_target_slot_key_v6>());
    let mut values = Vec::with_capacity(slots.len() * std::mem::size_of::<route_target_info_v6>());

    for (slot, target_index) in slots.into_iter().enumerate() {
        let (target, _) = filtered[target_index];
        let mut key = route_target_slot_key_v6::default();
        key.flow_id = flow_id;
        key.slot = slot as u32;

        let mut value = route_target_info_v6::default();
        value.ifindex = target.ifindex;
        value.is_docker = u8::from(target.is_docker);
        if let IpAddr::V6(ipv6_addr) = target.gateway_ip {
            value.gate_addr.bytes = ipv6_addr.to_bits().to_be_bytes();
        }
        match target.mac {
            Some(mac) => {
                value.has_mac = 1;
                value.mac = mac.octets();
            }
            None => value.has_mac = 0,
        }

        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&value) });
    }

    if let Err(e) =
        rt_target_map.update_batch(&keys, &values, slot_count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("replace ipv6 wan slot batch error:{e:?}");
    }
}

fn clear_wan_route_slots_v4<T>(rt_target_map: &T, flow_id: FlowId)
where
    T: MapCore,
{
    let mut keys = Vec::with_capacity(
        FLOW_TARGET_SLOT_COUNT * std::mem::size_of::<route_target_slot_key_v4>(),
    );
    let mut count = 0;
    for slot in 0..FLOW_TARGET_SLOT_COUNT as u32 {
        let mut key = route_target_slot_key_v4::default();
        key.flow_id = flow_id;
        key.slot = slot;
        let key_bytes = unsafe { plain::as_bytes(&key) };
        match rt_target_map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(_)) => {
                count += 1;
                keys.extend_from_slice(key_bytes);
            }
            Ok(None) => {}
            Err(e) => tracing::error!("lookup ipv4 wan slot before delete error:{e:?}"),
        }
    }

    if count > 0 {
        if let Err(e) = rt_target_map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY) {
            tracing::error!("delete ipv4 wan slot batch error:{e:?}");
        }
    }
}

fn clear_wan_route_slots_v6<T>(rt_target_map: &T, flow_id: FlowId)
where
    T: MapCore,
{
    let mut keys = Vec::with_capacity(
        FLOW_TARGET_SLOT_COUNT * std::mem::size_of::<route_target_slot_key_v6>(),
    );
    let mut count = 0;
    for slot in 0..FLOW_TARGET_SLOT_COUNT as u32 {
        let mut key = route_target_slot_key_v6::default();
        key.flow_id = flow_id;
        key.slot = slot;
        let key_bytes = unsafe { plain::as_bytes(&key) };
        match rt_target_map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(_)) => {
                count += 1;
                keys.extend_from_slice(key_bytes);
            }
            Ok(None) => {}
            Err(e) => tracing::error!("lookup ipv6 wan slot before delete error:{e:?}"),
        }
    }

    if count > 0 {
        if let Err(e) = rt_target_map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY) {
            tracing::error!("delete ipv6 wan slot batch error:{e:?}");
        }
    }
}

#[cfg(test)]
mod slot_tests {
    use super::build_slot_indices;

    fn counts(slots: &[usize], target_count: usize) -> Vec<usize> {
        let mut counts = vec![0; target_count];
        for &slot in slots {
            counts[slot] += 1;
        }
        counts
    }

    #[test]
    fn slot_builder_balances_equal_weights() {
        let slots = build_slot_indices(&[1, 1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 2), vec![8, 8]);
    }

    #[test]
    fn slot_builder_respects_three_to_one_ratio() {
        let slots = build_slot_indices(&[3, 1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 2), vec![12, 4]);
    }

    #[test]
    fn slot_builder_skips_zero_weight_targets() {
        let slots = build_slot_indices(&[2, 0, 1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 3), vec![11, 0, 5]);
    }

    #[test]
    fn slot_builder_fills_all_slots_for_single_target() {
        let slots = build_slot_indices(&[1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 1), vec![16]);
    }

    #[test]
    fn slot_builder_distributes_prime_sum_weights() {
        let slots = build_slot_indices(&[5, 2]);
        assert_eq!(slots.len(), 16);
        // 5:2 ratio over 16 slots → 11:5 (nearest integer distribution)
        assert_eq!(counts(&slots, 2), vec![11, 5]);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use libbpf_rs::{libbpf_sys, MapHandle, MapType};

    use super::*;

    fn dummy_v6_route_target(ifindex: u32) -> RouteTargetInfo {
        RouteTargetInfo {
            weight: 0,
            ifindex,
            mac: None,
            default_route: false,
            is_docker: false,
            iface_name: String::new(),
            iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    fn create_test_slot_map_v6() -> MapHandle {
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        MapHandle::create(
            MapType::Hash,
            None::<&str>,
            std::mem::size_of::<route_target_slot_key_v6>() as u32,
            std::mem::size_of::<route_target_info_v6>() as u32,
            256,
            &opts,
        )
        .expect("create test slot map v6")
    }

    fn insert_v6_slot(map: &MapHandle, flow_id: u32, slot: u32, ifindex: u32) {
        let mut key = route_target_slot_key_v6::default();
        key.flow_id = flow_id;
        key.slot = slot;

        let mut value = route_target_info_v6::default();
        value.ifindex = ifindex;

        let key_bytes = unsafe { plain::as_bytes(&key) };
        let value_bytes = unsafe { plain::as_bytes(&value) };
        map.update(key_bytes, value_bytes, MapFlags::ANY).expect("insert test slot entry");
    }

    fn lookup_v6_slot(map: &MapHandle, flow_id: u32, slot: u32) -> bool {
        let mut key = route_target_slot_key_v6::default();
        key.flow_id = flow_id;
        key.slot = slot;
        map.lookup(unsafe { plain::as_bytes(&key) }, MapFlags::ANY).is_ok_and(|v| v.is_some())
    }

    #[test]
    fn replace_slots_with_all_zero_weights_clears_existing_entries() {
        let map = create_test_slot_map_v6();

        // Pre-populate some slots for flow_id 5
        insert_v6_slot(&map, 5, 0, 11);
        insert_v6_slot(&map, 5, 1, 11);
        assert!(lookup_v6_slot(&map, 5, 0));
        assert!(lookup_v6_slot(&map, 5, 1));

        // Call replace with all-zero weights
        let zero_weight_target = (dummy_v6_route_target(11), 0);
        replace_wan_route_slots_v6_with_map(&map, 5, &[zero_weight_target]);

        // Slots should be cleared
        assert!(!lookup_v6_slot(&map, 5, 0));
        assert!(!lookup_v6_slot(&map, 5, 1));
    }

    #[test]
    fn pick_effective_flow_prefers_ip_then_mac_then_default() {
        assert_eq!(
            pick_effective_flow(Some(3), Some(7), FlowMatchSource::Ipv4),
            (7, FlowMatchSource::Ipv4)
        );
        assert_eq!(
            pick_effective_flow(Some(3), None, FlowMatchSource::Ipv4),
            (3, FlowMatchSource::Mac)
        );
        assert_eq!(
            pick_effective_flow(None, None, FlowMatchSource::Ipv4),
            (0, FlowMatchSource::Default)
        );
    }

    #[test]
    fn expected_cache_mark_value_expands_keep_going_flow_id() {
        let keep_going = FlowMark::from(0x0000);
        let direct = FlowMark::from(0x0100);
        let redirect = FlowMark::from(0x0305);

        assert_eq!(expected_cache_mark_value(9, &keep_going), 0x0009);
        assert_eq!(expected_cache_mark_value(9, &direct), 0x0100);
        assert_eq!(expected_cache_mark_value(9, &redirect), 0x0305);
    }

    #[test]
    fn compute_effective_mark_prefers_dns_on_equal_priority() {
        let ip_rule = Some(FlowRuleMatchResult { mark: FlowMark::from(0x0100), priority: 10 });
        let dns_rule = Some(FlowRuleMatchResult { mark: FlowMark::from(0x0305), priority: 10 });

        let (source, mark) = compute_effective_mark(&ip_rule, &dns_rule);
        let mark_value: u32 = mark.into();

        assert_eq!(source, FlowVerdictSource::DnsRule);
        assert_eq!(mark_value, 0x0305);
    }
}

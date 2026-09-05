//! Webserver-facing flow-verdict tracing: `trace_flow_match`, `trace_flow_verdict`,
//! per-flow rule lookups (`flow4/6_*` maps) and route-cache consistency checks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use landscape_common::{
    flow::mark::FlowMark,
    flow::trace::{
        FlowMatchRequest, FlowMatchResult, FlowMatchSource, FlowRuleMatchResult,
        FlowVerdictRequest, FlowVerdictResult, FlowVerdictSource, SingleVerdictResult,
    },
};
use libbpf_rs::{MapCore, MapFlags};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    maps::{
        FlowDnsMatchKeyV4, FlowDnsMatchKeyV6, FlowDnsMatchValueV4, FlowDnsMatchValueV6,
        FlowIpTrieKeyV4, FlowIpTrieKeyV6, FlowIpTrieValueV4, FlowIpTrieValueV6, FlowMatchKey,
        LandscapeMapPath, RtCacheKeyV4, RtCacheKeyV6, RtCacheValueV4, RtCacheValueV6,
    },
    LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE,
};
const FLOW_ENTRY_MODE_MAC: u8 = 0;
const FLOW_ENTRY_MODE_IP: u8 = 1;
const FLOW_ID_MASK: u32 = 0x000000FF;
const FLOW_ACTION_MASK: u32 = 0x00007F00;
const LAN_CACHE: u32 = 1;
pub(crate) fn pick_effective_flow(
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
#[allow(clippy::field_reassign_with_default)]
pub fn trace_flow_match(paths: &LandscapeMapPath, req: FlowMatchRequest) -> FlowMatchResult {
    let flow_match_map = match libbpf_rs::MapHandle::from_pinned_path(&paths.flow_match_map) {
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
        let mut key = FlowMatchKey::default();
        key.prefixlen = 80; // FLOW_MAC_MATCH_LEN
        key.l3_protocol = 0;
        key.is_match_ip = FLOW_ENTRY_MODE_MAC;
        key.set_src_mac(mac.octets());

        match flow_match_map.lookup(key.as_bytes(), MapFlags::ANY) {
            Ok(Some(val)) => u32::read_from_bytes(&val).ok(),
            _ => None,
        }
    } else {
        None
    };

    // IPv4 match
    let flow_id_by_ipv4 = if let Some(ipv4) = &req.src_ipv4 {
        let mut key = FlowMatchKey::default();
        key.prefixlen = 64; // FLOW_IP_IPV4_MATCH_LEN
        key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        key.is_match_ip = FLOW_ENTRY_MODE_IP;
        key.set_src_ipv4_be(ipv4.to_bits());

        match flow_match_map.lookup(key.as_bytes(), MapFlags::ANY) {
            Ok(Some(val)) => u32::read_from_bytes(&val).ok(),
            _ => None,
        }
    } else {
        None
    };

    // IPv6 match
    let flow_id_by_ipv6 = if let Some(ipv6) = &req.src_ipv6 {
        let mut key = FlowMatchKey::default();
        key.prefixlen = 160; // FLOW_IP_IPV6_MATCH_LEN
        key.l3_protocol = LANDSCAPE_IPV6_TYPE;
        key.is_match_ip = FLOW_ENTRY_MODE_IP;
        key.set_src_ipv6(*ipv6);

        match flow_match_map.lookup(key.as_bytes(), MapFlags::ANY) {
            Ok(Some(val)) => u32::read_from_bytes(&val).ok(),
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
pub fn trace_flow_verdict(paths: &LandscapeMapPath, req: FlowVerdictRequest) -> FlowVerdictResult {
    let verdicts = req
        .dst_ips
        .iter()
        .map(|dst_ip| match dst_ip {
            IpAddr::V4(v4) => {
                let (ip_rule_match, dns_rule_match, effective_rule_source, effective_mark) =
                    trace_flow_verdict_single_v4(paths, req.flow_id, *v4);
                let expected_cache_mark = expected_cache_mark_value(req.flow_id, &effective_mark);
                let (has_cache, cached_mark, cache_consistent) = if let Some(src) = req.src_ipv4 {
                    trace_cache_check_v4(paths, src, *v4, expected_cache_mark)
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
                    trace_flow_verdict_single_v6(paths, req.flow_id, *v6);
                let expected_cache_mark = expected_cache_mark_value(req.flow_id, &effective_mark);
                let (has_cache, cached_mark, cache_consistent) = if let Some(src) = req.src_ipv6 {
                    trace_cache_check_v6(paths, src, *v6, expected_cache_mark)
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
            let id = i32::read_from_bytes(&val).ok()?;
            libbpf_rs::MapHandle::from_map_id(id as u32).ok()
        }
        _ => None,
    }
}

pub(crate) fn compute_effective_mark(
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

pub(crate) fn expected_cache_mark_value(flow_id: u32, effective_mark: &FlowMark) -> u32 {
    let mark_value: u32 = (*effective_mark).into();
    let raw_action = ((mark_value & FLOW_ACTION_MASK) >> 8) as u8;

    if raw_action == 0 {
        return (mark_value & !FLOW_ID_MASK) | (flow_id & FLOW_ID_MASK);
    }

    mark_value
}

#[allow(clippy::field_reassign_with_default)]
fn trace_flow_verdict_single_v4(
    paths: &LandscapeMapPath,
    flow_id: u32,
    dst_ip: Ipv4Addr,
) -> (Option<FlowRuleMatchResult>, Option<FlowRuleMatchResult>, FlowVerdictSource, FlowMark) {
    let flow_id_key = flow_id.as_bytes();

    // IP trie lookup
    let ip_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_ip_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut trie_key = FlowIpTrieKeyV4::default();
        trie_key.prefixlen = 32;
        trie_key.addr = dst_ip.to_bits().to_be();

        let val_bytes = inner.lookup(trie_key.as_bytes(), MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<FlowIpTrieValueV4>() {
            return None;
        }
        let val = FlowIpTrieValueV4::read_from_bytes(&val_bytes).ok()?;
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    // DNS hash lookup
    let dns_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.flow4_dns_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut dns_key = FlowDnsMatchKeyV4::default();
        dns_key.addr = dst_ip.to_bits().to_be();

        let val_bytes = inner.lookup(dns_key.as_bytes(), MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<FlowDnsMatchValueV4>() {
            return None;
        }
        let val = FlowDnsMatchValueV4::read_from_bytes(&val_bytes).ok()?;
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    let (effective_rule_source, effective_mark) =
        compute_effective_mark(&ip_rule_match, &dns_rule_match);
    (ip_rule_match, dns_rule_match, effective_rule_source, effective_mark)
}

#[allow(clippy::field_reassign_with_default)]
fn trace_flow_verdict_single_v6(
    paths: &LandscapeMapPath,
    flow_id: u32,
    dst_ip: Ipv6Addr,
) -> (Option<FlowRuleMatchResult>, Option<FlowRuleMatchResult>, FlowVerdictSource, FlowMark) {
    let flow_id_key = flow_id.as_bytes();

    // IP trie lookup
    let ip_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_ip_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut trie_key = FlowIpTrieKeyV6::default();
        trie_key.prefixlen = 128;
        trie_key.addr = dst_ip.to_bits().to_be_bytes();

        let val_bytes = inner.lookup(trie_key.as_bytes(), MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<FlowIpTrieValueV6>() {
            return None;
        }
        let val = FlowIpTrieValueV6::read_from_bytes(&val_bytes).ok()?;
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    // DNS hash lookup
    let dns_rule_match = (|| -> Option<FlowRuleMatchResult> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.flow6_dns_map).ok()?;
        let inner = lookup_inner_map(&outer, flow_id_key)?;

        let mut dns_key = FlowDnsMatchKeyV6::default();
        dns_key.addr = dst_ip.to_bits().to_be_bytes();

        let val_bytes = inner.lookup(dns_key.as_bytes(), MapFlags::ANY).ok()??;
        if val_bytes.len() < size_of::<FlowDnsMatchValueV6>() {
            return None;
        }
        let val = FlowDnsMatchValueV6::read_from_bytes(&val_bytes).ok()?;
        Some(FlowRuleMatchResult {
            mark: FlowMark::from(val.mark),
            priority: val.priority,
        })
    })();

    let (effective_rule_source, effective_mark) =
        compute_effective_mark(&ip_rule_match, &dns_rule_match);
    (ip_rule_match, dns_rule_match, effective_rule_source, effective_mark)
}

#[allow(clippy::field_reassign_with_default)]
fn trace_cache_check_v4(
    paths: &LandscapeMapPath,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    expected_cache_mark: u32,
) -> (bool, Option<u32>, bool) {
    let result = (|| -> Option<(bool, Option<u32>, bool)> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.rt4_cache_map).ok()?;

        let cache_index = LAN_CACHE;
        let index_key = cache_index.as_bytes();
        let inner = lookup_inner_map(&outer, index_key)?;

        let mut cache_key = RtCacheKeyV4::default();
        cache_key.local_addr = src_ip.to_bits().to_be();
        cache_key.remote_addr = dst_ip.to_bits().to_be();

        match inner.lookup(cache_key.as_bytes(), MapFlags::ANY) {
            Ok(Some(val_bytes)) => {
                if val_bytes.len() < size_of::<RtCacheValueV4>() {
                    return Some((false, None, true));
                }
                let val = RtCacheValueV4::read_from_bytes(&val_bytes).ok()?;
                let cached_mark_value = val.mark_value;
                let consistent = cached_mark_value == expected_cache_mark;
                Some((true, Some(cached_mark_value), consistent))
            }
            _ => Some((false, None, true)),
        }
    })();

    result.unwrap_or((false, None, true))
}

#[allow(clippy::field_reassign_with_default)]
fn trace_cache_check_v6(
    paths: &LandscapeMapPath,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    expected_cache_mark: u32,
) -> (bool, Option<u32>, bool) {
    let result = (|| -> Option<(bool, Option<u32>, bool)> {
        let outer = libbpf_rs::MapHandle::from_pinned_path(&paths.rt6_cache_map).ok()?;

        let cache_index = LAN_CACHE;
        let index_key = cache_index.as_bytes();
        let inner = lookup_inner_map(&outer, index_key)?;

        let mut cache_key = RtCacheKeyV6::default();
        cache_key.local_addr = src_ip.to_bits().to_be_bytes();
        cache_key.remote_addr = dst_ip.to_bits().to_be_bytes();

        match inner.lookup(cache_key.as_bytes(), MapFlags::ANY) {
            Ok(Some(val_bytes)) => {
                if val_bytes.len() < size_of::<RtCacheValueV6>() {
                    return Some((false, None, true));
                }
                let val = RtCacheValueV6::read_from_bytes(&val_bytes).ok()?;
                let cached_mark_value = val.mark_value;
                let consistent = cached_mark_value == expected_cache_mark;
                Some((true, Some(cached_mark_value), consistent))
            }
            _ => Some((false, None, true)),
        }
    })();

    result.unwrap_or((false, None, true))
}

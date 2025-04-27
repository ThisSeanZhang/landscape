use landscape_common::flow::{FlowMathPair, PacketMatchMark};
use libbpf_rs::{MapCore, MapFlags};

use crate::{
    flow::verdict::flow_verdict_bpf::types::flow_match_key, LANDSCAPE_IPV4_TYPE,
    LANDSCAPE_IPV6_TYPE, MAP_PATHS,
};

/// 更新匹配规则到 flow 的映射
pub fn update_flow_match_rule(rules: Vec<FlowMathPair>) {
    if rules.is_empty() {
        return;
    }

    let flow_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_match_map).unwrap();
    let mut keys = vec![];
    let mut values = vec![];
    let counts = rules.len() as u32;

    for FlowMathPair { match_rule, flow_id } in rules.into_iter() {
        let mut match_key = flow_match_key {
            vlan_tci: match_rule.vlan_id.unwrap_or(0),
            tos: match_rule.qos.unwrap_or(0),
            l4_protocol: 6,
            ..Default::default()
        };

        match match_rule.ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
                match_key.src_addr.ip = ipv4_addr.to_bits().to_be();
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
                match_key.src_addr.bits = ipv6_addr.to_bits().to_be_bytes()
            }
        }
        keys.extend_from_slice(unsafe { plain::as_bytes(&match_key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&flow_id) });
    }
    if let Err(e) =
        flow_match_map.update_batch(&keys, &values, counts, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("update_flow_match_rule error:{e:?}");
    }
}

/// 删除匹配规则到 flow 的映射
pub fn del_flow_match_rule(rules: Vec<PacketMatchMark>) {
    if rules.is_empty() {
        return;
    }

    let flow_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_match_map).unwrap();
    let mut keys = vec![];
    let counts = rules.len() as u32;

    for match_rule in rules.into_iter() {
        let mut match_key = flow_match_key {
            vlan_tci: match_rule.vlan_id.unwrap_or(0),
            tos: match_rule.qos.unwrap_or(0),
            ..Default::default()
        };

        match match_rule.ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
                match_key.src_addr.ip = ipv4_addr.to_bits().to_be();
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
                match_key.src_addr.bits = ipv6_addr.to_bits().to_be_bytes()
            }
        }

        keys.extend_from_slice(unsafe { plain::as_bytes(&match_key) });
    }
    if let Err(e) = flow_match_map.delete_batch(&keys, counts, MapFlags::ANY, MapFlags::ANY) {
        tracing::error!("del_flow_match_rule error:{e:?}");
    }
}

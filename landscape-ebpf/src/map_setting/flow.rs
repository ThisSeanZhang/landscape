use landscape_common::flow::{
    ResolvedFlowEntryMatchMode, ResolvedFlowEntryRule, RuntimeFlowConfig,
};

use crate::bpf_error::LdEbpfResult;
use crate::{
    map_setting::share_map::types::flow_match_key, LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE,
    MAP_PATHS,
};

use super::{apply_raw_map_diff, diff_raw_map, snapshot_raw_map, RawEbpfMapEntries};

const FLOW_ENTRY_MODE_MAC: u8 = 0;
const FLOW_ENTRY_MODE_IP: u8 = 1;

impl From<ResolvedFlowEntryRule> for flow_match_key {
    fn from(val: ResolvedFlowEntryRule) -> Self {
        flow_match_key_from_rule(&val)
    }
}

fn flow_match_key_from_rule(rule: &ResolvedFlowEntryRule) -> flow_match_key {
    let mut match_key = flow_match_key::default();
    match &rule.mode {
        ResolvedFlowEntryMatchMode::Mac { mac_addr } => {
            match_key.prefixlen = 80;
            match_key.l3_protocol = 0;
            match_key.is_match_ip = FLOW_ENTRY_MODE_MAC;
            match_key.__anon_flow_match_key_1.mac.mac = mac_addr.octets();
        }
        ResolvedFlowEntryMatchMode::Ip { ip, prefix_len } => {
            match_key.prefixlen = 32 + *prefix_len as u32;
            match_key.is_match_ip = FLOW_ENTRY_MODE_IP;
            match ip {
                std::net::IpAddr::V4(ipv4_addr) => {
                    match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
                    match_key.__anon_flow_match_key_1.src_addr.ip = ipv4_addr.to_bits().to_be();
                }
                std::net::IpAddr::V6(ipv6_addr) => {
                    match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
                    match_key.__anon_flow_match_key_1.src_addr.bits =
                        ipv6_addr.to_bits().to_be_bytes();
                }
            }
        }
    }
    match_key
}

pub fn build_flow_match_entries(configs: &[RuntimeFlowConfig]) -> RawEbpfMapEntries {
    let mut entries = RawEbpfMapEntries::new();
    for config in configs {
        for rule in &config.flow_match_rules {
            let key = flow_match_key_from_rule(rule);
            entries.insert(
                unsafe { plain::as_bytes(&key) }.to_vec(),
                unsafe { plain::as_bytes(&config.flow_id) }.to_vec(),
            );
        }
    }
    entries
}

pub fn reconcile_flow_match_entries(desired: RawEbpfMapEntries) -> LdEbpfResult<()> {
    let flow_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_match_map)?;
    let current = snapshot_raw_map(&flow_match_map)?;
    let diff = diff_raw_map(&current, &desired);
    let changed = !diff.is_empty();
    apply_raw_map_diff(&flow_match_map, diff)?;
    if changed {
        crate::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    }
    Ok(())
}

pub fn reconcile_flow_match_map(configs: &[RuntimeFlowConfig]) -> LdEbpfResult<()> {
    reconcile_flow_match_entries(build_flow_match_entries(configs))
}

//! Startup creation/pinning of the per-flow DNS rule outer maps.
//!
//! Creation parameters mirror the C `SEC(".maps")` definitions in
//! `src/bpf/route/route_maps_v4.h` / `route_maps_v6.h`. Passing the pin
//! paths explicitly lets tests create the maps under an isolated (temporary)
//! bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{ensure_pinned_map, InnerMapSpec, MapCreateSpec};

use super::types::{
    FlowDnsMatchKeyV4, FlowDnsMatchKeyV6, FlowDnsMatchValueV4, FlowDnsMatchValueV6,
};

const FLOW_OUTER_MAX_ENTRIES: u32 = 256;
const DNS_MATCH_MAX_ENTRIES: u32 = 4096;

/// Pin 文件名 = C map 符号名（见 `route_maps_v4.h` / `route_maps_v6.h`）。
pub(crate) const FLOW4_DNS_MAP_PIN: &str = "flow4_dns_map";
pub(crate) const FLOW6_DNS_MAP_PIN: &str = "flow6_dns_map";

/// Inner template `each_flow_dns_v4`: `BPF_MAP_TYPE_LRU_HASH`.
pub(crate) const EACH_FLOW_DNS_V4: InnerMapSpec = InnerMapSpec {
    map_type: MapType::LruHash,
    name: "each_flow_dns_v4",
    key_size: size_of::<FlowDnsMatchKeyV4>() as u32,
    value_size: size_of::<FlowDnsMatchValueV4>() as u32,
    max_entries: DNS_MATCH_MAX_ENTRIES,
    map_flags: 0,
};

/// Inner template `each_flow_dns_v6`: `BPF_MAP_TYPE_LRU_HASH`.
pub(crate) const EACH_FLOW_DNS_V6: InnerMapSpec = InnerMapSpec {
    map_type: MapType::LruHash,
    name: "each_flow_dns_v6",
    key_size: size_of::<FlowDnsMatchKeyV6>() as u32,
    value_size: size_of::<FlowDnsMatchValueV6>() as u32,
    max_entries: DNS_MATCH_MAX_ENTRIES,
    map_flags: 0,
};

/// `flow4_dns_map`: `BPF_MAP_TYPE_HASH_OF_MAPS`, key `u32` flow id, 256
/// entries, inner `each_flow_dns_v4`.
pub(crate) const FLOW4_DNS_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::HashOfMaps,
    name: FLOW4_DNS_MAP_PIN,
    key_size: 4,
    value_size: 4,
    max_entries: FLOW_OUTER_MAX_ENTRIES,
    map_flags: 0,
    inner: Some(EACH_FLOW_DNS_V4),
};

/// `flow6_dns_map`: `BPF_MAP_TYPE_HASH_OF_MAPS`, key `u32` flow id, 256
/// entries, inner `each_flow_dns_v6`.
pub(crate) const FLOW6_DNS_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::HashOfMaps,
    name: FLOW6_DNS_MAP_PIN,
    key_size: 4,
    value_size: 4,
    max_entries: FLOW_OUTER_MAX_ENTRIES,
    map_flags: 0,
    inner: Some(EACH_FLOW_DNS_V6),
};

/// Create or reuse the pinned `flow4_dns_map` at `path`.
pub fn init_flow4_dns_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FLOW4_DNS_MAP_SPEC, path)
}

/// Create or reuse the pinned `flow6_dns_map` at `path`.
pub fn init_flow6_dns_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FLOW6_DNS_MAP_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xdp_wan_route::xdp_wan_route_skel::XdpWanRouteSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn flow_dns_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpWanRouteSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.flow4_dns_map, &FLOW4_DNS_MAP_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.flow6_dns_map, &FLOW6_DNS_MAP_SPEC);
    }
}

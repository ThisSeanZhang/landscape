//! Startup creation/pinning of the flow-match map.
//!
//! Creation parameters mirror the `flow_match_map` `SEC(".maps")` definition
//! in `src/bpf/flow_match.h`. Passing the pin path explicitly lets tests
//! create the map under an isolated (temporary) bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{libbpf_sys, MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{ensure_pinned_map, MapCreateSpec};

use super::types::FlowMatchKey;

/// Pin 文件名 = C map 符号名（见 `flow_match.h`）。
pub(crate) const FLOW_MATCH_MAP_PIN: &str = "flow_match_map";

/// `flow_match_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `flow_match_key` (24),
/// value `u32` flow id, 65536 entries, `BPF_F_NO_PREALLOC |
/// BPF_F_RDONLY_PROG`.
pub(crate) const FLOW_MATCH_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: FLOW_MATCH_MAP_PIN,
    key_size: size_of::<FlowMatchKey>() as u32,
    value_size: 4,
    max_entries: 65536,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC | libbpf_sys::BPF_F_RDONLY_PROG,
    inner: None,
};

/// Create or reuse the pinned `flow_match_map` at `path`.
pub fn init_flow_match_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FLOW_MATCH_MAP_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xdp_wan_route::xdp_wan_route_skel::XdpWanRouteSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn flow_match_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpWanRouteSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.flow_match_map, &FLOW_MATCH_MAP_SPEC);
    }
}

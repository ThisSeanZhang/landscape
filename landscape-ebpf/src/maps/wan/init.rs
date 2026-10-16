//! Startup creation/pinning of the WAN IP binding map.
//!
//! Creation parameters mirror the `wan_ip_binding` `SEC(".maps")` definition
//! in `src/bpf/wan_ip.h`. Passing the pin path explicitly lets tests
//! create the map under an isolated (temporary) bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{MapHandle, MapType, libbpf_sys};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};

use super::types::{WanIpInfoKey, WanIpInfoValue};

/// Pin 文件名 = C map 符号名（见 `wan_ip.h`）。
pub(crate) const WAN_IP_BINDING_PIN: &str = "wan_ip_binding";

/// `wan_ip_binding`: `BPF_MAP_TYPE_HASH`, key `wan_ip_info_key` (8),
/// value `wan_ip_info_value` (48), 256 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const WAN_IP_BINDING_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: WAN_IP_BINDING_PIN,
    key_size: size_of::<WanIpInfoKey>() as u32,
    value_size: size_of::<WanIpInfoValue>() as u32,
    max_entries: 256,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// Create or reuse the pinned `wan_ip_binding` map at `path`.
pub fn init_wan_ip_binding_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&WAN_IP_BINDING_SPEC, path)
}

/// Pin file name = the C map symbol (see `tc_wan_egress_route.bpf.c`).
pub(crate) const WAN_V6_LL_CHAIN_PIN: &str = "wan_v6_ll_chain";

/// `wan_v6_ll_chain`: `BPF_MAP_TYPE_HASH`, key `struct in6_addr` (16),
/// value chain id (4), 64 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const WAN_V6_LL_CHAIN_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: WAN_V6_LL_CHAIN_PIN,
    key_size: size_of::<std::net::Ipv6Addr>() as u32,
    value_size: size_of::<u32>() as u32,
    max_entries: 64,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// Create or reuse the pinned `wan_v6_ll_chain` map at `path`.
pub fn init_wan_v6_ll_chain_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&WAN_V6_LL_CHAIN_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_backbone::tc_wan_ingress_route_skel::TcWanIngressRouteSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn wan_v6_ll_chain_params_match_skel() {
        use crate::chain::tc_wan_route::tc_wan_egress_route_skel::TcWanEgressRouteSkelBuilder;
        let mut obj = std::mem::MaybeUninit::uninit();
        let open =
            TcWanEgressRouteSkelBuilder::default().open(&mut obj).expect("open egress route skel");
        crate::maps::assert_skel_map_matches(&open.maps.wan_v6_ll_chain, &WAN_V6_LL_CHAIN_SPEC);
    }

    #[test]
    fn wan_ip_binding_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open =
            TcWanIngressRouteSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.wan_ip_binding, &WAN_IP_BINDING_SPEC);
    }
}

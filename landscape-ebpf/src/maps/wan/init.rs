//! Startup creation/pinning of the WAN IP binding map.
//!
//! Creation parameters mirror the `wan_ip_binding` `SEC(".maps")` definition
//! in `src/bpf/land_wan_ip.h`. Passing the pin path explicitly lets tests
//! create the map under an isolated (temporary) bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{libbpf_sys, MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{ensure_pinned_map, MapCreateSpec};

use super::types::{WanIpInfoKey, WanIpInfoValue};

/// Pin 文件名 = C map 符号名（见 `land_wan_ip.h`）。
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::nat::xdp_nat_skel::XdpNatSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn wan_ip_binding_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpNatSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.wan_ip_binding, &WAN_IP_BINDING_SPEC);
    }
}

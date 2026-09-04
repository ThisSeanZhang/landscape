//! Startup creation/pinning of the XDP redirect-ability map.
//!
//! Creation parameters mirror the `xdp_redirect_able` `SEC(".maps")`
//! definition in `src/bpf/chain/redirect_able.h`. Passing the pin path
//! explicitly lets tests create the map under an isolated (temporary) bpffs
//! directory.

use std::path::Path;

use libbpf_rs::{MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{ensure_pinned_map, MapCreateSpec};

const XDP_REDIRECT_ABLE_MAX_ENTRIES: u32 = 1024;

/// Pin 文件名 = C map 符号名（见 `chain/redirect_able.h`）。
pub(crate) const XDP_REDIRECT_ABLE_PIN: &str = "xdp_redirect_able";

/// `xdp_redirect_able`: `BPF_MAP_TYPE_HASH`, key `u32` ifindex, value `u32`,
/// 1024 entries.
pub(crate) const XDP_REDIRECT_ABLE_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: XDP_REDIRECT_ABLE_PIN,
    key_size: 4,
    value_size: 4,
    max_entries: XDP_REDIRECT_ABLE_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

/// Create or reuse the pinned `xdp_redirect_able` map at `path`.
pub fn init_xdp_redirect_able(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&XDP_REDIRECT_ABLE_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xdp_wan_route::xdp_wan_route_skel::XdpWanRouteSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn xdp_redirect_able_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpWanRouteSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.xdp_redirect_able, &XDP_REDIRECT_ABLE_SPEC);
    }
}

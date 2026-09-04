//! Startup creation/pinning of the DNS socket map.
//!
//! Creation parameters mirror the `dns_flow_socks` `SEC(".maps")` definition
//! in `src/bpf/land_dns_dispatcher.h`. Passing the pin path explicitly lets
//! tests create the map under an isolated (temporary) bpffs directory.

use std::path::Path;

use libbpf_rs::{MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{ensure_pinned_map, MapCreateSpec};

/// Pin 文件名 = C map 符号名（见 `land_dns_dispatcher.h`）。
pub(crate) const DNS_FLOW_SOCKS_PIN: &str = "dns_flow_socks";

/// `dns_flow_socks`: `BPF_MAP_TYPE_SOCKMAP`, key `u32`, value `u64`,
/// 512 entries.
pub(crate) const DNS_FLOW_SOCKS_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Sockmap,
    name: DNS_FLOW_SOCKS_PIN,
    key_size: 4,
    value_size: 8,
    max_entries: 512,
    map_flags: 0,
    inner: None,
};

/// Create or reuse the pinned `dns_flow_socks` sockmap at `path`.
pub fn init_dns_flow_socks(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&DNS_FLOW_SOCKS_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_dispatcher::land_dns_dispatcher::LandDnsDispatcherSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn dns_flow_socks_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open =
            LandDnsDispatcherSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.dns_flow_socks, &DNS_FLOW_SOCKS_SPEC);
    }
}

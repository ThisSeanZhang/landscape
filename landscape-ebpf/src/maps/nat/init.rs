//! Startup creation/pinning of the NAT maps.
//!
//! Creation parameters mirror the C `SEC(".maps")` definitions in
//! `src/bpf/nat/nat6_static.h` and `nat_metric.h`. Passing the pin paths
//! explicitly lets tests create the maps under an isolated (temporary)
//! bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};

use super::types::{StaticNat6MappingKey, StaticNat6MappingValue};

pub const STATIC_NAT_MAPPING_CACHE_SIZE: u32 = 1024 * 64;

/// Pin 文件名 = C map 符号名（见 `nat6_static.h` / `nat_metric.h`）。
pub(crate) const NAT6_STATIC_MAP_PIN: &str = "nat6_static_map";
pub(crate) const NAT_METRIC_EVENTS_PIN: &str = "nat_metric_events";

/// `nat6_static_map`: `BPF_MAP_TYPE_HASH`, key `static_nat6_mapping_key` (12),
/// value `static_nat6_mapping_value` (8), `STATIC_NAT_MAPPING_CACHE_SIZE`
/// entries.
pub(crate) const NAT6_STATIC_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::Hash,
    name: NAT6_STATIC_MAP_PIN,
    key_size: size_of::<StaticNat6MappingKey>() as u32,
    value_size: size_of::<StaticNat6MappingValue>() as u32,
    max_entries: STATIC_NAT_MAPPING_CACHE_SIZE,
    map_flags: 0,
    inner: None,
};

/// `nat_metric_events`: `BPF_MAP_TYPE_RINGBUF`, `1 << 24` bytes.
pub(crate) const NAT_METRIC_EVENTS_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::RingBuf,
    name: NAT_METRIC_EVENTS_PIN,
    key_size: 0,
    value_size: 0,
    max_entries: 1 << 24,
    map_flags: 0,
    inner: None,
};

/// Create or reuse the pinned `nat6_static_map` at `path`.
pub fn init_nat6_static_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&NAT6_STATIC_MAP_SPEC, path)
}

/// Create or reuse the pinned `nat_metric_events` ringbuf at `path`.
pub fn init_nat_metric_events(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&NAT_METRIC_EVENTS_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skel::xdp_nat4_v4::XdpNat4V4SkelBuilder;
    use crate::skel::xdp_nat6::XdpNat6SkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn nat_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open4 = XdpNat4V4SkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(
            &open4.maps.nat_metric_events,
            &NAT_METRIC_EVENTS_SPEC,
        );
        let mut obj = std::mem::MaybeUninit::uninit();
        let open6 = XdpNat6SkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open6.maps.nat6_static_map, &NAT6_STATIC_MAP_SPEC);
    }
}

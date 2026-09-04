//! Startup creation/pinning of the IP-MAC maps and the DAD NS event ringbuf.
//!
//! Creation parameters mirror the C `SEC(".maps")` definitions in
//! `src/bpf/neigh_ip4.h`, `neigh_ip6.h` and `neigh_ip6_event.h`. Passing the
//! pin paths explicitly lets tests create the maps under an isolated
//! (temporary) bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{ensure_pinned_map, MapCreateSpec};

use super::types::{MacKeyV4, MacKeyV6, MacValueV4, MacValueV6};

const IP_MAC_MAX_ENTRIES: u32 = 4096;

/// Pin 文件名 = C map 符号名（见 `neigh_ip4.h` / `neigh_ip6.h` /
/// `neigh_ip6_event.h`）。
pub(crate) const IP_MAC_V4_PIN: &str = "ip_mac_v4";
pub(crate) const IP_MAC_V6_PIN: &str = "ip_mac_v6";
pub(crate) const IP6_DAO_EVENTS_PIN: &str = "ip6_dao_events";

/// `ip_mac_v4`: `BPF_MAP_TYPE_LRU_HASH`, key `mac_key_v4` (4), value
/// `mac_value_v4` (18), 4096 entries.
pub(crate) const IP_MAC_V4_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: IP_MAC_V4_PIN,
    key_size: size_of::<MacKeyV4>() as u32,
    value_size: size_of::<MacValueV4>() as u32,
    max_entries: IP_MAC_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

/// `ip_mac_v6`: `BPF_MAP_TYPE_LRU_HASH`, key `mac_key_v6` (16), value
/// `mac_value_v6` (19), 4096 entries.
pub(crate) const IP_MAC_V6_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash,
    name: IP_MAC_V6_PIN,
    key_size: size_of::<MacKeyV6>() as u32,
    value_size: size_of::<MacValueV6>() as u32,
    max_entries: IP_MAC_MAX_ENTRIES,
    map_flags: 0,
    inner: None,
};

/// `ip6_dao_events`: `BPF_MAP_TYPE_RINGBUF`, `1 << 24` bytes.
pub(crate) const IP6_DAO_EVENTS_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::RingBuf,
    name: IP6_DAO_EVENTS_PIN,
    key_size: 0,
    value_size: 0,
    max_entries: 1 << 24,
    map_flags: 0,
    inner: None,
};

/// Create or reuse the pinned `ip_mac_v4` map at `path`.
pub fn init_ip_mac_v4(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&IP_MAC_V4_SPEC, path)
}

/// Create or reuse the pinned `ip_mac_v6` map at `path`.
pub fn init_ip_mac_v6(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&IP_MAC_V6_SPEC, path)
}

/// Create or reuse the pinned `ip6_dao_events` ringbuf at `path`.
pub fn init_ip6_dao_events(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&IP6_DAO_EVENTS_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tc_lan_route::tc_lan_dao_skel::TcLanDaoSkelBuilder;
    use crate::maps::mac::neigh_update::NeighUpdateSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn ip_mac_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = NeighUpdateSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.ip_mac_v4, &IP_MAC_V4_SPEC);
        crate::maps::assert_skel_map_matches(&open.maps.ip_mac_v6, &IP_MAC_V6_SPEC);
    }

    #[test]
    fn ip6_dao_events_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = TcLanDaoSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(&open.maps.ip6_dao_events, &IP6_DAO_EVENTS_SPEC);
    }
}

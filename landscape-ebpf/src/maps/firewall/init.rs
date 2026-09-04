//! Startup creation/pinning of the firewall maps.
//!
//! Creation parameters mirror the C `SEC(".maps")` definitions in
//! `src/bpf/firewall/firewall_share.h`. Passing the pin paths explicitly lets
//! tests create the maps under an isolated (temporary) bpffs directory.

use std::mem::size_of;
use std::path::Path;

use libbpf_rs::{libbpf_sys, MapHandle, MapType};

use crate::bpf_error::LdEbpfResult;
use crate::maps::{ensure_pinned_map, MapCreateSpec};

use super::types::{FirewallAction, Ipv4LpmKey, Ipv6LpmKey};

const FIREWALL_BLOCK_MAX_ENTRIES: u32 = 65535;

/// Pin 文件名 = C map 符号名（见 `firewall_share.h`）。
pub(crate) const FIREWALL_BLOCK_IP4_MAP_PIN: &str = "firewall_block_ip4_map";
pub(crate) const FIREWALL_BLOCK_IP6_MAP_PIN: &str = "firewall_block_ip6_map";
pub(crate) const FIREWALL_CONN_METRIC_EVENTS_PIN: &str = "firewall_conn_metric_events";

/// `firewall_block_ip4_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `ipv4_lpm_key` (8),
/// value `firewall_action` (4), 65535 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const FIREWALL_BLOCK_IP4_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: FIREWALL_BLOCK_IP4_MAP_PIN,
    key_size: size_of::<Ipv4LpmKey>() as u32,
    value_size: size_of::<FirewallAction>() as u32,
    max_entries: FIREWALL_BLOCK_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `firewall_block_ip6_map`: `BPF_MAP_TYPE_LPM_TRIE`, key `ipv6_lpm_key` (20),
/// value `firewall_action` (4), 65535 entries, `BPF_F_NO_PREALLOC`.
pub(crate) const FIREWALL_BLOCK_IP6_MAP_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LpmTrie,
    name: FIREWALL_BLOCK_IP6_MAP_PIN,
    key_size: size_of::<Ipv6LpmKey>() as u32,
    value_size: size_of::<FirewallAction>() as u32,
    max_entries: FIREWALL_BLOCK_MAX_ENTRIES,
    map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
    inner: None,
};

/// `firewall_conn_metric_events`: `BPF_MAP_TYPE_RINGBUF`, `1 << 24` bytes.
pub(crate) const FIREWALL_CONN_METRIC_EVENTS_SPEC: MapCreateSpec = MapCreateSpec {
    map_type: MapType::RingBuf,
    name: FIREWALL_CONN_METRIC_EVENTS_PIN,
    key_size: 0,
    value_size: 0,
    max_entries: 1 << 24,
    map_flags: 0,
    inner: None,
};

/// Create or reuse the pinned `firewall_block_ip4_map` at `path`.
pub fn init_firewall_block_ip4_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_BLOCK_IP4_MAP_SPEC, path)
}

/// Create or reuse the pinned `firewall_block_ip6_map` at `path`.
pub fn init_firewall_block_ip6_map(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_BLOCK_IP6_MAP_SPEC, path)
}

/// Create or reuse the pinned `firewall_conn_metric_events` ringbuf at `path`.
pub fn init_firewall_conn_metric_events(path: &Path) -> LdEbpfResult<MapHandle> {
    ensure_pinned_map(&FIREWALL_CONN_METRIC_EVENTS_SPEC, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::firewall::xdp_firewall_skel::XdpFirewallSkelBuilder;
    use libbpf_rs::skel::SkelBuilder as _;

    #[test]
    fn firewall_map_params_match_skel() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let open = XdpFirewallSkelBuilder::default().open(&mut obj).expect("open anchor skel");
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_block_ip4_map,
            &FIREWALL_BLOCK_IP4_MAP_SPEC,
        );
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_block_ip6_map,
            &FIREWALL_BLOCK_IP6_MAP_SPEC,
        );
        crate::maps::assert_skel_map_matches(
            &open.maps.firewall_conn_metric_events,
            &FIREWALL_CONN_METRIC_EVENTS_SPEC,
        );
    }
}

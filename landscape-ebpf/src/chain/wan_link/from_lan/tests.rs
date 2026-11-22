use std::net::Ipv4Addr;
use std::sync::Arc;

use landscape_common::net::MacAddr;
use libbpf_rs::{MapCore, MapFlags};

use super::WanLinkDataplane;
use crate::LandscapeMapPath;
use crate::maps::{self, wan_trie::dispatcher::WanTrieDispatcher};
use crate::route_backbone::RouteBackbone;
use crate::route_backbone::pinned_map;
use crate::test_support::{PinRootGuard, isolated_pin_root};

const IFINDEX: u32 = 7;
const IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 7);

fn dataplane() -> (PinRootGuard, Arc<WanLinkDataplane>) {
    let pins = isolated_pin_root("from-lan-roots");
    let paths = Arc::new(LandscapeMapPath::from_root(&pins));
    maps::init_maps_for_test(&paths);
    let backbone = RouteBackbone::new(paths, Arc::new(WanTrieDispatcher::new())).unwrap();
    let dp = WanLinkDataplane::new(Arc::new(backbone), 17, Some(IFINDEX), true).unwrap();
    (pins, dp)
}

fn program_id(map: &impl MapCore, slot: u32) -> u32 {
    let bytes = map.lookup(&slot.to_ne_bytes(), MapFlags::ANY).unwrap().unwrap();
    u32::from_ne_bytes(bytes.try_into().unwrap())
}

fn root_ids(dp: &WanLinkDataplane) -> [u32; 2] {
    let paths = dp.backbone.paths();
    [paths.xdp_lan_pipe_root_progs_path(), paths.tc_wan_egress_roots_path()]
        .map(|path| program_id(&pinned_map(&path).unwrap(), dp.id.into()))
}

fn stage_ids(dp: &WanLinkDataplane) -> [[u32; 2]; 2] {
    let inner = dp.inner.lock().unwrap();
    let xdp = &inner.xdp.lan_root.as_ref().unwrap().skel.maps.root_next_stage;
    let tc = &inner.tc.egress_root.as_ref().unwrap().skel.maps.wan_egress_root_next_stage;
    [[program_id(xdp, 0), program_id(xdp, 1)], [program_id(tc, 0), program_id(tc, 1)]]
}

fn bind(dp: &WanLinkDataplane, prefix: u8) {
    dp.bind_wan_ipv4(IFINDEX, IP, Some(GATEWAY), prefix, Some(MAC));
}

fn assert_ipv4_config(dp: &WanLinkDataplane, mask: Option<[u8; 4]>) {
    let (xdp, tc) = {
        let inner = dp.inner.lock().unwrap();
        let xdp = &inner.xdp.lan_root.as_ref().unwrap().skel.maps;
        let tc = &inner.tc.egress_root.as_ref().unwrap().skel.maps;
        (
            xdp.rodata_data.as_ref().unwrap().egress_binding,
            tc.rodata_data.as_ref().unwrap().egress_binding,
        )
    };
    // Both skeletons generate their own Rust type for the common BPF struct.
    macro_rules! check {
        ($cfg:ident) => {{
            assert_eq!($cfg.ifindex, IFINDEX);
            assert_eq!($cfg.has_l2, 1);
            assert_eq!($cfg.has_ipv4, u8::from(mask.is_some()));
            assert_eq!($cfg.wan_mask4.to_ne_bytes(), mask.unwrap_or_default());
            if mask.is_some() {
                assert_eq!($cfg.wan_ip4.to_ne_bytes(), IP.octets());
                assert_eq!($cfg.gateway_ip4.to_ne_bytes(), GATEWAY.octets());
                assert_eq!($cfg.source_mac, MAC.octets());
            } else {
                assert_eq!(($cfg.wan_ip4, $cfg.gateway_ip4, $cfg.source_mac), (0, 0, [0; 6]));
            }
        }};
    }
    check!(xdp);
    check!(tc);
}

#[test]
fn renewal_keeps_roots_and_prefix_change_preserves_stage_slots() {
    let (_pins, dp) = dataplane();
    let initial = root_ids(&dp);
    assert_ipv4_config(&dp, None);
    let mss = dp.attach_mss(IFINDEX, 1450, true).unwrap();
    let stages = stage_ids(&dp);
    bind(&dp, 24);
    let bound = root_ids(&dp);
    assert_ne!(bound[0], initial[0]);
    assert_ne!(bound[1], initial[1]);
    assert_ipv4_config(&dp, Some([255, 255, 255, 0]));
    bind(&dp, 24);
    assert_eq!(root_ids(&dp), bound);
    bind(&dp, 25);
    let updated = root_ids(&dp);
    assert_ne!(updated[0], bound[0]);
    assert_ne!(updated[1], bound[1]);
    assert_ipv4_config(&dp, Some([255, 255, 255, 128]));
    assert_eq!(stage_ids(&dp), stages);
    for (prefix, mask) in [(0, [0; 4]), (32, [255; 4])] {
        bind(&dp, prefix);
        assert_ipv4_config(&dp, Some(mask));
    }
    dp.unbind_wan_ipv4();
    assert_ipv4_config(&dp, None);
    drop(mss);
    dp.close();
}

#[test]
fn switching_between_pppoe_and_ethernet_republishes_identical_addresses() {
    let (_pins, dp) = dataplane();
    dp.bind_pppoe_ipv4(IFINDEX, IP, GATEWAY, MAC);
    let pppoe = root_ids(&dp);
    let is_pppoe = || {
        let inner = dp.inner.lock().unwrap();
        inner
            .tc
            .egress_root
            .as_ref()
            .unwrap()
            .skel
            .maps
            .rodata_data
            .as_ref()
            .unwrap()
            .egress_binding
            .is_pppoe
    };
    assert_eq!(is_pppoe(), 1);
    bind(&dp, 32);
    assert_ne!(root_ids(&dp), pppoe);
    assert_eq!(is_pppoe(), 0);
    dp.close();
}

#[test]
fn second_publish_failure_restores_live_roots_and_renewal_retries() {
    let (_pins, dp) = dataplane();
    bind(&dp, 24);
    let old = root_ids(&dp);
    let paths = dp.backbone.paths();
    let tc_path = paths.tc_wan_egress_roots_path();
    let mut tc_slots = pinned_map(&tc_path).unwrap();
    let mut xdp_slots = pinned_map(&paths.xdp_lan_pipe_root_progs_path()).unwrap();

    // Stand in an XDP prog array for the TC pin: the first publication succeeds
    // and the kernel rejects the second program type. Hold the real TC map open.
    tc_slots.unpin(&tc_path).unwrap();
    xdp_slots.pin(&tc_path).unwrap();
    bind(&dp, 25);
    let slot = u32::from(dp.id);
    assert_eq!([program_id(&xdp_slots, slot), program_id(&tc_slots, slot)], old);
    assert_ipv4_config(&dp, Some([255, 255, 255, 0]));

    xdp_slots.unpin(&tc_path).unwrap();
    tc_slots.pin(&tc_path).unwrap();
    bind(&dp, 25);
    let retried = root_ids(&dp);
    assert_ne!(retried[0], old[0]);
    assert_ne!(retried[1], old[1]);
    assert_ipv4_config(&dp, Some([255, 255, 255, 128]));
    dp.close();
}

use std::net::{Ipv4Addr, Ipv6Addr};
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

const IP6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

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
    let tc = inner.tc.egress_root.as_ref().unwrap().next_stage_map();
    [[program_id(xdp, 0), program_id(xdp, 1)], [program_id(tc, 0), program_id(tc, 1)]]
}

fn xdp_lan_exit_id(dp: &WanLinkDataplane) -> u32 {
    program_id(&dp.xdp_lan_exit_map, 0)
}

fn tc_egress_exit_id(dp: &WanLinkDataplane) -> u32 {
    program_id(&dp.tc_wan_egress_exit_map, 0)
}

fn root_lan_exit_id(dp: &WanLinkDataplane) -> u32 {
    let inner = dp.inner.lock().unwrap();
    program_id(&inner.xdp.lan_root.as_ref().unwrap().skel.maps.xdp_from_lan_exit_map, 0)
}

fn root_egress_exit_id(dp: &WanLinkDataplane) -> u32 {
    let inner = dp.inner.lock().unwrap();
    let root = inner.tc.egress_root.as_ref().unwrap().l2_skel().expect("L2 egress root");
    program_id(&root.maps.tc_from_lan_exit_map, 0)
}

fn bind(dp: &WanLinkDataplane, prefix: u8) {
    dp.bind_wan_ipv4(IFINDEX, IP, Some(GATEWAY), prefix, Some(MAC));
}

#[test]
fn from_lan_exits_are_per_chain_and_wired_into_their_roots() {
    let (_pins, first) = dataplane();
    let second =
        WanLinkDataplane::new(first.backbone().clone(), first.id() + 1, Some(IFINDEX), true)
            .unwrap();

    assert_ne!(xdp_lan_exit_id(&first), xdp_lan_exit_id(&second));
    assert_ne!(tc_egress_exit_id(&first), tc_egress_exit_id(&second));
    assert_eq!(root_lan_exit_id(&first), xdp_lan_exit_id(&first));
    assert_eq!(root_lan_exit_id(&second), xdp_lan_exit_id(&second));
    assert_eq!(root_egress_exit_id(&first), tc_egress_exit_id(&first));
    assert_eq!(root_egress_exit_id(&second), tc_egress_exit_id(&second));

    first.close();
    second.close();
}

fn assert_root_gateway_mac(dp: &WanLinkDataplane, expected: MacAddr) {
    let inner = dp.inner.lock().unwrap();
    let tc = inner.tc.egress_root.as_ref().unwrap().l2_skel().expect("L2 egress root");
    let xdp = &inner.xdp.lan_root.as_ref().unwrap().skel;
    for word in [
        tc.maps.bss_data.as_ref().unwrap().confirmed_gateway_mac,
        xdp.maps.bss_data.as_ref().unwrap().confirmed_gateway_mac,
    ] {
        let bytes = word.to_ne_bytes();
        assert_eq!(bytes[..6], expected.octets());
        assert_eq!(bytes[6..], [0, 0]);
    }
}

fn assert_root_gateway_mac6(dp: &WanLinkDataplane, expected: MacAddr) {
    let inner = dp.inner.lock().unwrap();
    let tc = inner.tc.egress_root.as_ref().unwrap().l2_skel().expect("L2 egress root");
    let xdp = &inner.xdp.lan_root.as_ref().unwrap().skel;
    for word in [
        tc.maps.bss_data.as_ref().unwrap().confirmed_gateway_mac6,
        xdp.maps.bss_data.as_ref().unwrap().confirmed_gateway_mac6,
    ] {
        let bytes = word.to_ne_bytes();
        assert_eq!(bytes[..6], expected.octets());
        assert_eq!(bytes[6..], [0, 0]);
    }
}

#[test]
fn gateway_arp_tracks_bind_changes_and_rejects_late_replies() {
    let (_pins, dp) = dataplane();
    let mut targets = dp.subscribe_gateway_arp();
    let peer = MacAddr(2, 1, 2, 3, 4, 5);
    let new_peer = MacAddr(2, 6, 7, 8, 9, 10);
    assert!(targets.borrow().is_none());

    bind(&dp, 24);
    let roots = root_ids(&dp);
    let first = targets.borrow_and_update().clone().unwrap();
    assert_eq!(
        (first.ifindex, first.local_mac, first.local_ip, first.gateway_ip),
        (IFINDEX, MAC, IP, GATEWAY)
    );
    assert!(dp.confirm_gateway_mac(&first, peer));
    assert_root_gateway_mac(&dp, peer);
    assert!(!dp.confirm_gateway_mac(&first, peer));
    assert!(dp.confirm_gateway_mac(&first, new_peer));
    assert_root_gateway_mac(&dp, new_peer);
    assert_eq!(root_ids(&dp), roots);
    bind(&dp, 24);
    bind(&dp, 25);
    assert_ne!(root_ids(&dp)[1], roots[1]);
    assert_root_gateway_mac(&dp, new_peer);
    assert!(!targets.has_changed().unwrap());

    // Changing the sender address restarts probing the same gateway.
    dp.bind_wan_ipv4(IFINDEX, Ipv4Addr::new(192, 0, 2, 11), Some(GATEWAY), 24, Some(MAC));
    assert!(targets.has_changed().unwrap());
    assert_eq!(dp.confirmed_gateway_mac(), Some(new_peer));
    assert!(!dp.confirm_gateway_mac(&first, peer));

    dp.unbind_wan_ipv4();
    assert!(targets.borrow().is_none());
    assert_eq!(dp.confirmed_gateway_mac(), None);
    assert_root_gateway_mac(&dp, MacAddr::zero());
    bind(&dp, 24);
    assert_eq!(dp.confirmed_gateway_mac(), Some(new_peer));
    assert_root_gateway_mac(&dp, new_peer);
    assert!(!dp.confirm_gateway_mac(&first, peer)); // Same addresses, new binding.

    dp.bind_wan_ipv4(IFINDEX, IP, Some(Ipv4Addr::new(192, 0, 2, 2)), 24, Some(MAC));
    assert_eq!(dp.confirmed_gateway_mac(), None);
    assert_root_gateway_mac(&dp, MacAddr::zero());
    let other = targets.borrow().clone().unwrap();
    assert!(dp.confirm_gateway_mac(&other, peer));
    dp.observe(IFINDEX + 1, true);
    assert!(targets.borrow().is_none());
    assert!(!dp.confirm_gateway_mac(&other, new_peer));
    dp.observe(IFINDEX, true);
    assert_eq!(dp.confirmed_gateway_mac(), None);
    dp.close();
}

#[test]
fn gateway_arp_skips_ppp_and_forgets_explicitly_closed_bindings() {
    let (_pins, dp) = dataplane();
    let targets = dp.subscribe_gateway_arp();
    dp.bind_pppoe_ipv4(IFINDEX, IP, GATEWAY, MAC);
    assert!(targets.borrow().is_none());
    dp.bind_ppp_ipv4(IFINDEX, IP, GATEWAY, 32);
    assert!(targets.borrow().is_none());
    dp.bind_wan_ipv4(IFINDEX, IP, None, 24, Some(MAC));
    assert!(targets.borrow().is_none());
    dp.bind_wan_ipv4(IFINDEX, IP, Some(Ipv4Addr::UNSPECIFIED), 24, Some(MAC));
    assert!(targets.borrow().is_none());

    bind(&dp, 24);
    let before_disable = targets.borrow().clone().unwrap();
    let peer = MacAddr(2, 1, 2, 3, 4, 5);
    assert!(dp.confirm_gateway_mac(&before_disable, peer));
    dp.unbind_wan_ipv4();
    dp.clear_gateway_arp();
    bind(&dp, 24);
    assert_eq!(dp.confirmed_gateway_mac(), None);
    let before_close = targets.borrow().clone().unwrap();
    assert!(dp.confirm_gateway_mac(&before_close, peer));
    dp.close();
    assert_root_gateway_mac(&dp, MacAddr::zero());
    assert!(targets.borrow().is_none());
    assert!(targets.has_changed().is_err());
    assert_eq!(dp.confirmed_gateway_mac(), None);
    assert!(!dp.confirm_gateway_mac(&before_close, peer));
}

#[test]
fn gateway_ns_tracks_v6_bind_changes_and_rejects_late_replies() {
    let (_pins, dp) = dataplane();
    let mut targets = dp.subscribe_gateway_ns();
    let peer = MacAddr(2, 1, 2, 3, 4, 5);
    let new_peer = MacAddr(2, 6, 7, 8, 9, 10);
    assert!(targets.borrow().is_none());

    dp.bind_wan_ipv6(IFINDEX, IP6, Some(GATEWAY6), 64, Some(MAC));
    let first = targets.borrow_and_update().clone().unwrap();
    assert_eq!((first.ifindex, first.local_mac, first.gateway_ip), (IFINDEX, MAC, GATEWAY6));
    assert!(dp.confirm_gateway_mac6(&first, peer));
    assert_root_gateway_mac6(&dp, peer);
    assert!(!dp.confirm_gateway_mac6(&first, peer));
    assert!(dp.confirm_gateway_mac6(&first, new_peer));
    assert_root_gateway_mac6(&dp, new_peer);

    // A gateway change clears the confirmation and restarts probing.
    let other_gateway = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    dp.bind_wan_ipv6(IFINDEX, IP6, Some(other_gateway), 64, Some(MAC));
    assert_eq!(dp.confirmed_gateway_mac6(), None);
    assert_root_gateway_mac6(&dp, MacAddr::zero());
    let other = targets.borrow().clone().unwrap();
    assert_eq!(other.gateway_ip, other_gateway);
    assert!(!dp.confirm_gateway_mac6(&first, peer));
    assert!(dp.confirm_gateway_mac6(&other, peer));
    assert_root_gateway_mac6(&dp, peer);

    dp.unbind_wan_ipv6();
    assert!(targets.borrow().is_none());
    assert_eq!(dp.confirmed_gateway_mac6(), None);
    assert_root_gateway_mac6(&dp, MacAddr::zero());

    // A v4-only explicit clear must leave the IPv6 confirmation alone.
    bind(&dp, 24);
    dp.bind_wan_ipv6(IFINDEX, IP6, Some(GATEWAY6), 64, Some(MAC));
    let rebound = targets.borrow().clone().unwrap();
    assert!(dp.confirm_gateway_mac6(&rebound, new_peer));
    dp.clear_gateway_arp();
    assert_eq!(dp.confirmed_gateway_mac6(), Some(new_peer));
    assert_root_gateway_mac6(&dp, new_peer);
    // A v6 clear forgets it, so a same-address re-bind probes again.
    dp.clear_gateway_ns();
    assert_eq!(dp.confirmed_gateway_mac6(), None);
    assert_root_gateway_mac6(&dp, MacAddr::zero());
    dp.bind_wan_ipv6(IFINDEX, IP6, Some(GATEWAY6), 64, Some(MAC));
    assert_eq!(dp.confirmed_gateway_mac6(), None);

    // A native PPPoE v6 bind never probes: the session peer is the L2 next hop.
    dp.bind_pppoe_ipv6(IFINDEX, IP6, Some(GATEWAY6), 64, Some(MAC));
    assert!(targets.borrow().is_none());
    dp.close();
}

fn assert_ipv4_config(dp: &WanLinkDataplane, expected: Option<(Ipv4Addr, [u8; 4])>) {
    let (xdp, tc) = {
        let inner = dp.inner.lock().unwrap();
        let xdp = &inner.xdp.lan_root.as_ref().unwrap().skel.maps;
        let tc = &inner.tc.egress_root.as_ref().unwrap().l2_skel().expect("L2 egress root").maps;
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
            assert_eq!($cfg.has_ipv4, u8::from(expected.is_some()));
            if let Some((gateway, mask)) = expected {
                assert_eq!($cfg.wan_mask4.to_ne_bytes(), mask);
                assert_eq!($cfg.wan_ip4.to_ne_bytes(), IP.octets());
                assert_eq!($cfg.gateway_ip4.to_ne_bytes(), gateway.octets());
                assert_eq!($cfg.source_mac, MAC.octets());
            } else {
                assert_eq!($cfg.wan_mask4, 0);
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
    assert_ipv4_config(&dp, Some((GATEWAY, [255, 255, 255, 0])));
    bind(&dp, 24);
    assert_eq!(root_ids(&dp), bound);
    bind(&dp, 25);
    let updated = root_ids(&dp);
    assert_ne!(updated[0], bound[0]);
    assert_ne!(updated[1], bound[1]);
    assert_ipv4_config(&dp, Some((GATEWAY, [255, 255, 255, 128])));
    assert_eq!(stage_ids(&dp), stages);
    for (prefix, mask) in [(0, [0; 4]), (32, [255; 4])] {
        bind(&dp, prefix);
        assert_ipv4_config(&dp, Some((GATEWAY, mask)));
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
            .l2_skel()
            .expect("L2 egress root")
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
fn pppoe_exit_swap_restores_only_the_latest_session() {
    use super::super::BpfPppoeTmpl;

    let (_pins, dp) = dataplane();
    let plain = tc_egress_exit_id(&dp);
    let tmpl = BpfPppoeTmpl {
        dmac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        smac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        eth_proto: 0x8864u16.to_be(),
        ver_type: 0x11,
        code: 0x00,
        session_id: 0x2233u16.to_be(),
        ..Default::default()
    };

    let first = dp.install_tc_pppoe_exit(&tmpl).unwrap();
    let first_id = tc_egress_exit_id(&dp);
    assert_ne!(first_id, plain);
    assert_eq!(root_egress_exit_id(&dp), first_id);

    let second = dp.install_tc_pppoe_exit(&tmpl).unwrap();
    let second_id = tc_egress_exit_id(&dp);
    assert_ne!(second_id, first_id);
    drop(first);
    assert_eq!(tc_egress_exit_id(&dp), second_id, "stale guard must not restore");

    drop(second);
    let restored = tc_egress_exit_id(&dp);
    assert_eq!(restored, plain, "the held plain exit must be restored, not reloaded");
    assert_eq!(root_egress_exit_id(&dp), restored);
    dp.close();
}

#[test]
fn ppp_binding_selects_the_l3_egress_root_and_survives_unbind() {
    let (_pins, dp) = dataplane();
    let l2 = root_ids(&dp);
    assert!(dp.inner.lock().unwrap().tc.egress_root.as_ref().unwrap().l2_skel().is_some());

    dp.bind_ppp_ipv4(IFINDEX, IP, GATEWAY, 32);
    {
        let inner = dp.inner.lock().unwrap();
        let root = inner.tc.egress_root.as_ref().unwrap();
        assert!(root.ppp_skel().is_some());
        assert!(root.l2_skel().is_none());
    }
    let ppp = root_ids(&dp);
    assert_ne!(ppp[1], l2[1]);

    // A redial briefly unbinds IPv4; the link stays a pppd L3 link.
    dp.unbind_wan_ipv4();
    assert!(dp.inner.lock().unwrap().tc.egress_root.as_ref().unwrap().ppp_skel().is_some());

    bind(&dp, 24);
    assert!(dp.inner.lock().unwrap().tc.egress_root.as_ref().unwrap().l2_skel().is_some());
    dp.close();
}

#[test]
fn switching_to_ppp_keeps_stage_slots() {
    let (_pins, dp) = dataplane();
    bind(&dp, 24);
    let mss = dp.attach_mss(IFINDEX, 1450, true).unwrap();
    let stages = stage_ids(&dp);
    let l2 = root_ids(&dp);
    dp.bind_ppp_ipv4(IFINDEX, IP, GATEWAY, 32);
    let ppp = root_ids(&dp);
    assert_ne!(ppp[0], l2[0]);
    assert_ne!(ppp[1], l2[1]);
    assert_eq!(stage_ids(&dp), stages);
    drop(mss);
    dp.close();
}

#[test]
fn a_restarted_link_reuses_its_chain_id_with_fresh_roots_and_stages() {
    let (_pins, old) = dataplane();
    let backbone = old.backbone.clone();
    let id = old.id();
    let paths = backbone.paths();
    let root_slots = [
        paths.xdp_pipe_root_progs_path(),
        paths.xdp_lan_pipe_root_progs_path(),
        paths.tc_pipe_root_progs_path(),
        paths.tc_wan_egress_roots_path(),
    ]
    .map(|path| pinned_map(&path).unwrap());
    let slot = u32::from(id);
    bind(&old, 24);
    let mss = old.attach_mss(IFINDEX, 1450, true).unwrap();
    let roots = root_slots.each_ref().map(|map| program_id(map, slot));
    let stages = stage_ids(&old);
    drop(mss);
    drop(old);
    for map in &root_slots {
        assert!(map.lookup(&slot.to_ne_bytes(), MapFlags::ANY).unwrap().is_none());
    }

    let ppp = WanLinkDataplane::new(backbone, id, Some(IFINDEX), false).unwrap();
    ppp.bind_ppp_ipv4(IFINDEX, IP, GATEWAY, 32);
    let mss = ppp.attach_mss(IFINDEX, 1450, false).unwrap();
    for (old_id, map) in roots.into_iter().zip(&root_slots) {
        assert_ne!(old_id, program_id(map, slot));
    }
    for (old_id, new_id) in stages.into_iter().flatten().zip(stage_ids(&ppp).into_iter().flatten())
    {
        assert_ne!(old_id, new_id);
    }
    drop(mss);
    drop(ppp);
}

#[test]
fn second_publish_failure_restores_live_roots_and_renewal_retries() {
    let (_pins, dp) = dataplane();
    bind(&dp, 24);
    let targets = dp.subscribe_gateway_arp();
    let first = targets.borrow().clone().unwrap();
    let old_mac = MacAddr(2, 1, 2, 3, 4, 5);
    assert!(dp.confirm_gateway_mac(&first, old_mac));
    let old = root_ids(&dp);
    let paths = dp.backbone.paths();
    let tc_path = paths.tc_wan_egress_roots_path();
    let mut tc_slots = pinned_map(&tc_path).unwrap();
    let mut xdp_slots = pinned_map(&paths.xdp_lan_pipe_root_progs_path()).unwrap();

    // Stand in an XDP prog array for the TC pin: the first publication succeeds
    // and the kernel rejects the second program type. Hold the real TC map open.
    tc_slots.unpin(&tc_path).unwrap();
    xdp_slots.pin(&tc_path).unwrap();
    let gateway = Ipv4Addr::new(192, 0, 2, 2);
    dp.bind_wan_ipv4(IFINDEX, IP, Some(gateway), 25, Some(MAC));
    let slot = u32::from(dp.id);
    assert_eq!([program_id(&xdp_slots, slot), program_id(&tc_slots, slot)], old);
    assert_ipv4_config(&dp, Some((GATEWAY, [255, 255, 255, 0])));
    assert_root_gateway_mac(&dp, MacAddr::zero());
    let target = targets.borrow().clone().unwrap();
    let new_mac = MacAddr(2, 6, 7, 8, 9, 10);
    assert!(!dp.confirm_gateway_mac(&first, old_mac));
    assert!(dp.confirm_gateway_mac(&target, new_mac));
    assert_root_gateway_mac(&dp, MacAddr::zero());

    xdp_slots.unpin(&tc_path).unwrap();
    tc_slots.pin(&tc_path).unwrap();
    dp.bind_wan_ipv4(IFINDEX, IP, Some(gateway), 25, Some(MAC));
    let retried = root_ids(&dp);
    assert_ne!(retried[0], old[0]);
    assert_ne!(retried[1], old[1]);
    assert_root_gateway_mac(&dp, new_mac);
    assert_ipv4_config(&dp, Some((gateway, [255, 255, 255, 128])));
    dp.close();
}

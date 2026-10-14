use std::net::Ipv6Addr;
use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use crate::tests::net_utils::{
    NetNsGuard, VethPair, build_tcp_pkt, build_tcp6_pkt, dummy_recv_count, dummy_reset, route_slot,
    route_slot_v6, send_raw_packet, settle, wait_for,
};
use libbpf_rs::{
    MapCore, MapFlags,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::maps::wan_trie::builder::{v4_entry, v6_entry, wan_trie_publish};
use crate::maps::wan_trie::dispatcher::cast_arena_tbl;
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;
use crate::tests::wan_intro_skel::XdpWanIntroSkelBuilder;
use crate::tests::xdp_firewall_skel::XdpFirewallSkelBuilder;
use crate::tests::xdp_lan_exit_skel::XdpLanExitSkelBuilder;
use crate::tests::xdp_lan_root_skel::XdpLanRootSkelBuilder;
use crate::tests::xdp_lan_route_skel::XdpLanRouteSkelBuilder;
use crate::tests::xdp_mss_skel::XdpMssSkelBuilder;
use crate::tests::xdp_wan_root_skel::XdpWanRootSkelBuilder;
use crate::tests::xdp_wan_route_skel::XdpWanRouteSkelBuilder;
#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_firewall_pipeline() {
    // Two fresh netns: the router side (lan_h/wan_h + all XDP programs) and the
    // LAN/WAN segment side (lan_p/wan_p + dummies). Fresh netns restart the
    // ifindex counter at 1 (small PROG_ARRAY indexes) and keep host routes out
    // of the test.
    let test_ns = NetNsGuard::create("fw");
    let peer_ns = NetNsGuard::create("fwp");

    let lan_pair;
    let wan_pair;
    {
        let _e = test_ns.enter();
        lan_pair = VethPair::create_with_netns("fw", &peer_ns);
        wan_pair = VethPair::create_with_netns("fww", &peer_ns);
    }

    let lan_p = lan_pair.peer();
    let wan_p = wan_pair.peer();

    // ── load shared maps ──
    let share_pin = crate::tests::isolated_pin_root("xdp-fw-pipe");
    let maps = crate::tests::init_shared_maps_for_test(&share_pin);
    // ── load skeletons ──
    let mut lr_b = XdpLanRouteSkelBuilder::default();
    lr_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut lr_obj = std::mem::MaybeUninit::uninit();
    let lr = lr_b.open(&mut lr_obj).unwrap().load().unwrap();

    let mut wr_b = XdpWanRouteSkelBuilder::default();
    wr_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut wr_obj = std::mem::MaybeUninit::uninit();
    let wr = wr_b.open(&mut wr_obj).unwrap().load().unwrap();

    let d1_b = TestXdpDummySkelBuilder::default();
    let mut d1_obj = std::mem::MaybeUninit::uninit();
    let da = d1_b.open(&mut d1_obj).unwrap().load().unwrap();

    let d2_b = TestXdpDummySkelBuilder::default();
    let mut d2_obj = std::mem::MaybeUninit::uninit();
    let dc = d2_b.open(&mut d2_obj).unwrap().load().unwrap();

    let lan_root_b = XdpLanRootSkelBuilder::default();
    let mut lan_root_obj = std::mem::MaybeUninit::uninit();
    let lan_root = lan_root_b.open(&mut lan_root_obj).unwrap().load().unwrap();

    let lan_exit_b = XdpLanExitSkelBuilder::default();
    let mut lan_exit_obj = std::mem::MaybeUninit::uninit();
    let lan_exit = lan_exit_b.open(&mut lan_exit_obj).unwrap().load().unwrap();

    let wan_root_b = XdpWanRootSkelBuilder::default();
    let mut wan_root_obj = std::mem::MaybeUninit::uninit();
    let wan_root = wan_root_b.open(&mut wan_root_obj).unwrap().load().unwrap();

    let mss_b = XdpMssSkelBuilder::default();
    let mut mss_obj = std::mem::MaybeUninit::uninit();
    let mss = mss_b.open(&mut mss_obj).unwrap().load().unwrap();

    let mut fw_b = XdpFirewallSkelBuilder::default();
    fw_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut fw_obj = std::mem::MaybeUninit::uninit();
    let fw = fw_b.open(&mut fw_obj).unwrap().load().unwrap();

    let mut intro_b = XdpWanIntroSkelBuilder::default();
    intro_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut intro_obj = std::mem::MaybeUninit::uninit();
    let mut intro = intro_b.open(&mut intro_obj).unwrap().load().unwrap();

    // ── attach XDP programs (each side from inside its own netns) ──
    let lan_h_i;
    let wan_h_i;
    let lan_p_i;
    let wan_p_i;
    let _l0;
    let _l1;
    let _l2;
    let _l3;
    {
        let _e = test_ns.enter();
        lan_h_i = lan_pair.host_ifindex();
        crate::tests::check_ifindex("lan_h", lan_h_i);
        wan_h_i = wan_pair.host_ifindex();
        crate::tests::check_ifindex("wan_h", wan_h_i);
        _l0 = lr.progs.xdp_lan_route.attach_xdp(lan_h_i as i32).unwrap();
        _l1 = intro.progs.xdp_wan_intro.attach_xdp(wan_h_i as i32).unwrap();
    }
    {
        let _e = peer_ns.enter();
        lan_p_i = lan_pair.peer_ifindex();
        wan_p_i = wan_pair.peer_ifindex();
        _l2 = da.progs.xdp_test_dummy.attach_xdp(lan_p_i as i32).unwrap();
        _l3 = dc.progs.xdp_test_dummy.attach_xdp(wan_p_i as i32).unwrap();
    }

    // Sending must happen from inside the peer netns (AF_PACKET ifindexes are
    // per-netns). Counter/map reads are netns-independent.
    let send_lan = |pkt: &[u8]| {
        let _e = peer_ns.enter();
        send_raw_packet(lan_p, pkt);
    };
    let send_wan = |pkt: &[u8]| {
        let _e = peer_ns.enter();
        send_raw_packet(wan_p, pkt);
    };

    let root_fd = lan_root.progs.xdp_lan_root.as_fd().as_raw_fd();
    let mss_lan_v4_fd = mss.progs.xdp_mss_lan_v4.as_fd().as_raw_fd();
    let mss_lan_v6_fd = mss.progs.xdp_mss_lan_v6.as_fd().as_raw_fd();
    let mss_wan_v4_fd = mss.progs.xdp_mss_wan_v4.as_fd().as_raw_fd();
    let mss_wan_v6_fd = mss.progs.xdp_mss_wan_v6.as_fd().as_raw_fd();
    let fw_lan_v4_fd = fw.progs.xdp_firewall_lan_v4.as_fd().as_raw_fd();
    let fw_lan_v6_fd = fw.progs.xdp_firewall_lan_v6.as_fd().as_raw_fd();
    let fw_wan_v4_fd = fw.progs.xdp_firewall_wan_v4.as_fd().as_raw_fd();
    let fw_wan_v6_fd = fw.progs.xdp_firewall_wan_v6.as_fd().as_raw_fd();
    let exit_fd = lan_exit.progs.xdp_lan_exit.as_fd().as_raw_fd();
    let wan_root_fd = wan_root.progs.xdp_wan_root.as_fd().as_raw_fd();
    let wr_fd = wr.progs.xdp_wan_route_ingress.as_fd().as_raw_fd();

    // Mark redirect targets native-XDP able, otherwise xdp_lan_route falls back
    // to the TC handoff path and the XDP chain never runs.
    lr.maps
        .xdp_redirect_able
        .update(&wan_h_i.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    lr.maps
        .xdp_redirect_able
        .update(&lan_h_i.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    // xdp_wan_route reads its OWN xdp_redirect_able instance when caching
    // (xdp_route4_set_cache_in_wan) and when redirecting; populate it too or
    // cache hits take the TC handoff path and the chain never runs.
    wr.maps
        .xdp_redirect_able
        .update(&wan_h_i.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    wr.maps
        .xdp_redirect_able
        .update(&lan_h_i.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // ── LAN chain: root → mss_lan_{v4,v6} → firewall_lan_{v4,v6} → exit ──
    // Root slots are family-indexed (XDP_ROOT_SLOT_V4=0/V6=1, chain/xdp_cb.h);
    // stage slots are direction x family (XDP_FROM_LAN_SLOT_V4=0/V6=1,
    // XDP_FROM_WAN_SLOT_V4=2/V6=3, chain/xdp_stage.h).
    //
    // Both root prog-arrays and the dispatch trie are keyed by the WAN
    // link's chain id (ifindex keys are gone).
    const TEST_CHAIN: u32 = 9;
    lr.maps
        .xdp_lan_pipe_root_progs
        .update(&TEST_CHAIN.to_ne_bytes(), &root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    lan_root
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_lan_v4_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    lan_root
        .maps
        .root_next_stage
        .update(&1u32.to_ne_bytes(), &mss_lan_v6_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .next_stage
        .update(&0u32.to_ne_bytes(), &fw_lan_v4_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .next_stage
        .update(&1u32.to_ne_bytes(), &fw_lan_v6_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps.next_stage.update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY).unwrap();
    fw.maps.next_stage.update(&1u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY).unwrap();

    // LAN fallback exits: all point to exit
    lan_root
        .maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // ── WAN chain: wan_root → mss_wan_{v4,v6} → firewall_wan_{v4,v6} → wan_route ──
    wan_root
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_wan_v4_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    wan_root
        .maps
        .root_next_stage
        .update(&1u32.to_ne_bytes(), &mss_wan_v6_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .next_stage
        .update(&2u32.to_ne_bytes(), &fw_wan_v4_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .next_stage
        .update(&3u32.to_ne_bytes(), &fw_wan_v6_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps.next_stage.update(&2u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY).unwrap();
    fw.maps.next_stage.update(&3u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY).unwrap();

    // WAN fallback exits
    wan_root
        .maps
        .xdp_pipe_exits_wan
        .update(&0u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .xdp_pipe_exits_wan
        .update(&0u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps
        .xdp_pipe_exits_wan
        .update(&0u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // ── WAN dispatch trie: route 10.0.0.1 and fd00::/64 → the WAN link's
    // chain (dispatch values are chain ids) ──
    {
        let data = intro.maps.wan_trie_arena_data.as_mut().unwrap();
        wan_trie_publish(
            cast_arena_tbl(&mut data.wan_trie_tbl),
            &[
                v4_entry(std::net::Ipv4Addr::new(10, 0, 0, 1), 32, TEST_CHAIN).unwrap(),
                v6_entry(Ipv6Addr::from_str("fd00::").unwrap(), 64, TEST_CHAIN).unwrap(),
            ],
        )
        .unwrap();
    }
    intro
        .maps
        .xdp_pipe_root_progs
        .update(&TEST_CHAIN.to_ne_bytes(), &wan_root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // ── routing table setup ──
    let lan_ip: u32 = u32::from_be_bytes([10, 0, 0, 1]);
    let wan_ip: u32 = u32::from_be_bytes([203, 0, 113, 1]);

    // A→C: slot target → wan_h (chain-keyed tail; link_chain_id at bytes
    // 16..18 of the 20-byte route4_target_info)
    {
        let s = route_slot(wan_ip);
        let mut k = [0u8; 8];
        let mut v = [0u8; 20];
        k[0..4].copy_from_slice(&0u32.to_ne_bytes());
        k[4..8].copy_from_slice(&s.to_ne_bytes());
        v[0..4].copy_from_slice(&wan_h_i.to_ne_bytes());
        v[16..18].copy_from_slice(&(TEST_CHAIN as u16).to_ne_bytes());
        maps.rt4_slot_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // C→A: LAN route → lan_p
    {
        let mut k = [0u8; 8];
        let mut v = [0u8; 16];
        k[0..4].copy_from_slice(&32u32.to_ne_bytes());
        k[4..8].copy_from_slice(&lan_ip.to_be_bytes());
        v[8..12].copy_from_slice(&lan_h_i.to_ne_bytes());
        maps.rt4_lan_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // route slot for 203.0.113.2
    {
        let wan_ip2: u32 = u32::from_be_bytes([203, 0, 113, 2]);
        let s2 = route_slot(wan_ip2);
        let mut k = [0u8; 8];
        let mut v = [0u8; 20];
        k[0..4].copy_from_slice(&0u32.to_ne_bytes());
        k[4..8].copy_from_slice(&s2.to_ne_bytes());
        v[0..4].copy_from_slice(&wan_h_i.to_ne_bytes());
        v[16..18].copy_from_slice(&(TEST_CHAIN as u16).to_ne_bytes());
        maps.rt4_slot_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // v6 LAN route: fd00::1 → lan_h
    {
        let v6_lan: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut k = [0u8; 20];
        k[0..4].copy_from_slice(&128u32.to_le_bytes());
        k[4..20].copy_from_slice(&v6_lan);
        let mut v = [0u8; 28];
        v[0] = 1;
        v[8..12].copy_from_slice(&lan_h_i.to_ne_bytes());
        maps.rt6_lan_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // v6 WAN target slot: fd00::2 → wan_h (link_chain_id at bytes 28..30
    // of the 32-byte route6_target_info)
    {
        let v6_wan: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let slot = route_slot_v6(&v6_wan);
        let mut k = [0u8; 8];
        k[0..4].copy_from_slice(&0u32.to_ne_bytes());
        k[4..8].copy_from_slice(&slot.to_ne_bytes());
        let mut v = [0u8; 32];
        v[0..4].copy_from_slice(&wan_h_i.to_ne_bytes());
        v[28..30].copy_from_slice(&(TEST_CHAIN as u16).to_ne_bytes());
        maps.rt6_slot_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // ── block map helpers ──
    let block_action = 1u32.to_le_bytes();

    fn v4_block_key(addr: [u8; 4]) -> [u8; 8] {
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&32u32.to_le_bytes());
        key[4..8].copy_from_slice(&addr);
        key
    }

    fn add_block(map: &libbpf_rs::MapMut, ip: [u8; 4], val: &[u8]) {
        let key = v4_block_key(ip);
        map.update(&key, val, MapFlags::ANY).unwrap();
    }

    fn del_block(map: &libbpf_rs::MapMut, ip: [u8; 4]) {
        let key = v4_block_key(ip);
        map.delete(&key).ok();
    }

    fn v6_block_key(addr: [u8; 16]) -> [u8; 20] {
        let mut key = [0u8; 20];
        key[0..4].copy_from_slice(&128u32.to_le_bytes());
        key[4..20].copy_from_slice(&addr);
        key
    }

    fn add_block_v6(map: &libbpf_rs::MapMut, ip: [u8; 16], val: &[u8]) {
        let key = v6_block_key(ip);
        map.update(&key, val, MapFlags::ANY).unwrap();
    }

    fn del_block_v6(map: &libbpf_rs::MapMut, ip: [u8; 16]) {
        let key = v6_block_key(ip);
        map.delete(&key).ok();
    }

    // ════════════════════════════════════════
    // Scenario 1: no block → bidirectional flow
    // ════════════════════════════════════════

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);

    let a2c = build_tcp_pkt([10, 0, 0, 1], [203, 0, 113, 1]);
    let c2a = build_tcp_pkt([203, 0, 113, 1], [10, 0, 0, 1]);

    send_lan(&a2c);
    send_wan(&c2a);
    wait_for("v4 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, false)
            + dummy_recv_count(&dc.maps.dummy_recv_map, false)
            > 0
    });
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "no-block: expected v4 packet to reach dummy");

    // ════════════════════════════════════════
    // Scenario 2: block 203.0.113.1/32
    //   LAN→WAN: firewall_lan blocks dst (203.0.113.1)
    //   WAN→LAN: firewall_wan blocks src (203.0.113.1)
    // ════════════════════════════════════════
    add_block(&fw.maps.firewall_block_ip4_map, [203, 0, 113, 1], &block_action);

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_lan(&a2c);
    send_wan(&c2a);
    settle(300);
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert_eq!(v4_cnt, 0, "blocked: expected NO v4 packet in dummy");

    // ════════════════════════════════════════
    // Scenario 3: direction validation — block 10.0.0.1
    //   LAN: firewall_lan checks dst only → should ignore blocked src
    //   WAN: firewall_wan checks src only → should ignore blocked dst
    // ════════════════════════════════════════
    del_block(&fw.maps.firewall_block_ip4_map, [203, 0, 113, 1]);
    add_block(&fw.maps.firewall_block_ip4_map, [10, 0, 0, 1], &block_action);

    // 3a: LAN direction — A→C, LAN checks dst(203.0.113.1 not blocked) → PASS

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_lan(&a2c);
    wait_for("v4 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, false)
            + dummy_recv_count(&dc.maps.dummy_recv_map, false)
            > 0
    });
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "3a LAN: should PASS (checks dst, not src)");

    // 3b: WAN direction — C→A, WAN checks src(203.0.113.1 not blocked) → PASS

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_wan(&c2a);
    wait_for("v4 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, false)
            + dummy_recv_count(&dc.maps.dummy_recv_map, false)
            > 0
    });
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "3b WAN: should PASS (checks src, not dst)");

    // ════════════════════════════════════════
    // Scenario 4: block 203.0.113.1 only → 203.0.113.2 should still pass
    // ════════════════════════════════════════
    del_block(&fw.maps.firewall_block_ip4_map, [10, 0, 0, 1]);
    add_block(&fw.maps.firewall_block_ip4_map, [203, 0, 113, 1], &block_action);

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    let a2c_unblocked = build_tcp_pkt([10, 0, 0, 1], [203, 0, 113, 2]);
    send_lan(&a2c_unblocked);
    wait_for("v4 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, false)
            + dummy_recv_count(&dc.maps.dummy_recv_map, false)
            > 0
    });
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "4 unblocked: 203.0.113.2 should pass firewall");

    // ════════════════════════════════════════
    // Scenario 5: delete block → flow resumes
    // ════════════════════════════════════════
    del_block(&fw.maps.firewall_block_ip4_map, [203, 0, 113, 1]);

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_lan(&a2c);
    send_wan(&c2a);
    wait_for("v4 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, false)
            + dummy_recv_count(&dc.maps.dummy_recv_map, false)
            > 0
    });
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "unblocked: expected v4 packet after removing block");

    // ════════════════════════════════════════
    // IPv6 scenarios
    // ════════════════════════════════════════

    let v6_lan: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let v6_wan: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let a2c_v6 = build_tcp6_pkt(v6_lan, v6_wan);
    let c2a_v6 = build_tcp6_pkt(v6_wan, v6_lan);

    // Scenario 6: v6 no block → bidirectional flow

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_lan(&a2c_v6);
    send_wan(&c2a_v6);
    wait_for("v6 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, true)
            + dummy_recv_count(&dc.maps.dummy_recv_map, true)
            > 0
    });
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 no-block: expected v6 dump");

    // Scenario 7: v6 block fd00::2/128
    //   LAN→WAN: firewall_lan blocks dst (fd00::2)
    //   WAN→LAN: firewall_wan blocks src (fd00::2)
    add_block_v6(&fw.maps.firewall_block_ip6_map, v6_wan, &block_action);

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_lan(&a2c_v6);
    send_wan(&c2a_v6);
    settle(300);
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert_eq!(v6_cnt, 0, "v6 blocked: expected NO v6 dump");

    // Scenario 8: v6 direction validation — block fd00::1, LAN should ignore src
    del_block_v6(&fw.maps.firewall_block_ip6_map, v6_wan);
    add_block_v6(&fw.maps.firewall_block_ip6_map, v6_lan, &block_action);

    // 8a: LAN direction — A→C, LAN checks dst(fd00::2 not blocked) → PASS

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_lan(&a2c_v6);
    wait_for("v6 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, true)
            + dummy_recv_count(&dc.maps.dummy_recv_map, true)
            > 0
    });
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 8a LAN: should PASS (checks dst, not src)");

    // 8b: WAN direction — C→A, WAN checks src(fd00::2 not blocked) → PASS

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_wan(&c2a_v6);
    wait_for("v6 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, true)
            + dummy_recv_count(&dc.maps.dummy_recv_map, true)
            > 0
    });
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 8b WAN: should PASS (checks src, not dst)");

    // Scenario 9: v6 delete block → flow resumes
    del_block_v6(&fw.maps.firewall_block_ip6_map, v6_lan);

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    send_lan(&a2c_v6);
    send_wan(&c2a_v6);
    wait_for("v6 packet reached dummy", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, true)
            + dummy_recv_count(&dc.maps.dummy_recv_map, true)
            > 0
    });
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 unblocked: expected v6 dump");

    // ── cleanup ──
    drop(fw);
    drop(mss);
    drop(wan_root);
    drop(lan_root);
    drop(lan_exit);
    drop(dc);
    drop(da);
    drop(wr);
    drop(intro);
    drop(lr);
    drop(maps);
    let _ = Command::new("ip").args(["route", "del", "blackhole", "203.0.113.1"]).output();
}

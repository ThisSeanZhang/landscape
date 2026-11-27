use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;
use std::time::Duration;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use libbpf_rs::{
    MapCore, MapFlags, MapHandle, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::maps::route::cache::{CONN_PIN_CACHE, LAN_CACHE, WAN_CACHE};
use crate::maps::route::set_flow_balance_mode_with_map;
use crate::maps::wan_trie::arena::mapped_table;
use crate::maps::wan_trie::builder::{v4_entry, wan_trie_publish};
use crate::maps::{
    Route4CacheKey, Route4CacheValue, Route4ConnKey, Route4SlotKey, Route4TargetInfo,
    Route6CacheKey, Route6CacheValue, Route6ConnKey, Route6SlotKey, Route6TargetInfo,
    RouteConnValue, RouteFlowTargetKey,
};
use crate::skel::xdp_lan_exit::XdpLanExitSkelBuilder;
use crate::skel::xdp_lan_root::XdpLanRootSkelBuilder;
use crate::skel::xdp_lan_route::XdpLanRouteSkelBuilder;
use crate::skel::xdp_mss::XdpMssSkelBuilder;
use crate::skel::xdp_wan_intro::XdpWanIntroSkelBuilder;
use crate::skel::xdp_wan_root::XdpWanRootSkelBuilder;
use crate::skel::xdp_wan_route::XdpWanRouteSkelBuilder;
use crate::tests::helper::net::{
    NetNsGuard, VethPair, dummy_recv_count, dummy_reset, route_slot, route_slot_v6,
    send_raw_packet, settle, wait_for,
};
use crate::tests::pkt::{simple_ipv4_tcp, simple_ipv6_tcp_syn};
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;

mod l2_fixture;
mod l2_handoff;
mod l2_native;

fn build_ipv4_tcp_pkt(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip, dst_ip, 64)
        .tcp(12345, 80, 1000, 2000);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build packet");
    pkt
}

fn build_syn_pkt(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    mss: u16,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 14 + 20 + 24]; // eth + ip + tcp(syn+mss)
    pkt[0..6].copy_from_slice(&dst_mac);
    pkt[6..12].copy_from_slice(&src_mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    // IP
    pkt[14] = 0x45;
    pkt[15] = 0x00;
    let ip_len = 20u16 + 24;
    pkt[16..18].copy_from_slice(&ip_len.to_be_bytes());
    pkt[18..22].copy_from_slice(&0u32.to_be_bytes());
    pkt[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[22] = 64;
    pkt[23] = 6;
    pkt[26..30].copy_from_slice(&src_ip);
    pkt[30..34].copy_from_slice(&dst_ip);
    let ip_csum = csum(&pkt[14..34]);
    pkt[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    // TCP
    pkt[34..36].copy_from_slice(&12345u16.to_be_bytes());
    pkt[36..38].copy_from_slice(&80u16.to_be_bytes());
    pkt[38..42].copy_from_slice(&1000u32.to_be_bytes());
    pkt[46] = 0x60;
    pkt[47] = 0x02; // data_off=6, SYN
    pkt[48..50].copy_from_slice(&0xffffu16.to_be_bytes());
    pkt[54] = 2;
    pkt[55] = 4; // MSS option
    pkt[56..58].copy_from_slice(&mss.to_be_bytes());
    let tcp_csum = tcp_csum(&pkt[26..30], &pkt[30..34], &pkt[34..58]);
    pkt[50..52].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}

fn csum(data: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        s += if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]]) as u32
        } else {
            (data[i] as u32) << 8
        };
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn tcp_csum(src: &[u8], dst: &[u8], tcp: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for i in (0..src.len()).step_by(2) {
        s += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }
    for i in (0..dst.len()).step_by(2) {
        s += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    s += 6 + tcp.len() as u32;
    for i in (0..tcp.len()).step_by(2) {
        s += if i + 1 < tcp.len() {
            u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32
        } else {
            (tcp[i] as u32) << 8
        };
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

fn lookup_inner_map(outer_map: &impl MapCore, cache_index: u32) -> MapHandle {
    let val = outer_map
        .lookup(as_bytes(&cache_index), MapFlags::ANY)
        .unwrap()
        .expect("inner map missing");
    let id = read_unaligned::<i32>(&val);
    MapHandle::from_map_id(id as u32).expect("open inner map")
}

/// `struct xdp_md` as accepted by BPF_PROG_TEST_RUN's `ctx_in`.
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, Default)]
struct XdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

// ── Test A: verifier smoke ──

#[test]
fn xdp_lan_route_verifier_smoke() {
    let mut builder = XdpLanRouteSkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("xdp-lr-v");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let _skel = open.load().expect("verifier rejected");
}

// ── Test B: trace flow (empty maps, smoke test) ──

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_lan_route_trace_flow() {
    let test_ns = NetNsGuard::create("trx");
    let peer_ns = NetNsGuard::create("trxp");
    let pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("trx", &peer_ns);
    }
    let peer = pair.peer();

    let mut builder = XdpLanRouteSkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("xdp-lr-t");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let skel = open.load().expect("load");
    let _link;
    {
        let _e = test_ns.enter();
        let ifindex = pair.host_ifindex() as i32;
        _link = skel.progs.xdp_lan_route.attach_xdp(ifindex).expect("attach");
    }

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    );
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt);
    }
    settle(300);

    drop(skel);
}

// ── Test C: lan_map redirect ──

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_lan_route_map_redirect() {
    let share_pin = crate::tests::isolated_pin_root("xdp-lr-share");
    let maps = crate::tests::init_shared_maps_for_test(&share_pin);
    let test_ns = NetNsGuard::create("lrb");
    let peer_ns = NetNsGuard::create("lrbp");
    let pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("lrb", &peer_ns);
    }
    let peer = pair.peer();
    let h_i;
    let p_i;
    {
        let _e = test_ns.enter();
        h_i = pair.host_ifindex();
    }
    {
        let _e = peer_ns.enter();
        p_i = pair.peer_ifindex();
    }

    let mut lan_key = [0u8; 8];
    lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes());
    lan_key[4..8].copy_from_slice(&0x0A000002u32.to_be_bytes());
    let mut lan_val = [0u8; 16];
    lan_val[8..12].copy_from_slice(&p_i.to_ne_bytes());
    maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();

    let mut b = XdpLanRouteSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();
    let _link;
    {
        let _e = test_ns.enter();
        _link = skel.progs.xdp_lan_route.attach_xdp(h_i as i32).unwrap();
    }

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    );
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt);
    }
    settle(300);

    drop(skel);
    drop(maps);
}

// ── Test D: bidirectional A↔C (lan_route + wan_route) ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_lan_route_wan_pipeline() {
    let test_ns = NetNsGuard::create("pdl");
    let peer_ns = NetNsGuard::create("pdlp");

    let lan_pair;
    let wan_pair;
    {
        let _e = test_ns.enter();
        lan_pair = VethPair::create_with_netns("pdl", &peer_ns);
        wan_pair = VethPair::create_with_netns("pdw", &peer_ns);
    }
    let lan_p = lan_pair.peer();
    let wan_p = wan_pair.peer();

    let lan_h_i;
    let lan_p_i;
    let wan_h_i;
    let wan_p_i;
    {
        let _e = test_ns.enter();
        lan_h_i = lan_pair.host_ifindex();
        wan_h_i = wan_pair.host_ifindex();
    }
    {
        let _e = peer_ns.enter();
        lan_p_i = lan_pair.peer_ifindex();
        wan_p_i = wan_pair.peer_ifindex();
    }

    let share_pin = crate::tests::isolated_pin_root("xdp-lr-pipe");
    let maps = crate::tests::init_shared_maps_for_test(&share_pin);
    // Root prog-arrays and the dispatch trie are keyed by the WAN link's
    // chain id (ifindex keys are gone).
    const TEST_CHAIN: u32 = 9;
    // A→C: slot target → wan_h
    {
        let key = Route4SlotKey { flow_id: 0, slot: route_slot(0xCB007101) };
        let target = Route4TargetInfo {
            ifindex: wan_h_i,
            link_chain_id: TEST_CHAIN as u16,
            ..Default::default()
        };
        maps.rt4_slot_map.update(as_bytes(&key), as_bytes(&target), MapFlags::ANY).unwrap();
    }
    // C→A: lan route → lan_p
    {
        let mut k = [0u8; 8];
        let mut v = [0u8; 16];
        k[0..4].copy_from_slice(&32u32.to_ne_bytes());
        k[4..8].copy_from_slice(&0x0A000001u32.to_be_bytes());
        v[8..12].copy_from_slice(&lan_h_i.to_ne_bytes());
        maps.rt4_lan_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    let mut lr_b = XdpLanRouteSkelBuilder::default();
    lr_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut lr_obj = std::mem::MaybeUninit::uninit();
    let lr = lr_b.open(&mut lr_obj).unwrap().load().unwrap();

    let mut intro_b = XdpWanIntroSkelBuilder::default();
    intro_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut intro_obj = std::mem::MaybeUninit::uninit();
    let mut intro = intro_b.open(&mut intro_obj).unwrap().load().unwrap();

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

    let _l0;
    let _l1;
    let _l2;
    let _l3;
    {
        let _e = test_ns.enter();
        _l0 = lr.progs.xdp_lan_route.attach_xdp(lan_h_i as i32).unwrap();
        _l1 = intro.progs.xdp_wan_intro.attach_xdp(wan_h_i as i32).unwrap();
    }
    {
        let _e = peer_ns.enter();
        _l2 = da.progs.xdp_test_dummy.attach_xdp(lan_p_i as i32).unwrap();
        _l3 = dc.progs.xdp_test_dummy.attach_xdp(wan_p_i as i32).unwrap();
    }

    let root_fd = lan_root.progs.xdp_lan_root.as_fd().as_raw_fd();
    let mss_lan_fd = mss.progs.xdp_mss_lan_v4.as_fd().as_raw_fd();
    let exit_fd = lan_exit.progs.xdp_lan_exit.as_fd().as_raw_fd();

    let wan_root_fd = wan_root.progs.xdp_wan_root.as_fd().as_raw_fd();
    let mss_wan_fd = mss.progs.xdp_mss_wan_v4.as_fd().as_raw_fd();
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

    // ── LAN chain (A→C): lan_route → root → mss → exit ──
    lr.maps
        .xdp_lan_pipe_root_progs
        .update(&TEST_CHAIN.to_ne_bytes(), &root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    lan_root
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_lan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps.next_stage.update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY).unwrap();
    lan_root
        .maps
        .xdp_from_lan_exit_map
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .xdp_from_lan_exit_map
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // ── WAN chain (C→A): wan_intro → wan_root → mss → wan_route_ingress ──
    {
        // Dispatch trie: route 10.0.0.1 → the WAN link's chain (dispatch
        // values are chain ids).
        wan_trie_publish(
            mapped_table(&mut intro.maps.wan_trie_arena).expect("owned trie arena mapping"),
            &[v4_entry(Ipv4Addr::new(10, 0, 0, 1), 32, TEST_CHAIN).unwrap()],
        )
        .unwrap();
    }
    intro
        .maps
        .xdp_pipe_root_progs
        .update(&TEST_CHAIN.to_ne_bytes(), &wan_root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    wan_root
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_wan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    // XDP_FROM_WAN_SLOT_V4 = 2 (direction x family, see chain/xdp_stage.h)
    mss.maps.next_stage.update(&2u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY).unwrap();
    wan_root
        .maps
        .xdp_pipe_exits_wan
        .update(&0u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .xdp_pipe_exits_wan
        .update(&0u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);

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

    // A→C: TCP SYN → LAN chain → MSS clamp
    let pkt_a2c = build_syn_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [203, 0, 113, 1],
        1460,
    );
    send_lan(&pkt_a2c);

    // C→A: TCP SYN → wan_intro → WAN chain → MSS clamp
    let pkt_c2a = build_syn_pkt(
        [0x02, 0, 0, 0, 0, 3],
        [0x02, 0, 0, 0, 0, 4],
        [203, 0, 113, 1],
        [10, 0, 0, 1],
        1460,
    );
    send_wan(&pkt_c2a);

    wait_for("lan/wan pipeline dummy recv", Duration::from_secs(5), || {
        dummy_recv_count(&da.maps.dummy_recv_map, false)
            + dummy_recv_count(&dc.maps.dummy_recv_map, false)
            > 0
    });

    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "no dummy recv");

    // Verify cache entries exist
    let lan_inner = lookup_inner_map(&maps.rt4_cache_map, 1u32);
    let keys: Vec<_> = lan_inner.keys().collect();
    println!("LAN_CACHE (v4) entries: {}", keys.len());
    for k in &keys {
        let raw = lan_inner.lookup(k, MapFlags::ANY).unwrap().unwrap();
        let val: Route4CacheValue = read_unaligned(&raw);
        let key: Route4CacheKey = read_unaligned(k);
        println!(
            "  saddr={:08x} daddr={:08x} -> mark={} ifidx={}",
            u32::from_be(key.local_addr),
            u32::from_be(key.remote_addr),
            val.mark_value,
            val.ifindex
        );
    }
    assert!(!keys.is_empty(), "no LAN_CACHE entries found");
    let wan_inner = lookup_inner_map(&maps.rt4_cache_map, 0u32);
    let wan_keys: Vec<_> = wan_inner.keys().collect();
    println!("WAN_CACHE (v4) entries: {}", wan_keys.len());

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
}

// ── Test D2: WAN-cache return traffic pins to its original chain (surviving hits, missing drops) ──

#[test]
fn xdp_lan_route_missing_wan_cache_chain_drops_without_rerouting() {
    const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const ORIG_WAN_IFINDEX: u32 = 42;
    const ALT_WAN_IFINDEX: u32 = 43;
    const MISSING_CHAIN: u32 = 999;
    const ALT_CHAIN: u32 = 9;
    const XDP_DROP: u32 = 1;

    let share_pin = crate::tests::isolated_pin_root("xdp-lr-wan-missing");
    let maps = crate::tests::init_shared_maps_for_test(&share_pin);

    // The WAN cache pins return traffic to a link whose chain is no longer registered.
    let wan_inner = lookup_inner_map(&maps.rt4_cache_map, WAN_CACHE);
    let cache_key = Route4CacheKey {
        local_addr: LAN_HOST.to_bits().to_be(),
        remote_addr: REMOTE.to_bits().to_be(),
    };
    let cache_value = Route4CacheValue {
        xdp_redirect_able: 1,
        ifindex: ORIG_WAN_IFINDEX,
        link_chain_id: MISSING_CHAIN as u16,
        ..Default::default()
    };
    wan_inner
        .update(as_bytes(&cache_key), as_bytes(&cache_value), MapFlags::ANY)
        .expect("seed WAN cache entry");

    // An available alternative WAN exists in both LAN_CACHE and route slots.
    let lan_inner = lookup_inner_map(&maps.rt4_cache_map, LAN_CACHE);
    let alt_cache = Route4CacheValue {
        xdp_redirect_able: 1,
        ifindex: ALT_WAN_IFINDEX,
        link_chain_id: ALT_CHAIN as u16,
        ..Default::default()
    };
    lan_inner.update(as_bytes(&cache_key), as_bytes(&alt_cache), MapFlags::ANY).unwrap();

    let slot_key = Route4SlotKey {
        flow_id: 0,
        slot: route_slot(u32::from_be_bytes(REMOTE.octets())),
    };
    let slot_value = Route4TargetInfo {
        ifindex: ALT_WAN_IFINDEX,
        link_chain_id: ALT_CHAIN as u16,
        ..Default::default()
    };
    maps.rt4_slot_map.update(as_bytes(&slot_key), as_bytes(&slot_value), MapFlags::ANY).unwrap();

    let mut lr_b = XdpLanRouteSkelBuilder::default();
    lr_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut lr_obj = std::mem::MaybeUninit::uninit();
    let lr = lr_b.open(&mut lr_obj).unwrap().load().unwrap();

    lr.maps
        .xdp_redirect_able
        .update(&ORIG_WAN_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    lr.maps
        .xdp_redirect_able
        .update(&ALT_WAN_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let dummy_b = TestXdpDummySkelBuilder::default();
    let mut dummy_obj = std::mem::MaybeUninit::uninit();
    let dummy = dummy_b.open(&mut dummy_obj).unwrap().load().unwrap();
    let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
    lr.maps
        .xdp_lan_pipe_root_progs
        .update(&ALT_CHAIN.to_ne_bytes(), &(dummy_fd as u32).to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    const META_SIZE: usize = 12;
    let pkt = simple_ipv4_tcp(LAN_HOST, REMOTE);
    let mut input = vec![0u8; META_SIZE + pkt.len()];
    input[META_SIZE..].copy_from_slice(&pkt);
    let mut ctx = XdpMd {
        data: META_SIZE as u32,
        data_end: input.len() as u32,
        data_meta: 0,
        ingress_ifindex: 3,
        ..Default::default()
    };
    let mut out = vec![0u8; input.len() + 256];
    let mut run = || {
        lr.progs
            .xdp_lan_route
            .test_run(ProgramInput {
                data_in: Some(&input),
                data_out: Some(&mut out),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .expect("run xdp_lan_route")
            .return_value as u32
    };
    let ret = run();

    assert_eq!(ret, XDP_DROP, "missing WAN-cache chain must drop, not reroute");
    let rec = dummy
        .maps
        .dummy_recv_map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap()
        .expect("dummy recv record");
    let count = u64::from_ne_bytes(rec[..8].try_into().unwrap());
    assert_eq!(count, 0, "available alternative chain must not be chosen");

    let raw = wan_inner
        .lookup(as_bytes(&cache_key), MapFlags::ANY)
        .unwrap()
        .expect("WAN cache entry must remain untouched");
    let preserved: Route4CacheValue = read_unaligned(&raw);
    assert_eq!(preserved.link_chain_id, MISSING_CHAIN as u16);
    assert_eq!(preserved.ifindex, ORIG_WAN_IFINDEX);

    // The same cached return path works again once its own root is available.
    // The alternate slot remains configured but cannot supply this verdict.
    lr.maps.xdp_lan_pipe_root_progs.delete(&ALT_CHAIN.to_ne_bytes()).unwrap();
    lr.maps
        .xdp_lan_pipe_root_progs
        .update(&MISSING_CHAIN.to_ne_bytes(), &(dummy_fd as u32).to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    assert_eq!(run(), 2, "original chain is reached");
    let rec =
        dummy.maps.dummy_recv_map.lookup(&0u32.to_ne_bytes(), MapFlags::ANY).unwrap().unwrap();
    assert_eq!(u64::from_ne_bytes(rec[..8].try_into().unwrap()), 1);

    let invalid = Route4CacheValue { ifindex: 0, ..cache_value };
    wan_inner.update(as_bytes(&cache_key), as_bytes(&invalid), MapFlags::ANY).unwrap();
    assert_eq!(run(), XDP_DROP, "a chain without a cached exit interface cannot forward");
}

#[test]
fn xdp_lan_route_missing_wan_cache_chain_drops_without_rerouting_v6() {
    const LAN_HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const REMOTE: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const ORIG_WAN_IFINDEX: u32 = 42;
    const ALT_WAN_IFINDEX: u32 = 43;
    const MISSING_CHAIN: u32 = 999;
    const ALT_CHAIN: u32 = 9;
    const XDP_DROP: u32 = 1;

    let share_pin = crate::tests::isolated_pin_root("xdp-lr-wan-missing-v6");
    let maps = crate::tests::init_shared_maps_for_test(&share_pin);

    let wan_inner = lookup_inner_map(&maps.rt6_cache_map, WAN_CACHE);
    let cache_key = Route6CacheKey {
        local_addr: LAN_HOST.octets(),
        remote_addr: REMOTE.octets(),
    };
    let cache_value = Route6CacheValue {
        xdp_redirect_able: 1,
        ifindex: ORIG_WAN_IFINDEX,
        link_chain_id: MISSING_CHAIN as u16,
        ..Default::default()
    };
    wan_inner
        .update(as_bytes(&cache_key), as_bytes(&cache_value), MapFlags::ANY)
        .expect("seed WAN cache entry");

    let lan_inner = lookup_inner_map(&maps.rt6_cache_map, LAN_CACHE);
    let alt_cache = Route6CacheValue {
        xdp_redirect_able: 1,
        ifindex: ALT_WAN_IFINDEX,
        link_chain_id: ALT_CHAIN as u16,
        ..Default::default()
    };
    lan_inner.update(as_bytes(&cache_key), as_bytes(&alt_cache), MapFlags::ANY).unwrap();

    let slot_key = Route6SlotKey { flow_id: 0, slot: route_slot_v6(&REMOTE.octets()) };
    let slot_value = Route6TargetInfo {
        ifindex: ALT_WAN_IFINDEX,
        link_chain_id: ALT_CHAIN as u16,
        ..Default::default()
    };
    maps.rt6_slot_map.update(as_bytes(&slot_key), as_bytes(&slot_value), MapFlags::ANY).unwrap();

    let mut lr_b = XdpLanRouteSkelBuilder::default();
    lr_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut lr_obj = std::mem::MaybeUninit::uninit();
    let lr = lr_b.open(&mut lr_obj).unwrap().load().unwrap();

    lr.maps
        .xdp_redirect_able
        .update(&ORIG_WAN_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    lr.maps
        .xdp_redirect_able
        .update(&ALT_WAN_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let dummy_b = TestXdpDummySkelBuilder::default();
    let mut dummy_obj = std::mem::MaybeUninit::uninit();
    let dummy = dummy_b.open(&mut dummy_obj).unwrap().load().unwrap();
    let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
    lr.maps
        .xdp_lan_pipe_root_progs
        .update(&ALT_CHAIN.to_ne_bytes(), &(dummy_fd as u32).to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    const META_SIZE: usize = 12;
    let pkt = simple_ipv6_tcp_syn(LAN_HOST, REMOTE);
    let mut input = vec![0u8; META_SIZE + pkt.len()];
    input[META_SIZE..].copy_from_slice(&pkt);
    let mut ctx = XdpMd {
        data: META_SIZE as u32,
        data_end: input.len() as u32,
        data_meta: 0,
        ingress_ifindex: 3,
        ..Default::default()
    };
    let mut out = vec![0u8; input.len() + 256];
    let mut run = || {
        lr.progs
            .xdp_lan_route
            .test_run(ProgramInput {
                data_in: Some(&input),
                data_out: Some(&mut out),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .expect("run xdp_lan_route")
            .return_value as u32
    };
    let ret = run();

    assert_eq!(ret, XDP_DROP, "missing v6 WAN-cache chain must drop, not reroute");
    let rec = dummy
        .maps
        .dummy_recv_map
        .lookup(&1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap()
        .expect("dummy v6 recv record");
    let count = u64::from_ne_bytes(rec[..8].try_into().unwrap());
    assert_eq!(count, 0, "available alternative v6 chain must not be chosen");

    let raw = wan_inner
        .lookup(as_bytes(&cache_key), MapFlags::ANY)
        .unwrap()
        .expect("WAN cache entry must remain untouched");
    let preserved: Route6CacheValue = read_unaligned(&raw);
    assert_eq!(preserved.link_chain_id, MISSING_CHAIN as u16);
    assert_eq!(preserved.ifindex, ORIG_WAN_IFINDEX);

    // The same cached return path works again once its own root is available.
    // The alternate slot remains configured but cannot supply this verdict.
    lr.maps.xdp_lan_pipe_root_progs.delete(&ALT_CHAIN.to_ne_bytes()).unwrap();
    lr.maps
        .xdp_lan_pipe_root_progs
        .update(&MISSING_CHAIN.to_ne_bytes(), &(dummy_fd as u32).to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    assert_eq!(run(), 2, "original chain is reached");
    let rec =
        dummy.maps.dummy_recv_map.lookup(&1u32.to_ne_bytes(), MapFlags::ANY).unwrap().unwrap();
    assert_eq!(u64::from_ne_bytes(rec[..8].try_into().unwrap()), 1);

    let invalid = Route6CacheValue { ifindex: 0, ..cache_value };
    wan_inner.update(as_bytes(&cache_key), as_bytes(&invalid), MapFlags::ANY).unwrap();
    assert_eq!(run(), XDP_DROP, "a chain without a cached exit interface cannot forward");
}

// ── Test D3: an unresolved LAN cache entry must behave exactly like a miss ──

fn check_unresolved_lan_cache(
    pin: &std::path::Path,
    packet: &[u8],
    cache: MapHandle,
    key: &[u8],
    stale: &[u8],
    expected: &[u8],
) {
    let mut builder = XdpLanRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(pin).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let route = builder.open(&mut obj).unwrap().load().unwrap();

    // Flow 0 tail-calls the dummy. Flow 5 has a different, TC-only target:
    // choosing it would not reach the dummy and would cache a different ifindex.
    let mut dummy_obj = std::mem::MaybeUninit::uninit();
    let dummy = TestXdpDummySkelBuilder::default().open(&mut dummy_obj).unwrap().load().unwrap();
    let fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd() as u32;
    route
        .maps
        .xdp_lan_pipe_root_progs
        .update(&9u32.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    route
        .maps
        .xdp_redirect_able
        .update(&42u32.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let mut input = vec![0u8; 12]; // xdp_pipe_meta
    input.extend_from_slice(packet);
    let mut ctx = XdpMd {
        data: 12,
        data_end: input.len() as u32,
        ingress_ifindex: 3,
        ..Default::default()
    };
    let is_v6 = packet[12..14] == [0x86, 0xdd];
    for (i, entry) in [None, Some(stale)].into_iter().enumerate() {
        if let Some(entry) = entry {
            cache.update(key, entry, MapFlags::ANY).unwrap();
        }
        let ret = route
            .progs
            .xdp_lan_route
            .test_run(ProgramInput {
                data_in: Some(&input),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .unwrap()
            .return_value;
        assert_eq!(ret, 2, "expected XDP_PASS from the default flow's chain");
        assert_eq!(dummy_recv_count(&dummy.maps.dummy_recv_map, is_v6), (i + 1) as u64);
        assert_eq!(cache.lookup(key, MapFlags::ANY).unwrap().unwrap(), expected);
    }
}

#[test]
fn xdp_lan_route_zero_ifindex_lan_cache_rebuilds_to_current_flow() {
    let pin = crate::tests::isolated_pin_root("xdp-lr-zero-lan-v4");
    let maps = crate::tests::init_shared_maps_for_test(&pin);
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(203, 0, 113, 1);
    let slot = route_slot(remote.to_bits());
    for (flow_id, ifindex, link_chain_id) in [(0, 42, 9), (5, 43, 10)] {
        let key = Route4SlotKey { flow_id, slot };
        let target = Route4TargetInfo { ifindex, link_chain_id, ..Default::default() };
        maps.rt4_slot_map.update(as_bytes(&key), as_bytes(&target), MapFlags::ANY).unwrap();
    }
    let key = Route4CacheKey {
        local_addr: local.to_bits().to_be(),
        remote_addr: remote.to_bits().to_be(),
    };
    let stale = Route4CacheValue { mark_value: 0x0305, ..Default::default() };
    let expected = Route4CacheValue {
        ifindex: 42,
        link_chain_id: 9,
        xdp_redirect_able: 1,
        ..Default::default()
    };
    check_unresolved_lan_cache(
        &pin,
        &simple_ipv4_tcp(local, remote),
        lookup_inner_map(&maps.rt4_cache_map, LAN_CACHE),
        as_bytes(&key),
        as_bytes(&stale),
        as_bytes(&expected),
    );
}

#[test]
fn xdp_lan_route_zero_ifindex_lan_cache_rebuilds_to_current_flow_v6() {
    let pin = crate::tests::isolated_pin_root("xdp-lr-zero-lan-v6");
    let maps = crate::tests::init_shared_maps_for_test(&pin);
    let local = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let remote = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let slot = route_slot_v6(&remote.octets());
    for (flow_id, ifindex, link_chain_id) in [(0, 42, 9), (5, 43, 10)] {
        let key = Route6SlotKey { flow_id, slot };
        let target = Route6TargetInfo { ifindex, link_chain_id, ..Default::default() };
        maps.rt6_slot_map.update(as_bytes(&key), as_bytes(&target), MapFlags::ANY).unwrap();
    }
    let key = Route6CacheKey {
        local_addr: local.octets(),
        remote_addr: remote.octets(),
    };
    let stale = Route6CacheValue { mark_value: 0x0305, ..Default::default() };
    let expected = Route6CacheValue {
        ifindex: 42,
        link_chain_id: 9,
        xdp_redirect_able: 1,
        ..Default::default()
    };
    check_unresolved_lan_cache(
        &pin,
        &simple_ipv6_tcp_syn(local, remote),
        lookup_inner_map(&maps.rt6_cache_map, LAN_CACHE),
        as_bytes(&key),
        as_bytes(&stale),
        as_bytes(&expected),
    );
}

// ── Test D4: outbound LAN_CACHE / CONN_PIN_CACHE tailcall failure & XDP disable fallback ──

#[repr(C)]
#[derive(FromBytes, Immutable, Debug, Clone, Copy, PartialEq, Eq)]
struct FallbackTcRedirectMeta {
    magic: u32,
    mark: u32,
    target_ifindex: u32,
    link_chain_id: u16,
    _pad: u16,
    _reserved: [u8; 8],
}

const _: () = assert!(std::mem::size_of::<FallbackTcRedirectMeta>() == 24);

fn run_xdp_route_with_meta(
    prog: &libbpf_rs::ProgramMut<'_>,
    pkt: &[u8],
    initial_meta: &[u8],
) -> (u32, Vec<u8>, Vec<u8>) {
    let mut input = Vec::with_capacity(initial_meta.len() + pkt.len());
    input.extend_from_slice(initial_meta);
    input.extend_from_slice(pkt);

    let mut ctx_in = XdpMd {
        data: initial_meta.len() as u32,
        data_end: input.len() as u32,
        data_meta: 0,
        ingress_ifindex: 3,
        ..Default::default()
    };
    let mut ctx_out = XdpMd::default();
    let mut out_buf = vec![0u8; input.len() + 64];
    let (ret, out) = {
        let res = prog
            .test_run(ProgramInput {
                data_in: Some(&input),
                data_out: Some(&mut out_buf),
                context_in: Some(ctx_in.as_mut_bytes()),
                context_out: Some(ctx_out.as_mut_bytes()),
                ..Default::default()
            })
            .expect("test_run xdp_lan_route");
        (res.return_value, res.data.expect("xdp data_out").to_vec())
    };
    let meta_len = (ctx_out.data - ctx_out.data_meta) as usize;
    let end = (ctx_out.data_end - ctx_out.data_meta) as usize;
    assert_eq!(end, out.len(), "xdp data_end must match output slice");
    (ret, out[..meta_len].to_vec(), out[meta_len..end].to_vec())
}

#[test]
fn xdp_lan_route_conn_pin_cache_fallback_passes_without_meta_leak_v4_v6() {
    use landscape_common::flow::FlowBalanceMode;

    const XDP_PASS: u32 = 2;
    const XDP_HANDOFF_TC_REDIRECT_MAGIC: u32 = 0x4C44_5443;
    const WAN_IFINDEX: u32 = 42;
    const MISSING_CHAIN: u16 = 77;
    const FLOW_MARK: u32 = 0x0305;

    let pin = crate::tests::isolated_pin_root("xdp-lr-conn-fallback");
    let maps = crate::tests::init_shared_maps_for_test(&pin);
    set_flow_balance_mode_with_map(&maps.rt_flow_mode_map, 5, FlowBalanceMode::FiveTuple);

    let local4 = Ipv4Addr::new(10, 0, 0, 1);
    let remote4 = Ipv4Addr::new(203, 0, 113, 1);
    let local6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let remote6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2);

    let ft_key = RouteFlowTargetKey { flow_id: 5, ifindex: WAN_IFINDEX };
    let target4 = Route4TargetInfo {
        ifindex: WAN_IFINDEX,
        link_chain_id: MISSING_CHAIN,
        ..Default::default()
    };
    let target6 = Route6TargetInfo {
        ifindex: WAN_IFINDEX,
        link_chain_id: MISSING_CHAIN,
        ..Default::default()
    };
    maps.rt4_flow_targets.update(as_bytes(&ft_key), as_bytes(&target4), MapFlags::ANY).unwrap();
    maps.rt6_flow_targets.update(as_bytes(&ft_key), as_bytes(&target6), MapFlags::ANY).unwrap();

    let conn_val = RouteConnValue {
        mark_value: FLOW_MARK,
        has_mac: 0,
        is_docker: 0,
        xdp_redirect_able: 1,
        flags: 0,
        ifindex: WAN_IFINDEX,
        link_chain_id: MISSING_CHAIN,
        _pad: 0,
    };

    let conn4_key = Route4ConnKey {
        saddr: local4.to_bits().to_be(),
        daddr: remote4.to_bits().to_be(),
        sport: 12345_u16.to_be(),
        dport: 443_u16.to_be(),
        l4_proto: 6,
        _pad: [0; 3],
    };
    let conn4_inner = lookup_inner_map(&maps.rt4_conn_map, CONN_PIN_CACHE);
    conn4_inner.update(as_bytes(&conn4_key), as_bytes(&conn_val), MapFlags::ANY).unwrap();

    let conn6_key = Route6ConnKey {
        saddr: local6.octets(),
        daddr: remote6.octets(),
        sport: 12345_u16.to_be(),
        dport: 443_u16.to_be(),
        l4_proto: 6,
        _pad: [0; 3],
    };
    let conn6_inner = lookup_inner_map(&maps.rt6_conn_map, CONN_PIN_CACHE);
    conn6_inner.update(as_bytes(&conn6_key), as_bytes(&conn_val), MapFlags::ANY).unwrap();

    let mut builder = XdpLanRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = builder.open(&mut obj).unwrap().load().unwrap();

    let pkt4 = simple_ipv4_tcp(local4, remote4);
    let pkt6 = simple_ipv6_tcp_syn(local6, remote6);

    // 1) Target WAN dynamically disables XDP (xdp_redirect_able map lacks WAN_IFINDEX
    //    while cached conn_val.xdp_redirect_able is still 1): must emit TC redirect handoff.
    for (label, pkt) in [("v4", &pkt4), ("v6", &pkt6)] {
        let (ret, meta, frame) = run_xdp_route_with_meta(&skel.progs.xdp_lan_route, pkt, &[]);
        assert_eq!(ret, XDP_PASS, "{label}: !xdp_redirect_target_able must return XDP_PASS");
        assert_eq!(frame, *pkt);
        assert_eq!(meta.len(), std::mem::size_of::<FallbackTcRedirectMeta>());
        let ho = FallbackTcRedirectMeta::read_from_bytes(&meta).unwrap();
        assert_eq!(ho.magic, XDP_HANDOFF_TC_REDIRECT_MAGIC);
        assert_eq!(ho.mark, FLOW_MARK);
        assert_eq!(ho.target_ifindex, WAN_IFINDEX);
        assert_eq!(ho.link_chain_id, MISSING_CHAIN);
    }

    // 2) Target WAN is marked XDP-redirectable, but xdp_lan_pipe_root_progs[MISSING_CHAIN]
    //    is empty (teardown race): tailcall fails and must reclaim data_meta + XDP_PASS.
    skel.maps
        .xdp_redirect_able
        .update(&WAN_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let orig_meta: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    for (label, pkt) in [("v4", &pkt4), ("v6", &pkt6)] {
        let (ret, meta, frame) = run_xdp_route_with_meta(&skel.progs.xdp_lan_route, pkt, &[]);
        assert_eq!(ret, XDP_PASS, "{label}: conn_cache tailcall failure must return XDP_PASS");
        assert!(meta.is_empty(), "{label}: must not leak xdp_pipe_meta into TC");
        assert_eq!(frame, *pkt);

        let (ret_pre, meta_pre, frame_pre) =
            run_xdp_route_with_meta(&skel.progs.xdp_lan_route, pkt, &orig_meta);
        assert_eq!(ret_pre, XDP_PASS, "{label}: pre-existing meta tailcall failure must XDP_PASS");
        assert_eq!(meta_pre, orig_meta, "{label}: pre-existing data_meta must be restored intact");
        assert_eq!(frame_pre, *pkt);
    }
}

#[test]
fn xdp_lan_route_lan_cache_fallback_passes_without_meta_leak_v4_v6() {
    const XDP_PASS: u32 = 2;
    const XDP_HANDOFF_TC_REDIRECT_MAGIC: u32 = 0x4C44_5443;
    const WAN_IFINDEX: u32 = 42;
    const MISSING_CHAIN: u16 = 88;
    const FLOW_MARK: u32 = 0x0302;

    let pin = crate::tests::isolated_pin_root("xdp-lr-lancache-fallback");
    let maps = crate::tests::init_shared_maps_for_test(&pin);

    let local4 = Ipv4Addr::new(10, 0, 0, 2);
    let remote4 = Ipv4Addr::new(203, 0, 113, 2);
    let local6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let remote6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 3);

    let key4 = Route4CacheKey {
        local_addr: local4.to_bits().to_be(),
        remote_addr: remote4.to_bits().to_be(),
    };
    let val4 = Route4CacheValue {
        mark_value: FLOW_MARK,
        xdp_redirect_able: 1,
        ifindex: WAN_IFINDEX,
        link_chain_id: MISSING_CHAIN,
        ..Default::default()
    };
    let lan4_inner = lookup_inner_map(&maps.rt4_cache_map, LAN_CACHE);
    lan4_inner.update(as_bytes(&key4), as_bytes(&val4), MapFlags::ANY).unwrap();

    let key6 = Route6CacheKey {
        local_addr: local6.octets(),
        remote_addr: remote6.octets(),
    };
    let val6 = Route6CacheValue {
        mark_value: FLOW_MARK,
        xdp_redirect_able: 1,
        ifindex: WAN_IFINDEX,
        link_chain_id: MISSING_CHAIN,
        ..Default::default()
    };
    let lan6_inner = lookup_inner_map(&maps.rt6_cache_map, LAN_CACHE);
    lan6_inner.update(as_bytes(&key6), as_bytes(&val6), MapFlags::ANY).unwrap();

    let mut builder = XdpLanRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = builder.open(&mut obj).unwrap().load().unwrap();

    let pkt4 = simple_ipv4_tcp(local4, remote4);
    let pkt6 = simple_ipv6_tcp_syn(local6, remote6);

    // 1) Stale cached xdp_redirect_able == 1 while live xdp_redirect_able map lacks WAN_IFINDEX.
    for (label, pkt) in [("v4", &pkt4), ("v6", &pkt6)] {
        let (ret, meta, frame) = run_xdp_route_with_meta(&skel.progs.xdp_lan_route, pkt, &[]);
        assert_eq!(ret, XDP_PASS, "{label}: LAN_CACHE !xdp_redirect_target_able must XDP_PASS");
        assert_eq!(frame, *pkt);
        let ho = FallbackTcRedirectMeta::read_from_bytes(&meta).unwrap();
        assert_eq!(ho.magic, XDP_HANDOFF_TC_REDIRECT_MAGIC);
        assert_eq!(ho.mark, FLOW_MARK);
        assert_eq!(ho.target_ifindex, WAN_IFINDEX);
        assert_eq!(ho.link_chain_id, MISSING_CHAIN);
    }

    // 2) Live xdp_redirect_able == 1 but xdp_lan_pipe_root_progs[MISSING_CHAIN] is empty.
    skel.maps
        .xdp_redirect_able
        .update(&WAN_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    for (label, pkt) in [("v4", &pkt4), ("v6", &pkt6)] {
        let (ret, meta, frame) = run_xdp_route_with_meta(&skel.progs.xdp_lan_route, pkt, &[]);
        assert_eq!(ret, XDP_PASS, "{label}: LAN_CACHE tailcall failure must return XDP_PASS");
        assert!(meta.is_empty(), "{label}: LAN_CACHE fallback must not leak xdp_pipe_meta");
        assert_eq!(frame, *pkt);
    }
}

// ── Test E: unknown IP must not be redirected (regression guard) ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_lan_route_unknown_ip_no_redirect() {
    let test_ns = NetNsGuard::create("lre");
    let peer_ns = NetNsGuard::create("lrep");
    let pair;
    let out_pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("lre", &peer_ns);
        // redirect target must be a device other than the ingress (the program
        // passes when lan_info->ifindex == ingress), so use a second pair kept
        // in the test netns.
        out_pair = VethPair::create("lreout");
    }
    let peer = pair.peer();
    let h_i;
    let out_h_i;
    {
        let _e = test_ns.enter();
        h_i = pair.host_ifindex();
        out_h_i = out_pair.host_ifindex();
    }

    let pin_root = crate::tests::isolated_pin_root("xdp-lr-unk");
    let mut b = XdpLanRouteSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();

    // known route 10.0.0.5 → LAN redirect is functional: the redirect target is
    // the out-pair host veth (same netns as the program), which forwards the
    // redirected frame to its peer.
    {
        let mut lan_key = [0u8; 8];
        lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes());
        lan_key[4..8].copy_from_slice(&0x0A000005u32.to_be_bytes());
        let mut lan_val = [0u8; 16];
        lan_val[8..12].copy_from_slice(&out_h_i.to_ne_bytes());
        skel.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();
    }

    // ip_mac_v4 for unknown IP 10.0.0.99 (was the bug: old code redirected this)
    let mut mac_key = [0u8; 4];
    mac_key.copy_from_slice(&0x0A000063u32.to_be_bytes());
    {
        let mut mac_val = [0u8; 20];
        mac_val[0..4].copy_from_slice(&out_h_i.to_ne_bytes());
        mac_val[4..10].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x99]);
        mac_val[10..16].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        mac_val[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        skel.maps.ip_mac_v4.update(&mac_key, &mac_val, MapFlags::ANY).unwrap();
    }

    // allow XDP redirect to the out-pair host veth
    skel.maps
        .xdp_redirect_able
        .update(&out_h_i.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // counting dummy on the out-pair peer (where redirected packets land)
    let mut db = TestXdpDummySkelBuilder::default();
    db.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut dobj = std::mem::MaybeUninit::uninit();
    let dummy = db.open(&mut dobj).unwrap().load().unwrap();

    let _link;
    let _dl;
    {
        let _e = test_ns.enter();
        _link = skel.progs.xdp_lan_route.attach_xdp(h_i as i32).unwrap();
        _dl = dummy.progs.xdp_test_dummy.attach_xdp(out_pair.peer_ifindex() as i32).unwrap();
    }

    // 1) unknown IP: must NOT be redirected to the LAN peer
    let pkt_unknown = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 99],
    );
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt_unknown);
    }
    settle(300);
    assert_eq!(
        dummy_recv_count(&dummy.maps.dummy_recv_map, false),
        0,
        "unknown IP must not reach the LAN peer"
    );

    // ip_mac_v4 for the unknown IP must be untouched
    let mac_after = skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap();
    assert!(mac_after.is_some(), "ip_mac_v4 entry for unknown IP should still exist");
    let raw = mac_after.unwrap();
    assert_eq!(&raw[0..4], &out_h_i.to_ne_bytes(), "ifindex should remain unchanged");
    assert_eq!(&raw[4..10], &[0x02, 0, 0, 0, 0, 0x99], "mac should remain unchanged");
    assert_eq!(&raw[10..16], &[0x02, 0, 0, 0, 0, 0x01], "dev_mac should remain unchanged");
    assert_eq!(&raw[16..18], &0x0800u16.to_be_bytes(), "proto should remain unchanged");

    // 2) known IP: still redirected (map is functional)
    let pkt_known = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 5],
    );
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt_known);
    }
    wait_for("known IP redirected to LAN peer", Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    drop(dummy);
    drop(skel);
}
// ── Test F: known LAN without MAC → real FIB fallback + XDP redirect ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_lan_route_known_lan_fib_fallback() {
    let test_ns = NetNsGuard::create("lrf");
    let peer_ns = NetNsGuard::create("lrfp");
    let pair;
    let out_pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("lrf", &peer_ns);
        // FIB target must be a device other than the ingress (host end), so the
        // route points out a second pair kept in the test netns.
        out_pair = VethPair::create("lrfout");
    }
    let peer = pair.peer();

    let h_i;
    let out_h_i;
    {
        let _e = test_ns.enter();
        // route + static neigh so bpf_fib_lookup can resolve the MAC (test netns only)
        Command::new("ip")
            .args(["route", "add", "10.0.0.5/32", "dev", out_pair.host()])
            .output()
            .unwrap();
        Command::new("ip")
            .args([
                "neigh",
                "add",
                "10.0.0.5",
                "lladdr",
                "02:00:00:00:00:05",
                "dev",
                out_pair.host(),
            ])
            .output()
            .unwrap();
        h_i = pair.host_ifindex();
        out_h_i = out_pair.host_ifindex();
    }

    let pin_root = crate::tests::isolated_pin_root("xdp-lr-fibf");
    let mut b = XdpLanRouteSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();

    let dst_ip_be = 0x0A000005u32.to_be_bytes(); // 10.0.0.5

    // rt4_lan_map with has_mac=1 → ip_mac miss → real FIB fallback
    let mut lan_key = [0u8; 8];
    lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes());
    lan_key[4..8].copy_from_slice(&dst_ip_be);
    let mut lan_val = [0u8; 16];
    lan_val[0] = 1; // has_mac = true
    lan_val[8..12].copy_from_slice(&out_h_i.to_ne_bytes());
    skel.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();

    // allow XDP redirect to the FIB-resolved device
    skel.maps
        .xdp_redirect_able
        .update(&out_h_i.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // counting dummy on the out-pair peer (where the redirected packet lands)
    let mut db = TestXdpDummySkelBuilder::default();
    db.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut dobj = std::mem::MaybeUninit::uninit();
    let dummy = db.open(&mut dobj).unwrap().load().unwrap();

    let _link;
    let _dl;
    {
        let _e = test_ns.enter();
        _link = skel.progs.xdp_lan_route.attach_xdp(h_i as i32).unwrap();
        _dl = dummy.progs.xdp_test_dummy.attach_xdp(out_pair.peer_ifindex() as i32).unwrap();
    }

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 5],
    );
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt);
    }
    wait_for("FIB fallback redirected packet to out peer", Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    // FIB cache populated with the resolved MAC and redirect target
    let mut mac_key = [0u8; 4];
    mac_key.copy_from_slice(&dst_ip_be);
    let mac_after = skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap();
    assert!(mac_after.is_some(), "FIB should have populated ip_mac_v4 for 10.0.0.5");
    let raw = mac_after.unwrap();
    assert_eq!(&raw[0..4], &out_h_i.to_ne_bytes(), "FIB cache ifindex = lan_info->ifindex");
    assert_eq!(&raw[4..10], &[0x02, 0, 0, 0, 0, 0x05], "FIB resolved MAC from static neigh");
    assert_eq!(&raw[10..16], &[0u8; 6], "FIB cache dev_mac = lan_info->mac_addr");
    assert_eq!(&raw[16..18], &0x0800u16.to_be_bytes(), "FIB cache proto = ETH_P_IP");

    // second send: MAC cache hit → still redirected
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt);
    }
    wait_for("cached-MAC redirect to out peer", Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    drop(dummy);
    drop(skel);
}
fn build_ipv6_tcp_pkt(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv6(src_ip, dst_ip, 64)
        .tcp(12345, 80, 1000, 2000);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build ipv6 packet");
    pkt
}

// ── Test G: v4 FIB fallback with veth + map verification ──

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_lan_route_fib_fallback_v4() {
    let test_ns = NetNsGuard::create("f4x");
    let peer_ns = NetNsGuard::create("f4xp");
    let pair;
    let out_pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("f4x", &peer_ns);
        // FIB target must be a device other than the ingress (host end), so the
        // route points out a second pair kept in the test netns.
        out_pair = VethPair::create("f4o");
    }
    let peer = pair.peer();
    let out_host = out_pair.host();

    let h_i;
    let out_h_i;
    {
        let _e = test_ns.enter();
        // route + static ARP so bpf_fib_lookup can resolve the MAC (test netns only)
        Command::new("ip")
            .args(["route", "add", "10.0.0.200/32", "dev", out_host])
            .output()
            .unwrap();
        Command::new("ip")
            .args(["neigh", "add", "10.0.0.200", "lladdr", "02:00:00:00:00:c8", "dev", out_host])
            .output()
            .unwrap();
        h_i = pair.host_ifindex();
        out_h_i = out_pair.host_ifindex();
    }

    let pin_root = crate::tests::isolated_pin_root("xdp-lr-fib4v");
    let mut b = XdpLanRouteSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();

    let dst_ip_be = 0x0A0000C8u32.to_be_bytes(); // 10.0.0.200

    // delete stale entries
    let mut lan_key = [0u8; 8];
    lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes());
    lan_key[4..8].copy_from_slice(&dst_ip_be);
    skel.maps.rt4_lan_map.delete(&lan_key).ok();

    let mut mac_key = [0u8; 4];
    mac_key.copy_from_slice(&dst_ip_be);
    skel.maps.ip_mac_v4.delete(&mac_key).ok();

    // pre-fill rt4_lan_map with has_mac=1 (forces MAC lookup → FIB fallback).
    // ifindex must be a *local* (test-netns) index distinct from the ingress,
    // since peer-netns ifindexes numerically collide with local ones.
    let mut lan_val = [0u8; 16];
    lan_val[0] = 1; // has_mac = true
    lan_val[8..12].copy_from_slice(&out_h_i.to_ne_bytes());
    skel.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();

    // do NOT pre-fill ip_mac_v4 for 10.0.0.200

    let _link;
    {
        let _e = test_ns.enter();
        _link = skel.progs.xdp_lan_route.attach_xdp(h_i as i32).unwrap();
    }

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 200],
    );
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt);
    }
    wait_for("FIB fallback populated ip_mac_v4", Duration::from_secs(5), || {
        skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap().is_some()
    });

    let mac_after = skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap();
    assert!(mac_after.is_some(), "FIB should have populated ip_mac_v4 for known LAN IP 10.0.0.200");

    drop(skel);
    let _e = test_ns.enter();
    let _ = Command::new("ip").args(["neigh", "del", "10.0.0.200", "dev", out_host]).output();
    let _ = Command::new("ip").args(["route", "del", "10.0.0.200/32", "dev", out_host]).output();
}

// ── Test H: v6 FIB fallback with veth + map verification ──

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_lan_route_fib_fallback_v6() {
    let test_ns = NetNsGuard::create("f6x");
    let peer_ns = NetNsGuard::create("f6xp");
    let pair;
    let out_pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("f6x", &peer_ns);
        out_pair = VethPair::create("f6o");
    }
    let host = pair.host();
    let peer = pair.peer();
    let out_host = out_pair.host();

    let h_i;
    let out_h_i;
    {
        let _e = test_ns.enter();
        // bpf_fib_lookup for IPv6 requires forwarding=1 on the ingress device
        let fwd_path = format!("net.ipv6.conf.{}.forwarding", host);
        let fwd_was = Command::new("sysctl")
            .args(["-n", &fwd_path])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        Command::new("sysctl").args(["-w", &format!("{}=1", fwd_path)]).output().unwrap();
        // route + static neighbour so bpf_fib_lookup can resolve the MAC (test netns only)
        Command::new("ip")
            .args(["-6", "route", "add", "fd00::200/128", "dev", out_host])
            .output()
            .unwrap();
        Command::new("ip")
            .args([
                "-6",
                "neigh",
                "add",
                "fd00::200",
                "lladdr",
                "02:00:00:00:00:c8",
                "dev",
                out_host,
            ])
            .output()
            .unwrap();
        h_i = pair.host_ifindex();

        let pin_root = crate::tests::isolated_pin_root("xdp-lr-fib6v");
        let mut b = XdpLanRouteSkelBuilder::default();
        b.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut obj = std::mem::MaybeUninit::uninit();
        let skel = b.open(&mut obj).unwrap().load().unwrap();

        // 20-byte v6 route6_lan_key: prefixlen(4) + addr(16)
        let mut lan_key = [0u8; 20];
        lan_key[0..4].copy_from_slice(&128u32.to_ne_bytes());
        // fd00::200 in network byte order
        let dst_ip6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0];
        lan_key[4..20].copy_from_slice(&dst_ip6);

        // 28-byte v6 route6_lan_info: has_mac(1) + mac_addr(6) + route_type(1) + ifindex(4) + addr(16)
        // ifindex must be a *local* (test-netns) index distinct from the ingress,
        // since peer-netns ifindexes numerically collide with local ones.
        let mut lan_val = [0u8; 28];
        lan_val[0] = 1; // has_mac = true
        out_h_i = out_pair.host_ifindex();
        lan_val[8..12].copy_from_slice(&out_h_i.to_ne_bytes());
        // addr stays zero (not used when route_type=ROUTE_TYPE_LAN)

        skel.maps.rt6_lan_map.delete(&lan_key).ok();
        skel.maps.rt6_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();

        // 16-byte v6 mac_key (addr only)
        let mut mac_key = [0u8; 16];
        mac_key.copy_from_slice(&dst_ip6);
        skel.maps.ip_mac_v6.delete(&mac_key).ok();

        let _link = skel.progs.xdp_lan_route.attach_xdp(h_i as i32).unwrap();

        let pkt = build_ipv6_tcp_pkt(
            [0x02, 0, 0, 0, 0, 1],
            [0x02, 0, 0, 0, 0, 2],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3], // fd00::3
            dst_ip6,                                             // fd00::200
        );
        {
            let _e = peer_ns.enter();
            send_raw_packet(peer, &pkt);
        }
        wait_for("FIB fallback populated ip_mac_v6", Duration::from_secs(5), || {
            skel.maps.ip_mac_v6.lookup(&mac_key, MapFlags::ANY).unwrap().is_some()
        });

        let mac_after = skel.maps.ip_mac_v6.lookup(&mac_key, MapFlags::ANY).unwrap();
        assert!(
            mac_after.is_some(),
            "FIB should have populated ip_mac_v6 for known LAN IP fd00::200"
        );

        drop(skel);
        // restore forwarding
        if !fwd_was.is_empty() {
            let _ =
                Command::new("sysctl").args(["-w", &format!("{}={}", fwd_path, fwd_was)]).output();
        }
        let _ =
            Command::new("ip").args(["-6", "neigh", "del", "fd00::200", "dev", out_host]).output();
        let _ = Command::new("ip")
            .args(["-6", "route", "del", "fd00::200/128", "dev", out_host])
            .output();
    }
}

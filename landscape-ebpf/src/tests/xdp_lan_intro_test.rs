use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;
use std::time::Duration;

use libbpf_rs::{
    libbpf_sys,
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, MapHandle, MapType, ProgramInput,
};

use crate::map_setting::share_map::types::{
    rt_cache_key_v4, rt_cache_key_v6, rt_cache_value_v4, rt_cache_value_v6,
};
use crate::map_setting::share_map::ShareMapSkelBuilder;
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;
use crate::tests::wan_intro_skel::XdpWanIntroSkelBuilder;
use crate::tests::xdp_lan_chain_skel::XdpLanChainSkelBuilder;
use crate::tests::xdp_lan_intro_skel::XdpLanIntroSkelBuilder;
use crate::tests::xdp_mss_skel::XdpMssSkelBuilder;
use crate::tests::xdp_wan_chain_skel::XdpWanChainSkelBuilder;
use crate::tests::xdp_wan_route_skel::XdpWanRouteSkelBuilder;
use crate::tests::PinRootGuard;

fn test_pin_root(prefix: &str) -> PinRootGuard {
    PinRootGuard::new(&format!("xdp-lr-{prefix}"))
}

use crate::tests::net_utils::{
    dummy_recv_count, dummy_reset, send_raw_packet, settle, wait_for, NetNsGuard, VethPair,
};

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

fn route_slot(daddr: u32) -> u32 {
    let mut hash = daddr;
    hash ^= hash >> 16;
    hash ^= hash >> 8;
    hash & 0xF
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

// ── Test A: verifier smoke ──

#[test]
fn xdp_lan_intro_verifier_smoke() {
    let mut builder = XdpLanIntroSkelBuilder::default();
    let pin_root = test_pin_root("v");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let _skel = open.load().expect("verifier rejected");
}

// ── Test B: trace flow (empty maps, smoke test) ──

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_lan_intro_trace_flow() {
    let test_ns = NetNsGuard::create("trx");
    let peer_ns = NetNsGuard::create("trxp");
    let pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("trx", &peer_ns);
    }
    let peer = pair.peer();

    let mut builder = XdpLanIntroSkelBuilder::default();
    let pin_root = test_pin_root("t");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let skel = open.load().expect("load");
    let _link;
    {
        let _e = test_ns.enter();
        let ifindex = pair.host_ifindex() as i32;
        _link = skel.progs.xdp_lan_intro.attach_xdp(ifindex).expect("attach");
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
fn xdp_lan_intro_map_redirect() {
    let share_pin = test_pin_root("share");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

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
    share.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();

    let mut b = XdpLanIntroSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();
    let _link;
    {
        let _e = test_ns.enter();
        _link = skel.progs.xdp_lan_intro.attach_xdp(h_i as i32).unwrap();
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
    drop(share);
}

// ── Test D: bidirectional A↔C (lan_route + wan_route) ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_lan_intro_wan_pipeline() {
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

    let share_pin = test_pin_root("pipe");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    // A→C: slot target → wan_h
    {
        let s = route_slot(0xCB007101);
        let mut k = [0u8; 8];
        let mut v = [0u8; 16];
        k[0..4].copy_from_slice(&0u32.to_ne_bytes());
        k[4..8].copy_from_slice(&s.to_ne_bytes());
        v[0..4].copy_from_slice(&wan_h_i.to_ne_bytes());
        share.maps.rt4_target_slot_map.update(&k, &v, MapFlags::ANY).unwrap();
    }
    // C→A: lan route → lan_p
    {
        let mut k = [0u8; 8];
        let mut v = [0u8; 16];
        k[0..4].copy_from_slice(&32u32.to_ne_bytes());
        k[4..8].copy_from_slice(&0x0A000001u32.to_be_bytes());
        v[8..12].copy_from_slice(&lan_h_i.to_ne_bytes());
        share.maps.rt4_lan_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // Create inner LRU_HASH maps for rt4_cache_map / rt6_cache_map
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    for (cache_idx, name) in [(0u32, "wan"), (1u32, "lan")] {
        for (outer, ksz, vsz, label) in [
            (
                &share.maps.rt4_cache_map,
                std::mem::size_of::<rt_cache_key_v4>() as u32,
                std::mem::size_of::<rt_cache_value_v4>() as u32,
                "v4",
            ),
            (
                &share.maps.rt6_cache_map,
                std::mem::size_of::<rt_cache_key_v6>() as u32,
                std::mem::size_of::<rt_cache_value_v6>() as u32,
                "v6",
            ),
        ] {
            let inner = MapHandle::create(
                MapType::LruHash,
                Some(format!("rt{label}_cache_{name}")),
                ksz,
                vsz,
                65536,
                &opts,
            )
            .expect("create inner LRU");
            let fd = inner.as_fd().as_raw_fd().to_ne_bytes();
            outer.update(&cache_idx.to_ne_bytes(), &fd, MapFlags::ANY).unwrap();
        }
    }

    let mut lr_b = XdpLanIntroSkelBuilder::default();
    lr_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut lr_obj = std::mem::MaybeUninit::uninit();
    let lr = lr_b.open(&mut lr_obj).unwrap().load().unwrap();

    let mut intro_b = XdpWanIntroSkelBuilder::default();
    intro_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut intro_obj = std::mem::MaybeUninit::uninit();
    let intro = intro_b.open(&mut intro_obj).unwrap().load().unwrap();

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

    let chain_b = XdpLanChainSkelBuilder::default();
    let mut chain_obj = std::mem::MaybeUninit::uninit();
    let chain = chain_b.open(&mut chain_obj).unwrap().load().unwrap();

    let wan_root_b = XdpWanChainSkelBuilder::default();
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
        _l0 = lr.progs.xdp_lan_intro.attach_xdp(lan_h_i as i32).unwrap();
        _l1 = intro.progs.wan_intro_dispatch.attach_xdp(wan_h_i as i32).unwrap();
    }
    {
        let _e = peer_ns.enter();
        _l2 = da.progs.xdp_test_dummy.attach_xdp(lan_p_i as i32).unwrap();
        _l3 = dc.progs.xdp_test_dummy.attach_xdp(wan_p_i as i32).unwrap();
    }

    let root_fd = chain.progs.xdp_lan_chain_root.as_fd().as_raw_fd();
    let mss_lan_fd = mss.progs.xdp_mss_lan.as_fd().as_raw_fd();
    let exit_fd = chain.progs.xdp_lan_chain_exit.as_fd().as_raw_fd();

    let wan_root_fd = wan_root.progs.xdp_wan_chain_root.as_fd().as_raw_fd();
    let mss_wan_fd = mss.progs.xdp_mss_wan.as_fd().as_raw_fd();
    let wr_fd = wr.progs.xdp_wan_route_ingress.as_fd().as_raw_fd();

    // Mark redirect targets native-XDP able, otherwise xdp_lan_intro falls back
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
        .update(&wan_h_i.to_ne_bytes(), &root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    chain
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_lan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps.next_stage.update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY).unwrap();
    chain
        .maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // ── WAN chain (C→A): wan_intro → wan_root → mss → wan_route_ingress ──
    {
        // dispatch_key layout (16 bytes, 8-byte aligned due to __be64 in union):
        //   [0..4)  dispatch_type (u32 LE) = 0 (direct IPv4)
        //   [4..8)  padding
        //   [8..12) v4._pad = 0
        //   [12..16) v4.daddr (u32 BE) = 10.0.0.1
        let daddr_be = u32::from_be(0x0A000001_u32);
        let mut dispatch_key = [0u8; 16];
        dispatch_key[12..16].copy_from_slice(&daddr_be.to_ne_bytes());
        let dispatch_val = wan_h_i.to_ne_bytes();
        intro
            .maps
            .wan_intro_dispatch_map
            .update(&dispatch_key, &dispatch_val, MapFlags::ANY)
            .unwrap();
    }
    intro
        .maps
        .xdp_pipe_root_progs
        .update(&wan_h_i.to_ne_bytes(), &wan_root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    wan_root
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_wan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps.next_stage.update(&1u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY).unwrap();
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
        send_raw_packet(&lan_p, pkt);
    };
    let send_wan = |pkt: &[u8]| {
        let _e = peer_ns.enter();
        send_raw_packet(&wan_p, pkt);
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
    let lan_inner = lookup_inner_map(&share.maps.rt4_cache_map, 1u32);
    let keys: Vec<_> = lan_inner.keys().collect();
    println!("LAN_CACHE (v4) entries: {}", keys.len());
    for k in &keys {
        let raw = lan_inner.lookup(k, MapFlags::ANY).unwrap().unwrap();
        let val: rt_cache_value_v4 = read_unaligned(&raw);
        let key: rt_cache_key_v4 = read_unaligned(k);
        println!(
            "  saddr={:08x} daddr={:08x} -> mark={} ifidx={}",
            u32::from_be(key.local_addr),
            u32::from_be(key.remote_addr),
            val.mark_value,
            val.ifindex
        );
    }
    assert!(!keys.is_empty(), "no LAN_CACHE entries found");
    let wan_inner = lookup_inner_map(&share.maps.rt4_cache_map, 0u32);
    let wan_keys: Vec<_> = wan_inner.keys().collect();
    println!("WAN_CACHE (v4) entries: {}", wan_keys.len());

    drop(mss);
    drop(wan_root);
    drop(chain);
    drop(dc);
    drop(da);
    drop(wr);
    drop(intro);
    drop(lr);
    drop(share);
}

// ── Test E: test_run verification of unknown IP not redirected ──

#[test]
#[ignore = "requires specific BPF map / kernel environment"]
fn xdp_lan_intro_unknown_ip_no_redirect_test_run() {
    let pin_root = test_pin_root("trunk");
    let mut b = XdpLanIntroSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = b.open(&mut obj).unwrap();
    let skel = open.load().unwrap();

    // populate rt4_lan_map with 10.0.0.5 (known entry, to confirm map is functional)
    {
        let mut lan_key = [0u8; 8];
        lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes());
        lan_key[4..8].copy_from_slice(&0x0A000005u32.to_be_bytes());
        let mut lan_val = [0u8; 16];
        lan_val[8..12].copy_from_slice(&99u32.to_ne_bytes()); // dummy ifindex
        skel.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();
    }

    // populate ip_mac_v4 for unknown IP 10.0.0.99 (was the bug: old code would redirect this)
    let mut mac_key = [0u8; 4];
    mac_key.copy_from_slice(&0x0A000063u32.to_be_bytes());
    {
        let mut mac_val = [0u8; 20];
        mac_val[0..4].copy_from_slice(&99u32.to_ne_bytes());
        mac_val[4..10].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x99]);
        mac_val[10..16].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        mac_val[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        skel.maps.ip_mac_v4.update(&mac_key, &mac_val, MapFlags::ANY).unwrap();
    }

    // send packet to unknown IP 10.0.0.99
    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 99],
    );

    let run = skel
        .progs
        .xdp_lan_intro
        .test_run(ProgramInput { data_in: Some(&pkt), ..Default::default() })
        .expect("test_run");

    // XDP_PASS=2: unknown IP should continue to WAN, NOT be redirected via LAN
    let ret = run.return_value as i32;
    assert_eq!(ret, 2, "unknown IP should return XDP_PASS(2), got {}", ret);

    // known IP 10.0.0.5: should redirect
    let pkt2 = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 5],
    );

    let run2 = skel
        .progs
        .xdp_lan_intro
        .test_run(ProgramInput { data_in: Some(&pkt2), ..Default::default() })
        .expect("test_run");

    let ret2 = run2.return_value as i32;
    assert_eq!(ret2, 4, "known IP should be XDP_REDIRECT(4), got {}", ret2);

    // verify ip_mac_v4 for unknown IP was NOT modified (no FIB cache added)
    let mac_after = skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap();
    assert!(mac_after.is_some(), "ip_mac_v4 entry for unknown IP should still exist");
    let raw = mac_after.unwrap();
    assert_eq!(&raw[0..4], &99u32.to_ne_bytes(), "ifindex should remain unchanged");
    assert_eq!(&raw[4..10], &[0x02, 0, 0, 0, 0, 0x99], "mac should remain unchanged");
    assert_eq!(&raw[10..16], &[0x02, 0, 0, 0, 0, 0x01], "dev_mac should remain unchanged");
    assert_eq!(&raw[16..18], &0x0800u16.to_be_bytes(), "proto should remain unchanged");
}

// ── Test F: test_run verification of known LAN without MAC → FIB fallback ──

#[test]
#[ignore = "requires kernel FIB resolution support"]
fn xdp_lan_intro_known_lan_fib_fallback_test_run() {
    let pin_root = test_pin_root("trfib");
    let mut b = XdpLanIntroSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = b.open(&mut obj).unwrap();
    let skel = open.load().unwrap();

    // populate rt4_lan_map with has_mac=1 for 10.0.0.5 (so MAC required, triggers FIB fallback)
    {
        let mut lan_key = [0u8; 8];
        lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes());
        lan_key[4..8].copy_from_slice(&0x0A000005u32.to_be_bytes());
        let mut lan_val = [0u8; 16];
        lan_val[0] = 1; // has_mac = true
        lan_val[8..12].copy_from_slice(&99u32.to_ne_bytes()); // dummy ifindex
        skel.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();
    }

    // do NOT populate ip_mac_v4 for 10.0.0.5 — forces FIB fallback

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 5],
    );

    let run = skel
        .progs
        .xdp_lan_intro
        .test_run(ProgramInput { data_in: Some(&pkt), ..Default::default() })
        .expect("test_run");

    let ret = run.return_value as i32;
    // bpf_fib_lookup succeeds even in test_run (kernel FIB is still available).
    // The has_mac=1 path with no ip_mac cache entry should trigger FIB fallback
    // and redirect to lan_info->ifindex.
    assert_eq!(ret, 4, "FIB fallback: expected XDP_REDIRECT=4 when FIB resolves MAC, got {ret}");

    // After the run, verify ip_mac_v4 was populated by FIB fallback
    let mut mac_key = [0u8; 4];
    mac_key.copy_from_slice(&0x0A000005u32.to_be_bytes());
    let mac_after = skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap();
    assert!(
        mac_after.is_some(),
        "ip_mac_v4 should have been populated by FIB fallback for known LAN IP 10.0.0.5"
    );
    let raw = mac_after.unwrap();
    assert_eq!(&raw[0..4], &99u32.to_ne_bytes(), "FIB cache ifindex = lan_info->ifindex");
    assert_eq!(&raw[10..16], &[0u8; 6], "FIB cache dev_mac = lan_info->mac_addr");
    assert_ne!(&raw[4..10], &[0u8; 6], "FIB should have resolved MAC (non-zero)");
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
fn xdp_lan_intro_fib_fallback_v4() {
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

    let pin_root = test_pin_root("fib4v");
    let mut b = XdpLanIntroSkelBuilder::default();
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
        _link = skel.progs.xdp_lan_intro.attach_xdp(h_i as i32).unwrap();
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
fn xdp_lan_intro_fib_fallback_v6() {
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

        let pin_root = test_pin_root("fib6v");
        let mut b = XdpLanIntroSkelBuilder::default();
        b.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut obj = std::mem::MaybeUninit::uninit();
        let skel = b.open(&mut obj).unwrap().load().unwrap();

        // 20-byte v6 lan_route_key: prefixlen(4) + addr(16)
        let mut lan_key = [0u8; 20];
        lan_key[0..4].copy_from_slice(&128u32.to_ne_bytes());
        // fd00::200 in network byte order
        let dst_ip6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0];
        lan_key[4..20].copy_from_slice(&dst_ip6);

        // 28-byte v6 lan_route_info: has_mac(1) + mac_addr(6) + route_type(1) + ifindex(4) + addr(16)
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

        let _link = skel.progs.xdp_lan_intro.attach_xdp(h_i as i32).unwrap();

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

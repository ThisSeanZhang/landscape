use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use libbpf_rs::{
    libbpf_sys,
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, MapHandle, MapType, ProgramInput,
};
use nix::net::if_::if_nametoindex;

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

fn test_pin_root(prefix: &str) -> PathBuf {
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/xdp-lr-{}-{}-{}",
        prefix,
        std::process::id(),
        crate::tests::test_id()
    ));
    let _ = std::fs::create_dir_all(&path);
    path
}

fn dummy_recv_count(map: &libbpf_rs::MapMut, is_v6: bool) -> u64 {
    let k = if is_v6 { 1u32 } else { 0u32 }.to_ne_bytes();
    map.lookup(&k, MapFlags::ANY)
        .unwrap()
        .map_or(0, |v| u64::from_ne_bytes(v[0..8].try_into().unwrap()))
}

fn dummy_reset(map: &libbpf_rs::MapMut) {
    let v = [0u8; 8];
    map.update(&0u32.to_ne_bytes(), &v, MapFlags::ANY).unwrap();
    map.update(&1u32.to_ne_bytes(), &v, MapFlags::ANY).unwrap();
}

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

fn send_raw_packet(iface: &str, pkt: &[u8]) {
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(0x0300)),
    )
    .expect("create raw socket");
    let idx = if_nametoindex(iface).expect("if_nametoindex");
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: 0x0300u16.to_be(),
        sll_ifindex: idx as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };
    unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
    }
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
    builder.object_builder_mut().pin_root_path(&test_pin_root("v")).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let _skel = open.load().expect("verifier rejected");
}

// ── Test B: trace flow (empty maps, smoke test) ──

#[test]
fn xdp_lan_intro_trace_flow() {
    let pid = crate::tests::test_id();
    let (host, peer) = (format!("lxdh{pid}"), format!("lxdp{pid}"));
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", host.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", peer.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let ifindex = if_nametoindex(host.as_str()).expect("ifindex") as i32;

    let mut builder = XdpLanIntroSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&test_pin_root("t")).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let skel = open.load().expect("load");
    let _link = skel.progs.xdp_lan_intro.attach_xdp(ifindex).expect("attach");

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    );
    for _ in 0..5 {
        send_raw_packet(&peer, &pkt);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(500));

    drop(skel);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

// ── Test C: lan_map redirect ──

#[test]
fn xdp_lan_intro_map_redirect() {
    let pid = crate::tests::test_id();
    let share_pin = test_pin_root("share");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let (host, peer) = (format!("lrbh{pid}"), format!("lrbp{pid}"));
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", host.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", peer.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let h_i = if_nametoindex(host.as_str()).unwrap() as u32;
    let p_i = if_nametoindex(peer.as_str()).unwrap() as u32;

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
    let _link = skel.progs.xdp_lan_intro.attach_xdp(h_i as i32).unwrap();

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    );
    for _ in 0..5 {
        send_raw_packet(&peer, &pkt);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(500));

    drop(skel);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

// ── Test D: bidirectional A↔C (lan_route + wan_route) ──

#[test]
#[ignore = "requires specific network namespace setup"]
fn xdp_lan_intro_wan_pipeline() {
    let pid = crate::tests::test_id();
    let (lan_h, lan_p) = (format!("lrhlh{pid}"), format!("lrhlp{pid}"));
    let (wan_h, wan_p) = (format!("lrhwh{pid}"), format!("lrhwp{pid}"));

    let _ = Command::new("ip").args(["link", "del", &lan_h]).output();
    let _ = Command::new("ip").args(["link", "del", &wan_h]).output();
    Command::new("ip")
        .args(["link", "add", &lan_h, "type", "veth", "peer", "name", &lan_p])
        .output()
        .unwrap();
    Command::new("ip")
        .args(["link", "add", &wan_h, "type", "veth", "peer", "name", &wan_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", lan_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", lan_p.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", wan_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", wan_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let lan_h_i = if_nametoindex(lan_h.as_str()).unwrap() as u32;
    let lan_p_i = if_nametoindex(lan_p.as_str()).unwrap() as u32;
    let wan_h_i = if_nametoindex(wan_h.as_str()).unwrap() as u32;
    let wan_p_i = if_nametoindex(wan_p.as_str()).unwrap() as u32;

    Command::new("ip").args(["route", "add", "blackhole", "203.0.113.1"]).output().ok();

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

    let _l0 = lr.progs.xdp_lan_intro.attach_xdp(lan_h_i as i32).unwrap();
    let _l1 = intro.progs.wan_intro_dispatch.attach_xdp(wan_h_i as i32).unwrap();
    let _l2 = da.progs.xdp_test_dummy.attach_xdp(lan_p_i as i32).unwrap();
    let _l3 = dc.progs.xdp_test_dummy.attach_xdp(wan_p_i as i32).unwrap();

    let root_fd = chain.progs.xdp_lan_chain_root.as_fd().as_raw_fd();
    let mss_lan_fd = mss.progs.xdp_mss_lan.as_fd().as_raw_fd();
    let exit_fd = chain.progs.xdp_lan_chain_exit.as_fd().as_raw_fd();

    let wan_root_fd = wan_root.progs.xdp_wan_chain_root.as_fd().as_raw_fd();
    let mss_wan_fd = mss.progs.xdp_mss_wan.as_fd().as_raw_fd();
    let wr_fd = wr.progs.xdp_wan_route_ingress.as_fd().as_raw_fd();

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

    // A→C: TCP SYN → LAN chain → MSS clamp
    let pkt_a2c = build_syn_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [203, 0, 113, 1],
        1460,
    );
    for _ in 0..2 {
        send_raw_packet(&lan_p, &pkt_a2c);
        thread::sleep(Duration::from_millis(50));
    }

    // C→A: TCP SYN → wan_intro → WAN chain → MSS clamp
    let pkt_c2a = build_syn_pkt(
        [0x02, 0, 0, 0, 0, 3],
        [0x02, 0, 0, 0, 0, 4],
        [203, 0, 113, 1],
        [10, 0, 0, 1],
        1460,
    );
    for _ in 0..2 {
        send_raw_packet(&wan_p, &pkt_c2a);
        thread::sleep(Duration::from_millis(50));
    }

    thread::sleep(Duration::from_millis(3000));
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
    assert!(keys.len() >= 1, "no LAN_CACHE entries found");

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
    let _ = Command::new("ip").args(["route", "del", "blackhole", "203.0.113.1"]).output();
    let _ = Command::new("ip").args(["link", "del", &lan_h]).output();
    let _ = Command::new("ip").args(["link", "del", &wan_h]).output();
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
    let mut pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 99],
    );

    let run = skel
        .progs
        .xdp_lan_intro
        .test_run(ProgramInput { data_in: Some(&mut pkt), ..Default::default() })
        .expect("test_run");

    // XDP_PASS=2: unknown IP should continue to WAN, NOT be redirected via LAN
    let ret = run.return_value as i32;
    assert_eq!(ret, 2, "unknown IP should return XDP_PASS(2), got {}", ret);

    // known IP 10.0.0.5: should redirect
    let mut pkt2 = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 5],
    );

    let run2 = skel
        .progs
        .xdp_lan_intro
        .test_run(ProgramInput { data_in: Some(&mut pkt2), ..Default::default() })
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

    let mut pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 5],
    );

    let run = skel
        .progs
        .xdp_lan_intro
        .test_run(ProgramInput { data_in: Some(&mut pkt), ..Default::default() })
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

#[test]
fn xdp_lan_intro_fib_fallback_v4() {
    let pid = crate::tests::test_id();
    let (host, peer) = (format!("lrf4h{pid}"), format!("lrf4p{pid}"));

    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", host.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", peer.as_str(), "up"]).output().unwrap();
    // route + static ARP so bpf_fib_lookup can resolve the MAC
    Command::new("ip")
        .args(["route", "add", "10.0.0.200/32", "dev", peer.as_str()])
        .output()
        .unwrap();
    Command::new("ip")
        .args(["neigh", "add", "10.0.0.200", "lladdr", "02:00:00:00:00:c8", "dev", peer.as_str()])
        .output()
        .unwrap();
    Command::new("ip")
        .args(["neigh", "add", "10.0.0.200", "lladdr", "02:00:00:00:00:c8", "dev", host.as_str()])
        .output()
        .unwrap();
    thread::sleep(Duration::from_millis(100));

    let h_i = if_nametoindex(host.as_str()).unwrap() as u32;
    let p_i = if_nametoindex(peer.as_str()).unwrap() as u32;

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

    // pre-fill rt4_lan_map with has_mac=1 (forces MAC lookup → FIB fallback)
    let mut lan_val = [0u8; 16];
    lan_val[0] = 1; // has_mac = true
    lan_val[8..12].copy_from_slice(&p_i.to_ne_bytes());
    skel.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();

    // do NOT pre-fill ip_mac_v4 for 10.0.0.200

    let _link = skel.progs.xdp_lan_intro.attach_xdp(h_i as i32).unwrap();

    let pkt = build_ipv4_tcp_pkt(
        [0x02, 0, 0, 0, 0, 1],
        [0x02, 0, 0, 0, 0, 2],
        [10, 0, 0, 1],
        [10, 0, 0, 200],
    );
    for _ in 0..20 {
        send_raw_packet(&peer, &pkt);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(500));

    let mac_after = skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap();
    assert!(mac_after.is_some(), "FIB should have populated ip_mac_v4 for known LAN IP 10.0.0.200");

    drop(skel);
    let _ = Command::new("ip").args(["neigh", "del", "10.0.0.200", "dev", peer.as_str()]).output();
    let _ =
        Command::new("ip").args(["route", "del", "10.0.0.200/32", "dev", peer.as_str()]).output();
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

// ── Test H: v6 FIB fallback with veth + map verification ──

#[test]
fn xdp_lan_intro_fib_fallback_v6() {
    let pid = crate::tests::test_id();
    let (host, peer) = (format!("lrf6h{pid}"), format!("lrf6p{pid}"));

    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", host.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", peer.as_str(), "up"]).output().unwrap();
    // bpf_fib_lookup for IPv6 requires forwarding=1 on the ingress device
    let fwd_path = format!("net.ipv6.conf.{}.forwarding", host);
    let fwd_was = Command::new("sysctl")
        .args(["-n", &fwd_path])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    Command::new("sysctl").args(["-w", &format!("{}=1", fwd_path)]).output().unwrap();
    // route + static neighbour so bpf_fib_lookup can resolve the MAC
    Command::new("ip")
        .args(["-6", "route", "add", "fd00::200/128", "dev", peer.as_str()])
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
            peer.as_str(),
        ])
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
            host.as_str(),
        ])
        .output()
        .unwrap();
    thread::sleep(Duration::from_millis(100));

    let h_i = if_nametoindex(host.as_str()).unwrap() as u32;
    let p_i = if_nametoindex(peer.as_str()).unwrap() as u32;

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
    let mut lan_val = [0u8; 28];
    lan_val[0] = 1; // has_mac = true
    lan_val[8..12].copy_from_slice(&p_i.to_ne_bytes());
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
    for _ in 0..20 {
        send_raw_packet(&peer, &pkt);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(500));

    let mac_after = skel.maps.ip_mac_v6.lookup(&mac_key, MapFlags::ANY).unwrap();
    assert!(mac_after.is_some(), "FIB should have populated ip_mac_v6 for known LAN IP fd00::200");

    drop(skel);
    // restore forwarding
    if !fwd_was.is_empty() {
        let _ = Command::new("sysctl").args(["-w", &format!("{}={}", fwd_path, fwd_was)]).output();
    }
    let _ =
        Command::new("ip").args(["-6", "neigh", "del", "fd00::200", "dev", peer.as_str()]).output();
    let _ =
        Command::new("ip").args(["-6", "neigh", "del", "fd00::200", "dev", host.as_str()]).output();
    let _ = Command::new("ip")
        .args(["-6", "route", "del", "fd00::200/128", "dev", peer.as_str()])
        .output();
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

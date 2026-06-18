use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};
use nix::net::if_::if_nametoindex;

use crate::map_setting::share_map::ShareMapSkelBuilder;
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;
use crate::tests::wan_intro_skel::XdpWanIntroSkelBuilder;
use crate::tests::xdp_firewall_skel::XdpFirewallSkelBuilder;
use crate::tests::xdp_lan_chain_skel::XdpLanChainSkelBuilder;
use crate::tests::xdp_lan_intro_skel::XdpLanIntroSkelBuilder;
use crate::tests::xdp_mss_skel::XdpMssSkelBuilder;
use crate::tests::xdp_wan_chain_skel::XdpWanChainSkelBuilder;
use crate::tests::xdp_wan_route_skel::XdpWanRouteSkelBuilder;

fn test_pin_root(prefix: &str) -> PathBuf {
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/xdp-fw-{}-{}-{}",
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

fn sync_barrier() {
    thread::sleep(Duration::from_millis(200));
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

fn build_tcp_pkt(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(12345, 80, 1000, 2000);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build packet");
    pkt
}

fn build_tcp6_pkt(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv6(src, dst, 64)
        .tcp(12345, 80, 1000, 2000);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build v6 packet");
    pkt
}

fn route_slot(daddr: u32) -> u32 {
    let mut hash = daddr;
    hash ^= hash >> 16;
    hash ^= hash >> 8;
    hash & 0xF
}

fn route_slot_v6(daddr: &[u8; 16]) -> u32 {
    let w0 = u32::from_be_bytes([daddr[0], daddr[1], daddr[2], daddr[3]]);
    let w1 = u32::from_be_bytes([daddr[4], daddr[5], daddr[6], daddr[7]]);
    let mut hash = w0 ^ w1;
    hash ^= hash >> 16;
    hash ^= hash >> 8;
    hash & 0xF
}

#[test]
#[ignore = "requires veth pairs and root, run in dedicated environment"]
fn xdp_firewall_pipeline() {
    let pid = crate::tests::test_id();
    let (lan_h, lan_p) = (format!("fwh{pid}"), format!("fwp{pid}"));
    let (wan_h, wan_p) = (format!("fwwwh{pid}"), format!("fwwwp{pid}"));

    // ── create veth pairs ──
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
    crate::tests::check_ifindex("lan_h", lan_h_i);
    let lan_p_i = if_nametoindex(lan_p.as_str()).unwrap() as u32;
    let wan_h_i = if_nametoindex(wan_h.as_str()).unwrap() as u32;
    crate::tests::check_ifindex("wan_h", wan_h_i);
    let wan_p_i = if_nametoindex(wan_p.as_str()).unwrap() as u32;

    // Prevent kernel FIB from matching 203.0.113.1 so xdp_lan_intro falls through to chain
    Command::new("ip").args(["route", "add", "blackhole", "203.0.113.1"]).output().ok();

    // ── load shared maps ──
    let share_pin = test_pin_root("pipe");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    // ── load skeletons ──
    let mut lr_b = XdpLanIntroSkelBuilder::default();
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

    let chain_b = XdpLanChainSkelBuilder::default();
    let mut chain_obj = std::mem::MaybeUninit::uninit();
    let chain = chain_b.open(&mut chain_obj).unwrap().load().unwrap();

    let wan_root_b = XdpWanChainSkelBuilder::default();
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
    let intro = intro_b.open(&mut intro_obj).unwrap().load().unwrap();

    // ── attach XDP programs ──
    let _l0 = lr.progs.xdp_lan_intro.attach_xdp(lan_h_i as i32).unwrap();
    let _l1 = intro.progs.wan_intro_dispatch.attach_xdp(wan_h_i as i32).unwrap();
    let _l2 = da.progs.xdp_test_dummy.attach_xdp(lan_p_i as i32).unwrap();
    let _l3 = dc.progs.xdp_test_dummy.attach_xdp(wan_p_i as i32).unwrap();

    let root_fd = chain.progs.xdp_lan_chain_root.as_fd().as_raw_fd();
    let mss_lan_fd = mss.progs.xdp_mss_lan.as_fd().as_raw_fd();
    let mss_wan_fd = mss.progs.xdp_mss_wan.as_fd().as_raw_fd();
    let fw_lan_fd = fw.progs.xdp_firewall_lan.as_fd().as_raw_fd();
    let fw_wan_fd = fw.progs.xdp_firewall_wan.as_fd().as_raw_fd();
    let exit_fd = chain.progs.xdp_lan_chain_exit.as_fd().as_raw_fd();
    let wan_root_fd = wan_root.progs.xdp_wan_chain_root.as_fd().as_raw_fd();
    let wr_fd = wr.progs.xdp_wan_route_ingress.as_fd().as_raw_fd();

    // ── LAN chain: root → mss_lan → firewall_lan → exit ──
    lr.maps
        .xdp_lan_pipe_root_progs
        .update(&wan_h_i.to_ne_bytes(), &root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    chain
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_lan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .next_stage
        .update(&0u32.to_ne_bytes(), &fw_lan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps.next_stage.update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY).unwrap();

    // LAN fallback exits: all point to exit
    chain
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

    // ── WAN chain: wan_root → mss_wan → firewall_wan → wan_route ──
    wan_root
        .maps
        .root_next_stage
        .update(&0u32.to_ne_bytes(), &mss_wan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    mss.maps
        .next_stage
        .update(&1u32.to_ne_bytes(), &fw_wan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps.next_stage.update(&1u32.to_ne_bytes(), &wr_fd.to_ne_bytes(), MapFlags::ANY).unwrap();

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

    // ── WAN intro dispatch: route 10.0.0.1 → wan_h (the same interface, for chain processing) ──
    {
        let daddr_be = u32::from_be_bytes([10, 0, 0, 1]);
        let mut dispatch_key = [0u8; 16];
        dispatch_key[12..16].copy_from_slice(&daddr_be.to_be_bytes());
        let dispatch_val = wan_h_i.to_ne_bytes();
        intro
            .maps
            .wan_intro_dispatch_map
            .update(&dispatch_key, &dispatch_val, MapFlags::ANY)
            .unwrap();
    }
    // v6 dispatch: route fd00::1 → wan_h
    {
        let v6_lan: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&1u32.to_le_bytes());
        dispatch_key[8..16].copy_from_slice(&v6_lan[0..8]);
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

    // ── routing table setup ──
    let lan_ip: u32 = u32::from_be_bytes([10, 0, 0, 1]);
    let wan_ip: u32 = u32::from_be_bytes([203, 0, 113, 1]);

    // A→C: slot target → wan_h
    {
        let s = route_slot(wan_ip);
        let mut k = [0u8; 8];
        let mut v = [0u8; 16];
        k[0..4].copy_from_slice(&0u32.to_ne_bytes());
        k[4..8].copy_from_slice(&s.to_ne_bytes());
        v[0..4].copy_from_slice(&wan_h_i.to_ne_bytes());
        share.maps.rt4_target_slot_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // C→A: LAN route → lan_p
    {
        let mut k = [0u8; 8];
        let mut v = [0u8; 16];
        k[0..4].copy_from_slice(&32u32.to_ne_bytes());
        k[4..8].copy_from_slice(&lan_ip.to_be_bytes());
        v[8..12].copy_from_slice(&lan_h_i.to_ne_bytes());
        share.maps.rt4_lan_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // route slot for 203.0.113.2
    {
        let wan_ip2: u32 = u32::from_be_bytes([203, 0, 113, 2]);
        let s2 = route_slot(wan_ip2);
        let mut k = [0u8; 8];
        let mut v = [0u8; 16];
        k[0..4].copy_from_slice(&0u32.to_ne_bytes());
        k[4..8].copy_from_slice(&s2.to_ne_bytes());
        v[0..4].copy_from_slice(&wan_h_i.to_ne_bytes());
        share.maps.rt4_target_slot_map.update(&k, &v, MapFlags::ANY).unwrap();
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
        share.maps.rt6_lan_map.update(&k, &v, MapFlags::ANY).unwrap();
    }

    // v6 WAN target slot: fd00::2 → wan_h
    {
        let v6_wan: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let slot = route_slot_v6(&v6_wan);
        let mut k = [0u8; 8];
        k[0..4].copy_from_slice(&0u32.to_ne_bytes());
        k[4..8].copy_from_slice(&slot.to_ne_bytes());
        let mut v = [0u8; 28];
        v[0..4].copy_from_slice(&wan_h_i.to_ne_bytes());
        share.maps.rt6_target_slot_map.update(&k, &v, MapFlags::ANY).unwrap();
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

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);

    let a2c = build_tcp_pkt([10, 0, 0, 1], [203, 0, 113, 1]);
    let c2a = build_tcp_pkt([203, 0, 113, 1], [10, 0, 0, 1]);

    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c);
        send_raw_packet(&wan_p, &c2a);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "no-block: expected v4 packet to reach dummy");

    // ════════════════════════════════════════
    // Scenario 2: block 203.0.113.1/32
    //   LAN→WAN: firewall_lan blocks dst (203.0.113.1)
    //   WAN→LAN: firewall_wan blocks src (203.0.113.1)
    // ════════════════════════════════════════
    add_block(&fw.maps.firewall_block_ip4_map, [203, 0, 113, 1], &block_action);

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c);
        send_raw_packet(&wan_p, &c2a);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
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

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "3a LAN: should PASS (checks dst, not src)");

    // 3b: WAN direction — C→A, WAN checks src(203.0.113.1 not blocked) → PASS

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&wan_p, &c2a);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "3b WAN: should PASS (checks src, not dst)");

    // ════════════════════════════════════════
    // Scenario 4: block 203.0.113.1 only → 203.0.113.2 should still pass
    // ════════════════════════════════════════
    del_block(&fw.maps.firewall_block_ip4_map, [10, 0, 0, 1]);
    add_block(&fw.maps.firewall_block_ip4_map, [203, 0, 113, 1], &block_action);

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    let a2c_unblocked = build_tcp_pkt([10, 0, 0, 1], [203, 0, 113, 2]);
    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c_unblocked);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v4_cnt = dummy_recv_count(&da.maps.dummy_recv_map, false)
        + dummy_recv_count(&dc.maps.dummy_recv_map, false);
    assert!(v4_cnt > 0, "4 unblocked: 203.0.113.2 should pass firewall");

    // ════════════════════════════════════════
    // Scenario 5: delete block → flow resumes
    // ════════════════════════════════════════
    del_block(&fw.maps.firewall_block_ip4_map, [203, 0, 113, 1]);

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..3 {
        send_raw_packet(&lan_p, &a2c);
        send_raw_packet(&wan_p, &c2a);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
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

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c_v6);
        send_raw_packet(&wan_p, &c2a_v6);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 no-block: expected v6 dump");

    // Scenario 7: v6 block fd00::2/128
    //   LAN→WAN: firewall_lan blocks dst (fd00::2)
    //   WAN→LAN: firewall_wan blocks src (fd00::2)
    add_block_v6(&fw.maps.firewall_block_ip6_map, v6_wan, &block_action);

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c_v6);
        send_raw_packet(&wan_p, &c2a_v6);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert_eq!(v6_cnt, 0, "v6 blocked: expected NO v6 dump");

    // Scenario 8: v6 direction validation — block fd00::1, LAN should ignore src
    del_block_v6(&fw.maps.firewall_block_ip6_map, v6_wan);
    add_block_v6(&fw.maps.firewall_block_ip6_map, v6_lan, &block_action);

    // 8a: LAN direction — A→C, LAN checks dst(fd00::2 not blocked) → PASS

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c_v6);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 8a LAN: should PASS (checks dst, not src)");

    // 8b: WAN direction — C→A, WAN checks src(fd00::2 not blocked) → PASS

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&wan_p, &c2a_v6);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 8b WAN: should PASS (checks src, not dst)");

    // Scenario 9: v6 delete block → flow resumes
    del_block_v6(&fw.maps.firewall_block_ip6_map, v6_lan);

    sync_barrier();
    dummy_reset(&da.maps.dummy_recv_map);
    dummy_reset(&dc.maps.dummy_recv_map);
    for _ in 0..2 {
        send_raw_packet(&lan_p, &a2c_v6);
        send_raw_packet(&wan_p, &c2a_v6);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));
    let v6_cnt = dummy_recv_count(&da.maps.dummy_recv_map, true)
        + dummy_recv_count(&dc.maps.dummy_recv_map, true);
    assert!(v6_cnt > 0, "v6 unblocked: expected v6 dump");

    // ── cleanup ──
    drop(fw);
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

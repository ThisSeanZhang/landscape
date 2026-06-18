use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;
use std::thread;
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};
use nix::net::if_::if_nametoindex;

use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;
use crate::tests::xdp_mss_skel::XdpMssSkelBuilder;

fn build_syn_pkt(mss: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;

    let mut pkt = Vec::new();
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 80, 1000, 0);

    let _pkt_size = builder.size(0);

    pkt.resize(14 + 20 + 24, 0);

    pkt[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    pkt[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[16] = ((20 + 24) >> 8) as u8;
    pkt[17] = ((20 + 24) & 0xff) as u8;
    pkt[18..20].copy_from_slice(&0x0000u16.to_be_bytes());
    pkt[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[22] = 64;
    pkt[23] = 6;
    pkt[24..26].copy_from_slice(&0u16.to_be_bytes());
    pkt[26..30].copy_from_slice(&[10, 0, 0, 1]);
    pkt[30..34].copy_from_slice(&[10, 0, 0, 2]);

    let ip_csum = internet_checksum(&pkt[14..34]);
    pkt[24..26].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[34..36].copy_from_slice(&12345u16.to_be_bytes());
    pkt[36..38].copy_from_slice(&80u16.to_be_bytes());
    pkt[38..42].copy_from_slice(&1000u32.to_be_bytes());
    pkt[42..46].copy_from_slice(&0u32.to_be_bytes());
    pkt[46] = 0x60;
    pkt[47] = 0x02;
    pkt[48..50].copy_from_slice(&0xffffu16.to_be_bytes());
    pkt[50..52].copy_from_slice(&0u16.to_be_bytes());
    pkt[52..54].copy_from_slice(&0u16.to_be_bytes());

    pkt[54] = 2;
    pkt[55] = 4;
    pkt[56..58].copy_from_slice(&mss.to_be_bytes());

    let tcp_csum = tcp4_checksum(&pkt[26..30], &pkt[30..34], &pkt[34..58]);
    pkt[50..52].copy_from_slice(&tcp_csum.to_be_bytes());

    pkt
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp4_checksum(src_ip: &[u8], dst_ip: &[u8], tcp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6;
    sum += tcp.len() as u32;

    for chunk in tcp.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn dummy_tcp_mss_count(map: &libbpf_rs::MapMut) -> u64 {
    let k = 0u32.to_ne_bytes();
    map.lookup(&k, MapFlags::ANY)
        .unwrap()
        .map_or(0, |v| u64::from_ne_bytes(v[8..16].try_into().unwrap()))
}

fn dummy_tcp_mss_value(map: &libbpf_rs::MapMut) -> u16 {
    let k = 0u32.to_ne_bytes();
    map.lookup(&k, MapFlags::ANY).unwrap().map_or(0, |v| u16::from_be_bytes([v[0], v[1]]))
}

fn dummy_reset_tcp_mss(map: &libbpf_rs::MapMut) {
    map.update(&0u32.to_ne_bytes(), &[0u8; 16], MapFlags::ANY).unwrap();
}

fn dummy_recv_count(map: &libbpf_rs::MapMut, is_v6: bool) -> u64 {
    let k = if is_v6 { 1u32 } else { 0u32 }.to_ne_bytes();
    map.lookup(&k, MapFlags::ANY)
        .unwrap()
        .map_or(0, |v| u64::from_ne_bytes(v[0..8].try_into().unwrap()))
}

fn dummy_reset_recv(map: &libbpf_rs::MapMut) {
    let v = [0u8; 8];
    map.update(&0u32.to_ne_bytes(), &v, MapFlags::ANY).unwrap();
    map.update(&1u32.to_ne_bytes(), &v, MapFlags::ANY).unwrap();
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

#[test]
fn xdp_mss_verifier() {
    let builder = XdpMssSkelBuilder::default();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let _skel = open.load().expect("verifier rejected");
}

#[test]
fn xdp_mss_syn() {
    let pid = crate::tests::test_id();
    let (host, peer) = (format!("xmh{pid}"), format!("xmp{pid}"));
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", host.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", peer.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let ifindex = if_nametoindex(host.as_str()).unwrap() as i32;

    let builder = XdpMssSkelBuilder::default();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let skel = open.load().expect("load");
    let _link = skel.progs.xdp_mss_lan.attach_xdp(ifindex).expect("attach");

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).expect("open").load().expect("load");

    let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
    skel.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    dummy_reset_recv(&dummy.maps.dummy_recv_map);
    dummy_reset_tcp_mss(&dummy.maps.dummy_tcp_mss_map);

    let pkt = build_syn_pkt(1460);
    send_raw_packet(&peer, &pkt);
    thread::sleep(Duration::from_millis(500));

    let cnt = dummy_recv_count(&dummy.maps.dummy_recv_map, false);
    assert!(cnt > 0, "MSS clamp: no packet reached dummy");
    let mss = dummy_tcp_mss_value(&dummy.maps.dummy_tcp_mss_map);
    assert!(mss > 0, "MSS clamp: no MSS recorded by dummy");
    assert!(mss < 1480, "MSS not clamped, got {}", mss);

    drop(dummy);
    drop(skel);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

#[test]
fn xdp_mss_bidirectional() {
    let pid = crate::tests::test_id();
    let (host, peer) = (format!("xmh{pid}"), format!("xmp{pid}"));
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", host.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", peer.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let host_ifindex = if_nametoindex(host.as_str()).unwrap() as i32;
    let peer_ifindex = if_nametoindex(peer.as_str()).unwrap() as i32;

    let builder1 = XdpMssSkelBuilder::default();
    let mut obj1 = std::mem::MaybeUninit::uninit();
    let skel_h = builder1.open(&mut obj1).expect("open").load().expect("load");
    let _link_h = skel_h.progs.xdp_mss_lan.attach_xdp(host_ifindex).expect("attach host");

    let builder2 = XdpMssSkelBuilder::default();
    let mut obj2 = std::mem::MaybeUninit::uninit();
    let skel_p = builder2.open(&mut obj2).expect("open").load().expect("load");
    let _link_p = skel_p.progs.xdp_mss_lan.attach_xdp(peer_ifindex).expect("attach peer");

    let d_b1 = TestXdpDummySkelBuilder::default();
    let mut d1_obj = std::mem::MaybeUninit::uninit();
    let dummy_h = d_b1.open(&mut d1_obj).expect("open").load().expect("load");
    skel_h
        .maps
        .xdp_pipe_exits_lan
        .update(
            &0u32.to_ne_bytes(),
            &dummy_h.progs.xdp_test_dummy.as_fd().as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )
        .unwrap();

    let d_b2 = TestXdpDummySkelBuilder::default();
    let mut d2_obj = std::mem::MaybeUninit::uninit();
    let dummy_p = d_b2.open(&mut d2_obj).expect("open").load().expect("load");
    skel_p
        .maps
        .xdp_pipe_exits_lan
        .update(
            &0u32.to_ne_bytes(),
            &dummy_p.progs.xdp_test_dummy.as_fd().as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )
        .unwrap();

    let pkt = build_syn_pkt(1460);

    dummy_reset_recv(&dummy_h.maps.dummy_recv_map);
    dummy_reset_tcp_mss(&dummy_h.maps.dummy_tcp_mss_map);
    send_raw_packet(&peer, &pkt);
    thread::sleep(Duration::from_millis(300));
    let cnt = dummy_recv_count(&dummy_h.maps.dummy_recv_map, false);
    let mss = dummy_tcp_mss_value(&dummy_h.maps.dummy_tcp_mss_map);
    assert!(cnt > 0, "host direction: no packet reached dummy");
    assert!(mss > 0 && mss < 1480, "host MSS not clamped, got {}", mss);

    dummy_reset_recv(&dummy_p.maps.dummy_recv_map);
    dummy_reset_tcp_mss(&dummy_p.maps.dummy_tcp_mss_map);
    send_raw_packet(&host, &pkt);
    thread::sleep(Duration::from_millis(300));
    let cnt = dummy_recv_count(&dummy_p.maps.dummy_recv_map, false);
    let mss = dummy_tcp_mss_value(&dummy_p.maps.dummy_tcp_mss_map);
    assert!(cnt > 0, "peer direction: no packet reached dummy");
    assert!(mss > 0 && mss < 1480, "peer MSS not clamped, got {}", mss);

    drop(dummy_p);
    drop(dummy_h);
    drop(skel_p);
    drop(skel_h);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

fn build_non_syn_tcp_pkt() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 80, 1000, 2000);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build");
    pkt
}

#[test]
fn xdp_mss_non_syn_passthrough() {
    let pid = crate::tests::test_id();
    let (host, peer) = (format!("xmh{pid}"), format!("xmp{pid}"));
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", host.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", peer.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let ifindex = if_nametoindex(host.as_str()).unwrap() as i32;

    let builder = XdpMssSkelBuilder::default();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = builder.open(&mut obj).expect("open").load().expect("load");
    let _link = skel.progs.xdp_mss_lan.attach_xdp(ifindex).expect("attach");

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).expect("open").load().expect("load");
    skel.maps
        .xdp_pipe_exits_lan
        .update(
            &0u32.to_ne_bytes(),
            &dummy.progs.xdp_test_dummy.as_fd().as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )
        .unwrap();

    dummy_reset_recv(&dummy.maps.dummy_recv_map);
    dummy_reset_tcp_mss(&dummy.maps.dummy_tcp_mss_map);

    let pkt = build_non_syn_tcp_pkt();
    for _ in 0..3 {
        send_raw_packet(&peer, &pkt);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(300));

    let cnt = dummy_recv_count(&dummy.maps.dummy_recv_map, false);
    assert!(cnt > 0, "non-SYN: packet should pass through to dummy");
    let mss_cnt = dummy_tcp_mss_count(&dummy.maps.dummy_tcp_mss_map);
    assert_eq!(mss_cnt, 0, "non-SYN should not have MSS recorded");

    drop(dummy);
    drop(skel);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

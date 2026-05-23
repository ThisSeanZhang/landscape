use std::process::Command;
use std::thread;
use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder as _};
use nix::net::if_::if_nametoindex;

use crate::tests::xdp_mss_clamp_skel::XdpMssClampSkelBuilder;

fn build_syn_pkt(mss: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;

    let mut pkt = Vec::new();
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 80, 1000, 0);

    let _pkt_size = builder.size(0);

    // Build packet manually with custom MSS option in SYN
    // etherparse TCP builder defaults to no options. Write with custom MSS.
    // (etherparse doesn't expose MSS option easily, write manually)
    // Ethernet: 6+6+2 = 14
    // IP: 20 bytes
    // TCP SYN with MSS option: 20 + 4 (MSS) = 24 bytes
    pkt.resize(14 + 20 + 24, 0);

    // Ethernet header
    pkt[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst mac
    pkt[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
    pkt[12] = 0x08;
    pkt[13] = 0x00; // ethertype IPv4

    // IP header
    pkt[14] = 0x45; // version=4, IHL=5
    pkt[15] = 0x00; // DSCP
    pkt[16] = ((20 + 24) >> 8) as u8; // total length high
    pkt[17] = ((20 + 24) & 0xff) as u8; // total length low
    pkt[18..20].copy_from_slice(&0x0000u16.to_be_bytes()); // ID = 0
    pkt[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // flags + frag
    pkt[22] = 64; // TTL
    pkt[23] = 6; // protocol = TCP
                 // checksum at 24..26, compute later
    pkt[24..26].copy_from_slice(&0u16.to_be_bytes());
    pkt[26..30].copy_from_slice(&[10, 0, 0, 1]); // src IP
    pkt[30..34].copy_from_slice(&[10, 0, 0, 2]); // dst IP

    // IP checksum
    let ip_csum = internet_checksum(&pkt[14..34]);
    pkt[24..26].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP header (offset 34)
    pkt[34..36].copy_from_slice(&12345u16.to_be_bytes()); // src port
    pkt[36..38].copy_from_slice(&80u16.to_be_bytes()); // dst port
    pkt[38..42].copy_from_slice(&1000u32.to_be_bytes()); // seq
    pkt[42..46].copy_from_slice(&0u32.to_be_bytes()); // ack
    pkt[46] = 0x60; // data offset = 6 (24 bytes), reserved
    pkt[47] = 0x02; // flags: SYN
    pkt[48..50].copy_from_slice(&0xffffu16.to_be_bytes()); // window
    pkt[50..52].copy_from_slice(&0u16.to_be_bytes()); // checksum (fill after)
    pkt[52..54].copy_from_slice(&0u16.to_be_bytes()); // urgent

    // MSS option: kind=2, len=4, value=MSS
    pkt[54] = 2; // kind = MSS
    pkt[55] = 4; // len = 4
    pkt[56..58].copy_from_slice(&mss.to_be_bytes());

    // TCP checksum
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
    // pseudo header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6; // protocol = TCP
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

fn clear_trace() {
    let _ = Command::new("sh")
        .args(["-c", "echo 0 > /sys/kernel/debug/tracing/tracing_on; echo 16384 > /sys/kernel/debug/tracing/buffer_size_kb; echo > /sys/kernel/debug/tracing/trace; echo 1 > /sys/kernel/debug/tracing/tracing_on"])
        .output();
}

fn read_trace() -> String {
    let out =
        Command::new("cat").arg("/sys/kernel/debug/tracing/trace").output().expect("read trace");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn send_raw_packet(iface: &str, pkt: &[u8]) {
    use std::os::fd::AsRawFd;
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
fn xdp_mss_clamp_verifier() {
    let builder = XdpMssClampSkelBuilder::default();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let _skel = open.load().expect("verifier rejected");
}

#[test]
fn xdp_mss_clamp_syn() {
    // create veth
    let pid = std::process::id();
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

    let builder = XdpMssClampSkelBuilder::default();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let skel = open.load().expect("load");
    let _link = skel.progs.xdp_mss_clamp_lan.attach_xdp(ifindex).expect("attach");

    clear_trace();

    // Send SYN with MSS=1460 (will be clamped to 1452: 1492 - 20 - 20 = 1452)
    let pkt = build_syn_pkt(1460);
    send_raw_packet(&peer, &pkt);
    thread::sleep(Duration::from_millis(500));

    let trace = read_trace();
    println!("=== mss trace ===\n{trace}");

    assert!(trace.contains("[xdp_mss] clamped MSS"), "MSS not clamped, got:\n{trace}");

    drop(skel);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

#[test]
fn xdp_mss_clamp_bidirectional() {
    let pid = std::process::id();
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

    let builder1 = XdpMssClampSkelBuilder::default();
    let mut obj1 = std::mem::MaybeUninit::uninit();
    let skel_h = builder1.open(&mut obj1).expect("open").load().expect("load");
    let _link_h = skel_h.progs.xdp_mss_clamp_lan.attach_xdp(host_ifindex).expect("attach host");

    let builder2 = XdpMssClampSkelBuilder::default();
    let mut obj2 = std::mem::MaybeUninit::uninit();
    let skel_p = builder2.open(&mut obj2).expect("open").load().expect("load");
    let _link_p = skel_p.progs.xdp_mss_clamp_lan.attach_xdp(peer_ifindex).expect("attach peer");

    clear_trace();

    let pkt = build_syn_pkt(1460);

    send_raw_packet(&peer, &pkt);
    thread::sleep(Duration::from_millis(300));
    let trace_h = read_trace();
    println!("=== host trace ===\n{trace_h}");
    assert!(trace_h.contains("[xdp_mss] clamped MSS"), "host MSS not clamped:\n{trace_h}");

    clear_trace();

    send_raw_packet(&host, &pkt);
    thread::sleep(Duration::from_millis(300));
    let trace_p = read_trace();
    println!("=== peer trace ===\n{trace_p}");
    assert!(trace_p.contains("[xdp_mss] clamped MSS"), "peer MSS not clamped:\n{trace_p}");

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
fn xdp_mss_clamp_non_syn_passthrough() {
    let pid = std::process::id();
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

    let builder = XdpMssClampSkelBuilder::default();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = builder.open(&mut obj).expect("open").load().expect("load");
    let _link = skel.progs.xdp_mss_clamp_lan.attach_xdp(ifindex).expect("attach");

    clear_trace();

    let pkt = build_non_syn_tcp_pkt();
    for _ in 0..3 {
        send_raw_packet(&peer, &pkt);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(300));

    let trace = read_trace();
    println!("=== passthrough trace ===\n{trace}");

    assert!(!trace.contains("[xdp_mss] clamped MSS"), "non-SYN should not be clamped:\n{trace}");

    drop(skel);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

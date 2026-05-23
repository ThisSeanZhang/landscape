use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};
use nix::net::if_::if_nametoindex;

use crate::tests::xdp_lan_route_skel::XdpLanRouteSkelBuilder;

fn test_pin_root(prefix: &str) -> PathBuf {
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/xdp-lr-{}-{}",
        prefix,
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&path);
    path
}

fn clear_trace() {
    let _ = Command::new("sh")
        .args(["-c", "echo 0 > /sys/kernel/debug/tracing/tracing_on; echo > /sys/kernel/debug/tracing/trace; echo 1 > /sys/kernel/debug/tracing/tracing_on"])
        .output();
}

fn read_trace() -> String {
    let out =
        Command::new("cat").arg("/sys/kernel/debug/tracing/trace").output().expect("read trace");
    String::from_utf8_lossy(&out.stdout).to_string()
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

// ── Test A: verifier smoke ──

#[test]
fn xdp_lan_route_verifier_smoke() {
    let mut builder = XdpLanRouteSkelBuilder::default();
    {
        let b = builder.object_builder_mut();
        b.pin_root_path(&test_pin_root("v")).unwrap();
    }

    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let _skel = open.load().expect("verifier rejected");
}

// ── Test A: trace flow ──

#[test]
fn xdp_lan_route_trace_flow() {
    // create veth
    let (host, peer) =
        (format!("lxdh{}", std::process::id()), format!("lxdp{}", std::process::id()));
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", &host, "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", &peer, "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let ifindex = if_nametoindex(host.as_str()).expect("ifindex") as i32;

    clear_trace();

    // load & attach
    let mut builder = XdpLanRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&test_pin_root("t")).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open");
    let skel = open.load().expect("load");
    let _link = skel.progs.xdp_lan_route.attach_xdp(ifindex).expect("attach");

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

    let trace = read_trace();
    println!("=== trace ===\n{trace}");

    // Test: XDP program loads, attaches, and processes packets without crash.
    // With empty maps → cache miss → lan_redirect → fib_lookup → REDIRECT
    // We just verify the test doesn't panic (program loads and runs).

    drop(skel);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    let _ = Command::new("ip").args(["link", "del", &peer]).output();
}

// ── Test B: populate lan_map → verify map-based redirect ──

use crate::map_setting::share_map::ShareMapSkelBuilder;

#[test]
fn xdp_lan_route_map_redirect() {
    // 1. Load share_map to create & pin all route maps
    let share_pin = test_pin_root("share");
    let mut share_builder = ShareMapSkelBuilder::default();
    share_builder.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share_open = share_builder.open(&mut share_obj).expect("open share_map");
    let share_skel = share_open.load().expect("load share_map");

    // 2. Create veth
    let (host, peer) =
        (format!("lrbh{}", std::process::id()), format!("lrbp{}", std::process::id()));
    let _ = Command::new("ip").args(["link", "del", &host]).output();
    Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", &host, "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", &peer, "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let h_ifindex = if_nametoindex(host.as_str()).expect("h ifindex") as u32;
    let p_ifindex = if_nametoindex(peer.as_str()).expect("p ifindex") as u32;

    // 3. Populate rt4_lan_map: key={prefixlen=32, addr=10.0.0.2}, value={ifindex=p_ifindex}
    let mut lan_key = [0u8; 8];
    lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes()); // prefixlen=32
    lan_key[4..8].copy_from_slice(&0x0A000002u32.to_be_bytes()); // addr=10.0.0.2 (BE)

    let mut lan_val = [0u8; 16];
    lan_val[0] = 0; // has_mac=false
                    // mac_addr[6] stays 0
    lan_val[7] = 0; // is_next_hop=false
    lan_val[8..12].copy_from_slice(&p_ifindex.to_ne_bytes()); // ifindex
    lan_val[12..16].copy_from_slice(&0u32.to_ne_bytes()); // addr=0

    share_skel
        .maps
        .rt4_lan_map
        .update(&lan_key, &lan_val, MapFlags::ANY)
        .expect("populate rt4_lan_map");

    // 4. Load xdp_lan_route with same pin root (reuse maps)
    let mut builder = XdpLanRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open lan_route");
    let skel = open.load().expect("load lan_route");
    let _link = skel.progs.xdp_lan_route.attach_xdp(h_ifindex as i32).expect("attach");

    clear_trace();

    // 5. Send packet dst=10.0.0.2 from peer → enters host XDP
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

    let trace = read_trace();
    println!("=== trace B ===\n{trace}");

    // With lan_map populated: should see "redirect lan_map" instead of "redirect fib"
    assert!(
        trace.contains("[xdp_lan] redirect lan_map"),
        "expected lan_map redirect, got:\n{trace}"
    );

    drop(skel);
    drop(share_skel);
    let _ = Command::new("ip").args(["link", "del", &host]).output();
}

use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;
use std::thread;
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};
use nix::net::if_::if_nametoindex;

use crate::tests::test_xdp_chain_stage::TestXdpChainStageSkelBuilder;
use crate::tests::test_xdp_root::TestXdpRootSkelBuilder;

fn veth_names() -> (String, String) {
    let pid = crate::tests::test_id();
    (format!("ldxh{pid}"), format!("ldxp{pid}"))
}

fn create_veth_pair() -> (String, String, i32) {
    let (host, peer) = veth_names();

    let _ = Command::new("ip").args(["link", "del", &host]).output();
    let out = Command::new("ip")
        .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
        .output()
        .expect("create veth");
    assert!(out.status.success(), "create veth failed");
    Command::new("ip").args(["link", "set", &host, "up"]).output().expect("up host");
    Command::new("ip").args(["link", "set", &peer, "up"]).output().expect("up peer");
    thread::sleep(Duration::from_millis(100));

    let ifindex = if_nametoindex(host.as_str()).expect("ifindex") as i32;
    (host, peer, ifindex)
}

fn update_prog_array(map: &libbpf_rs::MapMut<'_>, idx: u32, fd: i32) {
    map.update(&idx.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY).expect("update PROG_ARRAY");
}

fn build_eth_ipv4_tcp(
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
        Some(socket2::Protocol::from(0x0300)), // ETH_P_ALL
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

    let addr_ptr = &addr as *const _ as *const libc::sockaddr;
    let addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

    unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            addr_ptr,
            addr_len,
        );
    }
}

#[test]
#[ignore = "requires creating veth pair, not suitable for parallel unit tests"]
fn xdp_chain_3level() {
    let (veth_host, _veth_peer, ifindex) = create_veth_pair();

    // ── load root skel ──
    let root_builder = TestXdpRootSkelBuilder::default();
    let mut root_obj = std::mem::MaybeUninit::uninit();
    let root_open = root_builder.open(&mut root_obj).expect("open root skel");
    let root_skel = root_open.load().expect("load root skel");

    // ── load chain1 skel ──
    let c1_builder = TestXdpChainStageSkelBuilder::default();
    let mut c1_obj = std::mem::MaybeUninit::uninit();
    let c1_open = c1_builder.open(&mut c1_obj).expect("open chain1 skel");
    let chain1_skel = c1_open.load().expect("load chain1 skel");

    // ── load chain2 skel ──
    let c2_builder = TestXdpChainStageSkelBuilder::default();
    let mut c2_obj = std::mem::MaybeUninit::uninit();
    let c2_open = c2_builder.open(&mut c2_obj).expect("open chain2 skel");
    let chain2_skel = c2_open.load().expect("load chain2 skel");

    // ── chain: root → chain1 → chain2 ──
    let c1_fd = chain1_skel.progs.xdp_test_chain_stage.as_fd().as_raw_fd();
    let c2_fd = chain2_skel.progs.xdp_test_chain_stage.as_fd().as_raw_fd();
    update_prog_array(&root_skel.maps.root_next_stage, 0, c1_fd);
    update_prog_array(&chain1_skel.maps.next_stage, 0, c2_fd);

    // ── attach root to veth host ──
    let _link = root_skel.progs.xdp_test_root.attach_xdp(ifindex).expect("attach XDP");

    // ── send packets ──
    let pkt = build_eth_ipv4_tcp(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    );
    for _ in 0..5 {
        send_raw_packet(&veth_host, &pkt);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(500));

    // ── verify: chain2 fallback counter > 0 (chain traversal completed) ──
    let k = 0u32.to_ne_bytes();
    let val = chain2_skel
        .maps
        .stage_fallback_map
        .lookup(&k, MapFlags::ANY)
        .expect("lookup stage_fallback_map");
    let count = val.map_or(0u64, |v| u64::from_ne_bytes(v[0..8].try_into().unwrap()));

    assert!(count > 0, "chain2 fallback counter is 0, chain may not have reached the end");

    // ── cleanup ──
    drop(chain2_skel);
    drop(chain1_skel);
    drop(root_skel);
    let _ = Command::new("ip").args(["link", "del", &veth_host]).output();
}

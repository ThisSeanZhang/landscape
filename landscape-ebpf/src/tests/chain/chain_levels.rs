use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};

use crate::tests::net_utils::{send_raw_packet, wait_for, VethPair};
use crate::tests::test_xdp_chain_stage::TestXdpChainStageSkelBuilder;
use crate::tests::test_xdp_root::TestXdpRootSkelBuilder;

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

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_chain_3level() {
    let pair = VethPair::create("ldx");
    let veth_host = pair.host();
    let ifindex = pair.host_ifindex() as i32;

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
    send_raw_packet(veth_host, &pkt);
    wait_for("chain2 fallback counter incremented", Duration::from_secs(5), || {
        chain2_skel
            .maps
            .stage_fallback_map
            .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
            .unwrap()
            .is_some_and(|v| u64::from_ne_bytes(v[0..8].try_into().unwrap()) > 0)
    });

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
}

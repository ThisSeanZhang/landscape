//! `BPF_PROG_TEST_RUN` coverage for `xdp_wan_route_ingress` (`xdp_wan_route.bpf.c`),
//! focusing on `ROUTE_TYPE_NEXTHOP` FIB resolution/caching and cold neighbor miss
//! TC `bpf_redirect_neigh` handoff for both IPv4 and IPv6.
//!
//! Run (requires root + `test-route` or `bpf-test`):
//!   cargo test -p landscape-ebpf --features test-route --lib route::xdp_wan_route -- --nocapture

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel as _, SkelBuilder as _},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::skel::xdp_wan_route::{XdpWanRouteSkel, XdpWanRouteSkelBuilder};
use crate::tests::helper::map::{
    LAN_ROUTE_TYPE, ROUTE_TYPE_NEXTHOP, TARGET_IFINDEX, WAN_CACHE, as_bytes,
    create_route4_cache_inner_map, create_route6_cache_inner_map, insert_route4_lan_entry,
    insert_route6_lan_entry, lookup_ip_mac_v4, lookup_ip_mac_v6, lookup_rt4_cache_value,
    lookup_rt6_cache_value,
};
use crate::tests::helper::net::{NetNsGuard, VethPair};
use crate::tests::isolated_pin_root;

const XDP_PASS: u32 = 2;
const XDP_REDIRECT: u32 = 4;

const INGRESS_STATIC_MARK: u32 = 1;
const XDP_HANDOFF_TC_REDIRECT_NEIGH_MAGIC: u32 = 0x4C44544E;

const WAN_SRC_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
const WAN_DST_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02];
const LAN_DEV_MAC: [u8; 6] = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
const NEXTHOP_MAC: [u8; 6] = [0x02, 0x55, 0x66, 0x77, 0x88, 0x99];

#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
struct XdpPipeMeta {
    mark: u32,
    target_ifindex: u32,
    target_chain_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
struct XdpTcRedirectNeighHandoff {
    magic: u32,
    target_ifindex: u32,
    nh_addr: [u8; 16],
}

#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable)]
struct XdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

const _: () = assert!(std::mem::size_of::<XdpPipeMeta>() == 12);
const _: () = assert!(std::mem::size_of::<XdpTcRedirectNeighHandoff>() == 24);

fn build_v4_tcp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(WAN_SRC_MAC, WAN_DST_MAC)
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(443, 54321, 100, 4096);
    let mut pkt = Vec::with_capacity(builder.size(8));
    builder.write(&mut pkt, &[0x11; 8]).expect("build ipv4 tcp");
    pkt
}

fn build_v6_tcp(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(WAN_SRC_MAC, WAN_DST_MAC)
        .ipv6(src.octets(), dst.octets(), 64)
        .tcp(443, 54321, 100, 4096);
    let mut pkt = Vec::with_capacity(builder.size(8));
    builder.write(&mut pkt, &[0x22; 8]).expect("build ipv6 tcp");
    pkt
}

macro_rules! load_skel {
    ($pin:expr, $skel:ident) => {
        let pin_root = isolated_pin_root($pin);
        let mut builder = XdpWanRouteSkelBuilder::default();
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_obj = MaybeUninit::uninit();
        let $skel = builder.open(&mut open_obj).expect("open xdp_wan_route").load().expect("load");
    };
}

fn run_xdp(skel: &XdpWanRouteSkel<'_>, pkt: &[u8]) -> (u32, Vec<u8>) {
    let mut out_buf = vec![0u8; pkt.len() + 64];
    let res = skel
        .progs
        .xdp_wan_route_ingress
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out_buf),
            ..Default::default()
        })
        .expect("test_run xdp_wan_route_ingress");
    (res.return_value, res.data.expect("data_out").to_vec())
}

fn run_xdp_with_pipe_meta(
    skel: &XdpWanRouteSkel<'_>,
    meta: XdpPipeMeta,
    pkt: &[u8],
) -> (u32, Vec<u8>) {
    let mut data_in = Vec::with_capacity(std::mem::size_of::<XdpPipeMeta>() + pkt.len());
    data_in.extend_from_slice(meta.as_bytes());
    data_in.extend_from_slice(pkt);
    let mut ctx = XdpMd {
        data: std::mem::size_of::<XdpPipeMeta>() as u32,
        data_end: data_in.len() as u32,
        data_meta: 0,
        ingress_ifindex: 0,
        rx_queue_index: 0,
        egress_ifindex: 0,
    };
    let mut out_buf = vec![0u8; data_in.len() + 64];
    let res = skel
        .progs
        .xdp_wan_route_ingress
        .test_run(ProgramInput {
            data_in: Some(&data_in),
            data_out: Some(&mut out_buf),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .expect("test_run xdp_wan_route_ingress with pipe meta");
    (res.return_value, res.data.expect("data_out").to_vec())
}

fn seed_xdp_redirect_able(skel: &XdpWanRouteSkel<'_>, ifindex: u32) {
    let able: u32 = 1;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&ifindex), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able");
}

// ---------------------------------------------------------------------------
// 1. Cold neighbor miss -> TC bpf_redirect_neigh handoff (never bare XDP_REDIRECT)
// ---------------------------------------------------------------------------

#[test]
fn xdp_wan_v4_nexthop_cold_neigh_hands_off_to_tc_neigh() {
    let ns = NetNsGuard::create("xw4cd");
    let _enter = ns.enter();
    load_skel!("xdp-wan-v4-nh-cold", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);

    let remote = Ipv4Addr::new(203, 0, 113, 7);
    let dst = Ipv4Addr::new(10, 200, 0, 20);
    let nexthop = Ipv4Addr::new(192, 168, 50, 1);

    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        24,
        Ipv4Addr::new(10, 200, 0, 0),
        nexthop,
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        LAN_DEV_MAC,
    );
    // Even when target LAN NIC supports native XDP redirect, a cold neighbor
    // miss must NOT emit a bare XDP_REDIRECT carrying the ingress WAN MAC.
    seed_xdp_redirect_able(&skel, TARGET_IFINDEX);

    let pkt = build_v4_tcp(remote, dst);
    let pipe_meta = XdpPipeMeta {
        mark: INGRESS_STATIC_MARK,
        target_ifindex: 0,
        target_chain_id: 7,
    };
    let (ret, out) = run_xdp_with_pipe_meta(&skel, pipe_meta, &pkt);

    assert_eq!(ret, XDP_PASS, "cold neighbor miss must hand off to TC via XDP_PASS");
    assert_eq!(
        out.len(),
        std::mem::size_of::<XdpTcRedirectNeighHandoff>() + pkt.len(),
        "output must carry 24-byte TC neigh handoff metadata plus intact frame"
    );

    let ho = XdpTcRedirectNeighHandoff::read_from_bytes(&out[..24]).expect("parse handoff");
    assert_eq!(ho.magic, XDP_HANDOFF_TC_REDIRECT_NEIGH_MAGIC);
    assert_eq!(ho.target_ifindex, TARGET_IFINDEX);
    assert_eq!(&ho.nh_addr[0..4], &nexthop.octets(), "must pass nexthop IP, not daddr");
    assert_eq!(&ho.nh_addr[4..16], &[0u8; 12]);
    assert_eq!(&out[24..], &pkt[..], "frame must remain intact for TC bpf_redirect_neigh");

    let cache = lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, dst, remote)
        .expect("static ingress mark must still populate reverse WAN cache on TC handoff");
    assert_eq!(cache.link_chain_id, 7);
}

#[test]
fn xdp_wan_v6_nexthop_cold_neigh_hands_off_to_tc_neigh() {
    let ns = NetNsGuard::create("xw6cd");
    let _enter = ns.enter();
    load_skel!("xdp-wan-v6-nh-cold", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);

    let remote = Ipv6Addr::from_str("2001:db8:1::7").unwrap();
    let dst = Ipv6Addr::from_str("2001:db8:200::20").unwrap();
    let nexthop = Ipv6Addr::from_str("fe80::50").unwrap();

    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        64,
        Ipv6Addr::from_str("2001:db8:200::").unwrap(),
        nexthop,
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        LAN_DEV_MAC,
    );
    seed_xdp_redirect_able(&skel, TARGET_IFINDEX);

    let pkt = build_v6_tcp(remote, dst);
    let pipe_meta = XdpPipeMeta {
        mark: INGRESS_STATIC_MARK,
        target_ifindex: 0,
        target_chain_id: 9,
    };
    let (ret, out) = run_xdp_with_pipe_meta(&skel, pipe_meta, &pkt);

    assert_eq!(ret, XDP_PASS, "cold neighbor miss must hand off to TC via XDP_PASS");
    assert_eq!(
        out.len(),
        std::mem::size_of::<XdpTcRedirectNeighHandoff>() + pkt.len(),
        "output must carry 24-byte TC neigh handoff metadata plus intact frame"
    );

    let ho = XdpTcRedirectNeighHandoff::read_from_bytes(&out[..24]).expect("parse handoff");
    assert_eq!(ho.magic, XDP_HANDOFF_TC_REDIRECT_NEIGH_MAGIC);
    assert_eq!(ho.target_ifindex, TARGET_IFINDEX);
    assert_eq!(ho.nh_addr, nexthop.octets(), "must pass nexthop IPv6, not daddr");
    assert_eq!(&out[24..], &pkt[..], "frame must remain intact for TC bpf_redirect_neigh");

    let cache = lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, dst, remote)
        .expect("static ingress mark must still populate reverse WAN cache on TC handoff");
    assert_eq!(cache.link_chain_id, 9);
}

#[test]
fn xdp_wan_v4_and_v6_direct_lan_cold_neigh_hands_off_with_daddr() {
    let ns = NetNsGuard::create("xwlcd");
    let _enter = ns.enter();
    load_skel!("xdp-wan-lan-cold", skel);
    seed_xdp_redirect_able(&skel, TARGET_IFINDEX);

    let dst4 = Ipv4Addr::new(192, 168, 1, 20);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        dst4,
        Ipv4Addr::new(192, 168, 1, 1),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        LAN_DEV_MAC,
    );
    let pkt4 = build_v4_tcp(Ipv4Addr::new(203, 0, 113, 7), dst4);
    let (ret4, out4) = run_xdp(&skel, &pkt4);
    assert_eq!(ret4, XDP_PASS);
    let ho4 = XdpTcRedirectNeighHandoff::read_from_bytes(&out4[..24]).expect("parse v4 handoff");
    assert_eq!(ho4.magic, XDP_HANDOFF_TC_REDIRECT_NEIGH_MAGIC);
    assert_eq!(&ho4.nh_addr[0..4], &dst4.octets());

    let dst6 = Ipv6Addr::from_str("fd00::20").unwrap();
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        dst6,
        Ipv6Addr::from_str("fd00::1").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        LAN_DEV_MAC,
    );
    let pkt6 = build_v6_tcp(Ipv6Addr::from_str("2001:db8:1::7").unwrap(), dst6);
    let (ret6, out6) = run_xdp(&skel, &pkt6);
    assert_eq!(ret6, XDP_PASS);
    let ho6 = XdpTcRedirectNeighHandoff::read_from_bytes(&out6[..24]).expect("parse v6 handoff");
    assert_eq!(ho6.magic, XDP_HANDOFF_TC_REDIRECT_NEIGH_MAGIC);
    assert_eq!(ho6.nh_addr, dst6.octets());
}

// ---------------------------------------------------------------------------
// 2. FIB hit on ROUTE_TYPE_NEXTHOP: lookup & cache backfill use hop_key (not dst_ip)
// ---------------------------------------------------------------------------

#[test]
fn xdp_wan_v4_nexthop_fib_caches_under_hop_key_and_second_packet_hits_cache() {
    let ns = NetNsGuard::create("xw4nh");
    let _enter = ns.enter();
    let out_pair = VethPair::create("xw4o");
    let out_ifindex = out_pair.host_ifindex();

    let remote = Ipv4Addr::new(203, 0, 113, 7);
    let dst1 = Ipv4Addr::new(10, 200, 0, 20);
    let dst2 = Ipv4Addr::new(10, 200, 0, 21);
    let nexthop = Ipv4Addr::new(192, 168, 50, 1);

    // Seed kernel route + static ARP ONLY for nexthop (NOT for 10.200.0.0/24).
    // Passing context->daddr into bpf_fib_lookup would fail here.
    assert!(
        Command::new("ip")
            .args(["route", "add", "192.168.50.1/32", "dev", out_pair.host()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ip")
            .args([
                "neigh",
                "add",
                "192.168.50.1",
                "lladdr",
                "02:55:66:77:88:99",
                "dev",
                out_pair.host()
            ])
            .status()
            .unwrap()
            .success()
    );

    load_skel!("xdp-wan-v4-nh-fib", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        24,
        Ipv4Addr::new(10, 200, 0, 0),
        nexthop,
        ROUTE_TYPE_NEXTHOP,
        out_ifindex,
        true,
        LAN_DEV_MAC,
    );
    seed_xdp_redirect_able(&skel, out_ifindex);

    // First packet: ip_mac_v4 miss -> bpf_fib_lookup(hop_key = nexthop) -> XDP_REDIRECT
    let pkt1 = build_v4_tcp(remote, dst1);
    let (ret1, out1) = run_xdp(&skel, &pkt1);
    assert_eq!(ret1, XDP_REDIRECT, "FIB hit on nexthop must XDP_REDIRECT");
    assert_eq!(&out1[0..6], &NEXTHOP_MAC, "dst MAC must be rewritten to nexthop MAC");
    assert_eq!(&out1[6..12], &LAN_DEV_MAC, "src MAC must be rewritten to LAN dev MAC");

    // Verify cache was populated under hop_key (nexthop), NOT dst1
    let cached = lookup_ip_mac_v4(&skel.maps.ip_mac_v4, nexthop)
        .expect("FIB hit must populate ip_mac_v4 under hop_key");
    assert_eq!(cached, (NEXTHOP_MAC, LAN_DEV_MAC, out_ifindex));
    assert!(
        lookup_ip_mac_v4(&skel.maps.ip_mac_v4, dst1).is_none(),
        "ROUTE_TYPE_NEXTHOP must NOT write ip_mac_v4 under dst IP"
    );

    // Remove kernel route & neigh so bpf_fib_lookup cannot succeed on packet 2.
    let _ =
        Command::new("ip").args(["neigh", "del", "192.168.50.1", "dev", out_pair.host()]).status();
    let _ = Command::new("ip")
        .args(["route", "del", "192.168.50.1/32", "dev", out_pair.host()])
        .status();

    // Second packet to another host in the same nexthop subnet must hit ip_mac_v4[hop_key].
    let pkt2 = build_v4_tcp(remote, dst2);
    let (ret2, out2) = run_xdp(&skel, &pkt2);
    assert_eq!(ret2, XDP_REDIRECT, "second packet must hit cached hop_key directly in XDP");
    assert_eq!(&out2[0..6], &NEXTHOP_MAC, "second packet dst MAC must match nexthop MAC");
    assert_eq!(&out2[6..12], &LAN_DEV_MAC, "second packet src MAC must match LAN dev MAC");
}

#[test]
fn xdp_wan_v6_nexthop_fib_caches_under_hop_key_and_second_packet_hits_cache() {
    let ns = NetNsGuard::create("xw6nh");
    let _enter = ns.enter();
    let out_pair = VethPair::create("xw6o");
    let out_ifindex = out_pair.host_ifindex();

    let remote = Ipv6Addr::from_str("2001:db8:1::7").unwrap();
    let dst1 = Ipv6Addr::from_str("2001:db8:200::20").unwrap();
    let dst2 = Ipv6Addr::from_str("2001:db8:200::21").unwrap();
    let nexthop = Ipv6Addr::from_str("fe80::50").unwrap();

    // Seed kernel route + static NDP ONLY for link-local nexthop (DHCPv6-PD pattern).
    // Passing context->daddr into bpf_fib_lookup would fail, and writing under mac_key
    // would miss on packet 2.
    assert!(
        Command::new("ip")
            .args(["-6", "route", "add", "fe80::50/128", "dev", out_pair.host()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ip")
            .args([
                "-6",
                "neigh",
                "add",
                "fe80::50",
                "lladdr",
                "02:55:66:77:88:99",
                "dev",
                out_pair.host()
            ])
            .status()
            .unwrap()
            .success()
    );

    load_skel!("xdp-wan-v6-nh-fib", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        64,
        Ipv6Addr::from_str("2001:db8:200::").unwrap(),
        nexthop,
        ROUTE_TYPE_NEXTHOP,
        out_ifindex,
        true,
        LAN_DEV_MAC,
    );
    seed_xdp_redirect_able(&skel, out_ifindex);

    // First packet: ip_mac_v6 miss -> bpf_fib_lookup(hop_key = fe80::50) -> XDP_REDIRECT
    let pkt1 = build_v6_tcp(remote, dst1);
    let (ret1, out1) = run_xdp(&skel, &pkt1);
    assert_eq!(ret1, XDP_REDIRECT, "FIB hit on IPv6 nexthop must XDP_REDIRECT");
    assert_eq!(&out1[0..6], &NEXTHOP_MAC, "dst MAC must be rewritten to nexthop MAC");
    assert_eq!(&out1[6..12], &LAN_DEV_MAC, "src MAC must be rewritten to LAN dev MAC");

    // Verify cache was populated under hop_key (fe80::50), NOT dst1
    let cached = lookup_ip_mac_v6(&skel.maps.ip_mac_v6, nexthop)
        .expect("FIB hit must populate ip_mac_v6 under hop_key");
    assert_eq!(cached, (NEXTHOP_MAC, LAN_DEV_MAC, out_ifindex));
    assert!(
        lookup_ip_mac_v6(&skel.maps.ip_mac_v6, dst1).is_none(),
        "ROUTE_TYPE_NEXTHOP must NOT write ip_mac_v6 under dst IP"
    );

    // Remove kernel route & NDP so bpf_fib_lookup cannot succeed on packet 2.
    let _ = Command::new("ip")
        .args(["-6", "neigh", "del", "fe80::50", "dev", out_pair.host()])
        .status();
    let _ = Command::new("ip")
        .args(["-6", "route", "del", "fe80::50/128", "dev", out_pair.host()])
        .status();

    // Second packet to another host in the same delegated /64 must hit ip_mac_v6[hop_key].
    let pkt2 = build_v6_tcp(remote, dst2);
    let (ret2, out2) = run_xdp(&skel, &pkt2);
    assert_eq!(ret2, XDP_REDIRECT, "second packet must hit cached hop_key directly in XDP");
    assert_eq!(&out2[0..6], &NEXTHOP_MAC, "second packet dst MAC must match nexthop MAC");
    assert_eq!(&out2[6..12], &LAN_DEV_MAC, "second packet src MAC must match LAN dev MAC");
}

//! Behavioral coverage for the WAN egress classifier's v6 control-plane
//! handoff (`ll_v6_session_chain_enter` in tc_wan_egress_route.bpf.c).
//!
//! An L3 (native PPPoE) WAN has no raw multicast: the session's v6
//! control plane (DHCPv6-PD renewals to ff02::1:2, MLD, ...) must ride
//! the PPP session.  The broadcast-mac pass-through therefore first
//! consults `wan_v6_ll_chain[src]` — keyed by the packet source, the
//! link-local composed from the session's IPv6CP interface-id — and
//! tail-calls into `tc_wan_egress_roots[chain]`.
//!
//! Witness: instead of a marker verdict, the REAL chain terminal is
//! registered — the `tc_pppoe` v6 stage — so a handed-off packet is
//! proven by its bytes growing the 8-byte PPPoE+PPP header and the
//! ethertype flipping to 0x8864 (mirrors tests/tc_chain/pppoe.rs).

use std::{
    mem::MaybeUninit,
    net::Ipv6Addr,
    os::fd::{AsFd, AsRawFd},
};

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::tests::TestSkb;

mod tc_wan_egress_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_route.skel.rs"));
}

mod tc_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_pppoe.skel.rs"));
}

use tc_pppoe_skel::types::pppoe_egress_tmpl;

/// Synthetic example session identity: the link-local composed from the
/// IPv6CP interface-id `aa:bb:cc:ff:fe:dd:ee:ff` of the synthetic
/// session MAC `AA:BB:CC:DD:EE:FF` below (EUI-64 layout WITHOUT the
/// U/L flip, see Ipv6cpState::new).
const SESSION_LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0xaabb, 0xccff, 0xfedd, 0xeeff, 0, 0, 0);
const CHAIN: u32 = 1;

fn default_tmpl(session_id: u16) -> pppoe_egress_tmpl {
    pppoe_egress_tmpl {
        dmac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        smac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        eth_proto: 0x8864u16.to_be(),
        ver_type: 0x11,
        code: 0x00,
        session_id: session_id.to_be(),
        ..Default::default()
    }
}

/// eth(33:33:00:01:00:02 -> us) + IPv6(src=ll, dst=ff02::1:2) + UDP,
/// shaped like a router's DHCPv6-PD traffic.  NOTE: `ethernet2` takes
/// (source, destination).
fn build_dhcpv6_multicast(src: Ipv6Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x33, 0x33, 0x00, 0x01, 0x00, 0x02],
    )
    .ipv6(src.octets(), Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x0001, 0x0002).octets(), 1)
    .udp(546, 547);
    let payload = [0x01, 0x12, 0x34, 0x56];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).unwrap();
    packet
}

/// eth(ff:ff:ff:ff:ff:ff -> us) + IPv4 bcast: the classic pass-through.
fn build_ipv4_broadcast() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    )
    .ipv4([192, 168, 1, 1], [255, 255, 255, 255], 1)
    .udp(68, 67);
    let payload = [0x01, 0x02, 0x03];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).unwrap();
    packet
}

struct Fixture {
    entry: tc_wan_egress_route_skel::TcWanEgressRouteSkel<'static>,
    _stage: tc_pppoe_skel::TcPppoeSkel<'static>,
}

fn load(pin: &str) -> Fixture {
    let pin_root = crate::tests::isolated_pin_root(pin);

    // The open objects must outlive the loaded skeletons; leak them for
    // the test's lifetime.
    let entry_object = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut entry_builder = tc_wan_egress_route_skel::TcWanEgressRouteSkelBuilder::default();
    entry_builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut entry_open = entry_builder.open(entry_object).unwrap();
    // locally generated packets on an ethernet WAN: L3 starts after 14B
    entry_open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = 14;
    let entry = entry_open.load().unwrap();

    let stage_object = Box::leak(Box::new(MaybeUninit::uninit()));
    let stage_builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let mut stage_open = stage_builder.open(stage_object).unwrap();
    stage_open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = default_tmpl(0xbeef);
    let stage = stage_open.load().unwrap();

    // Wire the chain terminal as the egress root of `CHAIN`, like the
    // chain's tc relink would.
    let stage_v6_fd = stage.progs.tc_pppoe_wan_egress_v6.as_fd().as_raw_fd();
    entry
        .maps
        .tc_wan_egress_roots
        .update(&CHAIN.to_ne_bytes(), &stage_v6_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    Fixture { entry, _stage: stage }
}

fn seed_session_ll(f: &Fixture, addr: Ipv6Addr, chain: u32) {
    f.entry
        .maps
        .wan_v6_ll_chain
        .update(&addr.octets(), &chain.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
}

/// Runs the entry classifier; returns (ret, data_out).
fn run_entry(f: &Fixture, pkt: &[u8]) -> (i32, Vec<u8>) {
    // Room for the +8 encap when the packet is handed off.
    let mut out = vec![0u8; pkt.len() + 8];
    let mut ctx = TestSkb {
        ifindex: 2,
        ingress_ifindex: 0,
        ..Default::default()
    };
    let ret = f
        .entry
        .progs
        .tc_wan_egress_route
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_wan_egress_route")
        .return_value as i32;
    (ret, out)
}

/// Registered src → the packet enters the chain and leaves with the
/// PPPoE session frame (bytes, not verdict: the stage's exit falls
/// back to TC_ACT_UNSPEC either way).
#[test]
fn ll_v6_session_traffic_enters_chain_and_is_encapped() {
    let f = load("ll-v6-hit");
    seed_session_ll(&f, SESSION_LL, CHAIN);

    let pkt = build_dhcpv6_multicast(SESSION_LL);
    let (ret, out) = run_entry(&f, &pkt);

    assert_eq!(ret, -1, "stage exit fallback is TC_ACT_UNSPEC; the bytes are the witness");
    assert_eq!(out[12], 0x88, "ethertype hi");
    assert_eq!(out[13], 0x64, "ethertype lo (PPPoE session)");
    assert_eq!(out[14], 0x11, "version/type");
    assert_eq!(out[16], 0xbe, "session id hi");
    assert_eq!(out[17], 0xef, "session id lo");
    assert_eq!(out[20], 0x00, "PPP proto hi");
    assert_eq!(out[21], 0x57, "PPP proto lo (IPv6)");
    assert_eq!(&out[22..pkt.len() + 8], &pkt[14..], "L3 payload preserved");
}

/// Unregistered src → the historic pass-through: verdict UNSPEC and
/// the packet leaves untouched.
#[test]
fn ll_v6_unknown_source_passes_raw() {
    let f = load("ll-v6-miss");

    let pkt =
        build_dhcpv6_multicast(Ipv6Addr::new(0xfe80, 0x1111, 0x1111, 0x1111, 0x1111, 0, 0, 0));
    let (ret, out) = run_entry(&f, &pkt);

    assert_eq!(ret, -1);
    assert!(out[..pkt.len()].iter().zip(pkt.iter()).all(|(a, b)| a == b), "untouched");
}

/// v4 broadcast keeps the classic behavior: pass, no chain.
#[test]
fn broadcast_v4_passes_raw() {
    let f = load("ll-v6-v4-ctrl");
    seed_session_ll(&f, SESSION_LL, CHAIN);

    let pkt = build_ipv4_broadcast();
    let (ret, out) = run_entry(&f, &pkt);

    assert_eq!(ret, -1);
    assert!(out[..pkt.len()].iter().zip(pkt.iter()).all(|(a, b)| a == b), "untouched");
}

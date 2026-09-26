//! Baseline for the TC WAN ingress intro `tc_wan_intro`
//! (tc_wan_ingress_intro.bpf.c).
//!
//!   * never parses PPPoE — session selectors in the TC dispatch map are
//!     dead by design: eth:PPPoE frames pass to the stack (kernel decaps
//!     them on the virtual ppp device, where a second instance of this
//!     intro with current_l3_offset = 0 re-dispatches by inner IP);
//!   * dispatches eth:IPv4 / eth:IPv6 (and, at offset 0, raw IP) through
//!     the shared ifindex-scoped dispatch map: hit → chain id in
//!     skb->cb[2] + tail call into tc_pipe_root_progs; miss → v4 unicast
//!     is WAN junk → TC_ACT_SHOT, while bcast/mcast daddrs (exempted
//!     before the lookup: DHCP replies, IGMP) and IPv6 (no v6 selector
//!     binding yet) keep flowing to the stack;
//!   * the PPP-chain metadata fast path reads skb->data_meta, which
//!     PROG_TEST_RUN controls — it stays inert here (data_meta == data),
//!     so the IP selector dispatch below remains the observable path.
//!     (Covered end-to-end by the SKB-mode integration test.)
//!
//! PROG_TEST_RUN honors `ingress_ifindex` freely (no device lookup) and
//! writes `cb[]` back through ctx_out, so the selected chain id is read
//! straight from the returned context.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libbpf_rs::skel::{OpenSkel, SkelBuilder as _};
use libbpf_rs::{MapCore, MapFlags, ProgramInput};
use zerocopy::{FromBytes, IntoBytes};

use crate::landscape::OwnedOpenObject;
use crate::tests::tc_wan_intro_skel::TcWanIngressIntroSkel;
use crate::tests::TestSkb;

use super::{
    build_arp_frame, build_ipv4_eth, build_ipv6_eth, build_pppoe_frame, build_raw_ipv4,
    build_raw_ipv6, seed_ip_selector, seed_ppp_session, TC_ACT_OK, TC_ACT_SHOT,
};

const V4_DST: [u8; 4] = [198, 51, 100, 7];
const V4_SRC: [u8; 4] = [203, 0, 113, 9];
const WAN_IFINDEX: u32 = 42;
const CHAIN: u32 = 7;

fn v6_dst() -> [u8; 16] {
    let a: Ipv6Addr = "fd00:aaaa:bbbb:cccc::7".parse().unwrap();
    a.octets()
}

/// Load the TC intro skeleton with the given L3 offset rodata, together
/// with its open-object backing.
fn load_skel(pin: &str, l3_offset: u32) -> super::SkelGuard<TcWanIngressIntroSkel<'static>> {
    let pin_root = crate::tests::isolated_pin_root(pin);
    let mut builder = crate::tests::tc_wan_intro_skel::TcWanIngressIntroSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open = builder.open(obj).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    super::SkelGuard { skel: open.load().unwrap(), _backing: backing }
}

/// Run the intro; returns (verdict, chain id in skb->cb[2], data_out).
fn tc_run(skel: &TcWanIngressIntroSkel, pkt: &[u8], ingress_ifindex: u32) -> (i32, u32, Vec<u8>) {
    let mut ctx = TestSkb {
        ifindex: 1, // loopback: PROG_TEST_RUN requires ifindex <= 1
        ingress_ifindex,
        cb: [0; 5],
        ..Default::default()
    };
    let mut out = vec![0u8; pkt.len() + 32];
    let mut ctx_out = vec![0u8; std::mem::size_of::<TestSkb>()];
    // `Output` borrows both buffers — extract the owned pieces inside a
    // scope, then parse the written-back context afterwards.
    let (ret, data) = {
        let result = skel
            .progs
            .tc_wan_intro
            .test_run(ProgramInput {
                data_in: Some(pkt),
                data_out: Some(&mut out),
                context_in: Some(ctx.as_mut_bytes()),
                context_out: Some(&mut ctx_out),
                ..Default::default()
            })
            .expect("tc_wan_intro test_run");
        (result.return_value as i32, result.data.as_deref().map(|d| d.to_vec()).unwrap_or_default())
    };
    let chain_id = TestSkb::read_from_bytes(&ctx_out).unwrap().cb[2];
    (ret, chain_id, data)
}

// ── IPv4 / IPv6 dispatch (current_l3_offset = 14) ──────────────────────

#[test]
fn ipv4_selector_hit_sets_chain_id() {
    let skel = load_skel("tc-wan-in-v4-hit", 14);
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        WAN_IFINDEX,
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        CHAIN,
    );

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK, "empty prog array → tail call falls through → OK");
    assert_eq!(chain, CHAIN, "hit must record the chain id in cb[2]");
    assert_eq!(out, pkt);
}

#[test]
fn ipv4_selector_miss_drops() {
    // v4 unicast with no selector is WAN junk (e.g. a decapped session
    // frame whose handoff metadata did not survive).
    let skel = load_skel("tc-wan-in-v4-miss", 14);

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, _chain, _out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_SHOT, "v4 unicast miss must be dropped");
}

#[test]
fn ipv4_broadcast_miss_passes_to_stack() {
    // DHCP replies / IGMP must reach the local stack even though no
    // selector can ever match their daddr.
    let skel = load_skel("tc-wan-in-bcast-miss", 14);

    let pkt = build_ipv4_eth(V4_SRC, [255, 255, 255, 255]);
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK);
    assert_eq!(chain, 0);
    assert_eq!(out, pkt);
}

#[test]
fn ipv6_selector_miss_passes_to_stack() {
    // v6 selectors are not bound yet — v6 misses keep flowing.
    let skel = load_skel("tc-wan-in-v6-miss", 14);

    let pkt =
        build_ipv6_eth(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], &v6_dst());
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK);
    assert_eq!(chain, 0);
    assert_eq!(out, pkt);
}

#[test]
fn selector_scoped_by_ingress_ifindex() {
    let skel = load_skel("tc-wan-in-scope", 14);
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        WAN_IFINDEX - 1,
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        CHAIN,
    );

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, _chain, _out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_SHOT, "entry registered for another iface must not match");
}

#[test]
fn ipv6_prefix_hit_sets_chain_id() {
    let skel = load_skel("tc-wan-in-v6-hit", 14);
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        WAN_IFINDEX,
        IpAddr::V6(Ipv6Addr::from(v6_dst())),
        CHAIN,
    );

    let pkt =
        build_ipv6_eth(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], &v6_dst());
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK);
    assert_eq!(chain, CHAIN);
    assert_eq!(out, pkt);
}

#[test]
fn non_ip_frame_passes_without_dispatch() {
    let skel = load_skel("tc-wan-in-arp", 14);

    let pkt = build_arp_frame();
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK, "non-IP frames pass to the stack");
    assert_eq!(chain, 0);
    assert_eq!(out, pkt);
}

#[test]
fn truncated_ip_header_passes_without_dispatch() {
    let skel = load_skel("tc-wan-in-runt", 14);
    let pkt = {
        let mut f = build_ipv4_eth(V4_SRC, V4_DST);
        f.truncate(16); // eth + 2 bytes of "IP"
        f
    };

    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK, "truncated IP header must pass, not drop");
    assert_eq!(chain, 0);
    assert_eq!(out, pkt);
}

#[test]
fn pppoe_frame_passes_even_with_session_selector() {
    // The TC intro never parses PPPoE: a session frame goes to the kernel
    // PPPoE layer untouched — even though a session selector sits in the
    // TC dispatch map (dead by design; the XDP stripper or the virtual ppp
    // device instance handle session frames).
    let skel = load_skel("tc-wan-in-pppoe", 14);
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, WAN_IFINDEX, 0x2001, CHAIN);

    let pkt = build_pppoe_frame(0x2001, super::PPP_PROTO_IPV4, &build_raw_ipv4(V4_SRC, V4_DST));
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK);
    assert_eq!(chain, 0, "session selectors must be inert on the TC side");
    assert_eq!(out, pkt);
}

// ── raw IP frames (current_l3_offset = 0, the pppN path) ───────────────

#[test]
fn raw_ipv4_dispatches_by_daddr() {
    // What a virtual ppp device hands to its TC intro: a bare IPv4 packet.
    let skel = load_skel("tc-wan-in-raw-v4", 0);
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        WAN_IFINDEX,
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        CHAIN,
    );

    let pkt = build_raw_ipv4(V4_SRC, V4_DST);
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK);
    assert_eq!(chain, CHAIN, "pppN re-dispatch must resolve the IP selector");
    assert_eq!(out, pkt);
}

#[test]
fn raw_ipv4_miss_drops() {
    // pppN path: junk v4 unicast decapped by the kernel is dropped rather
    // than leaking into the stack.
    let skel = load_skel("tc-wan-in-raw-v4-miss", 0);

    let pkt = build_raw_ipv4(V4_SRC, V4_DST);
    let (ret, _chain, _out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_SHOT, "raw v4 unicast miss must be dropped");
}

#[test]
fn raw_ipv6_dispatches_by_prefix() {
    let skel = load_skel("tc-wan-in-raw-v6", 0);
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        WAN_IFINDEX,
        IpAddr::V6(Ipv6Addr::from(v6_dst())),
        CHAIN,
    );

    let pkt =
        build_raw_ipv6(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], &v6_dst());
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK);
    assert_eq!(chain, CHAIN);
    assert_eq!(out, pkt);
}

#[test]
fn raw_non_ip_version_passes_to_stack() {
    let skel = load_skel("tc-wan-in-raw-nonip", 0);

    let pkt = {
        let mut p = build_raw_ipv4(V4_SRC, V4_DST);
        p[0] = 0x00; // version nibble 0
        p
    };
    let (ret, chain, out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK);
    assert_eq!(chain, 0);
    assert_eq!(out, pkt);
}

// ── chain entry via tail call ──────────────────────────────────────────

#[test]
fn dispatch_tail_calls_the_chain_root() {
    // Install the TC chain-stage test program at CHAIN: the intro must set
    // cb[2] and jump into it (counted in sniff_chain_map).
    let skel = load_skel("tc-wan-in-chainroot", 14);
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        WAN_IFINDEX,
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        CHAIN,
    );

    let stage_pin = crate::tests::isolated_pin_root("tc-wan-in-chainroot-stage");
    let mut stage_b = crate::tests::test_tc_sniff_skel::TestTcSniffSkelBuilder::default();
    stage_b.object_builder_mut().pin_root_path(&stage_pin).unwrap();
    let mut stage_obj = std::mem::MaybeUninit::uninit();
    let stage = stage_b.open(&mut stage_obj).unwrap().load().unwrap();

    use std::os::fd::{AsFd, AsRawFd};
    let fd = stage.progs.tc_test_chain_stage.as_fd().as_raw_fd();
    skel.maps
        .tc_pipe_root_progs
        .update(&CHAIN.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, chain, _out) = tc_run(&skel, &pkt, WAN_IFINDEX);

    assert_eq!(ret, TC_ACT_OK, "chain stage returns TC_ACT_OK");
    assert_eq!(chain, CHAIN);
    let k = 0u32.to_ne_bytes();
    let rec = stage.maps.sniff_chain_map.lookup(&k, MapFlags::ANY).unwrap().expect("chain record");
    assert_eq!(
        u64::from_ne_bytes(rec[0..8].try_into().unwrap()),
        1,
        "chain root must run exactly once"
    );
    assert_eq!(
        u32::from_ne_bytes(rec[8..12].try_into().unwrap()),
        CHAIN,
        "chain root must read the dispatched chain id from cb"
    );
}

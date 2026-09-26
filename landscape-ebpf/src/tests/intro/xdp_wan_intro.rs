//! Baseline for the native XDP WAN ingress intro `wan_intro_dispatch`
//! (xdp_wan_intro.bpf.c).
//!
//!   ├─ eth:IPv4 → broadcast-like daddr passes to the stack, otherwise
//!   │   dispatch-map lookup scoped by ingress ifindex (miss → XDP_DROP:
//!   │   v4 unicast junk); hit → chain id in `xdp_pipe_meta` + tail call
//!   ├─ eth:IPv6 → same, keyed by the destination /64 prefix (miss → PASS
//!   │   until v6 selector binding exists);
//!   └─ eth:PPPoE session → session selector lookup FIRST:
//!         non-IP PPP / truncated → PASS unmodified;
//!         session miss → PASS UNMODIFIED (pppd owns the session — the
//!           kernel decapsulates on the virtual ppp device; the inner IP
//!           is NOT re-dispatched here even when a selector exists);
//!         hit + unicast inner → strip 8 bytes, rewrite ethhdr,
//!           pipe meta + tail call;
//!         hit + bcast/mcast inner → strip 8 bytes, NO meta (pppd
//!           semantics: decapsulated for the local stack, never a chain).
//!
//! With an empty `xdp_pipe_root_progs` the tail call fails and the intro
//! returns XDP_PASS after storing metadata — the observable for "dispatch
//! happened" is the metadata-prefixed output. One test also installs the
//! `xdp_test_dummy` chain root to prove a real chain stage can read the
//! metadata.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::skel::{OpenSkel, SkelBuilder as _};
use libbpf_rs::{MapCore, MapFlags};

use crate::landscape::OwnedOpenObject;

use super::{
    build_arp_frame, build_ipv4_eth, build_ipv6_eth, build_pppoe_discovery_frame, build_pppoe_frame,
    build_raw_ipv4, build_raw_ipv6, expected_decapped, intro_pipe_out, seed_ip_selector,
    seed_ppp_session, xdp_effective_ifindex, xdp_run, PPP_PROTO_IPV4, PPP_PROTO_IPV6,
    PPP_PROTO_LCP, WRONG_IFINDEX, XDP_DROP, XDP_PASS,
};

const V4_DST: [u8; 4] = [198, 51, 100, 7];
const V4_SRC: [u8; 4] = [203, 0, 113, 9];
const SID: u16 = 0x2001;
const CHAIN: u32 = 5;

fn v6_dst() -> [u8; 16] {
    let a: Ipv6Addr = "fd00:aaaa:bbbb:cccc::7".parse().unwrap();
    a.octets()
}

/// Load the WAN intro skeleton together with its open-object backing.
fn load_skel(
    pin: &str,
) -> super::SkelGuard<crate::tests::wan_intro_skel::XdpWanIntroSkel<'static>> {
    let pin_root = crate::tests::isolated_pin_root(pin);
    let mut builder = crate::tests::wan_intro_skel::XdpWanIntroSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let (backing, obj) = OwnedOpenObject::new();
    super::SkelGuard {
        skel: builder.open(obj).unwrap().load().unwrap(),
        _backing: backing,
    }
}

// ── IPv4 dispatch ──────────────────────────────────────────────────────

#[test]
fn ipv4_selector_hit_stores_chain_meta() {
    let skel = load_skel("wan-in-v4-hit");
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        xdp_effective_ifindex(),
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        CHAIN,
    );

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS, "empty prog array → tail call fails → PASS after storing meta");
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, Some((0, 0, CHAIN)), "pipe meta must carry the selected chain id");
    assert_eq!(frame, pkt, "IP dispatch never rewrites the frame");
}

#[test]
fn ipv4_selector_miss_drops() {
    // A plain v4 unicast matching no selector is WAN junk: dropped at the
    // earliest point (v6 misses keep passing until v6 selector binding
    // exists).
    let skel = load_skel("wan-in-v4-miss");

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, _out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_DROP);
}

#[test]
fn ipv4_selector_scoped_by_ingress_ifindex() {
    let skel = load_skel("wan-in-v4-scope");
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        WRONG_IFINDEX,
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        CHAIN,
    );

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, _out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_DROP, "entry registered for another iface must not match");
}

#[test]
fn ipv4_broadcast_like_destinations_pass_even_when_registered() {
    // is_broadcast_ip4: 255.255.255.255, 0.0.0.0 and 224.0.0.0/4 always go
    // to the stack — before any selector lookup.
    let skel = load_skel("wan-in-v4-bcast");
    for dst in [
        Ipv4Addr::BROADCAST,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(224, 0, 0, 5),
        Ipv4Addr::new(239, 255, 255, 255),
    ] {
        seed_ip_selector(
            &skel.maps.wan_intro_dispatch_map,
            xdp_effective_ifindex(),
            IpAddr::V4(dst),
            CHAIN,
        );
        let pkt = build_ipv4_eth(V4_SRC, dst.octets());
        let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);
        assert_eq!(ret, XDP_PASS, "{dst}");
        let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
        assert_eq!(meta, None, "{dst} must never dispatch");
        assert_eq!(frame, pkt, "{dst}");
    }
}

#[test]
fn ipv4_truncated_header_passes_untouched() {
    let skel = load_skel("wan-in-v4-runt");
    let pkt = {
        let mut f = build_ipv4_eth(V4_SRC, V4_DST);
        f.truncate(16); // eth + 2 bytes of "IP"
        f
    };

    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None);
    assert_eq!(frame, pkt);
}

#[test]
fn arp_frame_passes_untouched() {
    let skel = load_skel("wan-in-arp");

    let pkt = build_arp_frame();
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None);
    assert_eq!(frame, pkt);
}

// ── IPv6 /64 dispatch ──────────────────────────────────────────────────

#[test]
fn ipv6_prefix_hit_stores_chain_meta() {
    let skel = load_skel("wan-in-v6-hit");
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        xdp_effective_ifindex(),
        IpAddr::V6(Ipv6Addr::from(v6_dst())),
        CHAIN,
    );

    let pkt =
        build_ipv6_eth(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], &v6_dst());
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, Some((0, 0, CHAIN)));
    assert_eq!(frame, pkt);
}

#[test]
fn ipv6_selector_matches_whole_prefix_and_misses_across_it() {
    let skel = load_skel("wan-in-v6-pfx");
    let registered: Ipv6Addr = "fd00:aaaa:bbbb:cccc::1".parse().unwrap();
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        xdp_effective_ifindex(),
        IpAddr::V6(registered),
        CHAIN,
    );

    // any address inside the registered /64 dispatches
    let inside: Ipv6Addr = "fd00:aaaa:bbbb:cccc:ffff:1234:5678:9abc".parse().unwrap();
    let pkt = build_ipv6_eth(
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        &inside.octets(),
    );
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);
    assert_eq!(ret, XDP_PASS);
    let (meta, _) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, Some((0, 0, CHAIN)), "same /64 prefix must match");

    // first byte outside the /64 → miss
    let outside: Ipv6Addr = "fd00:aaaa:bbbb:ccd1::1".parse().unwrap();
    let pkt = build_ipv6_eth(
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        &outside.octets(),
    );
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);
    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None, "different /64 prefix must not match");
    assert_eq!(frame, pkt);
}

#[test]
fn ipv6_multicast_and_link_local_pass_even_when_registered() {
    // is_broadcast_ip6: ff00::/8 and fe80::/10 always go to the stack.
    let skel = load_skel("wan-in-v6-bcast");
    for dst in ["ff02::1".parse::<Ipv6Addr>().unwrap(), "fe80::1".parse::<Ipv6Addr>().unwrap()] {
        seed_ip_selector(
            &skel.maps.wan_intro_dispatch_map,
            xdp_effective_ifindex(),
            IpAddr::V6(dst),
            CHAIN,
        );
        let pkt = build_ipv6_eth(
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            &dst.octets(),
        );
        let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);
        assert_eq!(ret, XDP_PASS, "{dst}");
        let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
        assert_eq!(meta, None, "{dst} must never dispatch");
        assert_eq!(frame, pkt, "{dst}");
    }
}

// ── PPPoE session dispatch ─────────────────────────────────────────────

fn pppoe_v4_frame(sid: u16, inner_dst: [u8; 4]) -> Vec<u8> {
    build_pppoe_frame(sid, PPP_PROTO_IPV4, &build_raw_ipv4(V4_SRC, inner_dst))
}

#[test]
fn pppoe_session_hit_decaps_and_stores_chain_meta() {
    let skel = load_skel("wan-in-ppp-hit");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = pppoe_v4_frame(SID, V4_DST);
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 8);
    assert_eq!(meta, Some((0, 0, CHAIN)), "session hit must store the session's chain id");
    assert_eq!(
        frame,
        expected_decapped(&pkt, 0x0800),
        "decapped frame must be eth:IPv4, MAC pair preserved"
    );
}

#[test]
fn pppoe_v6_session_hit_decaps_to_eth_ipv6() {
    let skel = load_skel("wan-in-ppp-v6");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = build_pppoe_frame(
        SID,
        PPP_PROTO_IPV6,
        &build_raw_ipv6(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], &v6_dst()),
    );
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 8);
    assert_eq!(meta, Some((0, 0, CHAIN)));
    assert_eq!(frame, expected_decapped(&pkt, 0x86DD));
}

#[test]
fn pppoe_session_miss_passes_frame_untouched_without_inner_fallback() {
    // THE core semantic: an unregistered session belongs to pppd. The frame
    // passes with the header intact, and the inner IP is NOT re-dispatched
    // even though a selector for it exists (the TC intro on the virtual ppp
    // device re-dispatches after the kernel decapsulation instead).
    let skel = load_skel("wan-in-ppp-miss");
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        xdp_effective_ifindex(),
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        CHAIN,
    );

    let pkt = pppoe_v4_frame(SID, V4_DST);
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None, "session miss must not dispatch on the inner IP");
    assert_eq!(frame, pkt, "session miss must pass the frame UNMODIFIED");
}

#[test]
fn pppoe_session_scoped_by_ingress_ifindex() {
    let skel = load_skel("wan-in-ppp-scope");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, WRONG_IFINDEX, SID, CHAIN);

    let pkt = pppoe_v4_frame(SID, V4_DST);
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None);
    assert_eq!(frame, pkt);
}

#[test]
fn pppoe_two_sessions_dispatch_their_own_chains() {
    let skel = load_skel("wan-in-ppp-dual");
    let eff = xdp_effective_ifindex();
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, eff, 0x1010, 11);
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, eff, 0x2020, 22);

    for (sid, chain) in [(0x1010u16, 11u32), (0x2020, 22)] {
        let pkt = pppoe_v4_frame(sid, V4_DST);
        let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);
        assert_eq!(ret, XDP_PASS);
        let (meta, _) = intro_pipe_out(&out, &pkt, 8);
        assert_eq!(meta, Some((0, 0, chain)), "session {sid:#06x} must select chain {chain}");
    }
}

#[test]
fn pppoe_inner_broadcast_decaps_to_stack_without_chain() {
    // pppd semantics: a registered session's multicast/broadcast inner
    // frame is decapsulated for the local stack — never into a chain (no
    // metadata; the TC intro's miss path exempts such daddrs).
    let skel = load_skel("wan-in-ppp-bcast");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = pppoe_v4_frame(SID, [255, 255, 255, 255]);
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 8);
    assert_eq!(meta, None, "inner bcast must not enter a chain");
    assert_eq!(
        frame,
        expected_decapped(&pkt, 0x0800),
        "decapped to eth:IPv4 bcast for the local stack"
    );
}

#[test]
fn pppoe_inner_v6_multicast_decaps_to_stack_without_chain() {
    let skel = load_skel("wan-in-ppp-bcast6");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let dst: [u8; 16] = "ff02::1".parse::<Ipv6Addr>().unwrap().octets();
    let pkt = build_pppoe_frame(
        SID,
        PPP_PROTO_IPV6,
        &build_raw_ipv6(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9], &dst),
    );
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 8);
    assert_eq!(meta, None, "inner mcast must not enter a chain");
    assert_eq!(frame, expected_decapped(&pkt, 0x86DD));
}

#[test]
fn pppoe_lcp_passes_untouched_even_for_registered_session() {
    let skel = load_skel("wan-in-ppp-lcp");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = build_pppoe_frame(SID, PPP_PROTO_LCP, &[0xff, 0x03, 0xc0, 0x21, 0x01, 0x01]);
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None);
    assert_eq!(frame, pkt);
}

#[test]
fn pppoe_discovery_frame_passes_untouched() {
    let skel = load_skel("wan-in-ppp-disc");

    let pkt = build_pppoe_discovery_frame();
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None);
    assert_eq!(frame, pkt);
}

#[test]
fn pppoe_truncated_header_passes_untouched() {
    let skel = load_skel("wan-in-ppp-runt");
    let pkt = {
        let mut f = pppoe_v4_frame(SID, V4_DST);
        f.truncate(18); // eth + 4 bytes of the PPPoE header
        f
    };

    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (meta, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(meta, None);
    assert_eq!(frame, pkt);
}

// ── chain stage observability ──────────────────────────────────────────

#[test]
fn chain_root_reads_the_stored_meta() {
    // Install xdp_test_dummy as the chain root: the tail call must succeed
    // and the dummy must observe the chain id the intro stored.
    let skel = load_skel("wan-in-chainroot");
    seed_ip_selector(
        &skel.maps.wan_intro_dispatch_map,
        xdp_effective_ifindex(),
        IpAddr::V4(Ipv4Addr::from(V4_DST)),
        77,
    );

    let dummy_pin = crate::tests::isolated_pin_root("wan-in-chainroot-dummy");
    let mut dummy_b = crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder::default();
    dummy_b.object_builder_mut().pin_root_path(&dummy_pin).unwrap();
    let mut dummy_obj = std::mem::MaybeUninit::uninit();
    let dummy = dummy_b.open(&mut dummy_obj).unwrap().load().unwrap();

    let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
    skel.maps
        .xdp_pipe_root_progs
        .update(&77u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let pkt = build_ipv4_eth(V4_SRC, V4_DST);
    let (ret, out) = xdp_run(&skel.progs.wan_intro_dispatch, &pkt);

    assert_eq!(ret, XDP_PASS, "xdp_test_dummy returns XDP_PASS");
    let (_, frame) = intro_pipe_out(&out, &pkt, 0);
    assert_eq!(frame, pkt);

    let k = 0u32.to_ne_bytes();
    let rec = dummy.maps.dummy_meta_map.lookup(&k, MapFlags::ANY).unwrap().expect("meta record");
    let chain_id = u32::from_ne_bytes(rec[8..12].try_into().unwrap());
    assert_eq!(chain_id, 77, "chain stage must read the dispatched chain id from xdp_pipe_meta");
    let v4 = u64::from_ne_bytes(
        dummy.maps.dummy_recv_map.lookup(&k, MapFlags::ANY).unwrap().unwrap()[0..8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(v4, 1, "chain stage must have received the frame exactly once");
}

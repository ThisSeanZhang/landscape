//! Baseline for the SKB-mode PPPoE stripper `xdp_skb_pppoe`
//! (xdp_skb_pppoe.bpf.c), the WAN ingress entry used when native XDP is not
//! available on the attach interface.
//!
//! Dispatch-map driven (the shared 16-byte `struct dispatch_key`, scoped by
//! ingress ifindex):
//!   * 0x8864 session frame + IP payload + registered session → strip the
//!     8-byte PPPoE/PPP header (rewritten ethhdr keeps the MAC pair):
//!     unicast → record the chain id in XDP handoff metadata; bcast/mcast
//!     inner → NO metadata (pppd semantics: the TC intro's miss path
//!     exempts such daddrs and passes the frame to the local stack);
//!   * anything else — discovery (0x8863), LCP, unregistered sessions
//!     (pppd's), other ethertypes, truncated frames — passes UNMODIFIED.

use libbpf_rs::skel::{OpenSkel, SkelBuilder as _};

use crate::landscape::OwnedOpenObject;

use super::{
    build_arp_frame, build_pppoe_discovery_frame, build_pppoe_frame, build_raw_ipv4,
    build_raw_ipv6, expected_decapped, ppp_stripper_out, seed_ppp_session, xdp_effective_ifindex,
    xdp_run, PPP_PROTO_IPV4, PPP_PROTO_IPV6, PPP_PROTO_LCP, WRONG_IFINDEX, XDP_PASS,
};

/// Load the stripper skeleton together with its open-object backing.
fn load_skel(
    pin: &str,
) -> super::SkelGuard<crate::bpf_rs_shared::xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>> {
    let pin_root = crate::tests::isolated_pin_root(pin);
    let mut builder = crate::bpf_rs_shared::xdp_skb_pppoe_skel::XdpSkbPppoeSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let (backing, obj) = OwnedOpenObject::new();
    super::SkelGuard {
        skel: builder.open(obj).unwrap().load().unwrap(),
        _backing: backing,
    }
}

const SID: u16 = 0x2107;
const CHAIN: u32 = 9;

fn sample_v4_frame() -> Vec<u8> {
    build_pppoe_frame(SID, PPP_PROTO_IPV4, &build_raw_ipv4([203, 0, 113, 9], [198, 51, 100, 7]))
}

fn sample_v6_frame() -> Vec<u8> {
    let src: &[u8; 16] = &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    let dst: &[u8; 16] = &[0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7];
    build_pppoe_frame(SID, PPP_PROTO_IPV6, &build_raw_ipv6(src, dst))
}

#[test]
fn registered_v4_session_decaps_and_writes_meta() {
    let skel = load_skel("skb-pppoe-v4");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = sample_v4_frame();
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, Some(CHAIN), "handoff metadata must carry the session's chain id");
    assert_eq!(
        frame,
        expected_decapped(&pkt, 0x0800),
        "decapped frame must be eth:IPv4 with the MAC pair preserved"
    );
}

#[test]
fn registered_v6_session_decaps_to_eth_ipv6() {
    let skel = load_skel("skb-pppoe-v6");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = sample_v6_frame();
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, Some(CHAIN));
    assert_eq!(frame, expected_decapped(&pkt, 0x86DD), "decapped frame must be eth:IPv6");
}

#[test]
fn unregistered_session_passes_frame_untouched() {
    // Unregistered sessions belong to pppd: the frame must reach the kernel
    // PPPoE layer with the header intact (no decap, no metadata).
    let skel = load_skel("skb-pppoe-miss");

    let pkt = sample_v4_frame();
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

#[test]
fn session_scoped_by_ingress_ifindex() {
    // The key includes the ingress ifindex: an entry registered for another
    // iface must never match (two WAN links may reuse the same session id).
    let skel = load_skel("skb-pppoe-scope");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, WRONG_IFINDEX, SID, CHAIN);

    let pkt = sample_v4_frame();
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

#[test]
fn other_session_id_passes_untouched() {
    let skel = load_skel("skb-pppoe-sid");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID + 1, CHAIN);

    let pkt = sample_v4_frame();
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

#[test]
fn inner_broadcast_decaps_to_stack_without_meta() {
    // pppd semantics: a registered session's multicast/broadcast inner
    // frame is decapsulated for the local stack — no handoff metadata, so
    // the TC intro's bcast exemption (not the chain fast path) handles it.
    let skel = load_skel("skb-pppoe-bcast");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = build_pppoe_frame(
        SID,
        PPP_PROTO_IPV4,
        &build_raw_ipv4([203, 0, 113, 9], [255, 255, 255, 255]),
    );
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None, "inner bcast must not enter a chain");
    assert_eq!(
        frame,
        expected_decapped(&pkt, 0x0800),
        "decapped to eth:IPv4 bcast for the local stack"
    );
}

#[test]
fn truncated_inner_ip_passes_untouched() {
    // eth + PPPoE header + a partial inner IPv4 header: the stripper must
    // not decap a frame whose inner header it cannot validate.
    let skel = load_skel("skb-pppoe-inner-runt");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = {
        let mut f = sample_v4_frame();
        f.truncate(14 + 8 + 10); // eth + pppoe/ppp + 10 bytes of IPv4 header
        f
    };

    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

#[test]
fn lcp_passes_untouched_even_for_registered_session() {
    // LCP (and any non-IP PPP protocol) always goes to pppd.
    let skel = load_skel("skb-pppoe-lcp");
    seed_ppp_session(&skel.maps.wan_intro_dispatch_map, xdp_effective_ifindex(), SID, CHAIN);

    let pkt = build_pppoe_frame(SID, PPP_PROTO_LCP, &[0xff, 0x03, 0xc0, 0x21, 0x01, 0x01]);
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

#[test]
fn discovery_frame_passes_untouched() {
    let skel = load_skel("skb-pppoe-disc");

    let pkt = build_pppoe_discovery_frame();
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

#[test]
fn non_pppoe_ethertype_passes_untouched() {
    let skel = load_skel("skb-pppoe-arp");

    let pkt = build_arp_frame();
    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

#[test]
fn truncated_pppoe_header_passes_untouched() {
    // eth header claiming 0x8864 with no room for the PPPoE header
    let skel = load_skel("skb-pppoe-runt");
    let pkt = {
        let mut f = build_pppoe_frame(SID, PPP_PROTO_IPV4, &[]);
        f.truncate(18); // eth(14) + 4 bytes of the PPPoE header
        f
    };

    let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);

    assert_eq!(ret, XDP_PASS);
    let (chain, frame) = ppp_stripper_out(&out, &pkt);
    assert_eq!(chain, None);
    assert_eq!(frame, pkt);
}

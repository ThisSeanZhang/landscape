//! Pins the WAN-type dispatch matrix of `xdp_wan_intro` through
//! BPF_PROG_TEST_RUN:
//!
//!   A raw IP      — trie hit on the v4/v6 daddr → chain root;
//!                   miss → XDP_DROP (default-deny);
//!                   bcast / multicast / link-local → untouched XDP_PASS
//!   B native PPPoE— own session (published under (ingress ifindex,
//!                   session)) → decap (len−8, eth rewritten) → chain
//!                   root; inner bcast/multicast → stripped XDP_PASS
//!   C pppd PPPoE  — foreign session → untouched XDP_PASS, even when the
//!                   inner IP would match a published prefix (the
//!                   inner-IP fallback is retired)
//!   control plane — non-IP PPP protocols and PPPoE discovery frames
//!                   pass untouched; so do malformed/truncated frames
//!
//! Dispatch is observed via sink progs planted in the `xdp_pipe_root_progs`
//! chain-root slots (`test_xdp_sink_a` flips packet byte 0, `test_xdp_sink_b`
//! flips byte 1), so "reached root A/B" is distinguishable from a miss.
//! test_run without a ctx reads `ctx->ingress_ifindex` as 1 (the loopback
//! rxq); the ctx-based test drives a real veth ifindex through
//! `context_in`, proving the (ifindex, session) key namespacing.
//!
//! Run (needs root + the `bpf-test` feature):
//!   cargo test -p landscape-ebpf --features bpf-test --lib route::xdp_wan_intro -- --nocapture

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::str::FromStr;

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel as _, SkelBuilder as _},
};
use landscape_common::wan_service::wan_chain::dataplane::PppoeEgressTmpl;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::maps::wan_trie::builder::{
    PrefixEntry, ppp_entry, v4_entry, v6_entry, wan_trie_publish,
};
use crate::maps::wan_trie::dispatcher::cast_arena_tbl;
use crate::tests::net_utils::VethPair;
use crate::tests::route::packet_builder::{
    simple_ipv4_tcp, simple_ipv6_tcp_syn, simple_pppoe_ipv4, simple_pppoe_ipv6,
};
use crate::tests::test_wan_trie_probe_skel::TestWanTrieProbeSkelBuilder;
use crate::tests::wan_intro_skel::{XdpWanIntroSkel, XdpWanIntroSkelBuilder};

const XDP_PASS: u32 = 2;
const XDP_DROP: u32 = 1;

/// Chain-root slot holding `test_xdp_sink_a` (flips packet byte 0).
const CHAIN_A: u32 = 5;
/// Chain-root slot holding `test_xdp_sink_b` (flips packet byte 1).
const CHAIN_B: u32 = 6;

const SESS: u16 = 0x1234;
const FOREIGN_SESS: u16 = 0x9999;

/// test_run without a ctx uses the loopback rxq, so the program reads
/// `ctx->ingress_ifindex == 1` (loopback is always ifindex 1).
const LO_IFINDEX: u32 = 1;

const ETH_P_IPV4_BE: [u8; 2] = [0x08, 0x00];
const ETH_P_IPV6_BE: [u8; 2] = [0x86, 0xDD];

fn publish(intro: &mut XdpWanIntroSkel<'_>, entries: &[PrefixEntry]) {
    let data = intro.maps.wan_trie_arena_data.as_mut().expect("wan_trie arena mmap data");
    wan_trie_publish(cast_arena_tbl(&mut data.wan_trie_tbl), entries).expect("publish trie");
}

/// One test_run: returns (retval, data_out).
fn run(intro: &XdpWanIntroSkel<'_>, pkt: &[u8]) -> (u32, Vec<u8>) {
    let mut out_buf = vec![0u8; pkt.len().max(64) + 32];
    let out = intro
        .progs
        .xdp_wan_intro
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out_buf),
            ..Default::default()
        })
        .expect("test_run xdp_wan_intro");
    let data = out.data.expect("data_out").to_vec();
    (out.return_value, data)
}

fn assert_untouched(label: &str, pkt: &[u8], out: &[u8]) {
    assert_eq!(out, pkt, "{label}: frame must come back untouched");
}

fn assert_flip0_only(label: &str, frame: &[u8]) {
    assert_eq!(frame[0], 0x02 ^ 0xff, "{label}: sink A must flip byte 0");
    assert_eq!(frame[1], 0x00, "{label}: byte 1 must stay intact");
}

fn assert_flip1_only(label: &str, frame: &[u8]) {
    assert_eq!(frame[0], 0x02, "{label}: byte 0 must stay intact");
    assert_eq!(frame[1], 0x00 ^ 0xff, "{label}: sink B must flip byte 1");
}

#[test]
fn wan_intro_dispatch_matrix() {
    // ── rig: intro + probe (sinks); chain-root slots A/B ──
    let builder = TestWanTrieProbeSkelBuilder::default();
    let mut probe_obj = MaybeUninit::uninit();
    let probe = builder.open(&mut probe_obj).expect("open probe").load().expect("load probe");

    let builder = XdpWanIntroSkelBuilder::default();
    let mut intro_obj = MaybeUninit::uninit();
    let open = builder.open(&mut intro_obj).expect("open intro");
    let mut intro = open.load().expect("load intro");

    let sink_a = probe.progs.test_xdp_sink_a.as_fd().as_raw_fd();
    let sink_b = probe.progs.test_xdp_sink_b.as_fd().as_raw_fd();
    for (slot, fd) in [(CHAIN_A, sink_a), (CHAIN_B, sink_b)] {
        intro
            .maps
            .xdp_pipe_root_progs
            .update(&slot.to_ne_bytes(), &(fd as u32).to_ne_bytes(), MapFlags::ANY)
            .expect("plant sink in chain-root slot");
    }

    // ── 1. type A: raw IPv4 ──
    publish(&mut intro, &[v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, CHAIN_A).unwrap()]);

    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len(), "raw v4: no head adjustment");
        assert_flip0_only("raw v4 hit", &out);
    }
    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 9));
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_DROP, "raw v4 miss: default-deny");
        assert_untouched("raw v4 miss", &pkt, &out);
    }
    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(255, 255, 255, 255));
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("raw v4 broadcast", &pkt, &out);
    }

    // ── 2. type A: raw IPv6 ──
    publish(
        &mut intro,
        &[v6_entry(Ipv6Addr::from_str("fd44:5555::").unwrap(), 48, CHAIN_A).unwrap()],
    );

    {
        let pkt = simple_ipv6_tcp_syn(
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("fd44:5555::1").unwrap(),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len(), "raw v6: no head adjustment");
        assert_flip0_only("raw v6 hit", &out);
    }
    {
        let pkt = simple_ipv6_tcp_syn(
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("fd99::1").unwrap(),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_DROP, "raw v6 miss: default-deny");
        assert_untouched("raw v6 miss", &pkt, &out);
    }
    {
        let pkt = simple_ipv6_tcp_syn(
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("ff02::1").unwrap(),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("raw v6 multicast", &pkt, &out);
    }
    {
        // unicast link-local (ND/SLAAC) stays exempt from default-deny
        let pkt = simple_ipv6_tcp_syn(
            Ipv6Addr::from_str("fe80::1").unwrap(),
            Ipv6Addr::from_str("fe80::42:1").unwrap(),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("raw v6 link-local", &pkt, &out);
    }

    // ── 3. type B: our native session, IPv4 payload ──
    publish(&mut intro, &[ppp_entry(LO_IFINDEX, SESS, CHAIN_A)]);

    {
        let pkt =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len() - 8, "ppp v4 hit: 8-byte session header stripped");
        assert_eq!(
            &out[1..12],
            &pkt[1..12],
            "ppp v4 hit: mac pair preserved (byte 0 flipped by the sink)"
        );
        assert_eq!(&out[12..14], &ETH_P_IPV4_BE, "ppp v4 hit: ethertype rewritten");
        assert_eq!(&out[14..], &pkt[22..], "ppp v4 hit: inner IP carried verbatim");
        assert_flip0_only("ppp v4 hit", &out);
    }
    {
        // inner broadcast: decapped, handed to the stack, never chained
        let pkt =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(255, 255, 255, 255));
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len() - 8, "ppp v4 bcast: stripped");
        assert_eq!(&out[12..14], &ETH_P_IPV4_BE);
        assert_eq!(out[0], 0x02, "ppp v4 bcast: sink must not run");
    }

    // ── 3b. production byte-order contract (regression) ──
    // Live sessions are published through `PppoeEgressTmpl::session_id_host()`
    // because `session_id` is network byte order like every wire field;
    // publishing the raw BE field would byte-swap the trie key and the
    // frame would silently miss into an untouched XDP_PASS.  0x000a is the
    // byte-asymmetric id a real BRAS assigned when this regressed.
    {
        const SESS_REAL: u16 = 0x000a;
        let tmpl =
            PppoeEgressTmpl { session_id: SESS_REAL.to_be(), ..Default::default() };
        publish(
            &mut intro,
            &[
                ppp_entry(LO_IFINDEX, SESS, CHAIN_A),
                ppp_entry(LO_IFINDEX, tmpl.session_id_host(), CHAIN_A),
            ],
        );
        let pkt =
            simple_pppoe_ipv4(SESS_REAL, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(
            out.len(),
            pkt.len() - 8,
            "wire-order session published via session_id_host(): decapped"
        );
        assert_flip0_only("wire-order session hit", &out);
    }

    // ── 4. type B: our native session, IPv6 payload ──
    {
        let pkt = simple_pppoe_ipv6(
            SESS,
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("fd44:5555:1234::1").unwrap(),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len() - 8, "ppp v6 hit: stripped");
        assert_eq!(&out[1..12], &pkt[1..12], "ppp v6 hit: mac pair preserved");
        assert_eq!(&out[12..14], &ETH_P_IPV6_BE, "ppp v6 hit: ethertype rewritten");
        assert_eq!(&out[14..], &pkt[22..]);
        assert_flip0_only("ppp v6 hit", &out);
    }
    {
        // inner multicast (e.g. ND): stripped, not chained
        let pkt = simple_pppoe_ipv6(
            SESS,
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("ff02::1").unwrap(),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len() - 8, "ppp v6 multicast: stripped");
        assert_eq!(&out[12..14], &ETH_P_IPV6_BE);
        assert_eq!(out[0], 0x02, "ppp v6 multicast: sink must not run");
    }

    // ── 5. type C: pppd-owned session → untouched, fallback is gone ──
    {
        // 5a. nothing published for the foreign session
        let pkt = simple_pppoe_ipv4(
            FOREIGN_SESS,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(203, 0, 113, 7),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("foreign session", &pkt, &out);
    }
    {
        // 5b. inner dst IS a published v4 prefix: still untouched — the
        // transitional inner-IP fallback must stay retired
        publish(
            &mut intro,
            &[
                ppp_entry(LO_IFINDEX, SESS, CHAIN_A),
                v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, CHAIN_A).unwrap(),
            ],
        );
        let pkt = simple_pppoe_ipv4(
            FOREIGN_SESS,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(203, 0, 113, 7),
        );
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("foreign session, published inner", &pkt, &out);
    }
    {
        // 5c. our session id published under ANOTHER ifindex: namespaced
        // away, so at ingress ifindex 1 it is a miss → untouched
        publish(&mut intro, &[ppp_entry(LO_IFINDEX + 900, SESS, CHAIN_A)]);
        let pkt =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("session under foreign ifindex", &pkt, &out);
    }

    // ── 6. control plane + malformed frames ──
    publish(&mut intro, &[ppp_entry(LO_IFINDEX, SESS, CHAIN_A)]);
    {
        // LCP inside the session ethertype: control traffic for the stack
        let mut pkt =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        pkt[20..22].copy_from_slice(&[0xc0, 0x21]); // PPP protocol: LCP
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("LCP control frame", &pkt, &out);
    }
    {
        // PPPoE discovery (PADI/PADO/PADR/PADS/PADT)
        let mut pkt =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        pkt[12..14].copy_from_slice(&[0x88, 0x63]); // ETH_P_PPP_DISC
        let (rv, out) = run(&intro, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("PPPoE discovery", &pkt, &out);
    }
    {
        // truncated pppoe header
        let full =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let pkt = &full[..18]; // eth + 4 bytes of pppoe header
        let (rv, out) = run(&intro, pkt);
        assert_eq!(rv, XDP_PASS);
        assert_untouched("truncated pppoe header", pkt, &out);
    }
}

/// `struct xdp_md` as accepted by BPF_PROG_TEST_RUN's `ctx_in`:
/// data/data_end/data_meta are offsets relative to data_meta; a zero meta
/// with data_end == packet length is the plain no-meta layout.
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

/// Same session id published under two ifindexes: the ctx-driven run must
/// resolve the (veth, session) root while the ctx-less run (loopback
/// rxq, ifindex 1) resolves the (lo, session) root — the BRAS-assigned
/// session ids of two NICs can never collide.
#[test]
fn ppp_ifindex_key_ctx_discrimination() {
    let builder = TestWanTrieProbeSkelBuilder::default();
    let mut probe_obj = MaybeUninit::uninit();
    let probe = builder.open(&mut probe_obj).expect("open probe").load().expect("load probe");

    let builder = XdpWanIntroSkelBuilder::default();
    let mut intro_obj = MaybeUninit::uninit();
    let open = builder.open(&mut intro_obj).expect("open intro");
    let mut intro = open.load().expect("load intro");

    // Attach any XDP program natively to the veth: this registers its
    // xdp_rxq, which ctx-carrying test runs require (xdp_rxq_info_is_reg).
    let veth = VethPair::create("winx");
    let veth_ifx = veth.host_ifindex();
    let _link =
        probe.progs.test_xdp_sink_b.attach_xdp(veth_ifx as i32).expect("native XDP on veth");

    let sink_a = probe.progs.test_xdp_sink_a.as_fd().as_raw_fd();
    let sink_b = probe.progs.test_xdp_sink_b.as_fd().as_raw_fd();
    for (slot, fd) in [(CHAIN_A, sink_a), (CHAIN_B, sink_b)] {
        intro
            .maps
            .xdp_pipe_root_progs
            .update(&slot.to_ne_bytes(), &(fd as u32).to_ne_bytes(), MapFlags::ANY)
            .expect("plant sink in chain-root slot");
    }
    publish(
        &mut intro,
        &[ppp_entry(LO_IFINDEX, SESS, CHAIN_A), ppp_entry(veth_ifx, SESS, CHAIN_B)],
    );

    let pkt = simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
    let mut out_buf = vec![0u8; pkt.len() + 32];

    // ctx-less run: loopback rxq → (1, session) → chain A
    {
        let out = intro
            .progs
            .xdp_wan_intro
            .test_run(ProgramInput {
                data_in: Some(&pkt),
                data_out: Some(&mut out_buf),
                ..Default::default()
            })
            .expect("test_run without ctx");
        assert_eq!(out.return_value, XDP_PASS);
        let frame = out.data.expect("data_out");
        assert_eq!(frame.len(), pkt.len() - 8, "decapped");
        assert_flip0_only("loopback ingress → chain A", frame);
    }

    // ctx-driven run: veth rxq → (veth, session) → chain B
    {
        let mut ctx = XdpMd {
            data: 0,
            data_end: pkt.len() as u32,
            data_meta: 0,
            ingress_ifindex: veth_ifx,
            rx_queue_index: 0,
            egress_ifindex: 0,
        };
        let mut ctx_bytes = ctx.as_mut_bytes();
        let out = intro
            .progs
            .xdp_wan_intro
            .test_run(ProgramInput {
                data_in: Some(&pkt),
                data_out: Some(&mut out_buf),
                context_in: Some(&mut ctx_bytes),
                ..Default::default()
            })
            .expect("test_run with ctx");
        assert_eq!(out.return_value, XDP_PASS);
        let frame = out.data.expect("data_out");
        assert_eq!(frame.len(), pkt.len() - 8, "decapped");
        assert_flip1_only("veth ingress → chain B", frame);
    }
}

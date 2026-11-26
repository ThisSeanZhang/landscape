//! Pins the dual-mode behaviour of `tc_wan_ingress_intro`:
//!
//!   TC-only mode (xdp_handoff_enabled = false):
//!     * non-IP ethertype (pppd PPPoE, ARP, ...) → TC_ACT_OK (stack)
//!     * IP broadcast/multicast → TC_ACT_OK
//!     * trie hit → chain root (observed via a sink in tc_pipe_root_progs)
//!     * trie miss → TC_ACT_SHOT (default-deny)
//!
//!   XDP mode (xdp_handoff_enabled = true): handoff landing pad —
//!   non-handoff packets return TC_ACT_UNSPEC without classification.
//!
//!   Native PPPoE data enters its session's chain in TC-only mode.
//!
//! PROG_TEST_RUN verdict mapping: OK=0, UNSPEC=-1, SHOT=2.
//!
//! Run (needs root + the `bpf-test` feature):
//!   cargo test -p landscape-ebpf --features bpf-test --lib route::tc_wan_ingress_intro -- --nocapture

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::str::FromStr;

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use crate::landscape::OwnedOpenObject;
use crate::maps::wan_trie::arena::mapped_table;
use crate::maps::wan_trie::builder::{
    PrefixEntry, ppp_entry, v4_entry, v6_entry, wan_trie_publish,
};
use crate::tests::pkt::{
    simple_ipv4_tcp, simple_ipv6_tcp_syn, simple_pppoe_ipv4, simple_pppoe_ipv6,
};
use crate::tests::test_wan_trie_probe_skel::{TestWanTrieProbeSkel, TestWanTrieProbeSkelBuilder};

use crate::skel::tc_wan_ingress_intro::{TcWanIngressIntroSkel, TcWanIngressIntroSkelBuilder};

const RET_OK: i32 = 0;
const RET_UNSPEC: i32 = -1;
const RET_SHOT: i32 = 2;

/// Chain-root slot holding `test_tc_sink_a` (flips packet byte 0).
const CHAIN_A: u32 = 5;
const CHAIN_B: u32 = 6;
// PROG_TEST_RUN uses loopback by default.
const LO_IFINDEX: u32 = 1;
const SESS: u16 = 0x1234;
const FOREIGN_SESS: u16 = 0x9999;

/// Loaded instance + the leaked object backing that keeps it alive.
struct IntroInstance {
    skel: TcWanIngressIntroSkel<'static>,
    _backing: OwnedOpenObject,
}

fn load_intro(handoff: bool) -> IntroInstance {
    let (backing, obj) = OwnedOpenObject::new();
    let builder = TcWanIngressIntroSkelBuilder::default();
    let mut open = builder.open(obj).expect("open tc_wan_ingress_intro");
    open.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = handoff;
    IntroInstance {
        skel: open.load().expect("load tc_wan_ingress_intro"),
        _backing: backing,
    }
}

struct ProbeSinks {
    _skel: TestWanTrieProbeSkel<'static>,
    _backing: OwnedOpenObject,
}

/// Install two observable chain roots and keep their program FDs alive.
fn plant_sinks(intro: &mut TcWanIngressIntroSkel<'_>) -> ProbeSinks {
    let (backing, obj) = OwnedOpenObject::new();
    let builder = TestWanTrieProbeSkelBuilder::default();
    let probe = builder.open(obj).expect("open probe").load().expect("load probe");
    for (chain, prog) in
        [(CHAIN_A, &probe.progs.test_tc_sink_a), (CHAIN_B, &probe.progs.test_tc_sink_b)]
    {
        let fd = prog.as_fd().as_raw_fd();
        intro
            .maps
            .tc_pipe_root_progs
            .update(&chain.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
            .expect("plant tc sink");
    }
    ProbeSinks { _skel: probe, _backing: backing }
}

fn publish(intro: &mut TcWanIngressIntroSkel<'_>, entries: &[PrefixEntry]) {
    wan_trie_publish(
        mapped_table(&mut intro.maps.wan_trie_arena).expect("owned trie arena mapping"),
        entries,
    )
    .expect("publish trie");
}

fn run(intro: &TcWanIngressIntroSkel<'_>, pkt: &[u8]) -> (i32, Vec<u8>) {
    let mut out_buf = vec![0u8; pkt.len().max(64) + 32];
    let out = intro
        .progs
        .tc_wan_ingress_intro
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out_buf),
            ..Default::default()
        })
        .expect("test_run tc_wan_ingress_intro");
    (out.return_value as i32, out.data.expect("data_out").to_vec())
}

#[test]
fn tc_only_mode_dispatch_matrix() {
    let mut inst = load_intro(false);
    let _sinks = plant_sinks(&mut inst.skel);
    publish(
        &mut inst.skel,
        &[
            v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, CHAIN_A).unwrap(),
            v6_entry(Ipv6Addr::from_str("fd44:5555::").unwrap(), 48, CHAIN_A).unwrap(),
        ],
    );

    // non-IP ethertype (pppd-owned PPPoE) → OK, untouched
    {
        let pkt = simple_pppoe_ipv4(
            FOREIGN_SESS,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(203, 0, 113, 7),
        );
        let (rv, out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_OK, "non-IP: pass to stack");
        assert_eq!(out, pkt);
    }

    // v4 broadcast → OK, untouched
    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(255, 255, 255, 255));
        let (rv, out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_OK, "v4 broadcast: pass to stack");
        assert_eq!(out, pkt);
    }

    // v4 hit → chain root (sink flips byte 0)
    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let (rv, out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_OK);
        assert_eq!(out[0], 0x02 ^ 0xff, "v4 hit: tc sink must flip byte 0");
        assert_eq!(&out[1..], &pkt[1..]);
    }

    // v4 miss → SHOT (default-deny)
    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 9));
        let (rv, _out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_SHOT, "v4 miss: default-deny");
    }

    // v6 hit → chain root
    {
        let pkt = simple_ipv6_tcp_syn(
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("fd44:5555::1").unwrap(),
        );
        let (rv, out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_OK);
        assert_eq!(out[0], 0x02 ^ 0xff, "v6 hit: tc sink must flip byte 0");
        assert_eq!(&out[1..], &pkt[1..]);
    }

    // v6 miss → SHOT
    {
        let pkt = simple_ipv6_tcp_syn(
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("fd99::1").unwrap(),
        );
        let (rv, _out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_SHOT, "v6 miss: default-deny");
    }
}

/// XDP mode: the intro is a pure handoff landing pad — every non-handoff
/// packet returns UNSPEC without classification.
#[test]
fn xdp_mode_is_handoff_pad_only() {
    let mut inst = load_intro(true);
    let _sinks = plant_sinks(&mut inst.skel);
    let dst = Ipv4Addr::new(203, 0, 113, 7);
    publish(
        &mut inst.skel,
        &[v4_entry(dst, 24, CHAIN_A).unwrap(), ppp_entry(LO_IFINDEX, SESS, CHAIN_A)],
    );

    let ppp = simple_pppoe_ipv4(SESS, Ipv4Addr::LOCALHOST, dst);
    assert_eq!(run(&inst.skel, &ppp), (RET_UNSPEC, ppp));

    // would-be miss (SHOT in TC-only mode): no drop, no classification
    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 9));
        let (rv, out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_UNSPEC, "handoff pad: no classify, no drop");
        assert_eq!(out, pkt);
    }

    // would-be hit: no dispatch either — the classify body is dead
    {
        let pkt = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let (rv, out) = run(&inst.skel, &pkt);
        assert_eq!(rv, RET_UNSPEC, "handoff pad: no dispatch");
        assert_eq!(out, pkt, "handoff pad: sink must not run");
    }
}

#[test]
fn pppoe_session_selects_chain() {
    let mut inst = load_intro(false);
    let _sinks = plant_sinks(&mut inst.skel);
    let dst4 = Ipv4Addr::new(203, 0, 113, 7);
    let dst6 = "2001:db8::7".parse().unwrap();
    let pkt4 = simple_pppoe_ipv4(SESS, Ipv4Addr::LOCALHOST, dst4);
    let pkt6 = simple_pppoe_ipv6(SESS, Ipv6Addr::LOCALHOST, dst6);
    let session = ppp_entry(LO_IFINDEX, SESS, CHAIN_A);

    for entries in [
        vec![session],
        vec![session, v4_entry(dst4, 32, CHAIN_B).unwrap(), v6_entry(dst6, 64, CHAIN_B).unwrap()],
    ] {
        publish(&mut inst.skel, &entries);
        for (pkt, proto) in [(&pkt4, [0x08, 0x00]), (&pkt6, [0x86, 0xdd])] {
            let (rv, out) = run(&inst.skel, pkt);
            let mut expected = pkt[..12].to_vec();
            expected[0] ^= 0xff; // sink A
            expected.extend_from_slice(&proto);
            expected.extend_from_slice(&pkt[22..]);
            assert_eq!(rv, RET_OK);
            assert_eq!(out, expected, "only the session selects the chain");
        }
    }

    // The same ID on another interface does not claim this frame.
    publish(
        &mut inst.skel,
        &[ppp_entry(LO_IFINDEX + 1, SESS, CHAIN_A), v4_entry(dst4, 32, CHAIN_B).unwrap()],
    );
    assert_eq!(run(&inst.skel, &pkt4), (RET_OK, pkt4));

    // An owned session whose root was removed cannot fall through to IP dispatch.
    inst.skel.maps.tc_pipe_root_progs.delete(&CHAIN_A.to_ne_bytes()).unwrap();
    publish(&mut inst.skel, &[session, v6_entry(dst6, 64, CHAIN_B).unwrap()]);
    assert_eq!(run(&inst.skel, &pkt6).0, RET_SHOT);
}

#[test]
fn pppoe_stack_traffic() {
    let mut inst = load_intro(false);
    let _sinks = plant_sinks(&mut inst.skel);
    publish(&mut inst.skel, &[ppp_entry(LO_IFINDEX, SESS, CHAIN_A)]);
    let broadcast = simple_pppoe_ipv4(SESS, Ipv4Addr::LOCALHOST, Ipv4Addr::BROADCAST);
    let multicast = simple_pppoe_ipv6(SESS, Ipv6Addr::LOCALHOST, "ff02::1".parse().unwrap());
    for (pkt, proto) in [(&broadcast, [0x08, 0x00]), (&multicast, [0x86, 0xdd])] {
        let mut expected = pkt[..12].to_vec();
        expected.extend_from_slice(&proto);
        expected.extend_from_slice(&pkt[22..]);
        assert_eq!(run(&inst.skel, pkt), (RET_OK, expected));
    }

    let mut lcp = broadcast.clone();
    lcp[20..22].copy_from_slice(&[0xc0, 0x21]);
    for pkt in [&lcp[..], &broadcast[..18], &multicast[..30]] {
        assert_eq!(run(&inst.skel, pkt), (RET_OK, pkt.to_vec()));
    }
}

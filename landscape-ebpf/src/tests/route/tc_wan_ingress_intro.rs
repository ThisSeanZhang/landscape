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
//!   Plus the TC-only native-PPPoE cooperation pin: the fallback decaps
//!   an own session, and the TC intro dispatches the stripped frame
//!   through the trie's IP entry.
//!
//! PROG_TEST_RUN verdict mapping: OK=0, UNSPEC=-1, SHOT=2.
//!
//! Run (needs root + the `bpf-test` feature):
//!   cargo test -p landscape-ebpf --features bpf-test --lib route::tc_wan_ingress_intro -- --nocapture

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::str::FromStr;

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use crate::bpf_rs_shared::pppoe_skb_fallback_skel::PppoeSkbFallbackSkelBuilder;
use crate::landscape::OwnedOpenObject;
use crate::maps::wan_trie::builder::{
    PrefixEntry, ppp_entry, v4_entry, v6_entry, wan_trie_publish,
};
use crate::maps::wan_trie::dispatcher::cast_arena_tbl;
use crate::tests::route::packet_builder::{
    simple_ipv4_tcp, simple_ipv6_tcp_syn, simple_pppoe_ipv4,
};
use crate::tests::test_wan_trie_probe_skel::{TestWanTrieProbeSkel, TestWanTrieProbeSkelBuilder};

pub(crate) mod tc_wan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_intro.skel.rs"));
}
use tc_wan_ingress_intro_skel::{TcWanIngressIntroSkel, TcWanIngressIntroSkelBuilder};

const RET_OK: i32 = 0;
const RET_UNSPEC: i32 = -1;
const RET_SHOT: i32 = 2;

/// Chain-root slot holding `test_tc_sink_a` (flips packet byte 0).
const CHAIN_A: u32 = 5;
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

/// Loads the probe object (for its tc sinks) and plants sink_a at CHAIN_A;
/// keep the returned value alive while its prog fd sits in the array.
fn plant_sink_a(intro: &mut TcWanIngressIntroSkel<'_>) -> ProbeSinks {
    let (backing, obj) = OwnedOpenObject::new();
    let builder = TestWanTrieProbeSkelBuilder::default();
    let probe = builder.open(obj).expect("open probe").load().expect("load probe");
    let fd = probe.progs.test_tc_sink_a.as_fd().as_raw_fd();
    intro
        .maps
        .tc_pipe_root_progs
        .update(&CHAIN_A.to_ne_bytes(), &(fd as u32).to_ne_bytes(), MapFlags::ANY)
        .expect("plant tc sink");
    ProbeSinks { _skel: probe, _backing: backing }
}

fn publish(intro: &mut TcWanIngressIntroSkel<'_>, entries: &[PrefixEntry]) {
    let data = intro.maps.wan_trie_arena_data.as_mut().expect("wan_trie arena mmap data");
    wan_trie_publish(cast_arena_tbl(&mut data.wan_trie_tbl), entries).expect("publish trie");
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
    let _sinks = plant_sink_a(&mut inst.skel);
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
    let _sinks = plant_sink_a(&mut inst.skel);
    publish(&mut inst.skel, &[v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, CHAIN_A).unwrap()]);

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

/// TC-only native PPPoE: the fallback decaps an own session and the TC
/// intro dispatches the stripped frame through the trie's IP entry.
#[test]
fn tc_only_pppoe_fallback_cooperation() {
    let mut inst = load_intro(false);
    let _sinks = plant_sink_a(&mut inst.skel);

    let fb_builder = PppoeSkbFallbackSkelBuilder::default();
    let mut fb_obj = MaybeUninit::uninit();
    let fb = fb_builder.open(&mut fb_obj).expect("open fallback").load().expect("load fallback");
    fb.maps
        .pppoe_sessions
        .update(&SESS.to_ne_bytes(), &CHAIN_A.to_ne_bytes(), MapFlags::ANY)
        .expect("publish session");

    let pkt = simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));

    // step 1: fallback decaps our session
    let mut decap_buf = vec![0u8; pkt.len() + 32];
    let out = fb
        .progs
        .pppoe_skb_fallback
        .test_run(ProgramInput {
            data_in: Some(&pkt),
            data_out: Some(&mut decap_buf),
            ..Default::default()
        })
        .expect("test_run fallback");
    assert_eq!(out.return_value, 2 /* XDP_PASS */);
    let decapped = out.data.expect("decapped frame").to_vec();
    assert_eq!(decapped.len(), pkt.len() - 8);

    // step 2: with the IP entry published, the TC intro dispatches it
    publish(
        &mut inst.skel,
        &[
            v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, CHAIN_A).unwrap(),
            ppp_entry(1, SESS, CHAIN_A),
        ],
    );
    {
        let (rv, out) = run(&inst.skel, &decapped);
        assert_eq!(rv, RET_OK);
        assert_eq!(out[0], 0x02 ^ 0xff, "decapped frame must reach the chain root");
        assert_eq!(&out[1..], &decapped[1..]);
    }

    // step 3: without any IP entry, the same frame is denied
    publish(&mut inst.skel, &[ppp_entry(1, SESS, CHAIN_A)]);
    {
        let (rv, _out) = run(&inst.skel, &decapped);
        assert_eq!(rv, RET_SHOT, "no IP entry: default-deny (fallback path needs it)");
    }
}

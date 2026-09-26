//! Root-only integration tests (`-- --include-ignored`): real veth pairs,
//! real XDP/TC attachments — the parts PROG_TEST_RUN cannot express.
//!
//!   * `skb_mode_pppoe_stripper_feeds_tc_intro_via_meta` — the SKB-mode
//!     deployment end to end: XDP stripper (generic mode) decaps a
//!     registered session and hands the resolved chain id to the TC
//!     ingress intro through skb metadata. NO IP selector is registered on
//!     the TC side, so the chain can only fire if the metadata survives the
//!     XDP→skb transition — the meta fast-path contract.
//!   * `native_two_sessions_dispatch_two_chains` — native XDP intro with
//!     two registered sessions tail-calling a chain root that reads the
//!     stored `xdp_pipe_meta` (chain id + frame count per session).
//!   * `native_session_miss_frame_reaches_tc_intact` — the pppd contract:
//!     an unregistered session passes native XDP unmodified; the TC ingress
//!     sniffer sees the 0x8864 frame with the session id intact.

use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, SkelBuilder as _};
use libbpf_rs::{MapCore, MapFlags};

use crate::tests::net_utils::{send_raw_packet, settle, wait_for, NetNsGuard, TCAttach, VethPair};

use super::{build_pppoe_frame, build_raw_ipv4, seed_ppp_session, PPP_PROTO_IPV4, PPP_PROTO_LCP};

const SID_A: u16 = 0x1010;
const SID_B: u16 = 0x2020;
const CHAIN_A: u32 = 11;
const CHAIN_B: u32 = 22;

/// Generic (SKB-mode) XDP attachment; detached with the same flags on drop.
struct XdpSkbAttach {
    ifindex: i32,
}

impl XdpSkbAttach {
    fn attach(prog: &libbpf_rs::Program, ifindex: i32) -> Self {
        let flags = libbpf_sys::XDP_FLAGS_SKB_MODE | libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST;
        let ret = unsafe {
            libbpf_sys::bpf_xdp_attach(ifindex, prog.as_fd().as_raw_fd(), flags, std::ptr::null())
        };
        assert_eq!(ret, 0, "bpf_xdp_attach(SKB mode) on ifindex {ifindex}");
        Self { ifindex }
    }
}

impl Drop for XdpSkbAttach {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_xdp_detach(
                self.ifindex,
                libbpf_sys::XDP_FLAGS_SKB_MODE,
                std::ptr::null(),
            );
        }
    }
}

fn dummy_meta_chain(map: &libbpf_rs::MapMut, v6: bool) -> Option<u32> {
    let k = if v6 { 1u32 } else { 0u32 }.to_ne_bytes();
    map.lookup(&k, MapFlags::ANY).unwrap().map(|v| u32::from_ne_bytes(v[8..12].try_into().unwrap()))
}

/// (count, chain_id) from `sniff_chain_map` (struct sniff_chain_record).
fn chain_record(map: &libbpf_rs::MapMut) -> (u64, u32) {
    let k = 0u32.to_ne_bytes();
    let v = map.lookup(&k, MapFlags::ANY).unwrap().expect("chain record");
    (
        u64::from_ne_bytes(v[0..8].try_into().unwrap()),
        u32::from_ne_bytes(v[8..12].try_into().unwrap()),
    )
}

/// (count buckets, last pppoe sid) from `sniff_ingress_map`
/// (struct sniff_ingress_record).
fn sniff_record(map: &libbpf_rs::MapMut) -> ([u64; 4], u16) {
    let k = 0u32.to_ne_bytes();
    let v = map.lookup(&k, MapFlags::ANY).unwrap().expect("sniff record");
    let counts = [
        u64::from_ne_bytes(v[0..8].try_into().unwrap()),
        u64::from_ne_bytes(v[8..16].try_into().unwrap()),
        u64::from_ne_bytes(v[16..24].try_into().unwrap()),
        u64::from_ne_bytes(v[24..32].try_into().unwrap()),
    ];
    let sid = u16::from_be_bytes([v[32], v[33]]);
    (counts, sid)
}

// ── SKB mode: stripper → metadata → TC intro fast path ────────────────

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn skb_mode_pppoe_stripper_feeds_tc_intro_via_meta() {
    let ns = NetNsGuard::create("sbm");
    let peer_ns = NetNsGuard::create("sbmp");
    let pair;
    {
        let _e = ns.enter();
        pair = VethPair::create_with_netns("sbm", &peer_ns);
    }
    let peer = pair.peer();
    let wan_ifindex = {
        let _e = ns.enter();
        pair.host_ifindex() as i32
    };

    let pin = crate::tests::isolated_pin_root("intro-skb-e2e");

    // SKB-mode stripper (the entry used when native XDP is unavailable)
    let mut stripper_b =
        crate::bpf_rs_shared::xdp_skb_pppoe_skel::XdpSkbPppoeSkelBuilder::default();
    stripper_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut stripper_obj = std::mem::MaybeUninit::uninit();
    let stripper = stripper_b.open(&mut stripper_obj).unwrap().load().unwrap();

    // TC ingress intro with the chain-stage test program as chain root
    let mut intro_b = crate::tests::tc_wan_intro_skel::TcWanIngressIntroSkelBuilder::default();
    intro_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut intro_obj = std::mem::MaybeUninit::uninit();
    let intro = intro_b.open(&mut intro_obj).unwrap().load().unwrap();

    let mut stage_b = crate::tests::test_tc_sniff_skel::TestTcSniffSkelBuilder::default();
    stage_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut stage_obj = std::mem::MaybeUninit::uninit();
    let stage = stage_b.open(&mut stage_obj).unwrap().load().unwrap();

    let stage_fd = stage.progs.tc_test_chain_stage.as_fd().as_raw_fd();
    intro
        .maps
        .tc_pipe_root_progs
        .update(&CHAIN_A.to_ne_bytes(), &stage_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // Register the session ONLY on the stripper side. The TC intro gets no
    // IP selector at all: entering the chain is possible exclusively via
    // the PPP-chain metadata written by the stripper.
    seed_ppp_session(&stripper.maps.wan_intro_dispatch_map, wan_ifindex as u32, SID_A, CHAIN_A);

    let _xdp;
    let _tc;
    {
        let _e = ns.enter();
        _xdp = XdpSkbAttach::attach(&stripper.progs.xdp_skb_pppoe, wan_ifindex);
        _tc = TCAttach::attach_ingress(&intro.progs.tc_wan_intro, wan_ifindex);
    }

    let inner = build_raw_ipv4([203, 0, 113, 9], [198, 51, 100, 7]);
    let hit = build_pppoe_frame(SID_A, PPP_PROTO_IPV4, &inner);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &hit);
    }

    wait_for("chain entry via PPP metadata", Duration::from_secs(5), || {
        let (count, chain_id) = chain_record(&stage.maps.sniff_chain_map);
        count == 1 && chain_id == CHAIN_A
    });

    // An unregistered session must NOT enter any chain (pppd owns it).
    let miss = build_pppoe_frame(SID_B, PPP_PROTO_IPV4, &inner);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &miss);
    }
    settle(300);
    let (count, _) = chain_record(&stage.maps.sniff_chain_map);
    assert_eq!(count, 1, "unregistered session must not enter a chain");

    drop(stage);
    drop(intro);
    drop(stripper);
}

// ── native mode: two sessions → two chains ────────────────────────────

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn native_two_sessions_dispatch_two_chains() {
    let ns = NetNsGuard::create("ntv");
    let peer_ns = NetNsGuard::create("ntvp");
    let pair;
    {
        let _e = ns.enter();
        pair = VethPair::create_with_netns("ntv", &peer_ns);
    }
    let peer = pair.peer();
    let wan_ifindex = {
        let _e = ns.enter();
        pair.host_ifindex() as i32
    };

    let pin = crate::tests::isolated_pin_root("intro-native-dual");

    let mut intro_b = crate::tests::wan_intro_skel::XdpWanIntroSkelBuilder::default();
    intro_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut intro_obj = std::mem::MaybeUninit::uninit();
    let intro = intro_b.open(&mut intro_obj).unwrap().load().unwrap();

    // One chain-root dummy serves both chains; the recorded meta.chain_id
    // tells them apart.
    let mut dummy_b = crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder::default();
    dummy_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut dummy_obj = std::mem::MaybeUninit::uninit();
    let dummy = dummy_b.open(&mut dummy_obj).unwrap().load().unwrap();

    let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
    for chain in [CHAIN_A, CHAIN_B] {
        intro
            .maps
            .xdp_pipe_root_progs
            .update(&chain.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
    }
    seed_ppp_session(&intro.maps.wan_intro_dispatch_map, wan_ifindex as u32, SID_A, CHAIN_A);
    seed_ppp_session(&intro.maps.wan_intro_dispatch_map, wan_ifindex as u32, SID_B, CHAIN_B);

    let _xdp;
    {
        let _e = ns.enter();
        _xdp = intro.progs.wan_intro_dispatch.attach_xdp(wan_ifindex).expect("native XDP attach");
    }

    let inner = build_raw_ipv4([203, 0, 113, 9], [198, 51, 100, 7]);
    for (sid, chain) in [(SID_A, CHAIN_A), (SID_B, CHAIN_B)] {
        crate::tests::net_utils::dummy_reset(&dummy.maps.dummy_recv_map);
        let pkt = build_pppoe_frame(sid, PPP_PROTO_IPV4, &inner);
        {
            let _e = peer_ns.enter();
            send_raw_packet(peer, &pkt);
        }
        wait_for(
            &format!("session {sid:#06x} reached chain {chain}"),
            Duration::from_secs(5),
            || {
                crate::tests::net_utils::dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
                    && dummy_meta_chain(&dummy.maps.dummy_meta_map, false) == Some(chain)
            },
        );
    }

    drop(dummy);
    drop(intro);
}

// ── native mode: session miss must reach the kernel intact (pppd) ─────

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn native_session_miss_frame_reaches_tc_intact() {
    let ns = NetNsGuard::create("ppdc");
    let peer_ns = NetNsGuard::create("ppdcp");
    let pair;
    {
        let _e = ns.enter();
        pair = VethPair::create_with_netns("ppdc", &peer_ns);
    }
    let peer = pair.peer();
    let wan_ifindex = {
        let _e = ns.enter();
        pair.host_ifindex() as i32
    };

    let pin = crate::tests::isolated_pin_root("intro-native-miss");

    let mut intro_b = crate::tests::wan_intro_skel::XdpWanIntroSkelBuilder::default();
    intro_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut intro_obj = std::mem::MaybeUninit::uninit();
    let intro = intro_b.open(&mut intro_obj).unwrap().load().unwrap();

    let mut sniff_b = crate::tests::test_tc_sniff_skel::TestTcSniffSkelBuilder::default();
    sniff_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut sniff_obj = std::mem::MaybeUninit::uninit();
    let sniff = sniff_b.open(&mut sniff_obj).unwrap().load().unwrap();

    // Some OTHER session is registered — misses are per session id, and the
    // frame must not be decapsulated for the registered one either way.
    seed_ppp_session(&intro.maps.wan_intro_dispatch_map, wan_ifindex as u32, SID_B, CHAIN_B);

    let _xdp;
    let _tc;
    {
        let _e = ns.enter();
        _xdp = intro.progs.wan_intro_dispatch.attach_xdp(wan_ifindex).expect("native XDP attach");
        _tc = TCAttach::attach_ingress(&sniff.progs.tc_test_sniff, wan_ifindex);
    }

    let inner = build_raw_ipv4([203, 0, 113, 9], [198, 51, 100, 7]);
    let miss = build_pppoe_frame(SID_A, PPP_PROTO_IPV4, &inner);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &miss);
    }

    wait_for("ppp-owned session frame reached TC ingress", Duration::from_secs(5), || {
        let (counts, _) = sniff_record(&sniff.maps.sniff_ingress_map);
        counts[2] == 1 // SNIFF_PPPOE bucket
    });
    let (_, last_sid) = sniff_record(&sniff.maps.sniff_ingress_map);
    assert_eq!(last_sid, SID_A, "the PPPoE header must arrive intact (pppd contract)");

    // LCP for a registered session id is equally pppd's business.
    let lcp = build_pppoe_frame(SID_B, PPP_PROTO_LCP, &[0xff, 0x03, 0xc0, 0x21, 0x01, 0x01]);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &lcp);
    }
    wait_for("LCP frame reached TC ingress", Duration::from_secs(5), || {
        let (counts, _) = sniff_record(&sniff.maps.sniff_ingress_map);
        counts[2] == 2
    });
    let (_, last_sid) = sniff_record(&sniff.maps.sniff_ingress_map);
    assert_eq!(last_sid, SID_B);

    drop(sniff);
    drop(intro);
}

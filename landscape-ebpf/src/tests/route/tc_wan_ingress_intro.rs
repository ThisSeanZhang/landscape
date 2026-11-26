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

use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use crate::landscape::OwnedOpenObject;
use crate::maps::wan_trie::arena::mapped_table;
use crate::maps::wan_trie::builder::{
    PrefixEntry, ppp_entry, v4_entry, v6_entry, wan_trie_publish,
};
use crate::skel::tc_wan_ingress_intro::{TcWanIngressIntroSkel, TcWanIngressIntroSkelBuilder};
use crate::skel::xdp_wan_route::XdpWanRouteSkelBuilder;
use crate::tests::helper::map::{
    ROUTE_TYPE_NEXTHOP, as_bytes, insert_route4_lan_entry, insert_route6_lan_entry,
};
use crate::tests::helper::net::{NetNsGuard, TCAttach, VethPair, send_raw_packet};
use crate::tests::isolated_pin_root;
use crate::tests::pkt::{
    simple_ipv4_tcp, simple_ipv6_tcp_syn, simple_pppoe_ipv4, simple_pppoe_ipv6,
};
use crate::tests::test_wan_trie_probe_skel::{TestWanTrieProbeSkel, TestWanTrieProbeSkelBuilder};

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

fn open_raw_recv_socket(ifindex: u32) -> socket2::Socket {
    let proto_be = (libc::ETH_P_ALL as u16).to_be();
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(i32::from(proto_be))),
    )
    .expect("create AF_PACKET raw socket");
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: proto_be,
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind AF_PACKET raw socket failed: {}", std::io::Error::last_os_error());
    sock.set_read_timeout(Some(Duration::from_millis(100))).expect("set raw socket read timeout");
    sock
}

fn recv_matching_frame(
    sock: &socket2::Socket,
    deadline: Duration,
    what: &str,
    mut matches: impl FnMut(&[u8]) -> bool,
) -> Vec<u8> {
    let start = Instant::now();
    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe {
            libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0)
        };
        if n > 0 {
            let frame = &buf[..n as usize];
            if matches(frame) {
                return frame.to_vec();
            }
        } else if n < 0 {
            let err = std::io::Error::last_os_error();
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ),
                "unexpected recv error while waiting for {what}: {err}"
            );
        }
        assert!(start.elapsed() < deadline, "timed out after {deadline:?} waiting for {what}");
    }
}

/// Real XDP -> TC `XDP_HANDOFF_TC_REDIRECT_NEIGH_MAGIC` consumer test.
///
/// Linux `bpf_prog_test_run_skb` (`convert___skb_to_skb`) rejects non-zero
/// `__sk_buff.data_meta` with `-EINVAL` and leaves `skb_shinfo->meta_len == 0`,
/// so TC metadata handoff cannot be synthesized via `PROG_TEST_RUN`. Attach
/// `xdp_wan_route_ingress` (producer) and `tc_wan_ingress_intro` with
/// `xdp_handoff_enabled = true` (consumer) onto the same veth inside an
/// isolated netns, then verify both IPv4 and IPv6 nexthop handoffs trigger
/// `bpf_redirect_neigh` and arrive on the target LAN peer with rewritten L2 MACs.
#[test]
fn xdp_mode_consumes_redirect_neigh_handoff_meta() {
    const WAN_SRC_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
    const WAN_DST_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02];
    const LAN_DEV_MAC: [u8; 6] = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    const NEXTHOP_MAC: [u8; 6] = [0x02, 0x55, 0x66, 0x77, 0x88, 0x99];

    let router_ns = NetNsGuard::create("twhr");
    let wan_peer_ns = NetNsGuard::create("twhw");
    let (wan_pair, lan_pair) = {
        let _e = router_ns.enter();
        (VethPair::create_with_netns("twhw", &wan_peer_ns), VethPair::create("twhl"))
    };

    let (wan_ifindex, lan_ifindex, lan_rx) = {
        let _e = router_ns.enter();
        let wan_ifindex = wan_pair.host_ifindex();
        let lan_ifindex = lan_pair.host_ifindex();
        let lan_peer_ifindex = lan_pair.peer_ifindex();

        for args in [
            ["link", "set", "dev", wan_pair.host(), "address", "02:aa:bb:cc:dd:02"],
            ["link", "set", "dev", lan_pair.host(), "address", "02:ee:dd:cc:bb:aa"],
            ["link", "set", "dev", lan_pair.peer(), "address", "02:55:66:77:88:99"],
        ] {
            assert!(Command::new("ip").args(args).status().unwrap().success());
        }

        // Seed permanent kernel neighbors WITHOUT kernel routes for the nexthops:
        // - In XDP, bpf_fib_lookup() misses (no route) -> emits 32B
        //   XDP_HANDOFF_TC_REDIRECT_NEIGH_MAGIC and returns XDP_PASS.
        // - In TC, tc_wan_ingress_intro consumes the magic and calls
        //   bpf_redirect_neigh(lan_ifindex, &param), which looks up the neighbor
        //   table directly and transmits the rewritten frame onto lan_pair.peer().
        assert!(
            Command::new("ip")
                .args([
                    "neigh",
                    "replace",
                    "192.168.50.1",
                    "lladdr",
                    "02:55:66:77:88:99",
                    "nud",
                    "permanent",
                    "dev",
                    lan_pair.host(),
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ip")
                .args([
                    "-6",
                    "neigh",
                    "replace",
                    "fd00:50::1",
                    "lladdr",
                    "02:55:66:77:88:99",
                    "nud",
                    "permanent",
                    "dev",
                    lan_pair.host(),
                ])
                .status()
                .unwrap()
                .success()
        );

        let lan_rx = open_raw_recv_socket(lan_peer_ifindex);
        (wan_ifindex, lan_ifindex, lan_rx)
    };

    let pin_root = isolated_pin_root("tc-intro-redir-neigh");
    let mut xb = XdpWanRouteSkelBuilder::default();
    xb.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut xobj = MaybeUninit::uninit();
    let xskel = xb.open(&mut xobj).expect("open xdp_wan_route").load().expect("load xdp_wan_route");

    let intro = load_intro(true);

    let dst4 = Ipv4Addr::new(10, 200, 0, 20);
    let nexthop4 = Ipv4Addr::new(192, 168, 50, 1);
    insert_route4_lan_entry(
        &xskel.maps.rt4_lan_map,
        24,
        Ipv4Addr::new(10, 200, 0, 0),
        nexthop4,
        ROUTE_TYPE_NEXTHOP,
        lan_ifindex,
        true,
        LAN_DEV_MAC,
    );

    let dst6 = Ipv6Addr::from_str("2001:db8:200::20").unwrap();
    let nexthop6 = Ipv6Addr::from_str("fd00:50::1").unwrap();
    insert_route6_lan_entry(
        &xskel.maps.rt6_lan_map,
        64,
        Ipv6Addr::from_str("2001:db8:200::").unwrap(),
        nexthop6,
        ROUTE_TYPE_NEXTHOP,
        lan_ifindex,
        true,
        LAN_DEV_MAC,
    );

    // Even if LAN supports native XDP redirect, cold FIB miss must hand off to TC neigh.
    let able: u32 = 1;
    xskel
        .maps
        .xdp_redirect_able
        .update(as_bytes(&lan_ifindex), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able");

    let _xdp_link;
    let _tc_attach;
    {
        let _e = router_ns.enter();
        _xdp_link = xskel
            .progs
            .xdp_wan_route_ingress
            .attach_xdp(wan_ifindex as i32)
            .expect("attach xdp_wan_route_ingress");
        _tc_attach =
            TCAttach::attach_ingress(&intro.skel.progs.tc_wan_ingress_intro, wan_ifindex as i32);
    }

    // 1) IPv4 cold nexthop handoff -> TC bpf_redirect_neigh(AF_INET, 192.168.50.1)
    let builder4 = PacketBuilder::ethernet2(WAN_SRC_MAC, WAN_DST_MAC)
        .ipv4([203, 0, 113, 7], dst4.octets(), 64)
        .tcp(443, 54321, 100, 4096);
    let mut pkt4 = Vec::with_capacity(builder4.size(8));
    builder4.write(&mut pkt4, &[0x11; 8]).expect("build ipv4 tcp");
    {
        let _e = wan_peer_ns.enter();
        send_raw_packet(wan_pair.peer(), &pkt4);
    }
    let rx4 = recv_matching_frame(
        &lan_rx,
        Duration::from_secs(5),
        "IPv4 TC redirect_neigh handoff on LAN peer",
        |f| f.len() >= 34 && f[12..14] == [0x08, 0x00] && f[30..34] == dst4.octets(),
    );
    assert_eq!(&rx4[0..6], &NEXTHOP_MAC, "IPv4 dst MAC must be resolved by bpf_redirect_neigh");
    assert_eq!(&rx4[6..12], &LAN_DEV_MAC, "IPv4 src MAC must be rewritten to LAN dev MAC");

    // 2) IPv6 cold nexthop handoff -> TC bpf_redirect_neigh(AF_INET6, fd00:50::1)
    let builder6 = PacketBuilder::ethernet2(WAN_SRC_MAC, WAN_DST_MAC)
        .ipv6(Ipv6Addr::from_str("2001:db8:1::7").unwrap().octets(), dst6.octets(), 64)
        .tcp(443, 54321, 100, 4096);
    let mut pkt6 = Vec::with_capacity(builder6.size(8));
    builder6.write(&mut pkt6, &[0x22; 8]).expect("build ipv6 tcp");
    {
        let _e = wan_peer_ns.enter();
        send_raw_packet(wan_pair.peer(), &pkt6);
    }
    let rx6 = recv_matching_frame(
        &lan_rx,
        Duration::from_secs(5),
        "IPv6 TC redirect_neigh handoff on LAN peer",
        |f| f.len() >= 54 && f[12..14] == [0x86, 0xdd] && f[38..54] == dst6.octets(),
    );
    assert_eq!(&rx6[0..6], &NEXTHOP_MAC, "IPv6 dst MAC must be resolved by bpf_redirect_neigh");
    assert_eq!(&rx6[6..12], &LAN_DEV_MAC, "IPv6 src MAC must be rewritten to LAN dev MAC");
}

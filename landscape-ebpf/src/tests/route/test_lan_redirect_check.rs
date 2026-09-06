//! Behaviour baseline for the three per-hook `lan_redirect_check`
//! implementations (F1 in_wan / F2 in_lan / F3 in_wan_egress).
//!
//! The tests lock CURRENT behaviour before any dedup refactor. Rows where the
//! three functions disagree (WAN-typed entries, same-iface handling) are
//! intentional baselines, not bugs — see the NOTE comments in
//! route4_path.h / route6_path.h (`tc_route[46]_lan_redirect_check_in_wan`).
//!
//! PROG_TEST_RUN verdict mapping observed on this kernel for SCHED_CLS
//! programs (verified empirically with bare return probes):
//!   TC_ACT_OK     (0) ->  0
//!   TC_ACT_UNSPEC (2) -> -1   (0xFFFFFFFF)
//!   TC_ACT_SHOT   (3) ->  2
//!   TC_ACT_REDIRECT(7) ->  7
//! All expectations below use RET_* constants matching that mapping.
//!
//! test_run caveats:
//!   * skb->ifindex is kernel-chosen (non-zero) while ingress_ifindex is 0,
//!     so only F2's same-iface branch (ingress_ifindex based) is controllable;
//!   * bpf_redirect(any) returns TC_ACT_REDIRECT (7) without device validation;
//!   * the `redirect_neigh` fallback and the l3_offset == 0 dummy-eth prepend
//!     branch are NOT covered here (unreliable under PROG_TEST_RUN).

use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::tests::{
    isolated_pin_root,
    route::{
        map_helper::{
            insert_ip_mac_v6, insert_route4_lan_entry, insert_route6_lan_entry, LAN_ROUTE_TYPE,
            TARGET_IFINDEX, WAN_ROUTE_TYPE,
        },
        packet_builder::{simple_ipv4_tcp, simple_ipv6_tcp_syn},
        test_route::TestRouteSkelBuilder,
    },
};

/// Observed PROG_TEST_RUN return values (see module docs).
const RET_OK: i32 = 0;
const RET_UNSPEC: i32 = -1;
const RET_REDIRECT: i32 = 7;

fn mac(a: [u8; 6]) -> MacAddr {
    MacAddr(a[0], a[1], a[2], a[3], a[4], a[5])
}

fn v6_src() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00::10").unwrap()
}
fn v6_dst() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00::20").unwrap()
}
fn v6_other() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00::99").unwrap()
}
fn v4_src() -> Ipv4Addr {
    Ipv4Addr::from_str("192.168.1.10").unwrap()
}
fn v4_dst() -> Ipv4Addr {
    Ipv4Addr::from_str("192.168.1.20").unwrap()
}
fn v4_other() -> Ipv4Addr {
    Ipv4Addr::from_str("192.168.1.99").unwrap()
}

struct V6Expect {
    in_wan: i32,
    in_lan: i32,
    in_wan_egress: i32,
}

fn run_v6_progs(
    skel: &crate::tests::route::test_route::TestRouteSkel<'_>,
    label: &str,
    expect: &V6Expect,
) {
    let pkt = simple_ipv6_tcp_syn(v6_src(), v6_dst());
    for (prog, name, want) in [
        (&skel.progs.test_route6_lan_redirect_check_in_wan, "in_wan", expect.in_wan),
        (&skel.progs.test_route6_lan_redirect_check_in_lan, "in_lan", expect.in_lan),
        (
            &skel.progs.test_route6_lan_redirect_check_in_wan_egress,
            "in_wan_egress",
            expect.in_wan_egress,
        ),
    ] {
        let mut out = vec![0_u8; pkt.len()];
        let r = prog
            .test_run(ProgramInput {
                data_in: Some(&pkt),
                data_out: Some(&mut out),
                ..Default::default()
            })
            .expect(label);
        assert_eq!(
            r.return_value as i32,
            want,
            "{label}: v6 {name} return (packet dst {})",
            v6_dst()
        );
    }
}

/// v6 scenario with a single lan entry; asserts the three return codes.
fn v6_with_entry(
    pin: &str,
    prefix: u8,
    key_addr: Ipv6Addr,
    value_addr: Ipv6Addr,
    route_type: u8,
    ifindex: u32,
    has_mac: bool,
    expect: &V6Expect,
) {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root(pin);
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        prefix,
        key_addr,
        value_addr,
        route_type,
        ifindex,
        has_mac,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    run_v6_progs(&skel, pin, expect);
}

// ---------------------------------------------------------------------------
// v6 matrix
// ---------------------------------------------------------------------------

#[test]
fn v6_lan_redirect_miss_passes_through_all_three() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("lan-redirect-v6-miss");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    run_v6_progs(
        &skel,
        "v6 miss",
        &V6Expect {
            in_wan: RET_OK,
            in_lan: RET_OK,
            in_wan_egress: RET_OK,
        },
    );
}

#[test]
fn v6_wan_self_entry() {
    // WAN-typed entry with addr == daddr: F1/F2 hand to the stack (UNSPEC),
    // F3 (egress context, no self-address concept) lets it continue.
    v6_with_entry(
        "lan-redirect-v6-wan-self",
        128,
        v6_dst(),
        v6_dst(),
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        &V6Expect {
            in_wan: RET_UNSPEC,
            in_lan: RET_UNSPEC,
            in_wan_egress: RET_OK,
        },
    );
}

#[test]
fn v6_wan_other_entry() {
    // WAN-typed entry (prefix wider than a single address, addr != daddr):
    // F1 SUSPECTED-BUG falls through into the redirect tail and returns
    // REDIRECT; F2/F3 skip (baseline only, see NOTE in route6_path.h).
    v6_with_entry(
        "lan-redirect-v6-wan-other",
        64,
        Ipv6Addr::from_str("fd00::1").unwrap(),
        Ipv6Addr::from_str("fd00::1").unwrap(),
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        &V6Expect {
            in_wan: RET_REDIRECT,
            in_lan: RET_OK,
            in_wan_egress: RET_OK,
        },
    );
}

#[test]
fn v6_lan_self_addr_entry() {
    // LAN-typed entry with addr == daddr (the router's own address on the
    // segment): all three hand the packet to the stack.
    v6_with_entry(
        "lan-redirect-v6-lan-self",
        128,
        v6_dst(),
        v6_dst(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        &V6Expect {
            in_wan: RET_UNSPEC,
            in_lan: RET_UNSPEC,
            in_wan_egress: RET_UNSPEC,
        },
    );
}

#[test]
fn v6_lan_other_no_mac_redirects() {
    // LAN-typed entry on another iface without mac: plain redirect on all
    // three hooks.
    v6_with_entry(
        "lan-redirect-v6-lan-nomac",
        128,
        v6_dst(),
        v6_other(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        &V6Expect {
            in_wan: RET_REDIRECT,
            in_lan: RET_REDIRECT,
            in_wan_egress: RET_REDIRECT,
        },
    );
}

#[test]
fn v6_lan_other_with_mac_rewrites_and_redirects() {
    // LAN-typed entry on another iface with a known host mac: dst mac is
    // rewritten (ip_mac host mac), src mac from the lan entry, then redirect.
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("lan-redirect-v6-lan-mac");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let host_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    insert_ip_mac_v6(
        &skel.maps.ip_mac_v6,
        v6_dst(),
        mac(host_mac),
        mac([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        TARGET_IFINDEX,
    );
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        v6_dst(),
        v6_other(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    let pkt = simple_ipv6_tcp_syn(v6_src(), v6_dst());
    for (prog, name, want) in [
        (&skel.progs.test_route6_lan_redirect_check_in_wan, "in_wan", RET_REDIRECT),
        (&skel.progs.test_route6_lan_redirect_check_in_lan, "in_lan", RET_REDIRECT),
        (&skel.progs.test_route6_lan_redirect_check_in_wan_egress, "in_wan_egress", RET_REDIRECT),
    ] {
        let mut out = vec![0_u8; pkt.len()];
        let r = prog
            .test_run(ProgramInput {
                data_in: Some(&pkt),
                data_out: Some(&mut out),
                ..Default::default()
            })
            .expect("lan-mac");
        assert_eq!(r.return_value as i32, want, "v6 {name} return");
        assert_eq!(&out[0..6], &host_mac, "v6 {name} dst mac");
        assert_eq!(&out[6..12], &[0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa], "v6 {name} src mac");
        assert_eq!(&out[12..14], &[0x86, 0xdd], "v6 {name} ethertype");
    }
}

#[test]
fn v6_f2_same_iface_hairpin_rewrites_and_reinjects() {
    // F2-only: lan entry on the ingress iface (ifindex 0 == ingress_ifindex in
    // test_run). The dst mac is rewritten to the ip_mac host entry and the
    // packet re-injected (bpf_redirect(0) reads TC_ACT_REDIRECT in this
    // harness). F1/F3 same-iface branches are not reachable here because
    // skb->ifindex is kernel-chosen and non-zero.
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("lan-redirect-v6-f2-hairpin");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let host_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let ip_mac_dev = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    insert_ip_mac_v6(
        &skel.maps.ip_mac_v6,
        v6_dst(),
        mac(host_mac),
        mac(ip_mac_dev),
        TARGET_IFINDEX,
    );
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        v6_dst(),
        v6_other(),
        LAN_ROUTE_TYPE,
        0, // == ingress_ifindex under test_run
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    let pkt = simple_ipv6_tcp_syn(v6_src(), v6_dst());
    let mut out = vec![0_u8; pkt.len()];
    let r = skel
        .progs
        .test_route6_lan_redirect_check_in_lan
        .test_run(ProgramInput {
            data_in: Some(&pkt),
            data_out: Some(&mut out),
            ..Default::default()
        })
        .expect("same-iface in_lan");
    assert_eq!(r.return_value as i32, RET_REDIRECT, "F2 same-iface hairpin");
    // Hairpin store writes the ip_mac value (mac + dev_mac), NOT the lan
    // entry mac_addr — this distinguishes the hairpin branch from the tail.
    assert_eq!(&out[0..6], &host_mac, "F2 hairpin dst mac");
    assert_eq!(&out[6..12], &ip_mac_dev, "F2 hairpin src mac");
    assert_eq!(&out[12..14], &[0x86, 0xdd], "F2 hairpin ethertype");
}

#[test]
fn v6_f2_same_iface_mac_miss_is_unspec() {
    // F2-only: same-ingress-iface entry but no ip_mac entry for the dst: no
    // mac to rewrite with, hand back to the stack (UNSPEC).
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("lan-redirect-v6-f2-hairpin-miss");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        v6_dst(),
        v6_other(),
        LAN_ROUTE_TYPE,
        0,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );

    let pkt = simple_ipv6_tcp_syn(v6_src(), v6_dst());
    let mut out = vec![0_u8; pkt.len()];
    let r = skel
        .progs
        .test_route6_lan_redirect_check_in_lan
        .test_run(ProgramInput {
            data_in: Some(&pkt),
            data_out: Some(&mut out),
            ..Default::default()
        })
        .expect("same-iface mac miss in_lan");
    assert_eq!(r.return_value as i32, RET_UNSPEC, "F2 same-iface mac miss");
    assert_eq!(&out, &pkt, "F2 same-iface mac miss leaves packet untouched");
}

// ---------------------------------------------------------------------------
// v4 smoke matrix (subset of the v6 rows)
// ---------------------------------------------------------------------------

fn run_v4_progs(
    skel: &crate::tests::route::test_route::TestRouteSkel<'_>,
    label: &str,
    want: [i32; 3],
) {
    let pkt = simple_ipv4_tcp(v4_src(), v4_dst());
    for (prog, want) in [
        (&skel.progs.test_route4_lan_redirect_check_in_wan, want[0]),
        (&skel.progs.test_route4_lan_redirect_check_in_lan, want[1]),
        (&skel.progs.test_route4_lan_redirect_check_in_wan_egress, want[2]),
    ] {
        let mut out = vec![0_u8; pkt.len()];
        let r = prog
            .test_run(ProgramInput {
                data_in: Some(&pkt),
                data_out: Some(&mut out),
                ..Default::default()
            })
            .expect(label);
        assert_eq!(r.return_value as i32, want, "{label}: v4 return (packet dst {})", v4_dst());
    }
}

#[test]
fn v4_smoke_miss_passes() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("lan-redirect-v4-miss");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    run_v4_progs(&skel, "v4 miss", [RET_OK; 3]);
}

#[test]
fn v4_smoke_wan_self() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("lan-redirect-v4-wan-self");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        v4_dst(),
        v4_dst(),
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    run_v4_progs(&skel, "v4 wan-self", [RET_UNSPEC, RET_UNSPEC, RET_OK]);
}

#[test]
fn v4_smoke_lan_other_no_mac_redirects() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("lan-redirect-v4-lan-nomac");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        v4_dst(),
        v4_other(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    run_v4_progs(&skel, "v4 lan-nomac", [RET_REDIRECT; 3]);
}

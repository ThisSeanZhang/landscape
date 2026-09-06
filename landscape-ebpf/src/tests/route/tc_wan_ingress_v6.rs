//! v6 baseline for the `tc_route6_wan_ingress` worker. Mirrors
//! `tc_wan_ingress.rs`; v6 specifics are called out inline.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};
use zerocopy::IntoBytes;

use crate::tests::{
    isolated_pin_root,
    route::{
        map_helper::{
            as_bytes, create_route6_cache_inner_map, insert_ip_mac_v6, insert_route6_lan_entry,
            lookup_rt6_cache_value, put_rt6_cache_value, LAN_CACHE, LAN_ROUTE_TYPE,
            ROUTE_TYPE_NEXTHOP, TARGET_IFINDEX, WAN_CACHE, WAN_IFINDEX, WAN_ROUTE_TYPE,
        },
        packet_builder::{simple_ipv4_tcp, simple_ipv6_tcp_syn},
    },
    TestSkb,
};

pub(crate) mod tc_wan_ingress_exit {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_exit.skel.rs"));
}
use tc_wan_ingress_exit::TcWanIngressExitSkel;

const RET_OK: i32 = 0;
const RET_UNSPEC: i32 = -1;
const RET_REDIRECT: i32 = 7;

const INGRESS_STATIC_MARK: u32 = 1;

/// skb->ifindex under PROG_TEST_RUN when ctx.ifindex <= 1 (loopback dev).
const LOOPBACK_IFINDEX: u32 = 1;

fn public_src() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:1::7").unwrap()
}
fn lan_client() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00::20").unwrap()
}

/// The wan-side self address (bound to the ingress wan device in tests).
fn wan_self_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:ffff::10").unwrap()
}

fn wan_ctx(mark: u32) -> TestSkb {
    TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        mark,
        cb: [0, 14, 0, 0, 0], // cb[1] = l3 offset, written by the wan ingress root
        ..Default::default()
    }
}

macro_rules! load_skel {
    ($pin:expr, $skel:ident) => {
        let pin_root = isolated_pin_root($pin);
        let mut builder = tc_wan_ingress_exit::TcWanIngressExitSkelBuilder::default();
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = std::mem::MaybeUninit::uninit();
        let $skel = builder.open(&mut open_object).unwrap().load().unwrap();
    };
}

fn run_wan6_ingress(
    skel: &TcWanIngressExitSkel<'_>,
    pkt: &[u8],
    ctx: &mut TestSkb,
) -> (i32, Vec<u8>) {
    let mut out = vec![0_u8; pkt.len()];
    let result = skel
        .progs
        .tc_route6_wan_ingress
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route6_wan_ingress");
    (result.return_value as i32, out)
}

fn seed_wan_self_binding(skel: &TcWanIngressExitSkel<'_>) {
    crate::maps::wan::add_wan_ip(
        &skel.maps.wan_ip_binding,
        WAN_IFINDEX,
        IpAddr::V6(wan_self_addr()),
        None,
        64,
        None,
    );
}

fn reply_pkt() -> Vec<u8> {
    simple_ipv6_tcp_syn(public_src(), lan_client())
}

fn seed_lan_entry(skel: &TcWanIngressExitSkel<'_>, has_mac: bool) {
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        lan_client(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        has_mac,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
}

#[test]
fn wan6_ingress_own_address_goes_to_stack_without_cache() {
    load_skel!("tc-wan6-self", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_wan_self_binding(&skel);

    let pkt = simple_ipv6_tcp_syn(public_src(), wan_self_addr());
    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "daddr == wan ingress address must go to the stack");
    assert_eq!(out, pkt);
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, wan_self_addr(), public_src())
            .is_none(),
        "self-addressed traffic must never be cached"
    );
}

#[test]
fn wan6_ingress_lan_redirect_without_static_mark_skips_cache() {
    load_skel!("tc-wan6-nomark", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, false);

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT);
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "cache write is gated on INGRESS_STATIC_MARK"
    );
}

#[test]
fn wan6_ingress_lan_redirect_with_static_mark_writes_reverse_wan_cache() {
    load_skel!("tc-wan6-static", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, false);

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse WAN-cache entry must be written");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
    assert_eq!(cache.has_mac, 1);
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, public_src(), lan_client())
            .is_none(),
        "forward-direction key must not exist"
    );
}

#[test]
fn wan6_ingress_no_lan_entry_passes_with_static_mark() {
    load_skel!("tc-wan6-miss", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_wan_self_binding(&skel);

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_OK, "no lan entry → continue through the wan pipe");
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "no redirect → no cache write"
    );
}

#[test]
fn wan6_ingress_wan_typed_self_entry_hands_to_stack() {
    load_skel!("tc-wan6-wan-self", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        lan_client(),
        lan_client(), // addr == daddr
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "WAN-typed entry whose addr is the daddr itself");
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "no redirect → no cache write"
    );
}

#[test]
fn wan6_ingress_wan_typed_other_entry_falls_through_to_redirect() {
    // SUSPECTED-BUG baseline (NOTE in route6_path.h F1): WAN-typed hit with
    // addr != daddr keeps executing into the LAN redirect tail — same as v4.
    load_skel!("tc-wan6-wan-other", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        lan_client(),
        Ipv6Addr::from_str("fd00::1").unwrap(), // addr != daddr
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT, "F1 fall-through baseline: WAN-typed entry redirects");
}

#[test]
fn wan6_ingress_has_mac_entry_rewrites_header_then_redirects() {
    load_skel!("tc-wan6-mac", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, true);
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, lan_client(), host_mac, dev_mac, TARGET_IFINDEX);

    let (ret, out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &host_mac.octets());
    assert_eq!(&out[6..12], &[0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]);
    assert_eq!(&out[12..14], &[0x86, 0xdd]);

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("static mark must still cache the reverse path");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
}

#[test]
fn wan6_ingress_lan_entry_same_iface_hands_to_stack() {
    // F1 same-ifindex guard (compares skb->ifindex).
    load_skel!("tc-wan6-sameif", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        lan_client(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        LOOPBACK_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "entry pointing at the incoming device itself");
    assert_eq!(out, reply_pkt());
    assert!(lookup_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        lan_client(),
        public_src()
    )
    .is_none());
}

#[test]
fn wan6_ingress_has_mac_entry_without_ip_mac_falls_to_neigh() {
    load_skel!("tc-wan6-macmiss", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, true);
    // no ip_mac_v6 entry for daddr

    let pkt = reply_pkt();
    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

#[test]
fn wan6_ingress_raw_l3_frame_prepends_mac_and_redirects() {
    // cb[1] == 0: raw L3 frame. F1 prepends a 14-byte eth header (86dd) and
    // the reverse cache entry records has_mac = 0.
    load_skel!("tc-wan6-rawl3", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, true);
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, lan_client(), host_mac, dev_mac, TARGET_IFINDEX);

    let raw = &simple_ipv6_tcp_syn(public_src(), lan_client())[14..]; // strip eth
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        mark: INGRESS_STATIC_MARK,
        cb: [0, 0, 0, 0, 0],
        ..Default::default()
    };
    let mut out = vec![0_u8; raw.len() + 64];
    let result = skel
        .progs
        .tc_route6_wan_ingress
        .test_run(ProgramInput {
            data_in: Some(raw),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route6_wan_ingress");
    let ret = result.return_value as i32;

    assert_eq!(ret, RET_REDIRECT);
    let written = result.data.expect("data_out must be returned");
    assert_eq!(written.len(), raw.len() + 14, "eth header must be prepended");
    assert_eq!(&written[0..6], &host_mac.octets());
    assert_eq!(&written[6..12], &[0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]);
    assert_eq!(&written[12..14], &[0x86, 0xdd]);
    assert_eq!(&written[14..], raw, "L3 payload must be untouched");

    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("static mark must cache the reverse path");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
    assert_eq!(cache.has_mac, 0, "l3_offset == 0 must record has_mac = 0");
}

#[test]
fn wan6_ingress_non_matching_wan_binding_continues_to_lan_redirect() {
    load_skel!("tc-wan6-bindmiss", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_wan_self_binding(&skel);
    seed_lan_entry(&skel, false);

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT, "non-matching binding must not swallow the packet");
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("redirect under static mark must still cache the reverse path");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
}

#[test]
fn wan6_ingress_static_mark_insert_sets_xdp_flag() {
    // set_cache_in_wan insert row (TRUE row of the xdp flag, key = skb->ifindex).
    load_skel!("tc-wan6-xdp-able", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, false);
    let able: u32 = 1;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&LOOPBACK_IFINDEX), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able[skb ifindex]");

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse WAN-cache entry must be written");
    assert_eq!(cache.xdp_redirect_able, 1);
}

#[test]
fn wan6_ingress_multicast_dst_hands_to_stack() {
    // v6-specific: multicast (ff00::/8) and link-local (fe80::/10) targets
    // are "broadcast-like" for the v6 worker.
    load_skel!("tc-wan6-mcast", skel);
    let pkt = simple_ipv6_tcp_syn(public_src(), Ipv6Addr::from_str("ff02::1").unwrap());
    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(0));
    assert_eq!(ret, RET_UNSPEC);
    assert_eq!(out, pkt);
}

#[test]
fn wan6_ingress_link_local_dst_hands_to_stack() {
    load_skel!("tc-wan6-linklocal", skel);
    let pkt = simple_ipv6_tcp_syn(public_src(), Ipv6Addr::from_str("fe80::1").unwrap());
    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(0));
    assert_eq!(ret, RET_UNSPEC);
    assert_eq!(out, pkt);
}

#[test]
fn wan6_ingress_arp_frame_passes_through() {
    load_skel!("tc-wan6-arp", skel);
    let mut pkt = vec![0xff_u8; 14 + 28];
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(0));
    assert_eq!(ret, RET_OK, "non-IP frames pass through the wan ingress worker");
    assert_eq!(out, pkt);
}

#[test]
fn wan6_ingress_ipv4_frame_hands_to_stack() {
    // route6_read_context_from_scan non-v6 row.
    load_skel!("tc-wan6-v4frame", skel);
    let pkt = simple_ipv4_tcp(
        Ipv4Addr::from_str("192.168.1.10").unwrap(),
        Ipv4Addr::from_str("10.0.0.20").unwrap(),
    );
    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(0));
    assert_eq!(ret, RET_OK);
    assert_eq!(out, pkt);
}

// ---------------------------------------------------------------------------
// F1 remaining rows: LAN own-addr + NEXTHOP
// ---------------------------------------------------------------------------

#[test]
fn wan6_ingress_lan_typed_own_addr_hands_to_stack() {
    // F1 row (route6_path.h:70-73): a LAN-typed entry whose addr equals the
    // daddr → UNSPEC before the redirect tail (and no cache write).
    load_skel!("tc-wan6-lan-self", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        lan_client(),
        lan_client(), // addr == daddr
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "LAN-typed entry for the daddr itself");
    assert_eq!(out, reply_pkt());
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "no redirect → no cache write"
    );
}

#[test]
fn wan6_ingress_nexthop_entry_resolves_mac_by_nh_addr() {
    // F1 NEXTHOP rows: the mac key comes from lan_info->addr (the nexthop),
    // not from the daddr.
    load_skel!("tc-wan6-nexthop", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        lan_client(),
        Ipv6Addr::from_str("fd00::1").unwrap(), // nexthop address
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        entry_mac,
    );
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v6(
        &skel.maps.ip_mac_v6,
        Ipv6Addr::from_str("fd00::1").unwrap(),
        gw_mac,
        gw_dev,
        TARGET_IFINDEX,
    );

    let (ret, out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v6(dst = ip_mac[nexthop].mac, src = lan entry mac_addr)
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &entry_mac);
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
}

#[test]
fn wan6_ingress_nexthop_without_mac_falls_to_neigh() {
    // F1 NEXTHOP + has_mac but no ip_mac_v6[nexthop]: falls into
    // bpf_redirect_neigh with the nexthop address as parameter.
    load_skel!("tc-wan6-nexthop-miss", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        lan_client(),
        Ipv6Addr::from_str("fd00::1").unwrap(),
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    // no ip_mac_v6 entry for the nexthop

    let pkt = reply_pkt();
    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

// ---------------------------------------------------------------------------
// raw L3 (cb[1] == 0) + no-mac combination
// ---------------------------------------------------------------------------

#[test]
fn wan6_ingress_raw_l3_no_mac_entry_redirects_bare() {
    // cb[1] == 0 with a mac-less entry: the eth-header prepend is gated on
    // has_mac, so the bare L3 skb is redirected as-is.
    load_skel!("tc-wan6-rawl3-nomac", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, false);

    let raw = &simple_ipv6_tcp_syn(public_src(), lan_client())[14..]; // strip eth
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        mark: 0,
        cb: [0, 0, 0, 0, 0], // cb[1] = 0 → l3_offset 0
        ..Default::default()
    };
    let (ret, out) = run_wan6_ingress(&skel, raw, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, raw, "no eth header may be prepended for a mac-less entry");
}

// ---------------------------------------------------------------------------
// truncation
// ---------------------------------------------------------------------------

#[test]
fn wan6_ingress_truncated_ip6_header_passes_to_stack() {
    // read_context truncation row (v6): ethertype claims IPv6 but the ip6
    // header is cut short → SHOT from read_context, mapped to "pass".
    load_skel!("tc-wan6-runt", skel);
    let mut pkt = vec![0xff_u8; 14 + 20]; // eth + partial ip6 header
    pkt[12] = 0x86;
    pkt[13] = 0xdd;

    let (ret, out) = run_wan6_ingress(&skel, &pkt, &mut wan_ctx(0));

    assert_eq!(ret, RET_OK, "truncated ip6 header must pass, not drop");
    assert_eq!(out, pkt);
}

// ---------------------------------------------------------------------------
// get_cache_mask semantics (low 8 bits only)
// ---------------------------------------------------------------------------

#[test]
fn wan6_ingress_static_mark_with_flow_bits_still_writes_cache() {
    // get_cache_mask only looks at the low 8 bits: flow-id/action bits above
    // the mask do not close the gate.
    load_skel!("tc-wan6-mask-hi", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    seed_lan_entry(&skel, false);

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(0x0305_0001));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("low mask byte 1 must satisfy the cache gate");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
}

// ---------------------------------------------------------------------------
// set_cache_in_wan v6 mirrors of the v4 cacheupd / lancache rows
// ---------------------------------------------------------------------------

#[test]
fn wan6_ingress_existing_wan_cache_entry_updated_in_place() {
    // set_cache_in_wan update row (route6_path.h:644-648): an existing
    // reverse entry gets its ifindex / has_mac / xdp flag refreshed while the
    // mark stays untouched.
    load_skel!("tc-wan6-cacheupd", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        lan_client(),
        public_src(),
        99,    // stale ifindex
        false, // stale has_mac
        0x1234,
    );
    seed_lan_entry(&skel, false);

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse entry must survive");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX, "ifindex refreshed to skb->ifindex");
    assert_eq!(cache.has_mac, 1, "l3_offset 14 must flip has_mac to 1");
    assert_eq!(cache.xdp_redirect_able, 0, "no xdp target in the harness");
    assert_eq!(cache.mark_value, 0x1234, "the mark value is never rewritten");
}

#[test]
fn wan6_ingress_existing_wan_cache_entry_xdp_flag_refreshed() {
    // set_cache_in_wan update row: the xdp flag is refreshed from the
    // xdp_redirect_able map keyed by skb->ifindex (TRUE row).
    load_skel!("tc-wan6-cacheupd-xdp", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        lan_client(),
        public_src(),
        99,
        false,
        0x1234,
    );
    seed_lan_entry(&skel, false);
    let able: u32 = 1;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&LOOPBACK_IFINDEX), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able[skb ifindex]");

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse entry must survive");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
    assert_eq!(cache.xdp_redirect_able, 1, "update row must refresh the xdp flag to 1");
}

#[test]
fn wan6_ingress_reverse_entry_in_lan_cache_blocks_wan_write() {
    // set_cache_in_wan checks the LAN cache first: if the reverse entry is
    // already there, the wan cache write is skipped entirely.
    load_skel!("tc-wan6-lancache", skel);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    put_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        lan_client(),
        public_src(),
        TARGET_IFINDEX,
        false,
        0,
    );
    seed_lan_entry(&skel, false);

    let (ret, _out) = run_wan6_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "lan-cache hit must suppress the wan cache write"
    );
}

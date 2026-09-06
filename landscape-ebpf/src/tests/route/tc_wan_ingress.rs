//! IPv4 whole-flow baseline for the WAN-ingress route worker
//! `tc_route4_wan_ingress` (tc_wan_ingress_exit.bpf.c).
//!
//! Each test runs the complete worker pipeline once — scan (l3 offset from
//! cb[1], normally written by tc_wan_chain_ingress_root) →
//! is_current_wan_packet → lan_redirect_check_in_wan → set_cache_in_wan —
//! and locks the current behaviour before any route rewrite.
//!
//! Baseline quirks locked here (see route4_path.h /
//! tc_wan_ingress_exit.bpf.c):
//!   * packets whose daddr equals the ingress WAN address go to the stack
//!     (UNSPEC) before the lan lookup and never touch the cache;
//!   * the reverse-path WAN-cache entry is written ONLY when
//!     get_cache_mask(skb->mark) == INGRESS_STATIC_MARK (set by the NAT stage)
//!     and only after a successful redirect; the cached ifindex is
//!     skb->ifindex;
//!   * F1 (in_wan) WAN-typed lan entries with addr != daddr fall through into
//!     the redirect tail — a suspected bug (the in_lan / in_wan_egress twins
//!     return OK instead), locked as current behaviour;
//!   * l3_offset > 0 → cached entries get has_mac = 1.
//!
//! PROG_TEST_RUN verdict mapping: OK=0, UNSPEC=-1, SHOT=2, REDIRECT=7.
//! ctx.ifindex = 1 (loopback) so no real device is required.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
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
            as_bytes, create_route4_cache_inner_map, insert_ip_mac_v4, insert_route4_lan_entry,
            lookup_rt4_cache_value, put_rt4_cache_value, LAN_CACHE, LAN_ROUTE_TYPE,
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

fn public_src() -> Ipv4Addr {
    Ipv4Addr::from_str("203.0.113.7").unwrap()
}
fn lan_client() -> Ipv4Addr {
    Ipv4Addr::from_str("192.168.1.20").unwrap()
}
fn wan_self_addr() -> Ipv4Addr {
    Ipv4Addr::from_str("100.64.0.1").unwrap()
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

fn run_wan_ingress(
    skel: &TcWanIngressExitSkel<'_>,
    pkt: &[u8],
    ctx: &mut TestSkb,
) -> (i32, Vec<u8>) {
    let mut out = vec![0_u8; pkt.len()];
    let result = skel
        .progs
        .tc_route4_wan_ingress
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route4_wan_ingress");
    (result.return_value as i32, out)
}

fn seed_wan_self_binding(skel: &TcWanIngressExitSkel<'_>) {
    crate::maps::wan::add_wan_ip(
        &skel.maps.wan_ip_binding,
        WAN_IFINDEX,
        std::net::IpAddr::V4(wan_self_addr()),
        None,
        24,
        None,
    );
}

fn reply_pkt() -> Vec<u8> {
    simple_ipv4_tcp(public_src(), lan_client())
}

#[test]
fn wan_ingress_own_address_goes_to_stack_without_cache() {
    load_skel!("tc-wan-in-flow-self", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    seed_wan_self_binding(&skel);

    let pkt = simple_ipv4_tcp(public_src(), wan_self_addr());
    // static mark: even so, the self-address check runs first and must not cache
    let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "daddr == wan ingress address must go to the stack");
    assert_eq!(out, pkt);
    assert!(
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, wan_self_addr(), public_src())
            .is_none(),
        "self-addressed traffic must never be cached"
    );
}

#[test]
fn wan_ingress_lan_redirect_without_static_mark_skips_cache() {
    load_skel!("tc-wan-in-flow-nomark", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT);
    assert!(
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "cache write is gated on INGRESS_STATIC_MARK"
    );
}

#[test]
fn wan_ingress_lan_redirect_with_static_mark_writes_reverse_wan_cache() {
    load_skel!("tc-wan-in-flow-static", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse WAN-cache entry must be written");
    // The cached ifindex is skb->ifindex (the ingress wan device) and
    // has_mac derives from l3_offset > 0.
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
    assert_eq!(cache.has_mac, 1);
    // forward-direction key must not exist
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        public_src(),
        lan_client()
    )
    .is_none());
}

#[test]
fn wan_ingress_no_lan_entry_passes_with_static_mark() {
    load_skel!("tc-wan-in-flow-miss", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    seed_wan_self_binding(&skel);

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_OK, "no lan entry → continue through the wan pipe");
    assert!(
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "no redirect → no cache write"
    );
}

#[test]
fn wan_ingress_wan_typed_self_entry_hands_to_stack() {
    load_skel!("tc-wan-in-flow-wan-self", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        lan_client(), // addr == daddr
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "WAN-typed entry whose addr is the daddr itself");
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        lan_client(),
        public_src()
    )
    .is_none());
}

#[test]
fn wan_ingress_wan_typed_other_entry_falls_through_to_redirect() {
    // SUSPECTED-BUG baseline (see NOTE in route4_path.h
    // tc_route4_lan_redirect_check_in_wan): F1 keeps executing after a
    // WAN-typed hit with addr != daddr and ends up redirecting, unlike the
    // in_lan / in_wan_egress twins which return OK. Locked as-is.
    load_skel!("tc-wan-in-flow-wan-other", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.0").unwrap(), // addr != daddr
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT, "F1 fall-through baseline: WAN-typed entry redirects");
}

#[test]
fn wan_ingress_has_mac_entry_rewrites_header_then_redirects() {
    load_skel!("tc-wan-in-flow-mac", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        entry_mac,
    );
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, lan_client(), host_mac, dev_mac, TARGET_IFINDEX);

    let (ret, out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v4(dst = ip_mac[daddr].mac, src = lan entry mac_addr)
    assert_eq!(&out[0..6], &host_mac.octets());
    assert_eq!(&out[6..12], &entry_mac);
    assert_eq!(&out[12..14], &[0x08, 0x00]);

    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("static mark must still cache the reverse path");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
}

#[test]
fn wan_ingress_lan_entry_same_iface_hands_to_stack() {
    // F1 same-ifindex guard (compares skb->ifindex): entry pointing at the
    // incoming device passes without caching.
    load_skel!("tc-wan-in-flow-sameif", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        LOOPBACK_IFINDEX, // == skb->ifindex under test_run
        false,
        [0; 6],
    );

    let (ret, out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "entry pointing at the incoming device itself");
    assert_eq!(out, reply_pkt());
    assert!(
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "no redirect → no cache write"
    );
}

#[test]
fn wan_ingress_has_mac_entry_without_ip_mac_falls_to_neigh() {
    // F1 has_mac entry with no ip_mac_v4[daddr] → bpf_redirect_neigh(daddr)
    // fallback, no rewrite.
    load_skel!("tc-wan-in-flow-macmiss", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    // no ip_mac_v4 entry for daddr

    let pkt = reply_pkt();
    let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

#[test]
fn wan_ingress_raw_l3_frame_prepends_mac_and_redirects() {
    // cb[1] == 0: raw L3 frame. F1 must prepend a 14-byte eth header
    // (bpf_skb_change_head) before the mac rewrite, and the reverse cache
    // entry must record has_mac = 0.
    load_skel!("tc-wan-in-flow-rawl3", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        entry_mac,
    );
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, lan_client(), host_mac, dev_mac, TARGET_IFINDEX);

    let raw = &simple_ipv4_tcp(public_src(), lan_client())[14..]; // strip eth
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        mark: INGRESS_STATIC_MARK,
        cb: [0, 0, 0, 0, 0], // cb[1] = 0 → l3_offset 0
        ..Default::default()
    };
    let mut out = vec![0_u8; raw.len() + 64]; // room for the prepended header
    let result = skel
        .progs
        .tc_route4_wan_ingress
        .test_run(ProgramInput {
            data_in: Some(raw),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route4_wan_ingress");
    let ret = result.return_value as i32;

    assert_eq!(ret, RET_REDIRECT);
    let written = result.data.expect("data_out must be returned");
    assert_eq!(written.len(), raw.len() + 14, "eth header must be prepended");
    assert_eq!(&written[0..6], &host_mac.octets(), "dst = ip_mac[daddr].mac");
    assert_eq!(&written[6..12], &entry_mac, "src = lan entry mac_addr");
    assert_eq!(&written[12..14], &[0x08, 0x00]);
    assert_eq!(&written[14..], raw, "L3 payload must be untouched");

    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("static mark must cache the reverse path");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
    assert_eq!(cache.has_mac, 0, "l3_offset == 0 must record has_mac = 0");
}

#[test]
fn wan_ingress_reverse_entry_in_lan_cache_blocks_wan_write() {
    // set_cache_in_wan checks the LAN cache first: if the reverse entry is
    // already there, the wan cache write is skipped entirely.
    load_skel!("tc-wan-in-flow-lancache", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        lan_client(),
        public_src(),
        TARGET_IFINDEX,
        false,
        0,
    );
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    assert!(
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "lan-cache hit must suppress the wan cache write"
    );
}

#[test]
fn wan_ingress_existing_wan_cache_entry_updated_in_place() {
    // set_cache_in_wan update row: an existing reverse entry gets its
    // ifindex / has_mac / xdp flag refreshed while the mark stays untouched.
    load_skel!("tc-wan-in-flow-cacheupd", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        lan_client(),
        public_src(),
        99,    // stale ifindex
        false, // stale has_mac
        0x1234,
    );
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse entry must survive");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX, "ifindex refreshed to skb->ifindex");
    assert_eq!(cache.has_mac, 1, "l3_offset 14 must flip has_mac to 1");
    assert_eq!(cache.xdp_redirect_able, 0, "no xdp target in the harness");
    assert_eq!(cache.mark_value, 0x1234, "the mark value is never rewritten");
}

#[test]
fn wan_ingress_existing_wan_cache_entry_xdp_flag_refreshed() {
    // set_cache_in_wan update row: the xdp flag is refreshed from the
    // xdp_redirect_able map keyed by skb->ifindex (TRUE row).
    load_skel!("tc-wan-in-flow-cacheupd-xdp", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    put_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        WAN_CACHE,
        lan_client(),
        public_src(),
        99,
        false,
        0x1234,
    );
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );
    let able: u32 = 1;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&LOOPBACK_IFINDEX), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able[skb ifindex]");

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse entry must survive");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
    assert_eq!(cache.xdp_redirect_able, 1, "update row must refresh the xdp flag to 1");
}

#[test]
fn wan_ingress_broadcast_dst_hands_to_stack() {
    load_skel!("tc-wan-in-flow-bcast", skel);
    let pkt = simple_ipv4_tcp(public_src(), Ipv4Addr::BROADCAST);
    let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(0));
    assert_eq!(ret, RET_UNSPEC);
    assert_eq!(out, pkt);
}

#[test]
fn wan_ingress_arp_frame_passes_through() {
    load_skel!("tc-wan-in-flow-arp", skel);
    let mut pkt = vec![0xff_u8; 14 + 28];
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(0));
    assert_eq!(ret, RET_OK, "non-IP frames pass through the wan ingress worker");
    assert_eq!(out, pkt);
}

// NOTE: LD_SCAN_ERR (eth-header read failure) is not reachable under
// PROG_TEST_RUN: the kernel rejects data_size_in < ETH_HLEN before the
// program runs (test_run.c `if (size < ETH_HLEN) return -EINVAL`).

#[test]
fn wan_ingress_non_matching_wan_binding_continues_to_lan_redirect() {
    // route4_is_current_wan_packet negative row: a binding exists for the
    // ingress device, but daddr is not that address → keep going into the F1
    // lan redirect check (and the static-mark cache write).
    load_skel!("tc-wan-in-flow-bindmiss", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    seed_wan_self_binding(&skel);
    seed_lan_entry_nomac(&skel);

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT, "non-matching binding must not swallow the packet");
    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("redirect under static mark must still cache the reverse path");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
}

/// mac-less LAN entry pointing at another iface — the plain redirect setup
/// shared by several cache-gating tests below.
fn seed_lan_entry_nomac(skel: &TcWanIngressExitSkel<'_>) {
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );
}

// ---------------------------------------------------------------------------
// F1 remaining rows: LAN own-addr + NEXTHOP
// ---------------------------------------------------------------------------

#[test]
fn wan_ingress_lan_typed_own_addr_hands_to_stack() {
    // F1 row (route4_path.h:68-70): a LAN-typed entry whose addr equals the
    // daddr → UNSPEC before the redirect tail (and no cache write: not a
    // redirect).
    load_skel!("tc-wan-in-flow-lan-self", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        lan_client(), // addr == daddr
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let (ret, out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_UNSPEC, "LAN-typed entry for the daddr itself");
    assert_eq!(out, reply_pkt());
    assert!(
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "no redirect → no cache write"
    );
}

#[test]
fn wan_ingress_nexthop_entry_resolves_mac_by_nh_addr() {
    // F1 NEXTHOP rows: the mac key comes from lan_info->addr (the nexthop),
    // not from the daddr.
    load_skel!("tc-wan-in-flow-nexthop", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.1").unwrap(), // nexthop address
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        entry_mac,
    );
    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v4(
        &skel.maps.ip_mac_v4,
        Ipv4Addr::from_str("192.168.1.1").unwrap(),
        gw_mac,
        gw_dev,
        TARGET_IFINDEX,
    );

    let (ret, out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v4(dst = ip_mac[nexthop].mac, src = lan entry mac_addr)
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &entry_mac);
    assert_eq!(&out[12..14], &[0x08, 0x00]);
}

#[test]
fn wan_ingress_nexthop_without_mac_falls_to_neigh() {
    // F1 NEXTHOP + has_mac but no ip_mac_v4[nexthop]: falls into
    // bpf_redirect_neigh with the nexthop address as parameter.
    load_skel!("tc-wan-in-flow-nexthop-miss", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        lan_client(),
        Ipv4Addr::from_str("192.168.1.1").unwrap(),
        ROUTE_TYPE_NEXTHOP,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    // no ip_mac_v4 entry for the nexthop

    let pkt = reply_pkt();
    let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(0));

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
}

// ---------------------------------------------------------------------------
// raw L3 (cb[1] == 0) + no-mac combination
// ---------------------------------------------------------------------------

#[test]
fn wan_ingress_raw_l3_no_mac_entry_redirects_bare() {
    // cb[1] == 0 with a mac-less entry: the eth-header prepend is gated on
    // has_mac, so the bare L3 skb is redirected as-is.
    load_skel!("tc-wan-in-flow-rawl3-nomac", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    seed_lan_entry_nomac(&skel);

    let raw = &simple_ipv4_tcp(public_src(), lan_client())[14..]; // strip eth
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        mark: 0,
        cb: [0, 0, 0, 0, 0], // cb[1] = 0 → l3_offset 0
        ..Default::default()
    };
    let (ret, out) = run_wan_ingress(&skel, raw, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, raw, "no eth header may be prepended for a mac-less entry");
}

// ---------------------------------------------------------------------------
// non-IPv4 frames + truncation
// ---------------------------------------------------------------------------

#[test]
fn wan_ingress_ipv6_frame_hands_to_stack() {
    // route4_read_context_from_scan non-v4 row (mirror of the v6 worker's
    // ipv4-frame test).
    load_skel!("tc-wan-in-flow-v6frame", skel);
    let pkt = simple_ipv6_tcp_syn(
        Ipv6Addr::from_str("2001:db8:1::7").unwrap(),
        Ipv6Addr::from_str("fd00::20").unwrap(),
    );
    let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(0));
    assert_eq!(ret, RET_OK, "v6 frame must pass the v4 worker");
    assert_eq!(out, pkt);
}

#[test]
fn wan_ingress_truncated_ip_header_passes_to_stack() {
    // read_context truncation row: ethertype claims IPv4 but the IP header
    // is cut short → SHOT from read_context, mapped to "pass to the stack".
    load_skel!("tc-wan-in-flow-runt", skel);
    let mut pkt = vec![0xff_u8; 16]; // eth header + 2 bytes of "IP"
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(0));

    assert_eq!(ret, RET_OK, "truncated IP header must pass, not drop");
    assert_eq!(out, pkt);
}

// ---------------------------------------------------------------------------
// broadcast sub-rows (0.0.0.0 / 224.0.0.0/4)
// ---------------------------------------------------------------------------

#[test]
fn wan_ingress_unspecified_and_multicast_dst_hands_to_stack() {
    // is_broadcast_ip4 sub-rows beyond 255.255.255.255 (landscape.h:202-209):
    // 0.0.0.0 and the multicast range are "broadcast-like".
    load_skel!("tc-wan-in-flow-bcast-subrows", skel);
    for dst in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::from_str("224.0.0.1").unwrap()] {
        let pkt = simple_ipv4_tcp(public_src(), dst);
        let (ret, out) = run_wan_ingress(&skel, &pkt, &mut wan_ctx(0));
        assert_eq!(ret, RET_UNSPEC, "{dst} must hand to the stack like broadcast");
        assert_eq!(out, pkt);
    }
}

// ---------------------------------------------------------------------------
// get_cache_mask semantics (low 8 bits only)
// ---------------------------------------------------------------------------

#[test]
fn wan_ingress_static_mark_with_flow_bits_still_writes_cache() {
    // get_cache_mask only looks at the low 8 bits (mark.h INGRESS_CACHE_MASK):
    // a NAT-stage mark carrying flow-id/action bits above the mask still
    // satisfies the gate.
    load_skel!("tc-wan-in-flow-mask-hi", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    seed_lan_entry_nomac(&skel);

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(0x0305_0001));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("low mask byte 1 must satisfy the cache gate");
    assert_eq!(cache.ifindex, LOOPBACK_IFINDEX);
}

#[test]
fn wan_ingress_zero_low_mask_byte_skips_cache() {
    // 0x0100: the overall mark is non-zero but the mask byte (low 8 bits) is
    // 0 → the gate stays closed.
    load_skel!("tc-wan-in-flow-mask-lo", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    seed_lan_entry_nomac(&skel);

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(0x0100));

    assert_eq!(ret, RET_REDIRECT);
    assert!(
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .is_none(),
        "cache write is gated on the low mask byte only"
    );
}

// ---------------------------------------------------------------------------
// set_cache_in_wan remaining rows
// ---------------------------------------------------------------------------

#[test]
fn wan_ingress_static_mark_insert_sets_xdp_flag_when_able() {
    // Insert row of set_cache_in_wan (route4_path.h:649): the xdp flag comes
    // from xdp_redirect_able[skb->ifindex] (TRUE row; v6 twin exists).
    load_skel!("tc-wan-in-flow-xdp-able", skel);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    seed_lan_entry_nomac(&skel);
    let able: u32 = 1;
    skel.maps
        .xdp_redirect_able
        .update(as_bytes(&LOOPBACK_IFINDEX), as_bytes(&able), MapFlags::ANY)
        .expect("seed xdp_redirect_able[skb ifindex]");

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT);
    let cache =
        lookup_rt4_cache_value(&skel.maps.rt4_cache_map, WAN_CACHE, lan_client(), public_src())
            .expect("reverse WAN-cache entry must be written");
    assert_eq!(
        cache.xdp_redirect_able, 1,
        "insert row must consult xdp_redirect_able[skb ifindex]"
    );
}

#[test]
fn wan_ingress_missing_wan_inner_map_is_inert() {
    // set_cache_in_wan with no WAN inner map (route4_path.h:668-670): the
    // worker only logs and returns — the redirect verdict is unaffected and
    // no inner map is created implicitly.
    load_skel!("tc-wan-in-flow-nowanmap", skel);
    // rt4_cache_map intentionally left without a WAN_CACHE inner map
    seed_lan_entry_nomac(&skel);

    let (ret, _out) = run_wan_ingress(&skel, &reply_pkt(), &mut wan_ctx(INGRESS_STATIC_MARK));

    assert_eq!(ret, RET_REDIRECT, "missing inner map must not break the redirect");
    assert!(
        skel.maps
            .rt4_cache_map
            .lookup(as_bytes(&WAN_CACHE), MapFlags::ANY)
            .expect("lookup rt4_cache_map outer")
            .is_none(),
        "no inner map may be created implicitly"
    );
}

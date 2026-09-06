//! IPv4 whole-flow baseline for the WAN-egress route worker
//! `tc_route4_wan_egress` (tc_wan_egress_intro.bpf.c).
//!
//! This worker only handles locally-generated traffic (ingress_ifindex == 0;
//! forwarded frames enter via the egress intro/root tail-call chain instead).
//! Each test runs the complete pipeline once — scan →
//! lan_redirect_check_in_wan_egress → flow_verdict → pick_wan_in_wan_egress —
//! and locks the current behaviour before any route rewrite.
//!
//! Baseline quirks locked here (see tc_wan_egress_intro.bpf.c):
//!   * no slot target + default flow → TC_ACT_SHOT (same divergence as the
//!     lan worker; the legacy route4_pick_wan_and_send_by_flow_id twin passes
//!     default-flow traffic instead);
//!   * a slot target on the egress device itself (ifindex == skb->ifindex)
//!     tail-calls into tc_wan_egress_roots[ifindex]; with the root map empty
//!     (no chain assembled) the packet is dropped — root assembly is out of
//!     scope for these worker-level tests;
//!   * the docker slot branch never sets the forwarded cb flag;
//!   * the worker never writes any route cache;
//!   * F3 (in_wan_egress) skips WAN-typed lan entries with TC_ACT_OK.
//!
//! PROG_TEST_RUN verdict mapping: OK=0, UNSPEC=-1, SHOT=2, REDIRECT=7.
//! ctx.ifindex = 1 (loopback) so no real device is required; the
//! redirect-neigh fallback still returns REDIRECT under PROG_TEST_RUN
//! (verified empirically, see test_lan_redirect_check.rs) and is asserted
//! directly by the `falls_to_neigh` tests below.

use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use landscape_common::{
    flow::{ip_mark::IpConfig, ip_mark::IpMarkInfo, mark::FlowMark, FlowMarkInfo},
    net::MacAddr,
    sys_service::route_service::RouteTargetInfo,
};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};
use zerocopy::IntoBytes;

use crate::{
    maps::{
        flow_dns::create_flow_dns_inner_map_v4, flow_wanip::create_inner_flow_match_map_v4,
        route::replace_wan_route_slots_v4_with_map,
    },
    tests::{
        isolated_pin_root,
        route::{
            map_helper::{
                create_route4_cache_inner_map, insert_ip_mac_v4, insert_route4_lan_entry,
                lookup_rt4_cache_value, seed_flow_match_ip_v4, seed_flow_match_mac, LAN_CACHE,
                LAN_ROUTE_TYPE, ROUTE_TYPE_NEXTHOP, TARGET_IFINDEX, WAN_ROUTE_TYPE,
            },
            packet_builder::{simple_ipv4_tcp, simple_ipv6_tcp_syn},
        },
        TestSkb,
    },
};

pub(crate) mod tc_wan_egress_intro {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_intro.skel.rs"));
}
use tc_wan_egress_intro::TcWanEgressIntroSkel;

const RET_OK: i32 = 0;
const RET_UNSPEC: i32 = -1;
const RET_SHOT: i32 = 2;
const RET_REDIRECT: i32 = 7;

const FLOW_REDIRECT_MARK: u32 = 0x0305; // action REDIRECT, flow id 5
const FLOW_DROP_MARK: u32 = 0x0200; // action DROP
const FLOW_DIRECT_MARK: u32 = 0x0100; // action DIRECT

/// Eth src mac of the packet_builder frames (match_flow_id_v4 reads it).
const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// skb->ifindex under PROG_TEST_RUN when ctx.ifindex <= 1 (loopback dev).
const LOOPBACK_IFINDEX: u32 = 1;

fn local_addr() -> Ipv4Addr {
    Ipv4Addr::from_str("192.168.1.10").unwrap()
}
fn remote_wan_addr() -> Ipv4Addr {
    Ipv4Addr::from_str("10.0.0.20").unwrap()
}
fn wan_gateway() -> Ipv4Addr {
    Ipv4Addr::from_str("100.64.0.2").unwrap()
}

fn egress_ctx() -> TestSkb {
    // locally generated: no ingress ifindex, no mark
    TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: 0,
        ..Default::default()
    }
}

macro_rules! load_skel {
    ($pin:expr, $skel:ident) => {
        let pin_root = isolated_pin_root($pin);
        let mut builder = tc_wan_egress_intro::TcWanEgressIntroSkelBuilder::default();
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = std::mem::MaybeUninit::uninit();
        let $skel = builder.open(&mut open_object).unwrap().load().unwrap();
    };
}

fn run_wan_egress(
    skel: &TcWanEgressIntroSkel<'_>,
    pkt: &[u8],
    ctx: &mut TestSkb,
) -> (i32, Vec<u8>, u32, u32) {
    let mut out = vec![0_u8; pkt.len()];
    let mut ctx_out = TestSkb::default();
    let ret = skel
        .progs
        .tc_route4_wan_egress
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: Some(ctx_out.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route4_wan_egress")
        .return_value as i32;
    // TestSkb is packed: copy the asserted fields out explicitly.
    let mark = ctx_out.mark;
    let forwarded = ctx_out.cb[0];
    (ret, out, mark, forwarded)
}

fn seed_flow_rule(skel: &TcWanEgressIntroSkel<'_>, dst: Ipv4Addr, mark: u32) {
    seed_flow_rule_under(skel, 0, dst, mark);
}

/// Seed flow `flow_id`'s ip-trie with a single dst rule.
fn seed_flow_rule_under(skel: &TcWanEgressIntroSkel<'_>, flow_id: u32, dst: Ipv4Addr, mark: u32) {
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(mark),
        cidr: IpConfig { ip: IpAddr::V4(dst), prefix: 32 },
        priority: 100,
    }];
    create_inner_flow_match_map_v4(&skel.maps.flow4_ip_map, flow_id, &rules).unwrap();
}

fn seed_wan_slots(
    skel: &TcWanEgressIntroSkel<'_>,
    flow_id: u32,
    ifindex: u32,
    is_docker: bool,
    mac: Option<MacAddr>,
) {
    let targets = [(
        RouteTargetInfo {
            weight: 0,
            ifindex,
            mac,
            default_route: false,
            is_docker,
            iface_name: "test-wan".to_string(),
            iface_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            gateway_ip: IpAddr::V4(wan_gateway()),
        },
        1,
    )];
    replace_wan_route_slots_v4_with_map(&skel.maps.rt4_slot_map, flow_id, &targets);
}

fn assert_no_route_cache(skel: &TcWanEgressIntroSkel<'_>) {
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    create_route4_cache_inner_map(
        &skel.maps.rt4_cache_map,
        crate::tests::route::map_helper::WAN_CACHE,
    );
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_wan_addr()
    )
    .is_none());
    assert!(lookup_rt4_cache_value(
        &skel.maps.rt4_cache_map,
        crate::tests::route::map_helper::WAN_CACHE,
        local_addr(),
        remote_wan_addr()
    )
    .is_none());
}

// ---------------------------------------------------------------------------
// flow verdict + pick_wan
// ---------------------------------------------------------------------------

#[test]
fn wan_egress_default_flow_without_slot_target_drops() {
    load_skel!("tc-wan-eg-flow-default-drop", skel);
    assert_no_route_cache(&skel);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "default flow without slot target must drop");
    assert_eq!(mark, 0x0400_0000, "mark must carry FLOW_FROM_WAN source only");
    assert_eq!(forwarded, 0);
}

#[test]
fn wan_egress_flow_redirect_sets_forwarded_cb() {
    load_skel!("tc-wan-eg-flow-redirect", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "no mac rewrite expected for a mac-less slot target");
    assert_eq!(mark, 0x0400_0305, "mark = flow mark + FLOW_FROM_WAN source");
    assert_eq!(forwarded, 1, "pick_wan must set the forwarded cb flag");
    assert_no_route_cache(&skel);
}

#[test]
fn wan_egress_slot_with_mac_rewrites_header() {
    load_skel!("tc-wan-eg-flow-mac", skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));

    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, wan_gateway(), gw_mac, gw_dev, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, _mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v4(dst = ip_mac[gate_addr].mac, src = slot target mac)
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &target_mac.octets());
    assert_eq!(&out[12..14], &[0x08, 0x00]);
}

#[test]
fn wan_egress_docker_slot_pushes_vlan_and_redirects() {
    load_skel!("tc-wan-eg-flow-docker", skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, true, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, _mark, forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "vlan tag is hwaccel-only under PROG_TEST_RUN");
    assert_eq!(forwarded, 0, "docker branch returns before the forwarded cb flag");
}

#[test]
fn wan_egress_same_device_target_tailcalls_into_empty_root_and_shots() {
    // A slot target on the egress device itself tail-calls into
    // tc_wan_egress_roots[ifindex]; with no chain assembled the tail call
    // fails and the worker falls back to TC_ACT_SHOT.
    load_skel!("tc-wan-eg-same-dev", skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, LOOPBACK_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, _mark, forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "empty egress root map → tail call falls through to SHOT");
    assert_eq!(forwarded, 0, "same-device branch never sets the forwarded flag");
}

// ---------------------------------------------------------------------------
// lan_redirect_check_in_wan_egress rows (F3)
// ---------------------------------------------------------------------------

#[test]
fn wan_egress_lan_entry_other_iface_redirects_before_verdict() {
    load_skel!("tc-wan-eg-lan-nomac", skel);
    assert_no_route_cache(&skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-less LAN entry on another iface plain-redirects");
    assert_eq!(mark, 0, "F3 return path leaves the mark untouched");
}

#[test]
fn wan_egress_lan_entry_own_addr_hands_to_stack() {
    load_skel!("tc-wan-eg-lan-self", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        remote_wan_addr(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, _mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());
    assert_eq!(ret, RET_UNSPEC);
}

#[test]
fn wan_egress_wan_typed_entry_falls_through_to_pick_wan() {
    // F3 skips WAN-typed entries with TC_ACT_OK, but unlike a real match the
    // packet then continues into flow verdict + pick_wan, where the default
    // flow has no slot -> SHOT.
    load_skel!("tc-wan-eg-wan-entry", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.0").unwrap(),
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());
    assert_eq!(ret, RET_SHOT);
    assert_eq!(mark, 0x0400_0000, "mark must carry the WAN source bits");
}

#[test]
fn wan_egress_flow_drop_shots_with_untouched_mark() {
    // FLOW_DROP verdict returns before the mark-source write.
    load_skel!("tc-wan-eg-flow-drop", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_wan_addr(), 0x0200); // action DROP

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "FLOW_DROP rule must drop");
    assert_eq!(mark, 0, "drop returns before the mark-source write");
}

#[test]
fn wan_egress_lan_entry_with_mac_rewrites_header() {
    // F3 LAN-type with has_mac: dst mac from ip_mac_v4[daddr], src mac from
    // the entry, then plain redirect.
    load_skel!("tc-wan-eg-lan-mac", skel);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        entry_mac,
    );
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v4(&skel.maps.ip_mac_v4, remote_wan_addr(), host_mac, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &host_mac.octets(), "dst = ip_mac[daddr].mac");
    assert_eq!(&out[6..12], &entry_mac, "src = lan entry mac_addr");
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan_egress_lan_entry_with_mac_without_ip_mac_falls_to_neigh() {
    // F3 has_mac entry with no ip_mac_v4[daddr]: like F1, the check ends in
    // the bpf_redirect_neigh fallback (param = daddr) instead of falling
    // through to the verdict.
    load_skel!("tc-wan-eg-lan-macmiss", skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    // no ip_mac_v4 entry for daddr

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan_egress_broadcast_dst_hands_to_stack() {
    load_skel!("tc-wan-eg-bcast", skel);
    let pkt = simple_ipv4_tcp(local_addr(), Ipv4Addr::BROADCAST);
    let (ret, _out, _mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());
    assert_eq!(ret, RET_UNSPEC);
}

#[test]
fn wan_egress_flow_redirect_without_slot_target_drops() {
    // pick_wan slot-miss with flow_id != 0 → SHOT, even though the flow rule
    // matched. The mark is already stamped when the drop happens.
    load_skel!("tc-wan-eg-flow-noslot", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    // rt4_slot_map intentionally left empty for flow 5

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "matched flow without slots must drop");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0400_0305, "mark is stamped before pick_wan drops");
    assert_eq!(forwarded, 0);
}

#[test]
fn wan_egress_lan_entry_same_iface_hands_to_stack() {
    // F3 hairpin guard: entry ifindex == skb->ifindex → UNSPEC before any
    // mark/verdict work.
    load_skel!("tc-wan-eg-lan-hairpin", skel);
    assert_no_route_cache(&skel);
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
        Ipv4Addr::from_str("192.168.1.99").unwrap(),
        LAN_ROUTE_TYPE,
        LOOPBACK_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_UNSPEC, "entry pointing at the egress device itself");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan_egress_lan_entry_nexthop_resolves_gateway_mac() {
    load_skel!("tc-wan-eg-lan-nexthop", skel);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route4_lan_entry(
        &skel.maps.rt4_lan_map,
        32,
        remote_wan_addr(),
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

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    // store_mac_v4(dst = ip_mac[nexthop].mac, src = lan entry mac_addr)
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &entry_mac);
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    assert_eq!(mark, 0, "returned before the mark-source write");
}

// ---------------------------------------------------------------------------
// flow_verdict: FLOW_DIRECT + DNS rules + flow_match classification
// ---------------------------------------------------------------------------

#[test]
fn wan_egress_flow_direct_resets_flow_id_to_default() {
    // FLOW_DIRECT semantics: the action survives but the flow id is reset to
    // 0, so pick_wan resolves through flow 0's slots while the ip-trie rule
    // was matched under the *incoming* flow id (5 here, via ctx.mark).
    load_skel!("tc-wan-eg-flow-direct", skel);
    seed_flow_rule_under(&skel, 5, remote_wan_addr(), FLOW_DIRECT_MARK);
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: 0,
        mark: 5, // incoming flow id from an earlier stage
        ..Default::default()
    };
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0400_0100, "source WAN + DIRECT mark with reset id");
}

#[test]
fn wan_egress_dns_rule_redirects_when_no_ip_rule() {
    // DNS rule row: with an empty ip-trie, the dns mark alone drives the
    // verdict.
    load_skel!("tc-wan-eg-dns-only", skel);
    assert_no_route_cache(&skel);
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V4(remote_wan_addr()),
            mark: FLOW_REDIRECT_MARK,
            priority: 100,
        }],
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "dns-only rule must drive the redirect");
    assert_eq!(mark, 0x0400_0305);
    assert_eq!(forwarded, 1);
}

#[test]
fn wan_egress_dns_rule_lower_or_equal_priority_wins() {
    // The dns comparison is `dns.priority <= priority`: with equal
    // priorities the dns rule overrides the ip rule.
    load_skel!("tc-wan-eg-dns-wins", skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK); // ip priority 100
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V4(remote_wan_addr()),
            mark: FLOW_DROP_MARK,
            priority: 100, // equal → dns wins
        }],
    );

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "dns rule with equal priority must win");
    assert_eq!(mark, 0, "drop returns before the mark-source write");
}

#[test]
fn wan_egress_dns_rule_higher_priority_loses_to_ip_rule() {
    load_skel!("tc-wan-eg-dns-loses", skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK); // ip priority 100
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V4(remote_wan_addr()),
            mark: FLOW_DROP_MARK,
            priority: 200, // higher → ip rule wins
        }],
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "lower-priority dns rule must not override");
    assert_eq!(mark, 0x0400_0305);
}

#[test]
fn wan_egress_flow_match_by_src_mac_selects_flow() {
    // match_flow_id_v4 MAC row: the sender's mac classifies the packet into
    // flow 5, whose rules/slots apply even though ctx.mark is 0.
    load_skel!("tc-wan-eg-class-mac", skel);
    assert_no_route_cache(&skel);
    seed_flow_match_mac(&skel.maps.flow_match_map, CLIENT_MAC, 5);
    seed_flow_rule_under(&skel, 5, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-classified flow 5 must drive the redirect");
    assert_eq!(mark, 0x0400_0305);
}

#[test]
fn wan_egress_flow_match_by_src_ip_selects_flow() {
    // match_flow_id_v4 IP row: same classification via the /32 src address.
    // The key mirrors the BPF construction (mac[4..6] union-tail leak, see
    // map_helper::seed_flow_match_ip_v4).
    load_skel!("tc-wan-eg-class-ip", skel);
    assert_no_route_cache(&skel);
    seed_flow_match_ip_v4(&skel.maps.flow_match_map, local_addr(), CLIENT_MAC, 5);
    seed_flow_rule_under(&skel, 5, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "ip-classified flow 5 must drive the redirect");
    assert_eq!(mark, 0x0400_0305);
}

#[test]
fn wan_egress_incoming_mark_source_replaced_by_wan() {
    // A mark arriving with LAN source bits (e.g. traffic re-routed back into
    // the wan pipe) must be re-stamped with FLOW_FROM_WAN after the verdict.
    load_skel!("tc-wan-eg-flow-markseed", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: 0,
        mark: 0x0200_0000, // FLOW_FROM_LAN source, default flow id
        ..Default::default()
    };
    let (ret, _out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0400_0305, "the LAN source bits must be replaced by FLOW_FROM_WAN");
}

// ---------------------------------------------------------------------------
// pick_wan has_mac + gateway-miss fallback
// ---------------------------------------------------------------------------

#[test]
fn wan_egress_slot_with_mac_gateway_miss_falls_to_neigh() {
    // pick_wan has_mac slot whose gate address has no ip_mac_v4 entry: the
    // forwarded cb flag is already stamped when the neigh fallback runs
    // (tc_wan_egress_intro.bpf.c:89 before :95-102).
    load_skel!("tc-wan-eg-flow-gwmiss", skel);
    seed_flow_rule(&skel, remote_wan_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));
    // no ip_mac_v4 entry for the slot gate address

    let pkt = simple_ipv4_tcp(local_addr(), remote_wan_addr());
    let (ret, out, mark, forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
    assert_eq!(mark, 0x0400_0305);
    assert_eq!(forwarded, 1, "the cb flag is stamped before the neigh fallback");
}

// ---------------------------------------------------------------------------
// broadcast sub-rows + non-IPv4/truncated frames
// ---------------------------------------------------------------------------

#[test]
fn wan_egress_unspecified_and_multicast_dst_hands_to_stack() {
    // is_broadcast_ip4 sub-rows beyond 255.255.255.255: 0.0.0.0 and the
    // 224.0.0.0/4 multicast range are "broadcast-like".
    load_skel!("tc-wan-eg-bcast-subrows", skel);
    for dst in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::from_str("224.0.0.1").unwrap()] {
        let pkt = simple_ipv4_tcp(local_addr(), dst);
        let (ret, _out, _mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());
        assert_eq!(ret, RET_UNSPEC, "{dst} must hand to the stack like broadcast");
    }
}

#[test]
fn wan_egress_ipv6_frame_hands_to_stack() {
    // route4_read_context_from_scan non-v4 row.
    load_skel!("tc-wan-eg-v6frame", skel);
    let pkt = simple_ipv6_tcp_syn(
        std::net::Ipv6Addr::from_str("fd00::10").unwrap(),
        std::net::Ipv6Addr::from_str("fd00::20").unwrap(),
    );
    let (ret, out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());
    assert_eq!(ret, RET_OK, "v6 frame must pass the v4 worker");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

#[test]
fn wan_egress_truncated_ip_header_passes_to_stack() {
    // read_context truncation row: ethertype claims IPv4 but the IP header
    // is cut short → SHOT from read_context, mapped to "pass to the stack".
    load_skel!("tc-wan-eg-runt", skel);
    let mut pkt = vec![0xff_u8; 16]; // eth header + 2 bytes of "IP"
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    let (ret, out, mark, _forwarded) = run_wan_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_OK, "truncated IP header must pass, not drop");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

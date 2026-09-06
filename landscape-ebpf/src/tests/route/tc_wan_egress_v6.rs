//! v6 baseline for the `tc_route6_wan_egress` worker. Mirrors
//! `tc_wan_egress.rs`; v6 specifics are called out inline.

use std::{
    net::{IpAddr, Ipv6Addr},
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
        flow_dns::create_flow_dns_inner_map_v6, flow_wanip::create_inner_flow_match_map_v6,
        route::replace_wan_route_slots_v6_with_map,
    },
    tests::{
        isolated_pin_root,
        route::{
            map_helper::{
                create_route6_cache_inner_map, gateway_addr, insert_ip_mac_v6,
                insert_route6_lan_entry, local_addr, lookup_rt6_cache_value, remote_addr,
                LAN_CACHE, LAN_ROUTE_TYPE, ROUTE_TYPE_NEXTHOP, TARGET_IFINDEX, WAN_CACHE,
                WAN_ROUTE_TYPE,
            },
            packet_builder::simple_ipv6_tcp_syn,
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
const FLOW_DIRECT_MARK: u32 = 0x0100; // action DIRECT

/// skb->ifindex under PROG_TEST_RUN when ctx.ifindex <= 1 (loopback dev).
const LOOPBACK_IFINDEX: u32 = 1;

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

fn run_wan6_egress(
    skel: &TcWanEgressIntroSkel<'_>,
    pkt: &[u8],
    ctx: &mut TestSkb,
) -> (i32, Vec<u8>, u32, u32) {
    let mut out = vec![0_u8; pkt.len()];
    let mut ctx_out = TestSkb::default();
    let ret = skel
        .progs
        .tc_route6_wan_egress
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: Some(ctx_out.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route6_wan_egress")
        .return_value as i32;
    let mark = ctx_out.mark;
    let forwarded = ctx_out.cb[0];
    (ret, out, mark, forwarded)
}

fn seed_flow_rule(skel: &TcWanEgressIntroSkel<'_>, dst: Ipv6Addr, mark: u32) {
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(mark),
        cidr: IpConfig { ip: IpAddr::V6(dst), prefix: 128 },
        priority: 100,
    }];
    create_inner_flow_match_map_v6(&skel.maps.flow6_ip_map, 0, &rules).unwrap();
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
            iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            gateway_ip: IpAddr::V6(gateway_addr()),
        },
        1,
    )];
    replace_wan_route_slots_v6_with_map(&skel.maps.rt6_slot_map, flow_id, &targets);
}

fn assert_no_route_cache(skel: &TcWanEgressIntroSkel<'_>) {
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    assert!(lookup_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        local_addr(),
        remote_addr()
    )
    .is_none());
    assert!(lookup_rt6_cache_value(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        local_addr(),
        remote_addr()
    )
    .is_none());
}

// ---------------------------------------------------------------------------
// flow verdict + pick_wan
// ---------------------------------------------------------------------------

#[test]
fn wan6_egress_default_flow_without_slot_target_drops() {
    load_skel!("tc-wan6-eg-default-drop", skel);
    assert_no_route_cache(&skel);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "default flow without slot target must drop");
    assert_eq!(mark, 0x0400_0000, "mark must carry FLOW_FROM_WAN source only");
    assert_eq!(forwarded, 0);
}

#[test]
fn wan6_egress_flow_redirect_sets_forwarded_cb() {
    load_skel!("tc-wan6-eg-flow-redirect", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "no mac rewrite expected for a mac-less slot target");
    assert_eq!(mark, 0x0400_0305, "mark = flow mark + FLOW_FROM_WAN source");
    assert_eq!(forwarded, 1, "pick_wan must set the forwarded cb flag");
    assert_no_route_cache(&skel);
}

#[test]
fn wan6_egress_flow_drop_shots_with_untouched_mark() {
    load_skel!("tc-wan6-eg-flow-drop", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_addr(), 0x0200); // action DROP

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "FLOW_DROP rule must drop");
    assert_eq!(mark, 0, "drop returns before the mark-source write");
}

#[test]
fn wan6_egress_flow_redirect_without_slot_target_drops() {
    load_skel!("tc-wan6-eg-flow-noslot", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_addr(), FLOW_REDIRECT_MARK);
    // rt6_slot_map intentionally left empty for flow 5

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "matched flow without slots must drop");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0x0400_0305, "mark is stamped before pick_wan drops");
    assert_eq!(forwarded, 0);
}

#[test]
fn wan6_egress_slot_with_mac_rewrites_header() {
    load_skel!("tc-wan6-eg-flow-mac", skel);
    seed_flow_rule(&skel, remote_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));

    let gw_mac = MacAddr::from_str("02:55:66:77:88:99").unwrap();
    let gw_dev = MacAddr::from_str("02:aa:bb:cc:dd:f0").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, gateway_addr(), gw_mac, gw_dev, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &target_mac.octets());
    assert_eq!(&out[12..14], &[0x86, 0xdd], "store_mac_v6 stamps the v6 ethertype");
}

#[test]
fn wan6_egress_docker_slot_pushes_vlan_and_redirects() {
    load_skel!("tc-wan6-eg-flow-docker", skel);
    seed_flow_rule(&skel, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, true, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(out, pkt, "vlan push only sets the hwaccel tag under test_run");
    assert_eq!(forwarded, 0, "docker branch returns before the forwarded cb flag");
}

#[test]
fn wan6_egress_same_device_target_tailcalls_into_empty_root_and_shots() {
    load_skel!("tc-wan6-eg-sameif", skel);
    seed_flow_rule(&skel, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, LOOPBACK_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, _mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT, "empty root prog array after the tail call → SHOT");
    assert_eq!(out, pkt);
}

// ---------------------------------------------------------------------------
// rt6_lan_map (lan_redirect_check_in_wan_egress) rows
// ---------------------------------------------------------------------------

#[test]
fn wan6_egress_lan_entry_other_iface_redirects_before_verdict() {
    load_skel!("tc-wan6-eg-lan-nomac", skel);
    assert_no_route_cache(&skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "mac-less LAN entry on another iface plain-redirects");
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan6_egress_lan_entry_own_addr_hands_to_stack() {
    load_skel!("tc-wan6-eg-lan-own", skel);
    assert_no_route_cache(&skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        remote_addr(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_UNSPEC, "LAN-typed entry for the target address itself");
    assert_eq!(mark, 0);
}

#[test]
fn wan6_egress_wan_typed_entry_falls_through_to_pick_wan() {
    // F3 skips WAN-typed entries with TC_ACT_OK, then the packet continues
    // into verdict + pick_wan where the default flow has no slot → SHOT.
    load_skel!("tc-wan6-eg-wan-entry", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::1").unwrap(),
        WAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_SHOT);
    assert_eq!(mark, 0x0400_0000, "mark must carry the WAN source bits");
}

#[test]
fn wan6_egress_lan_entry_same_iface_hands_to_stack() {
    // F3 hairpin guard: entry ifindex == skb->ifindex → UNSPEC.
    load_skel!("tc-wan6-eg-lan-hairpin", skel);
    assert_no_route_cache(&skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        LOOPBACK_IFINDEX,
        false,
        [0; 6],
    );

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_UNSPEC, "entry pointing at the egress device itself");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan6_egress_lan_entry_nexthop_resolves_gateway_mac() {
    load_skel!("tc-wan6-eg-lan-nexthop", skel);
    let entry_mac = [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
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

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &gw_mac.octets());
    assert_eq!(&out[6..12], &entry_mac);
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan6_egress_lan_entry_with_mac_rewrites_header() {
    load_skel!("tc-wan6-eg-lan-mac", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    let host_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, remote_addr(), host_mac, dev_mac, TARGET_IFINDEX);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(&out[0..6], &host_mac.octets(), "dst = ip_mac[daddr].mac");
    assert_eq!(&out[6..12], &[0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa], "src = lan entry mac_addr");
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan6_egress_lan_entry_with_mac_without_ip_mac_falls_to_neigh() {
    // F3 has_mac entry with no ip_mac_v6[daddr]: like F1, the check ends in
    // the bpf_redirect_neigh fallback instead of falling to the verdict.
    load_skel!("tc-wan6-eg-lan-macmiss", skel);
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        remote_addr(),
        Ipv6Addr::from_str("fd00::99").unwrap(),
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        true,
        [0x02, 0xee, 0xdd, 0xcc, 0xbb, 0xaa],
    );
    // no ip_mac_v6 entry for daddr

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
    assert_eq!(mark, 0, "returned before the mark-source write");
}

#[test]
fn wan6_egress_multicast_dst_hands_to_stack() {
    // v6-specific: multicast and link-local targets pass through F3.
    load_skel!("tc-wan6-eg-mcast", skel);
    let pkt = simple_ipv6_tcp_syn(local_addr(), Ipv6Addr::from_str("ff02::1").unwrap());
    let (ret, _out, _mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());
    assert_eq!(ret, RET_UNSPEC);
}

#[test]
fn wan6_egress_link_local_dst_hands_to_stack() {
    // is_broadcast_ip6 row 2: fe80::/10 link-local targets (the multicast
    // row above only covers ff00::/8).
    load_skel!("tc-wan6-eg-linklocal", skel);
    let pkt = simple_ipv6_tcp_syn(local_addr(), Ipv6Addr::from_str("fe80::1").unwrap());
    let (ret, out, _mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());
    assert_eq!(ret, RET_UNSPEC);
    assert_eq!(out, pkt);
}

// ---------------------------------------------------------------------------
// flow_verdict: FLOW_DIRECT + DNS rules
// ---------------------------------------------------------------------------

#[test]
fn wan6_egress_flow_direct_resets_flow_id_to_default() {
    // FLOW_DIRECT resets the flow id to 0: the rule matches under the
    // *incoming* flow id (5 via ctx.mark) but pick_wan uses flow 0's slots.
    load_skel!("tc-wan6-eg-flow-direct", skel);
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(FLOW_DIRECT_MARK),
        cidr: IpConfig { ip: IpAddr::V6(remote_addr()), prefix: 128 },
        priority: 100,
    }];
    create_inner_flow_match_map_v6(&skel.maps.flow6_ip_map, 5, &rules).unwrap();
    seed_wan_slots(&skel, 0, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: 0,
        mark: 5, // incoming flow id from an earlier stage
        ..Default::default()
    };
    let (ret, _out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0400_0100, "source WAN + DIRECT mark with reset id");
}

#[test]
fn wan6_egress_dns_rule_redirects_when_no_ip_rule() {
    // DNS rule row: with an empty ip-trie, the dns mark alone drives the
    // verdict (the priority-comparison rows are locked by the v4 egress and
    // v6 lan-ingress twins — same inlined route6_flow_verdict).
    load_skel!("tc-wan6-eg-dns-only", skel);
    assert_no_route_cache(&skel);
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        0,
        &[FlowMarkInfo {
            ip: IpAddr::V6(remote_addr()),
            mark: FLOW_REDIRECT_MARK,
            priority: 100,
        }],
    );
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, _out, mark, forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "dns-only rule must drive the redirect");
    assert_eq!(mark, 0x0400_0305);
    assert_eq!(forwarded, 1);
}

#[test]
fn wan6_egress_incoming_mark_source_replaced_by_wan() {
    // A mark arriving with LAN source bits must be re-stamped with
    // FLOW_FROM_WAN after the verdict.
    load_skel!("tc-wan6-eg-flow-markseed", skel);
    assert_no_route_cache(&skel);
    seed_flow_rule(&skel, remote_addr(), FLOW_REDIRECT_MARK);
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, None);

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let mut ctx = TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: 0,
        mark: 0x0200_0000, // FLOW_FROM_LAN source, default flow id
        ..Default::default()
    };
    let (ret, _out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut ctx);

    assert_eq!(ret, RET_REDIRECT);
    assert_eq!(mark, 0x0400_0305, "the LAN source bits must be replaced by FLOW_FROM_WAN");
}

// ---------------------------------------------------------------------------
// pick_wan has_mac + gateway-miss fallback
// ---------------------------------------------------------------------------

#[test]
fn wan6_egress_slot_with_mac_gateway_miss_falls_to_neigh() {
    // pick_wan has_mac slot whose gate address has no ip_mac_v6 entry: the
    // forwarded cb flag is already stamped when the neigh fallback runs.
    load_skel!("tc-wan6-eg-flow-gwmiss", skel);
    seed_flow_rule(&skel, remote_addr(), FLOW_REDIRECT_MARK);
    let target_mac = MacAddr::from_str("02:22:33:44:55:66").unwrap();
    seed_wan_slots(&skel, 5, TARGET_IFINDEX, false, Some(target_mac));
    // no ip_mac_v6 entry for the slot gate address

    let pkt = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let (ret, out, mark, forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_REDIRECT, "neigh fallback still redirects");
    assert_eq!(out, pkt, "no rewrite happened");
    assert_eq!(mark, 0x0400_0305);
    assert_eq!(forwarded, 1, "the cb flag is stamped before the neigh fallback");
}

// ---------------------------------------------------------------------------
// truncated frames
// ---------------------------------------------------------------------------

#[test]
fn wan6_egress_truncated_ip6_header_passes_to_stack() {
    // read_context truncation row (v6): ethertype claims IPv6 but the ip6
    // header is cut short → SHOT from read_context, mapped to "pass".
    load_skel!("tc-wan6-eg-runt", skel);
    let mut pkt = vec![0xff_u8; 14 + 20]; // eth + partial ip6 header
    pkt[12] = 0x86;
    pkt[13] = 0xdd;

    let (ret, out, mark, _forwarded) = run_wan6_egress(&skel, &pkt, &mut egress_ctx());

    assert_eq!(ret, RET_OK, "truncated ip6 header must pass, not drop");
    assert_eq!(out, pkt);
    assert_eq!(mark, 0);
}

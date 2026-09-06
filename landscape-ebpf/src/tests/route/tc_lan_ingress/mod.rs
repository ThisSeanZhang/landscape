//! IPv4 whole-flow baseline for the LAN-ingress route worker
//! `tc_route4_lan_ingress` (tc_lan_ingress_intro.bpf.c).
//!
//! Each test runs the complete worker pipeline once — scan → cache search →
//! neighbour learn → lan_redirect_check → flow_verdict → pick_wan →
//! set_cache_in_lan — and locks the current behaviour (including the TC-only
//! divergences noted below) before any route rewrite.
//!
//! Baseline quirks locked here (see tc_lan_ingress_intro.bpf.c):
//!   * no slot target + default flow (mark id 0) → TC_ACT_SHOT, i.e. the TC
//!     worker drops even default-flow traffic, unlike the XDP/legacy twin
//!     which passes it (DROP default flow branch);
//!   * the FLOW_FROM_LAN source bits are written to skb->mark only on two
//!     paths: search-cache non-OK returns and after a OK verdict — lan_redirect
//!     and flow-verdict short returns leave the mark untouched;
//!   * the docker slot branch returns early and never sets the
//!     TC_CHAIN_CB_FORWARDED_OFFSET cb flag;
//!   * a cache hit with ifindex != 0 redirects without learning or setting cb,
//!     a cache hit with ifindex == 0 goes through pick_wan (cb set);
//!   * a WAN-cache hit rewrites the full 14-byte header from the ip_mac value
//!     (dst mac, dev mac, proto) and does NOT update the flow mark value.
//!
//! PROG_TEST_RUN verdict mapping (verified empirically, see
//! test_lan_redirect_check.rs): OK=0, UNSPEC=-1, SHOT=2, REDIRECT=7.
//! ctx.ifindex must be <= 1 (loopback dev) so PROG_TEST_RUN never has to
//! resolve a real device; ingress_ifindex carries the simulated lan ifindex.
//!
//! Split: `first_packet` holds the slow-path matrix (scan → learn →
//! lan_redirect_check → verdict → pick_wan → set_cache), `cache_paths` the
//! `route4_search_cache_in_lan` fast paths; shared helpers live here.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use landscape_common::{
    flow::{ip_mark::IpConfig, ip_mark::IpMarkInfo, mark::FlowMark, FlowMarkInfo},
    net::MacAddr,
    sys_service::route_service::RouteTargetInfo,
};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
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
                as_bytes, create_route4_cache_inner_map, insert_ip_mac_v4, insert_route4_lan_entry,
                lookup_ip_mac_v4, lookup_rt4_cache_value, put_rt4_cache_full,
                put_rt4_cache_ifindex, put_rt4_cache_value, seed_flow_match_ip_v4,
                seed_flow_match_mac, LAN_CACHE, LAN_ROUTE_TYPE, ROUTE_TYPE_NEXTHOP, TARGET_IFINDEX,
                WAN_CACHE, WAN_IFINDEX, WAN_ROUTE_TYPE,
            },
            packet_builder::{simple_ipv4_tcp, simple_ipv6_tcp_syn},
        },
        TestSkb,
    },
};

pub(crate) mod tc_lan_ingress_intro {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_intro.skel.rs"));
}
use tc_lan_ingress_intro::TcLanIngressIntroSkel;

const RET_OK: i32 = 0;
const RET_UNSPEC: i32 = -1;
const RET_SHOT: i32 = 2;
const RET_REDIRECT: i32 = 7;

/// skb->ifindex under PROG_TEST_RUN when ctx.ifindex <= 1 (loopback dev).
const LOOPBACK_IFINDEX: u32 = 1;

const FLOW_REDIRECT_MARK: u32 = 0x0305; // action REDIRECT, flow id 5
const FLOW_DROP_MARK: u32 = 0x0200; // action DROP
const FLOW_DIRECT_MARK: u32 = 0x0100; // action DIRECT

const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

fn client_addr() -> Ipv4Addr {
    Ipv4Addr::from_str("192.168.1.10").unwrap()
}
/// WAN-side destination used by the flow/slot scenarios.
fn remote_wan_addr() -> Ipv4Addr {
    Ipv4Addr::from_str("10.0.0.20").unwrap()
}
fn wan_gateway() -> Ipv4Addr {
    Ipv4Addr::from_str("100.64.0.2").unwrap()
}

fn lan_ctx() -> TestSkb {
    TestSkb {
        ifindex: LOOPBACK_IFINDEX,
        ingress_ifindex: WAN_IFINDEX,
        ..Default::default()
    }
}

macro_rules! load_skel {
    ($pin:expr, $skel:ident) => {
        let pin_root = isolated_pin_root($pin);
        let mut builder = tc_lan_ingress_intro::TcLanIngressIntroSkelBuilder::default();
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = std::mem::MaybeUninit::uninit();
        let $skel = builder.open(&mut open_object).unwrap().load().unwrap();
    };
}

fn run_lan_ingress(
    skel: &TcLanIngressIntroSkel<'_>,
    pkt: &[u8],
    ctx: &mut TestSkb,
) -> (i32, Vec<u8>, u32, u32) {
    let mut out = vec![0_u8; pkt.len()];
    let mut ctx_out = TestSkb::default();
    let ret = skel
        .progs
        .tc_route4_lan_ingress
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: Some(ctx_out.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route4_lan_ingress")
        .return_value as i32;
    // TestSkb is packed: copy the asserted fields out explicitly.
    let mark = ctx_out.mark;
    let forwarded = ctx_out.cb[0];
    (ret, out, mark, forwarded)
}

/// Seed flow id 0's ip-trie with a single dst rule.
fn seed_flow_rule(skel: &TcLanIngressIntroSkel<'_>, dst: Ipv4Addr, mark: u32) {
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(mark),
        cidr: IpConfig { ip: IpAddr::V4(dst), prefix: 32 },
        priority: 100,
    }];
    create_inner_flow_match_map_v4(&skel.maps.flow4_ip_map, 0, &rules).unwrap();
}

/// Fill every slot of `flow_id` with a single WAN target.
fn seed_wan_slots(
    skel: &TcLanIngressIntroSkel<'_>,
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

/// WAN-binding entry for the redirect target (needed by the WAN-cache path).
fn seed_wan_binding(skel: &TcLanIngressIntroSkel<'_>) {
    crate::maps::wan::add_wan_ip(
        &skel.maps.wan_ip_binding,
        TARGET_IFINDEX,
        IpAddr::V4(Ipv4Addr::from_str("100.64.0.1").unwrap()),
        Some(IpAddr::V4(wan_gateway())),
        24,
        None,
    );
}

fn arp_frame() -> Vec<u8> {
    let mut pkt = vec![0xff_u8; 14 + 28];
    pkt[6..12].copy_from_slice(&CLIENT_MAC);
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    pkt
}

mod cache_paths;
mod first_packet;

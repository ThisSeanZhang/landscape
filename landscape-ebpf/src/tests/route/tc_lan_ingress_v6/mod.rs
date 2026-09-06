//! v6 baseline for the `tc_route6_lan_ingress` worker and the `route6_path.h`
//! functions it drives. Mirrors the v4 matrix (`tc_lan_ingress/`); v6
//! specifics are called out inline.
//!
//! Split: `first_packet` holds the slow-path matrix (scan → learn →
//! lan_redirect_check → verdict → pick_wan → set_cache), `cache_paths` the
//! `route6_search_cache_in_lan` fast paths; shared helpers live here.

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
        flow::types::FlowMatchKey, flow_dns::create_flow_dns_inner_map_v6,
        flow_wanip::create_inner_flow_match_map_v6, route::replace_wan_route_slots_v6_with_map,
    },
    tests::{
        isolated_pin_root,
        route::{
            map_helper::{
                as_bytes, create_route6_cache_inner_map, gateway_addr, insert_ip_mac_v6,
                insert_route6_lan_entry, local_addr, lookup_ip_mac_v6, lookup_rt6_cache_value,
                put_rt6_cache_full, put_rt6_cache_value, remote_addr, seed_flow_match_mac,
                LAN_CACHE, LAN_ROUTE_TYPE, ROUTE_TYPE_NEXTHOP, TARGET_IFINDEX, WAN_CACHE,
                WAN_IFINDEX, WAN_ROUTE_TYPE,
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

/// The wan-side self address (bound to the ingress wan device in tests).
fn wan_self_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:ffff::10").unwrap()
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

fn run_lan6_ingress(
    skel: &TcLanIngressIntroSkel<'_>,
    pkt: &[u8],
    ctx: &mut TestSkb,
) -> (i32, Vec<u8>, u32, u32) {
    let mut out = vec![0_u8; pkt.len()];
    let mut ctx_out = TestSkb::default();
    let ret = skel
        .progs
        .tc_route6_lan_ingress
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: Some(ctx_out.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run tc_route6_lan_ingress")
        .return_value as i32;
    let mark = ctx_out.mark;
    let forwarded = ctx_out.cb[0];
    (ret, out, mark, forwarded)
}

fn seed_flow_rule_under(skel: &TcLanIngressIntroSkel<'_>, flow_id: u32, dst: Ipv6Addr, mark: u32) {
    let rules = vec![IpMarkInfo {
        mark: FlowMark::from(mark),
        cidr: IpConfig { ip: IpAddr::V6(dst), prefix: 128 },
        priority: 100,
    }];
    create_inner_flow_match_map_v6(&skel.maps.flow6_ip_map, flow_id, &rules).unwrap();
}

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
            iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            gateway_ip: IpAddr::V6(gateway_addr()),
        },
        1,
    )];
    replace_wan_route_slots_v6_with_map(&skel.maps.rt6_slot_map, flow_id, &targets);
}

/// WAN-binding entry for the redirect target (needed by the WAN-cache path).
fn seed_wan_binding(skel: &TcLanIngressIntroSkel<'_>) {
    crate::maps::wan::add_wan_ip(
        &skel.maps.wan_ip_binding,
        TARGET_IFINDEX,
        IpAddr::V6(wan_self_addr()),
        Some(IpAddr::V6(gateway_addr())),
        64,
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

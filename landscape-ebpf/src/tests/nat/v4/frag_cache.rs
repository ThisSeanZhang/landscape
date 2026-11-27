//! NAT4 fragment-cache authorization: the cache may only be populated after
//! `napt_lan_state` / `napt_wan_state` has authorized the flow.

use std::net::Ipv4Addr;

use libbpf_rs::{MapCore, MapFlags};

use super::common::*;

const TC_ACT_UNSPEC: i32 = -1;
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

const FRAG_ID: u16 = 0x7777;
const WAN_PORT_UDP: u16 = 40000;

fn frag4_key(src: Ipv4Addr, dst: Ipv4Addr, ip_id: u16, proto: u8) -> [u8; 12] {
    let mut key = [0u8; 12];
    key[0..4].copy_from_slice(&src.octets());
    key[4..8].copy_from_slice(&dst.octets());
    key[8..10].copy_from_slice(&ip_id.to_be_bytes());
    key[10] = proto;
    key
}

#[test]
fn wan_first_fragment_without_mapping_is_dropped_without_caching() {
    with_skel(&[], &[], &[], |skel| {
        let first =
            ipv4_frag_udp_from_to(REMOTE_IP, WAN_IP, REMOTE_PORT, WAN_PORT_UDP, true, FRAG_ID);
        let (ret, _) = run(&skel.progs.tc_v4_from_wan, &first);
        assert_eq!(ret, TC_ACT_SHOT);
        assert_eq!(
            skel.maps.frag4_cache_wan.keys().count(),
            0,
            "unauthorized WAN first fragment must not populate frag4_cache_wan"
        );

        let later =
            ipv4_frag_udp_from_to(REMOTE_IP, WAN_IP, REMOTE_PORT, WAN_PORT_UDP, false, FRAG_ID);
        let (ret, _) = run(&skel.progs.tc_v4_from_wan, &later);
        assert_eq!(ret, TC_ACT_SHOT);
        assert_eq!(skel.maps.frag4_cache_wan.keys().count(), 0);
    });
}

#[test]
fn lan_first_fragment_with_mapping_populates_frag4_cache_lan() {
    with_skel(&[WAN_PORT_UDP], &[], &[], |skel| {
        let first = ipv4_frag_udp(true, FRAG_ID);
        let (ret, out) = run(&skel.progs.tc_v4_from_lan, &first);
        assert_eq!(ret, TC_ACT_UNSPEC);
        assert_eq!(parse_ipv4_src(&out), WAN_IP);

        let key = frag4_key(LAN_HOST, REMOTE_IP, FRAG_ID, PROTO_UDP);
        assert!(
            skel.maps.frag4_cache_lan.lookup(&key, MapFlags::ANY).unwrap().is_some(),
            "authorized LAN first fragment must populate frag4_cache_lan"
        );

        let later = ipv4_frag_udp(false, FRAG_ID);
        let (ret, out) = run(&skel.progs.tc_v4_from_lan, &later);
        assert_eq!(ret, TC_ACT_UNSPEC);
        assert_eq!(parse_ipv4_src(&out), WAN_IP);
    });
}

#[test]
fn static_wan_first_fragment_populates_frag4_cache_wan() {
    with_skel(&[], &[], &[], |skel| {
        seed_static(skel, PROTO_UDP, LAN_HOST, LAN_PORT, WAN_PORT_UDP);

        let first =
            ipv4_frag_udp_from_to(REMOTE_IP, WAN_IP, REMOTE_PORT, WAN_PORT_UDP, true, FRAG_ID);
        let (ret, out) = run(&skel.progs.tc_v4_from_wan, &first);
        assert_eq!(ret, TC_ACT_OK);
        assert_eq!(parse_ipv4_dst(&out), LAN_HOST);

        let key = frag4_key(REMOTE_IP, WAN_IP, FRAG_ID, PROTO_UDP);
        assert!(
            skel.maps.frag4_cache_wan.lookup(&key, MapFlags::ANY).unwrap().is_some(),
            "authorized static WAN first fragment must populate frag4_cache_wan"
        );

        let later =
            ipv4_frag_udp_from_to(REMOTE_IP, WAN_IP, REMOTE_PORT, WAN_PORT_UDP, false, FRAG_ID);
        let (ret, out) = run(&skel.progs.tc_v4_from_wan, &later);
        assert_eq!(ret, TC_ACT_OK);
        assert_eq!(parse_ipv4_dst(&out), LAN_HOST);
    });
}

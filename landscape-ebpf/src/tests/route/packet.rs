use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

use crate::tests::{
    route::package::{simple_ipv4_tcp, simple_ipv4_udp, simple_ipv6_tcp_syn, simple_ipv6_udp},
    scanner::package::{build_ipv6_frag_eth, build_ipv6_frag_nonfirst_eth},
    test_route_packet::TestRoutePacketSkelBuilder,
    wire::RoutePacketTestResult,
};
use zerocopy::FromBytes;

const MAP_KEY: u32 = 0;

fn run_route_packet_test(payload: Vec<u8>) -> RoutePacketTestResult {
    let builder = TestRoutePacketSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    skel.progs
        .test_route_packet
        .test_run(ProgramInput { data_in: Some(&payload), ..Default::default() })
        .expect("test_run failed");

    let result = skel
        .maps
        .route_packet_test_result_map
        .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
        .unwrap()
        .unwrap();
    RoutePacketTestResult::read_from_bytes(&result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TC_ACT_OK: i32 = 0;
    const TC_ACT_UNSPEC: i32 = -1;
    const LANDSCAPE_IPV4_TYPE: u8 = 0;
    const LANDSCAPE_IPV6_TYPE: u8 = 1;

    #[test]
    fn route_packet_ipv4_tcp_unicast_forwards() {
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let result = run_route_packet_test(simple_ipv4_tcp(src, dst));
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.forward_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV4_TYPE);
        assert_eq!(Ipv4Addr::from(result.v4.saddr.to_be()), src);
        assert_eq!(Ipv4Addr::from(result.v4.daddr.to_be()), dst);
    }

    #[test]
    fn route_packet_ipv4_udp_unicast_forwards() {
        let src = Ipv4Addr::new(10, 0, 0, 10);
        let dst = Ipv4Addr::new(10, 0, 0, 20);
        let result = run_route_packet_test(simple_ipv4_udp(src, dst));
        assert_eq!(result.forward_ret, TC_ACT_OK);
        assert_eq!(Ipv4Addr::from(result.v4.saddr.to_be()), src);
        assert_eq!(Ipv4Addr::from(result.v4.daddr.to_be()), dst);
    }

    #[test]
    fn route_packet_ipv4_broadcast_does_not_forward() {
        let result = run_route_packet_test(simple_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(255, 255, 255, 255),
        ));
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.forward_ret, TC_ACT_UNSPEC);
    }

    #[test]
    fn route_packet_ipv4_multicast_does_not_forward() {
        let result = run_route_packet_test(simple_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 10),
            Ipv4Addr::new(224, 0, 0, 1),
        ));
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.forward_ret, TC_ACT_UNSPEC);
    }

    #[test]
    fn route_packet_ipv6_tcp_unicast_forwards() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let result = run_route_packet_test(simple_ipv6_tcp_syn(src, dst));
        assert_eq!(result.forward_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(Ipv6Addr::from(result.v6.saddr), src);
        assert_eq!(Ipv6Addr::from(result.v6.daddr), dst);
    }

    #[test]
    fn route_packet_ipv6_udp_unicast_forwards() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
        let result = run_route_packet_test(simple_ipv6_udp(src, dst));
        assert_eq!(result.forward_ret, TC_ACT_OK);
        assert_eq!(Ipv6Addr::from(result.v6.saddr), src);
        assert_eq!(Ipv6Addr::from(result.v6.daddr), dst);
    }

    #[test]
    fn route_packet_ipv6_multicast_does_not_forward() {
        let result = run_route_packet_test(simple_ipv6_udp(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        ));
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.forward_ret, TC_ACT_UNSPEC);
    }

    #[test]
    fn route_packet_ipv6_link_local_does_not_forward() {
        let result = run_route_packet_test(simple_ipv6_udp(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        ));
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.forward_ret, TC_ACT_UNSPEC);
    }

    #[test]
    fn route_packet_ipv6_fragment_first_reads_l3() {
        let result = run_route_packet_test(build_ipv6_frag_eth());
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
    }

    #[test]
    fn route_packet_ipv6_fragment_nonfirst_reads_l3() {
        let result = run_route_packet_test(build_ipv6_frag_nonfirst_eth());
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
    }
}

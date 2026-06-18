use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

use crate::stages::firewall::tc_firewall_skel::TcFirewallSkelBuilder;
use crate::tests::test_firewall_packet::{
    types::firewall_packet_test_result, TestFirewallPacketSkelBuilder,
};

mod package;

unsafe impl plain::Plain for firewall_packet_test_result {}

const MAP_KEY: u32 = 0;

fn run_firewall_packet_test(mut payload: Vec<u8>) -> firewall_packet_test_result {
    let builder = TestFirewallPacketSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let input = ProgramInput { data_in: Some(&mut payload), ..Default::default() };
    skel.progs.test_firewall_packet.test_run(input).expect("test_run failed");

    let result = skel
        .maps
        .firewall_packet_test_result_map
        .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
        .unwrap()
        .unwrap();
    *plain::from_bytes::<firewall_packet_test_result>(&result).unwrap()
}

pub fn test_ingress_and_egress(mut egress_payload: Vec<u8>, mut ingress_payload: Vec<u8>) {
    let mut firewall_open_object = MaybeUninit::zeroed();
    let firewall_builder = TcFirewallSkelBuilder::default();

    let firewall_open_skel = firewall_builder.open(&mut firewall_open_object).unwrap();

    let repeat = 10_000;

    let skel = firewall_open_skel.load().unwrap();

    let egress_firewall = skel.progs.tc_firewall_wan_egress;
    let ingress_firewall = skel.progs.tc_firewall_wan_ingress;

    let egress_input = ProgramInput {
        data_in: Some(&mut egress_payload),
        context_in: None,
        context_out: None,
        data_out: None,
        repeat,
        ..Default::default()
    };
    let result = egress_firewall.test_run(egress_input).expect("test_run failed");

    assert_eq!(result.return_value as i32, -1);
    println!("time: {}", result.duration.as_nanos());

    let ingress_input = ProgramInput {
        data_in: Some(&mut ingress_payload),
        context_in: None,
        context_out: None,
        data_out: None,
        repeat,
        ..Default::default()
    };
    let result = ingress_firewall.test_run(ingress_input).expect("test_run failed");

    assert_eq!(result.return_value as i32, 0);
    println!("time: {}", result.duration.as_nanos());
}

#[cfg(test)]
pub mod tests {
    use crate::tests::firewall::{
        package::{
            icmpv6_error_with_inner_udp, icmpv6_error_with_mismatched_inner_source,
            icmpv6_ping_egress, icmpv6_ping_ingress,
        },
        run_firewall_packet_test, test_ingress_and_egress,
    };
    use crate::tests::scanner::package::{
        build_icmpv4_error_with_inner_ipv4_eth, build_ipv4_frag_first_eth,
        build_ipv4_frag_nonfirst_eth, build_ipv4_tcp_eth, build_ipv4_udp_eth, build_ipv6_frag_eth,
        build_ipv6_frag_nonfirst_eth, build_ipv6_tcp_eth,
    };

    const TC_ACT_OK: i32 = 0;
    const TC_ACT_SHOT: i32 = 2;
    const FRAG_FIRST: u8 = 1;
    const FRAG_MIDDLE: u8 = 2;
    const FRAG_LAST: u8 = 3;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const IPPROTO_ICMPV6: u8 = 58;
    const LANDSCAPE_IPV4_TYPE: u8 = 0;
    const LANDSCAPE_IPV6_TYPE: u8 = 1;

    #[test]
    fn test() {
        test_ingress_and_egress(icmpv6_ping_egress(), icmpv6_ping_ingress());
    }

    #[test]
    fn packet_reader_ipv4_tcp() {
        let result = run_firewall_packet_test(build_ipv4_tcp_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_OK);
        assert_eq!(result.did_frag_track, 1);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV4_TYPE);
        assert_eq!(result.offset.l4_protocol, IPPROTO_TCP);
        assert_eq!(u16::from_be(result.ip_pair.src_port), 21);
        assert_eq!(u16::from_be(result.ip_pair.dst_port), 1234);
    }

    #[test]
    fn packet_reader_ipv4_udp() {
        let result = run_firewall_packet_test(build_ipv4_udp_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_OK);
        assert_eq!(result.did_frag_track, 1);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV4_TYPE);
        assert_eq!(result.offset.l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.ip_pair.src_port), 5000);
        assert_eq!(u16::from_be(result.ip_pair.dst_port), 6000);
    }

    #[test]
    fn packet_reader_icmpv4_error_uses_inner_tuple() {
        let result = run_firewall_packet_test(build_icmpv4_error_with_inner_ipv4_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_OK);
        assert_eq!(result.did_frag_track, 0);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV4_TYPE);
        assert!(result.offset.icmp_error_inner_l4_offset > 0);
        assert_eq!(u16::from_be(result.ip_pair.src_port), 4321);
        assert_eq!(u16::from_be(result.ip_pair.dst_port), 1234);
    }

    #[test]
    fn packet_reader_icmpv6_error_uses_inner_tuple() {
        let result = run_firewall_packet_test(icmpv6_error_with_inner_udp());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_OK);
        assert_eq!(result.did_frag_track, 0);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.offset.l4_protocol, IPPROTO_ICMPV6);
        assert_eq!(result.offset.icmp_error_l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.offset.icmp_error_l4_protocol, IPPROTO_UDP);
        assert!(result.offset.icmp_error_inner_l4_offset > 0);
        assert_eq!(u16::from_be(result.ip_pair.src_port), 9);
        assert_eq!(u16::from_be(result.ip_pair.dst_port), 657);
    }

    #[test]
    fn packet_reader_icmpv6_error_rejects_mismatched_inner_source() {
        let result = run_firewall_packet_test(icmpv6_error_with_mismatched_inner_source());
        assert_eq!(result.parse_ret, TC_ACT_SHOT);
        assert_eq!(result.did_frag_track, 0);
    }

    #[test]
    fn packet_reader_ipv6_tcp() {
        let result = run_firewall_packet_test(build_ipv6_tcp_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.offset.l4_protocol, IPPROTO_TCP);
        assert_eq!(u16::from_be(result.ip_pair.src_port), 21);
        assert_eq!(u16::from_be(result.ip_pair.dst_port), 1234);
    }

    #[test]
    fn packet_reader_fragment_first_tracks_ports() {
        let result = run_firewall_packet_test(build_ipv4_frag_first_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_OK);
        assert_eq!(result.offset.fragment_type, FRAG_FIRST);
        assert_eq!(u16::from_be(result.ip_pair.src_port), 21);
        assert_eq!(u16::from_be(result.ip_pair.dst_port), 1234);
    }

    #[test]
    fn packet_reader_fragment_nonfirst_without_cache_drops() {
        let result = run_firewall_packet_test(build_ipv4_frag_nonfirst_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_SHOT);
        assert_eq!(result.offset.fragment_type, FRAG_MIDDLE);
    }

    #[test]
    fn packet_reader_ipv6_fragment_nonfirst_without_cache_drops() {
        let result = run_firewall_packet_test(build_ipv6_frag_nonfirst_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_SHOT);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.offset.fragment_type, FRAG_LAST);
    }

    #[test]
    fn packet_reader_ipv6_fragment_first_tracks() {
        let result = run_firewall_packet_test(build_ipv6_frag_eth());
        assert_eq!(result.parse_ret, TC_ACT_OK);
        assert_eq!(result.frag_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.offset.fragment_type, FRAG_FIRST);
    }
}

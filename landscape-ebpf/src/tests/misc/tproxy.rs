use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
};

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::maps::Inet6Bytes;
use crate::tests::{
    helper::wire::TproxyPacketTestResult,
    pkt::{
        build_icmpv4_echo_eth, build_ipv4_tcp_eth, build_ipv4_udp_eth, build_ipv6_tcp_eth,
        build_ipv6_udp_eth,
    },
    test_tproxy_packet::TestTproxyPacketSkelBuilder,
};
use zerocopy::FromBytes;

const MAP_KEY: u32 = 0;

// `tproxy_ingress` cannot be exercised through `BPF_PROG_TEST_RUN`: the
// kernel's `convert___skb_to_skb()` rejects non-zero `vlan_present` / `vlan_tci`
// in `ctx_in`, so the landscape VLAN tag cannot be injected. These tests cover
// the packet parser; ingress-level VLAN behaviour needs a live TC/veth test.

fn run_tproxy_packet_test(payload: Vec<u8>) -> TproxyPacketTestResult {
    let builder = TestTproxyPacketSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    skel.progs
        .test_tproxy_packet
        .test_run(ProgramInput { data_in: Some(&payload), ..Default::default() })
        .expect("test_run failed");

    let result = skel
        .maps
        .tproxy_packet_test_result_map
        .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
        .unwrap()
        .unwrap();
    TproxyPacketTestResult::read_from_bytes(&result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TC_ACT_OK: i32 = 0;
    const TC_ACT_UNSPEC: i32 = -1;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_UDP: u8 = 17;
    const LANDSCAPE_IPV4_TYPE: u8 = 0;
    const LANDSCAPE_IPV6_TYPE: u8 = 1;

    #[test]
    fn tproxy_packet_ipv4_tcp() {
        let result = run_tproxy_packet_test(build_ipv4_tcp_eth());
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l3_protocol, LANDSCAPE_IPV4_TYPE);
        assert_eq!(result.view.l4_protocol, IPPROTO_TCP);
        assert_eq!(Ipv4Addr::from(result.pair.src_addr.ipv4()), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Ipv4Addr::from(result.pair.dst_addr.ipv4()), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(u16::from_be(result.pair.src_port), 21);
        assert_eq!(u16::from_be(result.pair.dst_port), 1234);
    }

    #[test]
    fn tproxy_packet_ipv4_udp() {
        let result = run_tproxy_packet_test(build_ipv4_udp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 5000);
        assert_eq!(u16::from_be(result.pair.dst_port), 6000);
    }

    #[test]
    fn tproxy_packet_ipv6_tcp() {
        let result = run_tproxy_packet_test(build_ipv6_tcp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.view.l4_protocol, IPPROTO_TCP);
        assert_eq!(
            Ipv6Addr::from(result.pair.src_addr),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            Ipv6Addr::from(result.pair.dst_addr),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2)
        );
        assert_eq!(u16::from_be(result.pair.src_port), 21);
        assert_eq!(u16::from_be(result.pair.dst_port), 1234);
    }

    #[test]
    fn tproxy_packet_ipv6_udp() {
        let result = run_tproxy_packet_test(build_ipv6_udp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.view.l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 5000);
        assert_eq!(u16::from_be(result.pair.dst_port), 6000);
    }

    #[test]
    fn tproxy_packet_icmpv4_classified_without_inner_parse() {
        let result = run_tproxy_packet_test(build_icmpv4_echo_eth());
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_UNSPEC);
        assert_eq!(result.view.l4_protocol, IPPROTO_ICMP);
    }

    #[test]
    fn tproxy_packet_unsupported_protocol_returns_unspec() {
        let mut pkt = build_icmpv4_echo_eth();
        pkt[14 + 9] = 47;
        let result = run_tproxy_packet_test(pkt);
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_UNSPEC);
        assert_eq!(result.view.l4_protocol, 47);
    }
}

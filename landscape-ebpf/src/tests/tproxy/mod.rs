use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr},
};

use etherparse::{IcmpEchoHeader, Icmpv4Type, PacketBuilder};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

use crate::map_types::Inet6Bytes;
use crate::tests::{
    scanner::package::{
        build_icmpv4_error_with_inner_ipv4_eth, build_ipv4_tcp_eth, build_ipv4_udp_eth,
        build_ipv6_tcp_eth,
    },
    test_tproxy_packet::TestTproxyPacketSkelBuilder,
    wire::TproxyPacketTestResult,
};
use zerocopy::FromBytes;

const MAP_KEY: u32 = 0;

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

fn build_ipv6_udp_eth() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        64,
    )
    .udp(5000, 6000);

    let payload = [1_u8, 2, 3, 4, 5, 6, 7, 8];
    let mut bytes = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut bytes, &payload).unwrap();
    bytes
}

fn build_icmpv4_echo_with_id(id: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
    .icmpv4(Icmpv4Type::EchoRequest(IcmpEchoHeader { id, seq: 1 }));

    let mut bytes = Vec::with_capacity(builder.size(4));
    builder.write(&mut bytes, &[1_u8, 2, 3, 4]).unwrap();
    bytes
}

fn build_icmpv6_error_with_inner_udp() -> Vec<u8> {
    let outer_src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let inner_src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
    let inner_dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03];

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    bytes.extend_from_slice(&[0x86, 0xdd]);

    let payload_len: u16 = 8 + 40 + 8;
    bytes.extend_from_slice(&[0x60, 0, 0, 0]);
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.push(58);
    bytes.push(64);
    bytes.extend_from_slice(&outer_src);
    bytes.extend_from_slice(&inner_src);

    bytes.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 0]);

    bytes.extend_from_slice(&[0x60, 0, 0, 0]);
    bytes.extend_from_slice(&(8u16).to_be_bytes());
    bytes.push(17);
    bytes.push(30);
    bytes.extend_from_slice(&inner_src);
    bytes.extend_from_slice(&inner_dst);

    bytes.extend_from_slice(&(657u16).to_be_bytes());
    bytes.extend_from_slice(&(9u16).to_be_bytes());
    bytes.extend_from_slice(&(8u16).to_be_bytes());
    bytes.extend_from_slice(&(0x1234u16).to_be_bytes());
    bytes
}

fn build_icmpv6_echo_with_id(id: u16) -> Vec<u8> {
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let payload = [1_u8, 2, 3, 4];
    let payload_len = 8 + payload.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    bytes.extend_from_slice(&[0x86, 0xdd]);
    bytes.extend_from_slice(&[0x60, 0, 0, 0]);
    bytes.extend_from_slice(&(payload_len as u16).to_be_bytes());
    bytes.push(58);
    bytes.push(64);
    bytes.extend_from_slice(&src);
    bytes.extend_from_slice(&dst);
    bytes.extend_from_slice(&[128, 0, 0, 0]);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&(1_u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

fn build_icmpv4_error_with_inner_tcp_eth() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    bytes.extend_from_slice(&[0x08, 0x00]);

    let outer_total_len: u16 = 20 + 8 + 20 + 20;
    bytes.extend_from_slice(&[0x45, 0, 0, 0]);
    bytes[16..18].copy_from_slice(&outer_total_len.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 0, 64, 1, 0, 0]);
    bytes.extend_from_slice(&[8, 8, 8, 8]);
    bytes.extend_from_slice(&[10, 0, 0, 1]);

    bytes.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0]);

    bytes.extend_from_slice(&[0x45, 0, 0, 40]);
    bytes.extend_from_slice(&[0, 2, 0, 0, 64, 6, 0, 0]);
    bytes.extend_from_slice(&[10, 0, 0, 1]);
    bytes.extend_from_slice(&[10, 0, 0, 2]);
    bytes.extend_from_slice(&(1234_u16).to_be_bytes());
    bytes.extend_from_slice(&(4321_u16).to_be_bytes());
    bytes.extend_from_slice(&[0_u8; 16]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const TC_ACT_OK: i32 = 0;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_ICMPV6: u8 = 58;
    const LANDSCAPE_IPV4_TYPE: u8 = 0;
    const LANDSCAPE_IPV6_TYPE: u8 = 1;

    #[test]
    fn tproxy_packet_ipv4_tcp() {
        let result = run_tproxy_packet_test(build_ipv4_tcp_eth());
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV4_TYPE);
        assert_eq!(result.offset.l4_protocol, IPPROTO_TCP);
        assert_eq!(Ipv4Addr::from(result.pair.src_addr.ipv4()), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Ipv4Addr::from(result.pair.dst_addr.ipv4()), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(u16::from_be(result.pair.src_port), 21);
        assert_eq!(u16::from_be(result.pair.dst_port), 1234);
    }

    #[test]
    fn tproxy_packet_ipv4_udp() {
        let result = run_tproxy_packet_test(build_ipv4_udp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 5000);
        assert_eq!(u16::from_be(result.pair.dst_port), 6000);
    }

    #[test]
    fn tproxy_packet_ipv6_tcp() {
        let result = run_tproxy_packet_test(build_ipv6_tcp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.offset.l4_protocol, IPPROTO_TCP);
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
        assert_eq!(result.offset.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.offset.l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 5000);
        assert_eq!(u16::from_be(result.pair.dst_port), 6000);
    }

    #[test]
    fn tproxy_packet_icmpv4_echo_uses_echo_id_as_ports() {
        let result = run_tproxy_packet_test(build_icmpv4_echo_with_id(0x1234));
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l4_protocol, IPPROTO_ICMP);
        assert_eq!(u16::from_be(result.pair.src_port), 0x1234);
        assert_eq!(u16::from_be(result.pair.dst_port), 0x1234);
    }

    #[test]
    fn tproxy_packet_icmpv6_echo_uses_echo_id_as_ports() {
        let result = run_tproxy_packet_test(build_icmpv6_echo_with_id(0x4567));
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l4_protocol, IPPROTO_ICMPV6);
        assert_eq!(u16::from_be(result.pair.src_port), 0x4567);
        assert_eq!(u16::from_be(result.pair.dst_port), 0x4567);
    }

    #[test]
    fn tproxy_packet_icmpv4_error_inner_udp_reverses_ports() {
        let result = run_tproxy_packet_test(build_icmpv4_error_with_inner_ipv4_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l4_protocol, IPPROTO_ICMP);
        assert_eq!(result.offset.icmp_error_l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 4321);
        assert_eq!(u16::from_be(result.pair.dst_port), 1234);
    }

    #[test]
    fn tproxy_packet_icmpv4_error_inner_tcp_reverses_ports() {
        let result = run_tproxy_packet_test(build_icmpv4_error_with_inner_tcp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l4_protocol, IPPROTO_ICMP);
        assert_eq!(result.offset.icmp_error_l4_protocol, IPPROTO_TCP);
        assert_eq!(u16::from_be(result.pair.src_port), 4321);
        assert_eq!(u16::from_be(result.pair.dst_port), 1234);
    }

    #[test]
    fn tproxy_packet_icmpv6_error_inner_udp_reverses_ports() {
        let result = run_tproxy_packet_test(build_icmpv6_error_with_inner_udp());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.offset.l4_protocol, IPPROTO_ICMPV6);
        assert_eq!(result.offset.icmp_error_l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 9);
        assert_eq!(u16::from_be(result.pair.dst_port), 657);
    }
}

//! Boundary coverage for the shared ICMPv6 error parser used by the TC and
//! XDP NAT6 readers. Both call sites have their own thin wrapper around the
//! same wire-format rules, so every case runs against both readers.

use std::mem::MaybeUninit;

use etherparse::{
    IcmpEchoHeader, Icmpv6Type, IpFragOffset, Ipv6FragmentHeader, Ipv6Header, PacketBuilder,
    icmpv6::TimeExceededCode, ip_number,
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::FromBytes;

use crate::tests::helper::wire::{TcReadHead6Result, XdpReadHead6Result};
use crate::tests::pkt::build_ipv6_hop_udp_eth;
use crate::tests::test_xdp_read_head6_skel::TestXdpReadHead6SkelBuilder;

const L3_OFFSET: u32 = 14;
const DIR_LAN: u32 = 0;
const MAP_KEY: u32 = 0;

const OUTER_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const OUTER_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const INNER_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
const INNER_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2];

fn run_tc(pkt: &[u8]) -> TcReadHead6Result {
    super::tc_read_head6::run_reader(pkt, DIR_LAN)
}

fn run_xdp(pkt: &[u8]) -> XdpReadHead6Result {
    let builder = TestXdpReadHead6SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = L3_OFFSET;
        rodata.current_direction = DIR_LAN;
    }
    let skel = open.load().unwrap();
    let mut data = pkt.to_vec();
    skel.progs
        .test_xdp_read_head6
        .test_run(ProgramInput { data_in: Some(&mut data), ..Default::default() })
        .expect("xdp test_run failed");

    let bytes = skel
        .maps
        .xdp_reader_test_map
        .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
        .unwrap()
        .expect("missing xdp reader result");
    XdpReadHead6Result::read_from_bytes(&bytes).unwrap()
}

fn outer_icmp6_error(quoted: &[u8], pad_after_icmp: Option<usize>) -> Vec<u8> {
    let mut payload = quoted.to_vec();
    if let Some(len) = pad_after_icmp {
        assert!(len >= payload.len(), "padding must not truncate the quote");
        payload.resize(len, 0);
    }

    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(OUTER_SRC, OUTER_DST, 64)
    .icmpv6(Icmpv6Type::TimeExceeded(TimeExceededCode::HopLimitExceeded));

    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

fn inner_udp() -> Vec<u8> {
    let builder = PacketBuilder::ipv6(INNER_SRC, INNER_DST, 64).udp(5555, 6666);
    let mut pkt = Vec::with_capacity(builder.size(8));
    builder.write(&mut pkt, &[0xAA; 8]).unwrap();
    pkt
}

fn inner_icmp6_echo(id: u16) -> Vec<u8> {
    let builder = PacketBuilder::ipv6(INNER_SRC, INNER_DST, 64)
        .icmpv6(Icmpv6Type::EchoRequest(IcmpEchoHeader { id, seq: 1 }));
    let mut pkt = Vec::with_capacity(builder.size(0));
    builder.write(&mut pkt, &[]).unwrap();
    pkt
}

fn inner_frag_udp(offset: u16) -> Vec<u8> {
    const UDP_PAYLOAD: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
    let udp_len = 8 + UDP_PAYLOAD.len() as u16;

    let mut pkt = Vec::new();
    let mut ipv6 = Ipv6Header {
        traffic_class: 0,
        flow_label: Default::default(),
        payload_length: 0,
        next_header: ip_number::IPV6_FRAGMENTATION_HEADER,
        hop_limit: 64,
        source: INNER_SRC,
        destination: INNER_DST,
    };
    ipv6.set_payload_length(Ipv6FragmentHeader::LEN + udp_len as usize).unwrap();
    ipv6.write(&mut pkt).unwrap();

    let frag =
        Ipv6FragmentHeader::new(ip_number::UDP, IpFragOffset::try_new(offset).unwrap(), false, 7);
    frag.write(&mut pkt).unwrap();

    if offset == 0 {
        pkt.extend_from_slice(&7000u16.to_be_bytes());
        pkt.extend_from_slice(&8000u16.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&UDP_PAYLOAD);
    } else {
        pkt.extend_from_slice(&UDP_PAYLOAD);
    }
    pkt
}

fn assert_accept(
    pkt: &[u8],
    src: [u8; 16],
    dst: [u8; 16],
    inner_offset: u16,
    proto: u8,
    sport: u16,
    dport: u16,
) {
    let tc = run_tc(pkt);
    assert_eq!(tc.read_ret, 1, "TC reader rejected a valid ICMPv6 error");
    assert_eq!(tc.src_addr, src);
    assert_eq!(tc.dst_addr, dst);
    assert_eq!(tc.icmp_inner_l4_offset, inner_offset);
    assert_eq!(tc.icmp_inner_l4_protocol, proto);
    assert_eq!(u16::from_be(tc.sport), sport);
    assert_eq!(u16::from_be(tc.dport), dport);
    assert_eq!(tc.ports_valid, 1);

    let xdp = run_xdp(pkt);
    assert_eq!(xdp.read_ret, 1, "XDP reader rejected a valid ICMPv6 error");
    assert_eq!(xdp.src_addr, src);
    assert_eq!(xdp.dst_addr, dst);
    assert_eq!(xdp.icmp_inner_l4_offset, inner_offset);
    assert_eq!(xdp.icmp_inner_l4_protocol, proto);
    assert_eq!(u16::from_be(xdp.sport), sport);
    assert_eq!(u16::from_be(xdp.dport), dport);
    assert_eq!(xdp.ports_valid, 1);
}

fn assert_reject(pkt: &[u8]) {
    assert_eq!(run_tc(pkt).read_ret, 0, "TC reader accepted a malformed ICMPv6 error");
    assert_eq!(run_xdp(pkt).read_ret, -1, "XDP reader accepted a malformed ICMPv6 error");
}

#[test]
fn icmp6_error_inner_udp() {
    let pkt = outer_icmp6_error(&inner_udp(), None);
    assert_accept(&pkt, INNER_DST, OUTER_DST, 102, 17, 6666, 5555);
}

#[test]
fn icmp6_error_truncated_inner_ipv6_rejected() {
    let inner = inner_udp();
    let pkt = outer_icmp6_error(&inner[..30], None);
    assert_reject(&pkt);
}

#[test]
fn icmp6_error_inner_hop_by_hop_udp() {
    let eth = build_ipv6_hop_udp_eth();
    let inner_dst = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = outer_icmp6_error(&eth[14..], None);
    assert_accept(&pkt, inner_dst, OUTER_DST, 110, 17, 6000, 5000);
}

#[test]
fn icmp6_error_inner_initial_fragment_udp() {
    let pkt = outer_icmp6_error(&inner_frag_udp(0), None);
    assert_accept(&pkt, INNER_DST, OUTER_DST, 110, 17, 8000, 7000);
}

#[test]
fn icmp6_error_inner_noninitial_fragment_rejected() {
    let pkt = outer_icmp6_error(&inner_frag_udp(1), None);
    assert_reject(&pkt);
}

#[test]
fn icmp6_error_inner_icmpv6_echo() {
    let pkt = outer_icmp6_error(&inner_icmp6_echo(0x1234), None);
    assert_accept(&pkt, INNER_DST, OUTER_DST, 102, 58, 0x1234, 0x1234);
}

#[test]
fn icmp6_error_total_length_1280_accepted() {
    let pkt = outer_icmp6_error(&inner_udp(), Some(1280 - 8));
    assert_accept(&pkt, INNER_DST, OUTER_DST, 102, 17, 6666, 5555);
}

#[test]
fn icmp6_error_total_length_1281_rejected() {
    let pkt = outer_icmp6_error(&inner_udp(), Some(1281 - 8));
    assert_reject(&pkt);
}

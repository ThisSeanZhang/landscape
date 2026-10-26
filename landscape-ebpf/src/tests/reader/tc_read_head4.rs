use std::mem::MaybeUninit;

use etherparse::{IpFragOffset, IpHeaders, IpNumber, Ipv4Extensions, Ipv4Header, PacketBuilder};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::FromBytes;

use crate::tests::helper::wire::TcReadHead4Result;
use crate::tests::pkt::*;
use crate::tests::test_tc_read_head4_skel::TestTcReadHead4SkelBuilder;

const MAP_KEY: u32 = 0;
const L3_OFFSET: u32 = 14;
const DIR_LAN: u32 = 0;
const DIR_WAN: u32 = 1;

const LAND_FRAG_NONE: u8 = 0;
const LAND_FRAG_FIRST: u8 = 1;
const LAND_FRAG_NON_INITIAL: u8 = 2;

const TCP_PHASE_NONE: u8 = 0;
const TCP_PHASE_SYN: u8 = 1;
const TCP_PHASE_FIN: u8 = 3;
const TCP_PHASE_RST: u8 = 4;

fn run_reader_seq(payloads: &[&[u8]], direction: u32) -> Vec<TcReadHead4Result> {
    let builder = TestTcReadHead4SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = L3_OFFSET;
        rodata.current_direction = direction;
    }
    let skel = open.load().unwrap();
    let prog = &skel.progs.test_tc_read_head4;

    let mut results = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let mut data = payload.to_vec();
        let input = ProgramInput { data_in: Some(&mut data), ..Default::default() };
        let run_result = prog.test_run(input).expect("test_run failed");
        println!("return={} duration={:?}", run_result.return_value as i32, run_result.duration);

        let bytes = skel
            .maps
            .reader_test_map
            .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .expect("no result");
        results.push(TcReadHead4Result::read_from_bytes(&bytes).unwrap());
    }
    results
}

fn run_reader(payload: &[u8], direction: u32) -> TcReadHead4Result {
    run_reader_at(payload, direction, L3_OFFSET)
}

fn run_reader_at(payload: &[u8], direction: u32, l3_offset: u32) -> TcReadHead4Result {
    let builder = TestTcReadHead4SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = l3_offset;
        rodata.current_direction = direction;
    }
    let skel = open.load().unwrap();
    let prog = &skel.progs.test_tc_read_head4;
    let mut data = payload.to_vec();
    let input = ProgramInput { data_in: Some(&mut data), ..Default::default() };
    prog.test_run(input).expect("test_run failed");
    let bytes =
        skel.maps.reader_test_map.lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY).unwrap().unwrap();
    TcReadHead4Result::read_from_bytes(&bytes).unwrap()
}

fn assert_read_ok(r: &TcReadHead4Result) {
    assert_eq!(r.read_ret, 1, "read_ret={}", r.read_ret);
}

fn be16(value: u16) -> u16 {
    u16::from_be(value)
}

fn build_ipv4_frag_udp(first: bool, id: u16) -> Vec<u8> {
    let l4 = if first {
        let payload = [0x11_u8, 0x22, 0x33, 0x44];
        let mut bytes = Vec::with_capacity(8 + payload.len());
        bytes.extend_from_slice(&5000_u16.to_be_bytes());
        bytes.extend_from_slice(&6000_u16.to_be_bytes());
        bytes.extend_from_slice(&(8_u16 + payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    } else {
        vec![0xAB_u8; 32]
    };

    let mut ipv4 =
        Ipv4Header::new(0u16, 64, IpNumber::UDP, [192, 168, 1, 1], [192, 168, 1, 2]).unwrap();
    ipv4.identification = id;
    ipv4.more_fragments = true;
    ipv4.fragment_offset = IpFragOffset::try_new(if first { 0 } else { 1 }).unwrap();
    ipv4.set_payload_len(l4.len()).unwrap();
    ipv4.header_checksum = ipv4.calc_header_checksum();

    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ip(IpHeaders::Ipv4(ipv4, Ipv4Extensions::default()));

    let mut bytes = Vec::with_capacity(builder.size(l4.len()));
    builder.write(&mut bytes, IpNumber::UDP, &l4).unwrap();
    bytes
}

fn build_ipv4_frag_icmp_echo(first: bool, id: u16) -> Vec<u8> {
    let l4 = if first {
        let mut bytes = vec![8_u8, 0, 0, 0];
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0x11_u8, 0x22, 0x33, 0x44]);
        bytes
    } else {
        vec![0xAB_u8; 32]
    };

    let mut ipv4 =
        Ipv4Header::new(0u16, 64, IpNumber::ICMP, [192, 168, 1, 1], [192, 168, 1, 2]).unwrap();
    ipv4.identification = id;
    ipv4.more_fragments = true;
    ipv4.fragment_offset = IpFragOffset::try_new(if first { 0 } else { 1 }).unwrap();
    ipv4.set_payload_len(l4.len()).unwrap();
    ipv4.header_checksum = ipv4.calc_header_checksum();

    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ip(IpHeaders::Ipv4(ipv4, Ipv4Extensions::default()));

    let mut bytes = Vec::with_capacity(builder.size(l4.len()));
    builder.write(&mut bytes, IpNumber::ICMP, &l4).unwrap();
    bytes
}

fn build_ipv4_frag_nonfirst_tcp_eth() -> Vec<u8> {
    let fragment_payload = vec![0xAB_u8; 32];

    let mut ipv4 =
        Ipv4Header::new(0u16, 64, IpNumber::TCP, [192, 168, 1, 1], [192, 168, 1, 2]).unwrap();
    ipv4.identification = 0x4242;
    ipv4.more_fragments = true;
    ipv4.fragment_offset = IpFragOffset::try_new(1).unwrap();
    ipv4.set_payload_len(fragment_payload.len()).unwrap();
    ipv4.header_checksum = ipv4.calc_header_checksum();

    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ip(IpHeaders::Ipv4(ipv4, Ipv4Extensions::default()));

    let mut bytes = Vec::with_capacity(builder.size(fragment_payload.len()));
    builder.write(&mut bytes, IpNumber::TCP, &fragment_payload).unwrap();
    bytes
}

fn build_ipv4_tcp_noeth() -> Vec<u8> {
    let builder = PacketBuilder::ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
        .tcp(21, 1234, 12345, 4000)
        .syn();
    let payload = [0u8; 0];
    let mut bytes = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut bytes, &payload).unwrap();
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_v4_tcp() {
        let pkt = build_ipv4_tcp_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.src_addr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.dst_addr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(r.l3_offset, L3_OFFSET as u16);
        assert_eq!(r.l4_offset, 34);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(be16(r.sport), 21);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.tcp_phase, TCP_PHASE_NONE);
        assert_eq!(r.frag_code, LAND_FRAG_NONE);
        assert_eq!(r.ports_valid, 1);
        assert_eq!(r.icmp_inner_l4_offset, 0);
        assert_eq!(r.icmp_inner_l4_protocol, 0);
    }

    #[test]
    fn reader_v4_tcp_syn() {
        let pkt = build_ipv4_tcp_syn_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(r.tcp_phase, TCP_PHASE_SYN);
    }

    #[test]
    fn reader_v4_tcp_without_ethernet() {
        let pkt = build_ipv4_tcp_noeth();
        let r = run_reader_at(&pkt, DIR_LAN, 0);
        assert_read_ok(&r);
        assert_eq!(r.src_addr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.dst_addr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(r.l3_offset, 0);
        assert_eq!(r.l4_offset, 20);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(be16(r.sport), 21);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.tcp_phase, TCP_PHASE_SYN);
    }

    #[test]
    fn reader_v4_tcp_rst() {
        let pkt = build_ipv4_tcp_rst_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(r.tcp_phase, TCP_PHASE_RST);
    }

    #[test]
    fn reader_v4_tcp_fin() {
        let builder = PacketBuilder::ethernet2(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        )
        .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
        .tcp(21, 1234, 12345, 4000)
        .fin();
        let payload = [0u8; 8];
        let mut pkt = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut pkt, &payload).unwrap();

        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(r.tcp_phase, TCP_PHASE_FIN);
    }

    #[test]
    fn reader_v4_tcp_with_options() {
        let pkt = ipv4_tcp_syn_with_mss(1460, true);
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_offset, 34);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(be16(r.sport), 12345);
        assert_eq!(be16(r.dport), 443);
        assert_eq!(r.tcp_phase, TCP_PHASE_SYN);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v4_udp() {
        let pkt = build_ipv4_udp_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.src_addr.to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(r.dst_addr.to_ne_bytes(), [10, 0, 0, 2]);
        assert_eq!(r.l4_offset, 34);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 5000);
        assert_eq!(be16(r.dport), 6000);
        assert_eq!(r.tcp_phase, TCP_PHASE_NONE);
        assert_eq!(r.frag_code, LAND_FRAG_NONE);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v4_icmp_echo_lan() {
        let pkt = build_icmpv4_echo_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_protocol, 1);
        assert_eq!(r.sport, 0);
        assert_eq!(r.dport, 0);
        assert_eq!(r.ports_valid, 1);
        assert_eq!(r.icmp_inner_l4_offset, 0);
        assert_eq!(r.icmp_inner_l4_protocol, 0);
    }

    #[test]
    fn reader_v4_icmp_echo_wan_rejects_request() {
        let pkt = build_icmpv4_echo_eth();
        let r = run_reader(&pkt, DIR_WAN);
        assert_eq!(r.read_ret, 0);
        assert_eq!(r.l4_protocol, 1);
        assert_eq!(r.ports_valid, 0);
    }

    #[test]
    fn reader_v4_icmp_error_inner_udp() {
        let pkt = build_icmpv4_error_with_inner_ipv4_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.src_addr.to_ne_bytes(), [10, 0, 0, 2]);
        assert_eq!(r.dst_addr.to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(r.l4_offset, 34);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 4321);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.icmp_inner_l4_offset, 62);
        assert_eq!(r.icmp_inner_l4_protocol, 17);
        assert_eq!(r.tcp_phase, TCP_PHASE_NONE);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v4_icmp_error_without_ethernet() {
        let eth = build_icmpv4_error_with_inner_ipv4_eth();
        let pkt = &eth[14..];
        let r = run_reader_at(pkt, DIR_LAN, 0);
        assert_read_ok(&r);
        assert_eq!(r.src_addr.to_ne_bytes(), [10, 0, 0, 2]);
        assert_eq!(r.dst_addr.to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(r.l4_offset, 20);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 4321);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.icmp_inner_l4_offset, 48);
        assert_eq!(r.icmp_inner_l4_protocol, 17);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v4_icmp_error_inner_first_fragment() {
        let mut pkt = build_icmpv4_error_with_inner_ipv4_eth();
        let inner_off = L3_OFFSET as usize + 20 + 8;
        let frag_off = u16::from_be_bytes([pkt[inner_off + 6], pkt[inner_off + 7]]);
        pkt[inner_off + 6..inner_off + 8].copy_from_slice(&(frag_off | 0x2000_u16).to_be_bytes());

        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.src_addr.to_ne_bytes(), [10, 0, 0, 2]);
        assert_eq!(r.dst_addr.to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 4321);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.icmp_inner_l4_offset, 62);
        assert_eq!(r.icmp_inner_l4_protocol, 17);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v4_icmp_error_inner_tcp_min_quote() {
        let pkt = build_icmpv4_error_with_inner_tcp_min_quote_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.src_addr.to_ne_bytes(), [10, 0, 0, 2]);
        assert_eq!(r.dst_addr.to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(be16(r.sport), 4321);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.icmp_inner_l4_offset, 62);
        assert_eq!(r.icmp_inner_l4_protocol, 6);
        assert_eq!(r.tcp_phase, TCP_PHASE_NONE);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v4_first_fragment() {
        let pkt = build_ipv4_frag_first_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.frag_code, LAND_FRAG_FIRST);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(be16(r.sport), 21);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v4_nonfirst_fragment_cache_miss() {
        let pkt = build_ipv4_frag_nonfirst_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.frag_code, LAND_FRAG_NON_INITIAL);
        assert_eq!(r.l4_offset, 0);
        assert_eq!(r.ports_valid, 0);
        assert_eq!(r.sport, 0);
        assert_eq!(r.dport, 0);
    }

    #[test]
    fn reader_v4_nonfirst_fragment_cache_hit() {
        let first = build_ipv4_frag_first_eth();
        let nonfirst = build_ipv4_frag_nonfirst_tcp_eth();
        let results = run_reader_seq(&[&first, &nonfirst], DIR_LAN);
        assert_eq!(results.len(), 2);

        let first = &results[0];
        assert_read_ok(first);
        assert_eq!(first.frag_code, LAND_FRAG_FIRST);
        assert_eq!(be16(first.sport), 21);
        assert_eq!(be16(first.dport), 1234);

        let nonfirst = &results[1];
        assert_read_ok(nonfirst);
        assert_eq!(nonfirst.frag_code, LAND_FRAG_NON_INITIAL);
        assert_eq!(nonfirst.l4_offset, 0);
        assert_eq!(nonfirst.ports_valid, 1);
        assert_eq!(be16(nonfirst.sport), 21);
        assert_eq!(be16(nonfirst.dport), 1234);
    }

    #[test]
    fn reader_v4_frag_udp_cache_hit() {
        let first = build_ipv4_frag_udp(true, 0x5151);
        let nonfirst = build_ipv4_frag_udp(false, 0x5151);
        let results = run_reader_seq(&[&first, &nonfirst], DIR_LAN);
        assert_eq!(results.len(), 2);

        let first = &results[0];
        assert_read_ok(first);
        assert_eq!(first.frag_code, LAND_FRAG_FIRST);
        assert_eq!(first.l4_offset, 34);
        assert_eq!(first.l4_protocol, 17);
        assert_eq!(be16(first.sport), 5000);
        assert_eq!(be16(first.dport), 6000);

        let nonfirst = &results[1];
        assert_read_ok(nonfirst);
        assert_eq!(nonfirst.frag_code, LAND_FRAG_NON_INITIAL);
        assert_eq!(nonfirst.l4_offset, 0);
        assert_eq!(nonfirst.l4_protocol, 17);
        assert_eq!(nonfirst.ports_valid, 1);
        assert_eq!(be16(nonfirst.sport), 5000);
        assert_eq!(be16(nonfirst.dport), 6000);
    }

    #[test]
    fn reader_v4_frag_icmp_query_cache_hit() {
        let id = 0x4321;
        let first = build_ipv4_frag_icmp_echo(true, id);
        let nonfirst = build_ipv4_frag_icmp_echo(false, id);
        let results = run_reader_seq(&[&first, &nonfirst], DIR_LAN);
        assert_eq!(results.len(), 2);

        let first = &results[0];
        assert_read_ok(first);
        assert_eq!(first.frag_code, LAND_FRAG_FIRST);
        assert_eq!(first.l4_offset, 34);
        assert_eq!(first.l4_protocol, 1);
        assert_eq!(be16(first.sport), id);
        assert_eq!(be16(first.dport), id);

        let nonfirst = &results[1];
        assert_read_ok(nonfirst);
        assert_eq!(nonfirst.frag_code, LAND_FRAG_NON_INITIAL);
        assert_eq!(nonfirst.l4_offset, 0);
        assert_eq!(nonfirst.l4_protocol, 1);
        assert_eq!(nonfirst.ports_valid, 1);
        assert_eq!(be16(nonfirst.sport), id);
        assert_eq!(be16(nonfirst.dport), id);
    }

    #[test]
    fn reader_rejects_non_ipv4() {
        let pkt = build_ipv6_udp_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_eq!(r.read_ret, 0);
        assert_eq!(r.src_addr, 0);
        assert_eq!(r.dst_addr, 0);
    }
}

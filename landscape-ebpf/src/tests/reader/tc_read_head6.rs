use std::mem::MaybeUninit;

use etherparse::{
    Ethernet2Header, IcmpEchoHeader, Icmpv6Type, IpFragOffset, Ipv6FragmentHeader, Ipv6Header,
    PacketBuilder, TcpHeader, ether_type, ip_number,
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::FromBytes;

use crate::tests::helper::wire::TcReadHead6Result;
use crate::tests::pkt::*;
use crate::tests::test_tc_read_head6_skel::TestTcReadHead6SkelBuilder;

const MAP_KEY: u32 = 0;
const L3_OFFSET: u32 = 14;
const DIR_LAN: u32 = 0;

const LAND_FRAG_NONE: u8 = 0;
const LAND_FRAG_FIRST: u8 = 1;
const LAND_FRAG_NON_INITIAL: u8 = 2;
const LAND_FRAG_SINGLE_V6H: u8 = 4;

const TCP_PHASE_NONE: u8 = 0;
const TCP_PHASE_SYN: u8 = 1;

const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn run_reader_seq(payloads: &[&[u8]], direction: u32) -> Vec<TcReadHead6Result> {
    let builder = TestTcReadHead6SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = L3_OFFSET;
        rodata.current_direction = direction;
    }
    let skel = open.load().unwrap();
    let prog = &skel.progs.test_tc_read_head6;

    let mut results = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let data = payload.to_vec();
        let input = ProgramInput { data_in: Some(&data), ..Default::default() };
        let run_result = prog.test_run(input).expect("test_run failed");
        println!("return={} duration={:?}", run_result.return_value as i32, run_result.duration);

        let bytes = skel
            .maps
            .reader_test_map
            .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .expect("no result");
        results.push(TcReadHead6Result::read_from_bytes(&bytes).unwrap());
    }
    results
}

pub(super) fn run_reader(payload: &[u8], direction: u32) -> TcReadHead6Result {
    run_reader_seq(&[payload], direction).remove(0)
}

fn run_reader_at(payload: &[u8], direction: u32, l3_offset: u32) -> TcReadHead6Result {
    let builder = TestTcReadHead6SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = l3_offset;
        rodata.current_direction = direction;
    }
    let skel = open.load().unwrap();
    let data = payload.to_vec();
    skel.progs
        .test_tc_read_head6
        .test_run(ProgramInput { data_in: Some(&data), ..Default::default() })
        .expect("test_run failed");
    let bytes =
        skel.maps.reader_test_map.lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY).unwrap().unwrap();
    TcReadHead6Result::read_from_bytes(&bytes).unwrap()
}

fn assert_read_ok(r: &TcReadHead6Result) {
    assert_eq!(r.read_ret, 1, "read_ret={}", r.read_ret);
}

fn be16(value: u16) -> u16 {
    u16::from_be(value)
}

fn build_ipv6_icmpv6_echo(id: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(SRC6, DST6, 64)
    .icmpv6(Icmpv6Type::EchoRequest(IcmpEchoHeader { id, seq: 1 }));

    let mut bytes = Vec::with_capacity(builder.size(0));
    builder.write(&mut bytes, &[]).unwrap();
    bytes
}

fn build_ipv6_frag_tcp(offset: u16, more: bool, id: u32) -> Vec<u8> {
    let l4 = if offset == 0 {
        let payload = [0x11_u8, 0x22, 0x33, 0x44];
        let mut tcp = TcpHeader::new(12345, 443, 0x1020_3040, 4096);
        tcp.syn = true;
        let mut bytes = Vec::with_capacity(tcp.header_len() + payload.len());
        tcp.write(&mut bytes).unwrap();
        bytes.extend_from_slice(&payload);
        bytes
    } else {
        vec![0xAB_u8; 32]
    };

    let mut ipv6 = Ipv6Header {
        traffic_class: 0,
        flow_label: Default::default(),
        payload_length: 0,
        next_header: ip_number::IPV6_FRAGMENTATION_HEADER,
        hop_limit: 64,
        source: SRC6,
        destination: DST6,
    };
    ipv6.set_payload_length(Ipv6FragmentHeader::LEN + l4.len()).unwrap();
    let fragment =
        Ipv6FragmentHeader::new(ip_number::TCP, IpFragOffset::try_new(offset).unwrap(), more, id);
    let eth = Ethernet2Header {
        source: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        destination: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        ether_type: ether_type::IPV6,
    };

    let mut packet = Vec::new();
    eth.write(&mut packet).unwrap();
    ipv6.write(&mut packet).unwrap();
    fragment.write(&mut packet).unwrap();
    packet.extend_from_slice(&l4);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_v6_tcp() {
        let pkt = build_ipv6_tcp_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.src_addr, [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(r.dst_addr, [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(r.l3_offset, L3_OFFSET as u16);
        assert_eq!(r.l4_offset, 54);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(be16(r.sport), 21);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.tcp_phase, TCP_PHASE_NONE);
        assert_eq!(r.frag_code, LAND_FRAG_NONE);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v6_udp() {
        let pkt = build_ipv6_udp_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_offset, 54);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 5000);
        assert_eq!(be16(r.dport), 6000);
        assert_eq!(r.frag_code, LAND_FRAG_NONE);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v6_hop_by_hop_udp() {
        let pkt = build_ipv6_hop_udp_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_offset, 62);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 5000);
        assert_eq!(be16(r.dport), 6000);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v6_icmpv6_echo() {
        let pkt = build_ipv6_icmpv6_echo(0x1234);
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.l4_offset, 54);
        assert_eq!(r.l4_protocol, 58);
        assert_eq!(be16(r.sport), 0x1234);
        assert_eq!(be16(r.dport), 0x1234);
        assert_eq!(r.ports_valid, 1);
        assert_eq!(r.frag_code, LAND_FRAG_NONE);
    }

    #[test]
    fn reader_v6_first_fragment_icmpv6() {
        let pkt = build_ipv6_frag_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.frag_code, LAND_FRAG_FIRST);
        assert_eq!(r.l4_offset, 62);
        assert_eq!(r.l4_protocol, 58);
        assert_eq!(be16(r.sport), 0x5edf);
        assert_eq!(be16(r.dport), 0x5edf);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v6_without_ethernet() {
        let eth = build_ipv6_udp_eth();
        let r = run_reader_at(&eth[14..], DIR_LAN, 0);
        assert_read_ok(&r);
        assert_eq!(r.l3_offset, 0);
        assert_eq!(r.l4_offset, 40);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 5000);
        assert_eq!(be16(r.dport), 6000);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v6_icmp_error_inner_udp() {
        let pkt = build_icmpv6_error_with_inner_ipv6_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.src_addr, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2]);
        assert_eq!(r.dst_addr, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]);
        assert_eq!(r.l4_offset, 54);
        assert_eq!(r.l4_protocol, 17);
        assert_eq!(be16(r.sport), 4321);
        assert_eq!(be16(r.dport), 1234);
        assert_eq!(r.icmp_inner_l4_offset, 102);
        assert_eq!(r.icmp_inner_l4_protocol, 17);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v6_nonfirst_fragment_cache_miss() {
        let pkt = build_ipv6_frag_nonfirst_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.frag_code, LAND_FRAG_NON_INITIAL);
        assert_eq!(r.l4_offset, 0);
        assert_eq!(r.l4_protocol, 58);
        assert_eq!(r.ports_valid, 0);
    }

    #[test]
    fn reader_v6_atomic_fragment() {
        let pkt = build_ipv6_frag_tcp(0, false, 8);
        let r = run_reader(&pkt, DIR_LAN);
        assert_read_ok(&r);
        assert_eq!(r.frag_code, LAND_FRAG_SINGLE_V6H);
        assert_eq!(r.l4_offset, 62);
        assert_eq!(r.l4_protocol, 6);
        assert_eq!(be16(r.sport), 12345);
        assert_eq!(be16(r.dport), 443);
        assert_eq!(r.tcp_phase, TCP_PHASE_SYN);
        assert_eq!(r.ports_valid, 1);
    }

    #[test]
    fn reader_v6_nonfirst_fragment_cache_hit() {
        let first = build_ipv6_frag_tcp(0, true, 7);
        let nonfirst = build_ipv6_frag_tcp(1, true, 7);

        let builder = TestTcReadHead6SkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let mut open = builder.open(&mut open_object).unwrap();
        {
            let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
            rodata.current_l3_offset = L3_OFFSET;
            rodata.current_direction = DIR_LAN;
        }
        let skel = open.load().unwrap();
        let prog = &skel.progs.test_tc_read_head6;

        prog.test_run(ProgramInput { data_in: Some(&first), ..Default::default() })
            .expect("test_run failed");
        let bytes = skel
            .maps
            .reader_test_map
            .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
            .unwrap()
            .unwrap();
        let first_res = TcReadHead6Result::read_from_bytes(&bytes).unwrap();
        assert_read_ok(&first_res);
        assert_eq!(first_res.frag_code, LAND_FRAG_FIRST);
        assert_eq!(first_res.l4_offset, 62);
        assert_eq!(first_res.l4_protocol, 6);
        assert_eq!(be16(first_res.sport), 12345);
        assert_eq!(be16(first_res.dport), 443);
        assert_eq!(first_res.tcp_phase, TCP_PHASE_SYN);
        // Reader alone must not store into frag6_cache before NAT6 authorizes the flow.
        assert_eq!(skel.maps.frag6_cache_lan.keys().count(), 0);
        assert_eq!(skel.maps.frag6_cache_wan.keys().count(), 0);

        // Seed the cache entry that NAT6 writes after validating the binding.
        let mut cache_key = [0u8; 36];
        cache_key[0..16].copy_from_slice(&SRC6);
        cache_key[16..32].copy_from_slice(&DST6);
        cache_key[32..36].copy_from_slice(&7u32.to_be_bytes());
        let mut cache_val = [0u8; 8];
        cache_val[0..2].copy_from_slice(&12345u16.to_be_bytes());
        cache_val[2..4].copy_from_slice(&443u16.to_be_bytes());
        cache_val[4] = 6; // proto = TCP
        cache_val[5] = 6; // frag_next_header = TCP
        cache_val[6] = 1; // NPTV6_FRAG_FLAG_HAS_PORTS
        skel.maps.frag6_cache_lan.update(&cache_key, &cache_val, MapFlags::ANY).unwrap();

        prog.test_run(ProgramInput { data_in: Some(&nonfirst), ..Default::default() })
            .expect("test_run failed");
        let bytes = skel
            .maps
            .reader_test_map
            .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
            .unwrap()
            .unwrap();
        let nonfirst_res = TcReadHead6Result::read_from_bytes(&bytes).unwrap();
        assert_read_ok(&nonfirst_res);
        assert_eq!(nonfirst_res.frag_code, LAND_FRAG_NON_INITIAL);
        assert_eq!(nonfirst_res.l4_offset, 0);
        assert_eq!(nonfirst_res.l4_protocol, 6);
        assert_eq!(nonfirst_res.tcp_phase, TCP_PHASE_NONE);
        assert_eq!(nonfirst_res.ports_valid, 1);
        assert_eq!(be16(nonfirst_res.sport), 12345);
        assert_eq!(be16(nonfirst_res.dport), 443);
    }

    #[test]
    fn reader_rejects_non_ipv6() {
        let pkt = build_ipv4_tcp_eth();
        let r = run_reader(&pkt, DIR_LAN);
        assert_eq!(r.read_ret, 0);
        assert_eq!(r.src_addr, [0_u8; 16]);
        assert_eq!(r.dst_addr, [0_u8; 16]);
    }
}

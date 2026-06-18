use std::{mem::MaybeUninit, net::Ipv6Addr};

use etherparse::{
    ether_type, ip_number, Ethernet2Header, IpFragOffset, Ipv6FragmentHeader, Ipv6Header,
    PacketBuilder, PacketHeaders, TcpHeader, TcpOptionElement, TransportHeader,
};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::stages::mss::tc_mss_skel::TcMssSkelBuilder;

const MTU: u16 = 1492;
const IPV4_TARGET_MSS: u16 = MTU - 20 - 20;
const IPV6_TARGET_MSS: u16 = MTU - 40 - 20;

fn run_mss_clamp(mut payload: Vec<u8>) -> Vec<u8> {
    let builder = TcMssSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().mtu_size = MTU;
    open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = 14;
    let skel = open.load().unwrap();

    let mut packet_out = vec![0_u8; payload.len()];
    skel.progs
        .tc_mss_wan_ingress
        .test_run(ProgramInput {
            data_in: Some(&mut payload),
            data_out: Some(&mut packet_out),
            ..Default::default()
        })
        .expect("test_run failed");

    packet_out
}

fn tcp_mss(packet: &[u8]) -> Option<u16> {
    let headers = PacketHeaders::from_ethernet_slice(packet).expect("parse ethernet packet");
    let Some(TransportHeader::Tcp(tcp)) = headers.transport else { return None };

    let mut options = tcp.options.as_slice();
    while !options.is_empty() {
        match options[0] {
            0 => return None,
            1 => options = &options[1..],
            2 if options.len() >= 4 && options[1] == 4 => {
                return Some(u16::from_be_bytes([options[2], options[3]]));
            }
            _ if options.len() >= 2 && options[1] >= 2 && options[1] as usize <= options.len() => {
                options = &options[options[1] as usize..];
            }
            _ => return None,
        }
    }
    None
}

fn ipv4_tcp_syn_with_mss(mss: u16, syn: bool) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4([192, 0, 2, 10], [198, 51, 100, 20], 64)
        .tcp(12345, 443, 0x1020_3040, 4096)
        .options(&[TcpOptionElement::MaximumSegmentSize(mss)])
        .unwrap();

    let builder = if syn { builder.syn() } else { builder.ack(1) };
    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv4 tcp packet");
    packet
}

fn ipv4_tcp_syn_with_raw_options(options: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4([192, 0, 2, 10], [198, 51, 100, 20], 64)
        .tcp(12345, 443, 0x1020_3040, 4096)
        .syn()
        .options_raw(options)
        .unwrap();

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv4 tcp packet");
    packet
}

fn ipv6_tcp_syn_with_mss(src: Ipv6Addr, dst: Ipv6Addr, mss: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv6(src.octets(), dst.octets(), 64)
        .tcp(12345, 443, 0x1020_3040, 4096)
        .syn()
        .options(&[TcpOptionElement::MaximumSegmentSize(mss)])
        .unwrap();

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv6 tcp packet");
    packet
}

fn ipv6_fragmented_tcp_syn_with_mss(mss: u16) -> Vec<u8> {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let payload = [0x11_u8, 0x22, 0x33, 0x44];

    let mut tcp = TcpHeader::new(12345, 443, 0x1020_3040, 4096);
    tcp.syn = true;
    tcp.set_options(&[TcpOptionElement::MaximumSegmentSize(mss)]).unwrap();
    tcp.checksum = tcp.calc_checksum_ipv6_raw(src.octets(), dst.octets(), &payload).unwrap();

    let mut tcp_and_payload = Vec::with_capacity(tcp.header_len() + payload.len());
    tcp.write(&mut tcp_and_payload).expect("write tcp header");
    tcp_and_payload.extend_from_slice(&payload);

    let mut ipv6 = Ipv6Header {
        traffic_class: 0,
        flow_label: Default::default(),
        payload_length: 0,
        next_header: ip_number::IPV6_FRAGMENTATION_HEADER,
        hop_limit: 64,
        source: src.octets(),
        destination: dst.octets(),
    };
    ipv6.set_payload_length(Ipv6FragmentHeader::LEN + tcp_and_payload.len()).unwrap();
    let fragment = Ipv6FragmentHeader::new(
        ip_number::TCP,
        IpFragOffset::try_new(0).unwrap(),
        false,
        0x1020_3040,
    );
    let eth = Ethernet2Header {
        source: [0x02, 0, 0, 0, 0, 1],
        destination: [0x02, 0, 0, 0, 0, 2],
        ether_type: ether_type::IPV6,
    };

    let mut packet = Vec::new();
    eth.write(&mut packet).expect("write ethernet header");
    ipv6.write(&mut packet).expect("write ipv6 header");
    fragment.write(&mut packet).expect("write fragment header");
    packet.extend_from_slice(&tcp_and_payload);
    packet
}

fn ipv6_ah_tcp_syn_with_mss(mss: u16) -> Vec<u8> {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let payload = [0x11_u8, 0x22, 0x33, 0x44];

    let mut tcp = TcpHeader::new(12345, 443, 0x1020_3040, 4096);
    tcp.syn = true;
    tcp.set_options(&[TcpOptionElement::MaximumSegmentSize(mss)]).unwrap();
    tcp.checksum = tcp.calc_checksum_ipv6_raw(src.octets(), dst.octets(), &payload).unwrap();

    let mut tcp_and_payload = Vec::with_capacity(tcp.header_len() + payload.len());
    tcp.write(&mut tcp_and_payload).expect("write tcp header");
    tcp_and_payload.extend_from_slice(&payload);

    let ah_len = 12_usize;
    let mut ipv6 = Ipv6Header {
        traffic_class: 0,
        flow_label: Default::default(),
        payload_length: 0,
        next_header: ip_number::AUTHENTICATION_HEADER,
        hop_limit: 64,
        source: src.octets(),
        destination: dst.octets(),
    };
    ipv6.set_payload_length(ah_len + tcp_and_payload.len()).unwrap();

    let eth = Ethernet2Header {
        source: [0x02, 0, 0, 0, 0, 1],
        destination: [0x02, 0, 0, 0, 0, 2],
        ether_type: ether_type::IPV6,
    };

    let mut packet = Vec::new();
    eth.write(&mut packet).expect("write ethernet header");
    ipv6.write(&mut packet).expect("write ipv6 header");
    packet.extend_from_slice(&[ip_number::TCP.0, 1, 0, 0]);
    packet.extend_from_slice(&0x1020_3040_u32.to_be_bytes());
    packet.extend_from_slice(&1_u32.to_be_bytes());
    packet.extend_from_slice(&tcp_and_payload);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_clamp_ipv4_syn_clamps_large_mss() {
        let packet_out = run_mss_clamp(ipv4_tcp_syn_with_mss(1460, true));
        assert_eq!(tcp_mss(&packet_out), Some(IPV4_TARGET_MSS));
    }

    #[test]
    fn mss_clamp_ipv4_syn_keeps_small_mss() {
        let packet_out = run_mss_clamp(ipv4_tcp_syn_with_mss(1400, true));
        assert_eq!(tcp_mss(&packet_out), Some(1400));
    }

    #[test]
    fn mss_clamp_ipv4_non_syn_is_ignored() {
        let packet_out = run_mss_clamp(ipv4_tcp_syn_with_mss(1460, false));
        assert_eq!(tcp_mss(&packet_out), Some(1460));
    }

    #[test]
    fn mss_clamp_ipv4_nop_before_mss_clamps_large_mss() {
        let packet_out =
            run_mss_clamp(ipv4_tcp_syn_with_raw_options(&[1, 1, 2, 4, 0x05, 0xb4, 0, 0]));
        assert_eq!(tcp_mss(&packet_out), Some(IPV4_TARGET_MSS));
    }

    #[test]
    fn mss_clamp_ipv4_malformed_option_is_ignored() {
        let packet = ipv4_tcp_syn_with_raw_options(&[3, 1, 2, 4, 0x05, 0xb4, 0, 0]);
        let packet_out = run_mss_clamp(packet.clone());
        assert_eq!(packet_out, packet);
    }

    #[test]
    fn mss_clamp_ipv6_syn_clamps_large_mss() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let packet_out = run_mss_clamp(ipv6_tcp_syn_with_mss(src, dst, 1460));
        assert_eq!(tcp_mss(&packet_out), Some(IPV6_TARGET_MSS));
    }

    #[test]
    fn mss_clamp_ipv6_fragment_header_is_ignored() {
        let packet = ipv6_fragmented_tcp_syn_with_mss(1460);
        let packet_out = run_mss_clamp(packet.clone());
        assert_eq!(packet_out, packet);
    }

    #[test]
    fn mss_clamp_ipv6_ah_is_ignored() {
        let packet = ipv6_ah_tcp_syn_with_mss(1460);
        let packet_out = run_mss_clamp(packet.clone());
        assert_eq!(packet_out, packet);
    }
}

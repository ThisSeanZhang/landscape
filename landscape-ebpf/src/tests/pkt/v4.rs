//! Parameterized IPv4 packet construction (L3+ over ethernet).

use std::net::Ipv4Addr;

use etherparse::{PacketBuilder, TcpOptionElement};

pub(crate) fn simple_ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .tcp(12345, 443, 0x1020_3040, 4096);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv4 tcp packet");
    packet
}

pub(crate) fn simple_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .udp(10000, 53);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv4 udp packet");
    packet
}

pub(crate) fn ipv4_tcp_syn_with_mss(mss: u16, syn: bool) -> Vec<u8> {
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

pub(crate) fn ipv4_tcp_syn_with_raw_options(options: &[u8]) -> Vec<u8> {
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

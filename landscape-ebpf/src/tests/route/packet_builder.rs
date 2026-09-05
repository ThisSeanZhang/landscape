use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::PacketBuilder;

pub(crate) fn simple_ipv6_tcp_syn(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .tcp(12345, 443, 0x1020_3040, 4096);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv6 tcp packet");
    packet
}

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

pub(crate) fn simple_ipv6_udp(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .udp(10000, 53);

    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).expect("build ipv6 udp packet");
    packet
}

/// Solicited-node multicast address ff02::1:ffXX:XXXX for `addr`.
fn solicited_node_multicast(addr: Ipv6Addr) -> Ipv6Addr {
    let bits = addr.to_bits();
    let snma = 0xff02_0000_0000_0000_0000_0001_ff00_0000_u128 | (bits & 0xffffff);
    Ipv6Addr::from_bits(snma)
}

/// Ethernet multicast MAC (33:33:ff:XX:XX:XX) for a solicited-node multicast.
fn solicited_node_mac(addr: Ipv6Addr) -> [u8; 6] {
    let bits = addr.to_bits();
    [0x33, 0x33, 0xff, ((bits >> 16) & 0xff) as u8, ((bits >> 8) & 0xff) as u8, (bits & 0xff) as u8]
}

/// DAD Neighbor Solicitation: ethernet + IPv6 (nexthdr=ICMPv6) + NS header
/// (type 135, code 0, cksum, reserved) + 16-byte Target Address, sent to the
/// solicited-node multicast of `target`. The IPv6 source is unspecified
/// (`::`) as required by DAD (RFC 4862).
pub(crate) fn simple_ipv6_ns_dad(src_mac: [u8; 6], target: Ipv6Addr) -> Vec<u8> {
    let snma = solicited_node_multicast(target);
    let ns_len = 8 + 16;
    let mut packet = Vec::with_capacity(14 + 40 + ns_len);
    packet.extend_from_slice(&solicited_node_mac(target));
    packet.extend_from_slice(&src_mac);
    packet.extend_from_slice(&0x86DD_u16.to_be_bytes());
    // IPv6 header
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&(ns_len as u16).to_be_bytes());
    packet.push(58); // nexthdr = ICMPv6
    packet.push(255); // hop limit
    packet.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
    packet.extend_from_slice(&snma.octets());
    // ICMPv6 Neighbor Solicitation
    packet.extend_from_slice(&[135, 0, 0, 0, 0, 0, 0, 0]); // type, code, cksum, reserved
    packet.extend_from_slice(&target.octets());
    packet
}

//! PPPoE session encapsulation on top of the v4/v6 TCP builders.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::v4::simple_ipv4_tcp;
use super::v6::simple_ipv6_tcp_syn;

/// Minimal PPPoE session packet carrying an IPv4 payload: eth(0x8864) +
/// 8-byte pppoe header (session id big-endian, protocol 0x0021) + 20-byte
/// IPv4 header. Just enough parse depth for dispatch benchmarks.
pub(crate) fn simple_pppoe_ipv4(session: u16, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let inner = simple_ipv4_tcp(src, dst);
    let ip = &inner[14..]; // strip the ethernet header

    let mut packet = Vec::with_capacity(14 + 8 + ip.len());
    packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // eth dst
    packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // eth src
    packet.extend_from_slice(&[0x88, 0x64]); // ETH_P_PPP_SES
    packet.extend_from_slice(&[0x11]); // ver=1, type=1
    packet.push(0); // code: session data
    packet.extend_from_slice(&session.to_be_bytes());
    packet.extend_from_slice(&((ip.len() as u16).to_be_bytes())); // ppp length
    packet.extend_from_slice(&[0x00, 0x21]); // PPP protocol: IPv4
    packet.extend_from_slice(ip);
    packet
}

/// Minimal PPPoE session packet carrying an IPv6 payload: eth(0x8864) +
/// 8-byte pppoe header (session id big-endian, protocol 0x0057) + IPv6
/// header. Just enough parse depth for dispatch tests.
pub(crate) fn simple_pppoe_ipv6(session: u16, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let inner = simple_ipv6_tcp_syn(src, dst);
    let ip = &inner[14..]; // strip the ethernet header

    let mut packet = Vec::with_capacity(14 + 8 + ip.len());
    packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // eth dst
    packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // eth src
    packet.extend_from_slice(&[0x88, 0x64]); // ETH_P_PPP_SES
    packet.extend_from_slice(&[0x11]); // ver=1, type=1
    packet.push(0); // code: session data
    packet.extend_from_slice(&session.to_be_bytes());
    packet.extend_from_slice(&((ip.len() as u16).to_be_bytes())); // ppp length
    packet.extend_from_slice(&[0x00, 0x57]); // PPP protocol: IPv6
    packet.extend_from_slice(ip);
    packet
}

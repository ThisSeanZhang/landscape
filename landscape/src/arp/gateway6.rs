use std::io::{self, Read};
use std::net::Ipv6Addr;
use std::time::Duration;

use landscape_common::net::MacAddr;
use landscape_common::wan_link::GatewayNsTarget;
use tokio::io::Interest;
use tokio::time::{Instant, timeout_at};

use super::open_ip6_socket;

/// Send one ICMPv6 Neighbor Solicitation for the given WAN gateway.
/// Returns the gateway's advertised MAC, or `None` if no matching Neighbor
/// Advertisement arrives in time. Socket and send failures are returned.
///
/// The solicitation is sourced from the interface's link-local address:
/// Linux ignores an NS for a link-local target whose source is a global
/// address, and this mirrors what the kernel uses for its own NDP.
pub async fn probe_gateway_mac6(
    ifindex: u32,
    local_mac: MacAddr,
    gateway_ip: Ipv6Addr,
    timeout: Duration,
) -> io::Result<Option<MacAddr>> {
    GatewayNsTarget { ifindex, local_mac, gateway_ip }.validate()?;
    let local_ip = interface_linklocal(ifindex)?;

    let socket = open_ip6_socket(ifindex)?;
    let request = build_ns_packet(local_ip, local_mac, gateway_ip);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "NS timeout is too large"))?;
    let sent =
        timeout_at(deadline, socket.async_io(Interest::WRITABLE, |s| s.send(&request))).await??;
    if sent != request.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "incomplete NS request"));
    }

    let mut frame = [0u8; 86]; // Ethernet + IPv6 + NA, excluding options.
    while Instant::now() < deadline {
        let read = socket.async_io(Interest::READABLE, |mut s| s.read(&mut frame));
        let len = match timeout_at(deadline, read).await {
            Ok(received) => received?,
            Err(_) => break,
        };
        if let Some(mac) = gateway_reply6(&frame[..len], local_mac, local_ip, gateway_ip) {
            return Ok(Some(mac));
        }
    }
    Ok(None)
}

/// The unicast link-local address assigned to `ifindex`.
fn interface_linklocal(ifindex: u32) -> io::Result<Ipv6Addr> {
    let mut interfaces: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut interfaces) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut current = interfaces;
    let mut found = None;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() {
            let address = unsafe { &*entry.ifa_addr };
            if address.sa_family as i32 == libc::AF_INET6 {
                let socket_address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                let candidate = Ipv6Addr::from(socket_address.sin6_addr.s6_addr);
                if socket_address.sin6_scope_id == ifindex && candidate.is_unicast_link_local() {
                    found = Some(candidate);
                    break;
                }
            }
        }
        current = entry.ifa_next;
    }
    unsafe { libc::freeifaddrs(interfaces) };
    found.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "the WAN interface has no IPv6 link-local address")
    })
}

fn solicited_node(gateway: Ipv6Addr) -> [u8; 16] {
    let mut multicast = [0u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[11] = 0x01;
    multicast[12] = 0xff;
    multicast[13] = gateway.octets()[13];
    multicast[14] = gateway.octets()[14];
    multicast[15] = gateway.octets()[15];
    multicast
}

/// 86-byte Ethernet + IPv6 + ICMPv6 Neighbor Solicitation frame.
pub fn build_ns_packet(local_ip: Ipv6Addr, local_mac: MacAddr, gateway_ip: Ipv6Addr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(86);

    // Ethernet header: the solicited-node multicast MAC of the target.
    packet.extend_from_slice(&[0x33, 0x33, 0xff]);
    packet.extend_from_slice(&gateway_ip.octets()[13..16]);
    packet.extend_from_slice(&local_mac.octets());
    packet.extend_from_slice(&[0x86, 0xdd]);

    // IPv6 header: hop limit 255, ICMPv6 payload (8 + 16 + 8 bytes).
    packet.extend_from_slice(&[0x60, 0, 0, 0, 0, 0x20, 58, 255]);
    packet.extend_from_slice(&local_ip.octets());
    packet.extend_from_slice(&solicited_node(gateway_ip));

    // ICMPv6 Neighbor Solicitation: type 135, code 0, target, source lladdr.
    packet.extend_from_slice(&[135, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&gateway_ip.octets());
    packet.extend_from_slice(&[1, 1]); // option: source link-layer address
    packet.extend_from_slice(&local_mac.octets());

    let checksum = icmpv6_checksum(local_ip, solicited_node(gateway_ip).into(), &packet[54..]);
    packet[56..58].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Ones-complement ICMPv6 checksum over the pseudo-header and message.
fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, message: &[u8]) -> u16 {
    fn add(sum: &mut u32, bytes: &[u8]) {
        for word in bytes.as_chunks::<2>().0 {
            *sum += u32::from(u16::from_be_bytes(*word));
        }
        if bytes.len() % 2 == 1 {
            *sum += u32::from(bytes[bytes.len() - 1]) << 8;
        }
    }
    let mut sum: u32 = 0;
    add(&mut sum, &src.octets());
    add(&mut sum, &dst.octets());
    sum += message.len() as u32;
    sum += 58;
    add(&mut sum, message);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Validate a received frame as the Neighbor Advertisement for this exchange
/// and extract the target link-layer address it carries.
fn gateway_reply6(
    frame: &[u8],
    local_mac: MacAddr,
    local_ip: Ipv6Addr,
    gateway_ip: Ipv6Addr,
) -> Option<MacAddr> {
    if frame.len() < 14 + 40 + 24
        || frame[0..6] != local_mac.octets()
        || frame[12..14] != [0x86, 0xdd]
    {
        return None;
    }
    let ip = &frame[14..54];
    if ip[0] >> 4 != 6 || ip[6] != 58 {
        return None;
    }
    if ip[24..40] != local_ip.octets() {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap());
    if src.is_unspecified() || src.is_multicast() || src.is_loopback() {
        return None;
    }
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap());
    if frame[54] != 136 || frame[62..78] != gateway_ip.octets() {
        return None;
    }
    let message = &frame[54..];
    if icmpv6_checksum(src, dst, message) != 0 {
        return None;
    }
    for option in message[24..].chunks(8) {
        // Target link-layer address option carries the gateway MAC.
        if option.len() == 8 && option[0] == 2 {
            let mac =
                MacAddr::new(option[2], option[3], option[4], option[5], option[6], option[7]);
            if !mac.is_zero() && mac.is_unicast() {
                return Some(mac);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAN_IP: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
    const WAN_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 10);
    const GATEWAY_IP: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const GATEWAY_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);

    fn na_frame(src: Ipv6Addr, dst: Ipv6Addr, target: Ipv6Addr, mac: MacAddr) -> Vec<u8> {
        let mut packet = Vec::with_capacity(86);
        packet.extend_from_slice(&WAN_MAC.octets());
        packet.extend_from_slice(&mac.octets());
        packet.extend_from_slice(&[0x86, 0xdd]);
        packet.extend_from_slice(&[0x60, 0, 0, 0, 0, 0x20, 58, 255]);
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(&[136, 0, 0, 0, 0, 0, 0, 0]);
        packet.extend_from_slice(&target.octets());
        packet.extend_from_slice(&[2, 1]);
        packet.extend_from_slice(&mac.octets());
        let checksum = icmpv6_checksum(src, dst, &packet[54..]);
        packet[56..58].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn parses_only_a_matching_unicast_neighbor_advertisement() {
        let parse = |frame: &[u8]| gateway_reply6(frame, WAN_MAC, WAN_IP, GATEWAY_IP);
        assert_eq!(
            parse(&na_frame(GATEWAY_IP, WAN_IP, GATEWAY_IP, GATEWAY_MAC)),
            Some(GATEWAY_MAC)
        );
        assert_eq!(parse(&na_frame(GATEWAY_IP, WAN_IP, GATEWAY_IP, GATEWAY_MAC)[..85]), None);

        for frame in [
            na_frame(GATEWAY_IP, WAN_IP, GATEWAY_IP, MacAddr::zero()),
            na_frame(GATEWAY_IP, WAN_IP, GATEWAY_IP, MacAddr(1, 0, 0, 0, 0, 1)),
            na_frame(GATEWAY_IP, WAN_IP, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2), GATEWAY_MAC),
            na_frame(Ipv6Addr::UNSPECIFIED, WAN_IP, GATEWAY_IP, GATEWAY_MAC),
            na_frame(
                GATEWAY_IP,
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 11),
                GATEWAY_IP,
                GATEWAY_MAC,
            ),
        ] {
            assert_eq!(parse(&frame), None);
        }
        // A corrupted option MAC breaks the checksum.
        let mut corrupt = na_frame(GATEWAY_IP, WAN_IP, GATEWAY_IP, GATEWAY_MAC);
        corrupt[84] ^= 1;
        assert_eq!(parse(&corrupt), None);
    }

    #[test]
    fn solicited_node_multicast_tracks_the_target() {
        let first = solicited_node(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let second = solicited_node(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        assert_eq!(first[..13], [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]);
        assert_eq!(&first[13..], &[0, 0, 1]);
        assert_eq!(&second[13..], &[0, 0, 2]);
    }

    #[test]
    fn ns_frame_is_well_formed() {
        let packet = build_ns_packet(WAN_IP, WAN_MAC, GATEWAY_IP);
        assert_eq!(packet.len(), 86);
        assert_eq!(&packet[..6], &[0x33, 0x33, 0xff, 0, 0, 1]);
        assert_eq!(&packet[6..12], &WAN_MAC.octets());
        assert_eq!(packet[12..14], [0x86, 0xdd]);
        assert_eq!(&packet[14..22], &[0x60, 0, 0, 0, 0, 0x20, 58, 255]);
        assert_eq!(&packet[22..38], &WAN_IP.octets());
        assert_eq!(&packet[38..54], &solicited_node(GATEWAY_IP));
        assert_eq!(packet[54], 135);
        assert_eq!(&packet[62..78], &GATEWAY_IP.octets());
        assert_eq!(&packet[78..80], &[1, 1]);
        assert_eq!(&packet[80..86], &WAN_MAC.octets());
        let stored = u16::from_be_bytes([packet[56], packet[57]]);
        let mut message = packet[54..].to_vec();
        message[2..4].copy_from_slice(&[0, 0]);
        assert_ne!(stored, 0);
        assert_eq!(stored, icmpv6_checksum(WAN_IP, solicited_node(GATEWAY_IP).into(), &message));
    }

    #[test]
    #[ignore = "requires network namespace privileges, CAP_NET_RAW and iproute2"]
    fn veth_resolves_gateway_mac_over_ns_and_times_out_for_another_address() {
        // The namespace and both links disappear when this thread exits, including on panic.
        std::thread::spawn(|| {
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) },
                0,
                "{}",
                io::Error::last_os_error()
            );
            let ip = |args: &[&str]| {
                let output = std::process::Command::new("ip").args(args).output().unwrap();
                assert!(
                    output.status.success(),
                    "ip {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            };
            ip(&["link", "add", "wan0", "type", "veth", "peer", "name", "gw0"]);
            ip(&["link", "set", "wan0", "address", &WAN_MAC.to_string(), "up"]);
            ip(&["link", "set", "gw0", "address", &GATEWAY_MAC.to_string(), "up"]);
            // nodad: a tentative address does not answer NS yet.
            ip(&["-6", "addr", "add", "2001:db8::1/64", "dev", "gw0", "nodad"]);
            let gateway_ip = "2001:db8::1".parse().unwrap();
            let ifindex = unsafe { libc::if_nametoindex(c"wan0".as_ptr()) };
            assert_ne!(ifindex, 0);

            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
                async {
                    let probe = |ip, wait| probe_gateway_mac6(ifindex, WAN_MAC, ip, wait);
                    let absent = "2001:db8::2".parse().unwrap();
                    let (missing, found) = tokio::join!(
                        probe(absent, Duration::from_millis(200)),
                        probe(gateway_ip, Duration::from_secs(2)),
                    );
                    assert_eq!(found.unwrap(), Some(GATEWAY_MAC));
                    assert_eq!(missing.unwrap(), None);
                },
            );
        })
        .join()
        .unwrap();
    }
}

use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::time::Duration;

use landscape_common::net::MacAddr;
use landscape_common::wan_link::GatewayArpTarget;
use tokio::io::Interest;
use tokio::time::{Instant, timeout_at};

use super::{build_arp_request_packet, open_arp_socket, parse_arp_reply};

/// Broadcast one IPv4 ARP request on the given WAN interface.
/// Returns the gateway's advertised MAC, or `None` if no matching reply arrives in time.
/// Socket and send failures are returned to the caller.
pub async fn probe_gateway_mac(
    ifindex: u32,
    local_mac: MacAddr,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    timeout: Duration,
) -> io::Result<Option<MacAddr>> {
    GatewayArpTarget { ifindex, local_mac, local_ip, gateway_ip }.validate()?;

    let socket = open_arp_socket(ifindex)?;
    let request = build_arp_request_packet(gateway_ip, local_mac, local_ip);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ARP timeout is too large"))?;
    let sent =
        timeout_at(deadline, socket.async_io(Interest::WRITABLE, |s| s.send(&request))).await??;
    if sent != request.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "incomplete ARP request"));
    }

    let mut frame = [0u8; 42]; // Ethernet header and Ethernet/IPv4 ARP payload, excluding padding.
    while Instant::now() < deadline {
        let read = socket.async_io(Interest::READABLE, |mut s| s.read(&mut frame));
        let len = match timeout_at(deadline, read).await {
            Ok(received) => received?,
            Err(_) => break,
        };
        if let Some(mac) = gateway_reply(&frame[..len], local_mac, local_ip, gateway_ip) {
            return Ok(Some(mac));
        }
    }
    Ok(None)
}

fn gateway_reply(
    frame: &[u8],
    local_mac: MacAddr,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
) -> Option<MacAddr> {
    let (mac, ip) = parse_arp_reply(frame)?;
    (ip == gateway_ip
        && !mac.is_zero()
        && mac.is_unicast()
        && frame[32..38] == local_mac.octets()
        && frame[38..42] == local_ip.octets())
    .then_some(mac)
}

#[cfg(test)]
mod tests;

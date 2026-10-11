//! WAN link health probing: one ICMP echo exchange confined to the link's
//! iface and source address (`SO_BINDTODEVICE` + explicit source bind), so
//! a probe always leaves through the link it judges.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Local probe failure (missing `CAP_NET_RAW`, socket setup, send error).
/// A timed-out or unanswered probe is `Ok(None)`, never an error.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("icmp socket: {0}")]
    Socket(#[from] std::io::Error),
    #[error("probe task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

/// One health probe exchange, injected into the health-check runner so
/// tests can drive it with a fake.
#[async_trait::async_trait]
pub trait WanHealthProbe: Send + Sync {
    async fn ping_v4(
        &self,
        dev: &str,
        src: Ipv4Addr,
        target: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Option<Duration>, ProbeError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IcmpV4Probe;

#[async_trait::async_trait]
impl WanHealthProbe for IcmpV4Probe {
    async fn ping_v4(
        &self,
        dev: &str,
        src: Ipv4Addr,
        target: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Option<Duration>, ProbeError> {
        let dev = dev.to_string();
        tokio::task::spawn_blocking(move || icmp_ping_blocking(&dev, src, target, timeout))
            .await
            .map_err(ProbeError::Task)?
    }
}

fn icmp_ping_blocking(
    dev: &str,
    src: Ipv4Addr,
    target: Ipv4Addr,
    timeout: Duration,
) -> Result<Option<Duration>, ProbeError> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.bind_device(Some(dev.as_bytes()))?;
    socket.bind(&SockAddr::from(SocketAddr::from((src, 0))))?;

    let ident: u16 = rand::random();
    let seq: u16 = rand::random();
    let request = echo_request(ident, seq);

    let start = Instant::now();
    let dest = SockAddr::from(SocketAddr::from((target, 0)));
    socket.send_to(&request, &dest)?;

    let mut buf = [std::mem::MaybeUninit::<u8>::new(0); 1500];
    loop {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Ok(None);
        }
        socket.set_read_timeout(Some(remaining))?;
        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            // SO_RCVTIMEO expiry surfaces as EAGAIN on Linux.
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        if !from.as_socket().is_some_and(|addr| addr.ip() == IpAddr::V4(target)) {
            continue;
        }
        // SAFETY: recv_from initialized the first `len` bytes of `buf`.
        let packet = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), len) };
        let Some(icmp) = echo_reply_payload(packet) else { continue };
        let reply_id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let reply_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
        if reply_id == ident && reply_seq == seq {
            return Ok(Some(start.elapsed()));
        }
    }
}

/// Strip the IP header of an echo reply; `None` for short packets or
/// non-echo-reply ICMP messages.
fn echo_reply_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 28 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    let icmp = &packet[ihl..];
    if icmp[0] != 0 || icmp[1] != 0 {
        return None;
    }
    Some(icmp)
}

fn echo_request(ident: u16, seq: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + 16);
    packet.extend_from_slice(&[8, 0, 0, 0]);
    packet.extend_from_slice(&ident.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&[0x37; 16]);
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;
    packet
}

/// RFC 1071 16-bit one's complement checksum.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Test double scripting each target's outcome.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct FakeProbe<F>(pub F);

#[cfg(test)]
#[async_trait::async_trait]
impl<F> WanHealthProbe for FakeProbe<F>
where
    F: Fn(Ipv4Addr) -> Result<Option<Duration>, ProbeError> + Send + Sync,
{
    async fn ping_v4(
        &self,
        _dev: &str,
        _src: Ipv4Addr,
        target: Ipv4Addr,
        _timeout: Duration,
    ) -> Result<Option<Duration>, ProbeError> {
        self.0(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_socket_available() -> bool {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
    }

    #[test]
    fn checksum_matches_known_vector() {
        // echo header, id 0, seq 0, no payload.
        assert_eq!(icmp_checksum(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0xf7ff);
    }

    #[test]
    fn checksum_of_packet_with_checksum_verifies_to_zero() {
        let packet = echo_request(0x1234, 5);
        assert_eq!(icmp_checksum(&packet), 0, "checksum must self-verify");
    }

    #[test]
    fn echo_reply_payload_parses_and_rejects() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[20] = 0x00;
        packet[24..26].copy_from_slice(&0xabcdu16.to_be_bytes());
        packet[26..28].copy_from_slice(&0x0102u16.to_be_bytes());
        let icmp = echo_reply_payload(&packet).expect("echo reply passes");
        assert_eq!(&icmp[4..8], &[0xab, 0xcd, 0x01, 0x02]);

        packet[20] = 0x08;
        assert!(echo_reply_payload(&packet).is_none(), "echo request is not a reply");

        let mut with_options = vec![0u8; 32];
        with_options[0] = 0x46;
        with_options[24] = 0x00;
        let icmp = echo_reply_payload(&with_options).expect("IHL > 5 skips the option words");
        assert_eq!(icmp.len(), 8);

        assert!(echo_reply_payload(&packet[..20]).is_none(), "short packets are dropped");
    }

    #[tokio::test]
    async fn loopback_ping_roundtrips() {
        if !raw_socket_available() {
            eprintln!("skipping: no CAP_NET_RAW for raw ICMP sockets");
            return;
        }
        let probe = IcmpV4Probe;
        let rtt = probe
            .ping_v4("lo", Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, Duration::from_secs(2))
            .await
            .expect("raw socket is available");
        assert!(rtt.is_some(), "loopback echo must answer");
    }
}

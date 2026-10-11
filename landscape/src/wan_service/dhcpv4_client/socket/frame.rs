use bytes::BytesMut;
use landscape_common::net_proto::NetProtoCodec;
use landscape_common::net_proto::udp::dhcp::DhcpV4Message;
use std::net::Ipv4Addr;

pub(crate) fn build_raw_frame(
    mac: [u8; 6],
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    msg: &DhcpV4Message,
) -> std::io::Result<Vec<u8>> {
    let mut payload = BytesMut::new();
    msg.encode(&mut payload).map_err(|e| std::io::Error::other(e.to_string()))?;
    let builder = etherparse::PacketBuilder::ethernet2(mac, [0xff; 6])
        .ipv4(source_ip.octets(), dest_ip.octets(), 64)
        .udp(source_port, dest_port);
    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut frame, &payload).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(frame)
}

pub(crate) fn decode_raw_frame(
    buf: &[u8],
    client_port: u16,
    server_port: u16,
) -> Option<DhcpV4Message> {
    if buf.is_empty() {
        return None;
    }
    let headers = etherparse::PacketHeaders::from_ethernet_slice(buf).ok()?;
    let etherparse::TransportHeader::Udp(udp) = headers.transport? else {
        return None;
    };
    if udp.destination_port != client_port || udp.source_port != server_port {
        return None;
    }
    let mut payload = BytesMut::from(headers.payload.slice());
    match DhcpV4Message::decode(&mut payload) {
        Ok(Some(msg)) => Some(msg),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_msg() -> DhcpV4Message {
        let mut msg = DhcpV4Message::default();
        msg.set_xid(0x1234_5678);
        msg.opts_mut().insert(landscape_common::net_proto::dhcp::DhcpV4Option::MessageType(
            landscape_common::net_proto::dhcp::DhcpV4MessageType::Discover,
        ));
        msg
    }

    #[test]
    fn raw_frame_roundtrip() {
        let msg = sample_msg();
        let frame = build_raw_frame(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            67,
            68,
            &msg,
        )
        .unwrap();
        let decoded = decode_raw_frame(&frame, 68, 67).expect("frame should decode");
        assert_eq!(decoded.xid(), 0x1234_5678);
    }

    #[test]
    fn decode_rejects_wrong_ports() {
        let msg = sample_msg();
        let frame = build_raw_frame(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            67,
            68,
            &msg,
        )
        .unwrap();
        assert!(decode_raw_frame(&frame, 68, 68).is_none());
        assert!(decode_raw_frame(&frame, 69, 67).is_none());
    }
}

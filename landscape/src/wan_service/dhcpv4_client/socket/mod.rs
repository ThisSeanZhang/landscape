mod frame;
mod raw;

use bytes::BytesMut;
use landscape_common::net_proto::NetProtoCodec;
use landscape_common::net_proto::udp::dhcp::{DhcpV4Message, try_decode_dhcpv4};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

use frame::decode_raw_frame;
use raw::RawPacketSocket;

pub(crate) struct AdaptiveDhcpV4Socket {
    iface_name: String,
    ifindex: u32,
    mac_addr: [u8; 6],
    client_port: u16,
    server_port: u16,
    raw: Option<RawPacketSocket>,
    udp: Option<UdpSocket>,
}

impl AdaptiveDhcpV4Socket {
    pub(crate) fn new(
        iface_name: &str,
        ifindex: u32,
        mac_addr: [u8; 6],
        client_port: u16,
        server_port: u16,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            ifindex,
            mac_addr,
            client_port,
            server_port,
            raw: None,
            udp: None,
        }
    }

    pub(crate) async fn update_mode(&mut self, is_initial: bool) -> io::Result<()> {
        if is_initial {
            if self.raw.is_none() {
                tracing::info!("AdaptiveSocket: Switching to RAW mode (Broadcast/Init)");
                self.udp = None;
                self.raw = Some(RawPacketSocket::new(
                    &self.iface_name,
                    self.ifindex,
                    self.mac_addr,
                    self.client_port,
                    self.server_port,
                )?);
            }
        } else if self.udp.is_none() {
            tracing::info!("AdaptiveSocket: Switching to UDP mode (Unicast/Bound)");
            self.raw = None;
            self.udp = Some(bind_udp_socket(self.client_port)?);
        }
        Ok(())
    }

    pub(crate) async fn send(&self, msg: &DhcpV4Message, dest_ip: Ipv4Addr) -> io::Result<()> {
        if let Some(udp) = &self.udp {
            let mut buf = BytesMut::new();
            msg.encode(&mut buf).map_err(|e| std::io::Error::other(e.to_string()))?;
            udp.send_to(&buf, (dest_ip, self.server_port)).await?;
            Ok(())
        } else if let Some(raw) = &self.raw {
            raw.send_dhcp_packet(msg, dest_ip).await
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No active socket in AdaptiveDhcpV4Socket",
            ))
        }
    }

    pub(crate) async fn recv(&mut self) -> io::Result<DhcpV4Message> {
        let mut udp_buf = [0u8; 2048];
        loop {
            tokio::select! {
                res = async {
                    match &self.raw {
                        Some(raw) => raw.recv_frame().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match res {
                        Ok(frame) => {
                            if let Some(msg) = decode_raw_frame(&frame, self.client_port, self.server_port) {
                                return Ok(msg);
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }

                res = async {
                    match &self.udp {
                        Some(udp) => udp.recv_from(&mut udp_buf).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let (len, _addr) = res?;
                    if let Some(msg) = try_decode_dhcpv4(&udp_buf[..len]) {
                        return Ok(msg);
                    }
                }
            }
        }
    }
}

fn bind_udp_socket(client_port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.set_broadcast(true)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), client_port);
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

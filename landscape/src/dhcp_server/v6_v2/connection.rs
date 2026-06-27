use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use landscape_common::LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT;
use tokio::sync::mpsc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

static DHCPV6_MULTICAST_ROUTER: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2);
static ICMPV6_MULTICAST_ROUTER: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x2);

pub async fn get_dhcpv6_connect(
    ifindex: u32,
    iface_name: &String,
) -> anyhow::Result<(mpsc::Receiver<(Vec<u8>, SocketAddr)>, Arc<UdpSocket>)> {
    let socket_addr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT);

    let socket2 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    socket2.set_only_v6(true).unwrap();
    socket2.set_reuse_address(true).unwrap();
    socket2.set_reuse_port(true).unwrap();

    socket2.bind(&socket_addr.into()).unwrap();
    socket2.set_nonblocking(true).unwrap();

    socket2.bind_device(Some(iface_name.as_bytes()))?;

    socket2.join_multicast_v6(&DHCPV6_MULTICAST_ROUTER, ifindex).unwrap();

    let socket = UdpSocket::from_std(socket2.into()).unwrap();
    let send_socket = Arc::new(socket);
    let recv_socket = send_socket.clone();

    let (message_tx, message_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    // Receive loop
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                result = recv_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            tracing::debug!("DHCPv6 received {} bytes from {}", len, addr);
                            let message = buf[..len].to_vec();
                            if let Err(e) = message_tx.try_send((message, addr)) {
                                tracing::error!("DHCPv6 channel send error: {:?}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("DHCPv6 recv error: {:?}", e);
                        }
                    }
                },
                _ = message_tx.closed() => {
                    break;
                }
            }
        }
        tracing::info!("DHCPv6 recv loop down");
    });

    return Ok((message_rx, send_socket));
}

pub async fn get_icmp_connect(
    ifindex: u32,
    iface_name: &String,
) -> anyhow::Result<(mpsc::Receiver<(Vec<u8>, SocketAddr)>, Arc<UdpSocket>)> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    socket.set_unicast_hops_v6(255)?;
    socket.set_multicast_hops_v6(255)?;
    socket.bind_device(Some(iface_name.as_bytes()))?;

    socket.join_multicast_v6(&ICMPV6_MULTICAST_ROUTER, ifindex).unwrap();

    let udp_socket = UdpSocket::from_std(socket.into()).unwrap();
    let send_socket = Arc::new(udp_socket);

    let recive_socket_raw = send_socket.clone();

    let (message_tx, message_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = recive_socket_raw.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            let message = buf[..len].to_vec();
                            if let Err(e) = message_tx.try_send((message, addr)) {
                                tracing::error!("Error sending message to channel: {:?}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error receiving data: {:?}", e);
                        }
                    }
                },
                _ = message_tx.closed() => {
                    tracing::error!("message_tx closed");
                    break;
                }
            }
        }

        tracing::info!("ICMP recv loop down");
    });

    return Ok((message_rx, send_socket));
}

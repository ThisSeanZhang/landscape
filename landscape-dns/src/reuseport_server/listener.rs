use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use tokio::net::UdpSocket;

pub async fn create_udp_socket(address: SocketAddr) -> std::io::Result<(UdpSocket, i32)> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;

    let fd = socket.as_raw_fd();

    let udp_socket = UdpSocket::from_std(socket.into())?;
    Ok((udp_socket, fd))
}

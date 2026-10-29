use std::{
    io,
    io::{IoSlice, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
    thread,
};

use nix::{
    cmsg_space,
    sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, recvmsg, sendmsg,
        setsockopt, sockopt,
    },
};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket, Type};
use tokio::sync::{mpsc, mpsc::error::TrySendError};
use tokio_util::sync::CancellationToken;

use super::interface::MdnsInterface;
use super::packet::{MdnsFamily, MdnsPacket, MdnsSource, parse_query_unicast_response};
use super::{MDNS_PORT, MDNS_SOCKET_READ_TIMEOUT, MDNS_V4_GROUP, MDNS_V6_GROUP};

pub(super) enum MdnsSocket {
    V4(Arc<std::net::UdpSocket>),
    V6(Arc<std::net::UdpSocket>),
}

pub(super) fn spawn_socket_listener(
    socket: MdnsSocket,
    tx: mpsc::Sender<io::Result<MdnsPacket>>,
    token: CancellationToken,
) {
    thread::spawn(move || {
        loop {
            if token.is_cancelled() {
                break;
            }

            let result = match &socket {
                MdnsSocket::V4(socket) => recv_v4_packet(socket.as_raw_fd()),
                MdnsSocket::V6(socket) => recv_v6_packet(socket.as_raw_fd()),
            };

            match result {
                Ok(packet) => match tx.try_send(Ok(packet)) {
                    Ok(()) | Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Closed(_)) => break,
                },
                Err(e) if is_temporary_recv_error(&e) => {}
                Err(e) => {
                    let _ = tx.try_send(Err(e));
                    break;
                }
            }
        }
    });
}

fn is_temporary_recv_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

pub(super) fn create_v4_socket(interfaces: &[MdnsInterface]) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos"
    ))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into())?;
    for interface in interfaces.iter().filter(|interface| interface.has_ipv4) {
        if let Err(e) = socket
            .join_multicast_v4_n(&MDNS_V4_GROUP, &InterfaceIndexOrAddress::Index(interface.ifindex))
        {
            tracing::warn!("join IPv4 mDNS group on {} failed: {e}", interface.name);
        }
    }
    socket.set_multicast_ttl_v4(255)?;
    socket.set_ttl_v4(255)?;
    socket.set_multicast_loop_v4(true)?;
    setsockopt(&socket, sockopt::Ipv4PacketInfo, &true).map_err(nix_to_io)?;
    setsockopt(&socket, sockopt::Ipv4RecvTtl, &true).map_err(nix_to_io)?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(MDNS_SOCKET_READ_TIMEOUT))?;
    Ok(socket)
}

pub(super) fn create_v6_socket(interfaces: &[MdnsInterface]) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos"
    ))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0).into())?;
    for interface in interfaces.iter().filter(|interface| interface.has_ipv6) {
        if let Err(e) = socket.join_multicast_v6(&MDNS_V6_GROUP, interface.ifindex) {
            tracing::warn!("join IPv6 mDNS group on {} failed: {e}", interface.name);
        }
    }
    socket.set_multicast_hops_v6(255)?;
    socket.set_unicast_hops_v6(255)?;
    socket.set_multicast_loop_v6(true)?;
    setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &true).map_err(nix_to_io)?;
    setsockopt(&socket, sockopt::Ipv6RecvHopLimit, &true).map_err(nix_to_io)?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(MDNS_SOCKET_READ_TIMEOUT))?;
    Ok(socket)
}

pub(super) fn send_v4_message(
    fd: RawFd,
    message: &[u8],
    response_addr: Option<&MdnsSource>,
    ifindex: u32,
) -> io::Result<()> {
    let addr = match response_addr {
        Some(MdnsSource::V4(src)) => *src,
        _ => SockaddrIn::from(SocketAddrV4::new(MDNS_V4_GROUP, MDNS_PORT)),
    };
    let iov = [IoSlice::new(message)];
    let packet_info = libc::in_pktinfo {
        ipi_ifindex: ifindex as libc::c_int,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };
    let cmsgs = [ControlMessage::Ipv4PacketInfo(&packet_info)];
    sendmsg(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&addr)).map_err(nix_to_io)?;
    Ok(())
}

pub(super) fn send_v6_message(
    fd: RawFd,
    message: &[u8],
    response_addr: Option<&MdnsSource>,
    ifindex: u32,
) -> io::Result<()> {
    let addr = match response_addr {
        Some(MdnsSource::V6(src)) => *src,
        _ => SockaddrIn6::from(SocketAddrV6::new(MDNS_V6_GROUP, MDNS_PORT, 0, ifindex)),
    };
    let iov = [IoSlice::new(message)];
    let packet_info = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
        ipi6_ifindex: ifindex,
    };
    let cmsgs = [ControlMessage::Ipv6PacketInfo(&packet_info)];
    sendmsg(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&addr)).map_err(nix_to_io)?;
    Ok(())
}

fn recv_v4_packet(fd: RawFd) -> io::Result<MdnsPacket> {
    let mut buf = vec![0_u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg = cmsg_space!(libc::in_pktinfo, libc::c_int);
    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(nix_to_io)?;
    let bytes = msg.bytes;
    let src = msg.address.ok_or_else(|| io::Error::other("missing source address"))?;
    let mut ifindex = 0;
    let mut hop_limit = None;
    let mut destination_is_multicast = false;
    for cmsg in msg.cmsgs().map_err(nix_to_io)? {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(info) => {
                ifindex = info.ipi_ifindex as u32;
                destination_is_multicast =
                    Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()) == MDNS_V4_GROUP;
            }
            ControlMessageOwned::Ipv4Ttl(ttl) => {
                hop_limit = Some(ttl as u32);
            }
            _ => {}
        }
    }

    buf.truncate(bytes);
    let query_unicast_response = parse_query_unicast_response(&buf[..bytes]);

    Ok(MdnsPacket {
        bytes: buf,
        ifindex,
        hop_limit,
        destination_is_multicast,
        family: MdnsFamily::V4,
        src: MdnsSource::V4(src),
        query_unicast_response,
    })
}

fn recv_v6_packet(fd: RawFd) -> io::Result<MdnsPacket> {
    let mut buf = vec![0_u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg = cmsg_space!(libc::in6_pktinfo, libc::c_int);
    let msg = recvmsg::<SockaddrIn6>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(nix_to_io)?;
    let bytes = msg.bytes;
    let src = msg.address.ok_or_else(|| io::Error::other("missing source address"))?;
    let mut ifindex = 0;
    let mut hop_limit = None;
    let mut destination_is_multicast = false;
    for cmsg in msg.cmsgs().map_err(nix_to_io)? {
        match cmsg {
            ControlMessageOwned::Ipv6PacketInfo(info) => {
                ifindex = info.ipi6_ifindex;
                destination_is_multicast = Ipv6Addr::from(info.ipi6_addr.s6_addr) == MDNS_V6_GROUP;
            }
            ControlMessageOwned::Ipv6HopLimit(limit) => {
                hop_limit = Some(limit as u32);
            }
            _ => {}
        }
    }

    buf.truncate(bytes);
    let query_unicast_response = parse_query_unicast_response(&buf[..bytes]);

    Ok(MdnsPacket {
        bytes: buf,
        ifindex,
        hop_limit,
        destination_is_multicast,
        family: MdnsFamily::V6,
        src: MdnsSource::V6(src),
        query_unicast_response,
    })
}

fn nix_to_io(err: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

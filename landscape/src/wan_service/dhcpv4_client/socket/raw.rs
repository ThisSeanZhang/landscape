use landscape_common::net_proto::udp::dhcp::DhcpV4Message;
use libc::{AF_PACKET, ETH_P_IP, SO_ATTACH_FILTER, SOL_SOCKET, sock_filter, sock_fprog};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;

use super::frame::build_raw_frame;

pub(crate) struct RawPacketSocket {
    inner: AsyncFd<Socket>,
    ifindex: u32,
    mac: [u8; 6],
    client_port: u16,
    server_port: u16,
}

impl RawPacketSocket {
    pub(crate) fn new(
        iface_name: &str,
        ifindex: u32,
        mac: [u8; 6],
        client_port: u16,
        server_port: u16,
    ) -> io::Result<Self> {
        let protocol = (ETH_P_IP as u16).to_be() as i32;
        let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(protocol)))?;
        socket.bind_device(Some(iface_name.as_bytes()))?;
        socket.set_nonblocking(true)?;

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_ifindex = ifindex as i32;
        addr.sll_protocol = (ETH_P_IP as u16).to_be();
        socket.bind(&sockaddr_ll_to_sockaddr(addr))?;

        attach_dhcp_filter(&socket, client_port)?;

        Ok(Self {
            inner: AsyncFd::new(socket)?,
            ifindex,
            mac,
            client_port,
            server_port,
        })
    }

    pub(crate) async fn send_dhcp_packet(
        &self,
        msg: &DhcpV4Message,
        dest_ip: Ipv4Addr,
    ) -> io::Result<()> {
        let packet = build_raw_frame(
            self.mac,
            Ipv4Addr::UNSPECIFIED,
            dest_ip,
            self.client_port,
            self.server_port,
            msg,
        )?;

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_ifindex = self.ifindex as i32;
        addr.sll_protocol = (ETH_P_IP as u16).to_be();
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let dest = sockaddr_ll_to_sockaddr(addr);

        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(&packet, &dest)) {
                Ok(result) => {
                    result?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }

    pub(crate) async fn recv_frame(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let mut sock = inner.get_ref();
                std::io::Read::read(&mut sock, &mut buf)
            }) {
                Ok(Ok(len)) => {
                    buf.truncate(len);
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

fn sockaddr_ll_to_sockaddr(addr: libc::sockaddr_ll) -> SockAddr {
    unsafe {
        let mut storage = std::mem::zeroed::<socket2::SockAddrStorage>();
        std::ptr::copy_nonoverlapping(&addr, &mut storage as *mut _ as *mut libc::sockaddr_ll, 1);
        SockAddr::new(storage, std::mem::size_of::<libc::sockaddr_ll>() as u32)
    }
}

fn attach_dhcp_filter(socket: &Socket, client_port: u16) -> io::Result<()> {
    let filter = [
        sock_filter { code: 0x28, jt: 0, jf: 0, k: 0x0000000c }, // Ld ethertype
        sock_filter { code: 0x15, jt: 0, jf: 6, k: 0x00000800 }, // Jeq IP
        sock_filter { code: 0x30, jt: 0, jf: 0, k: 0x00000017 }, // Ld proto
        sock_filter { code: 0x15, jt: 0, jf: 4, k: 0x00000011 }, // Jeq UDP
        sock_filter { code: 0x28, jt: 0, jf: 0, k: 0x00000014 }, // Ld flags/off
        sock_filter { code: 0x45, jt: 2, jf: 0, k: 0x00001fff }, // Jset offset -> skip frag
        sock_filter { code: 0xb1, jt: 0, jf: 0, k: 0x0000000e }, // Ldxb 4*([14]&0xf)
        sock_filter { code: 0x48, jt: 0, jf: 0, k: 0x00000010 }, // Ld dst port (offset 14+2)
        sock_filter { code: 0x15, jt: 0, jf: 1, k: client_port as u32 }, // Jeq client_port
        sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x0000ffff }, // Ret all
        sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00000000 }, // Ret 0
    ];

    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut sock_filter,
    };

    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            std::mem::size_of::<sock_fprog>() as libc::socklen_t,
        )
    };

    if ret == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

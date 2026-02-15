use bytes::{Buf, BufMut, BytesMut};
use landscape_common::net_proto::dhcp::DhcpV4Message;
use landscape_common::net_proto::NetProtoCodec;
use libc::{sock_filter, sock_fprog, AF_PACKET, ETH_P_IP, SOL_SOCKET, SO_ATTACH_FILTER};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed};

/// A codec for raw packet injection, wrapping a protocol in Ethernet/IPv4/UDP headers.
pub struct RawPacketCodec<T> {
    pub mac: [u8; 6],
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub dest_port: u16,
    pub _phantom: std::marker::PhantomData<T>,
}

impl<T> RawPacketCodec<T> {
    pub fn new(mac: [u8; 6], source_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Self {
        Self {
            mac,
            source_ip,
            source_port,
            dest_port,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: NetProtoCodec> Decoder for RawPacketCodec<T> {
    type Item = T;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<T>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        match etherparse::PacketHeaders::from_ethernet_slice(src) {
            Ok(headers) => {
                if let Some(etherparse::TransportHeader::Udp(udp)) = headers.transport {
                    // Check if the destination port matches our source port (incoming packet)
                    if udp.destination_port == self.source_port {
                        let payload = headers.payload.slice();
                        let mut payload_mut = BytesMut::from(payload);
                        let msg = T::decode(&mut payload_mut).map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                        })?;
                        src.advance(src.len());
                        return Ok(msg);
                    }
                }
            }
            Err(_) => {}
        }

        src.clear();
        Ok(None)
    }
}

impl<T: NetProtoCodec> Encoder<(T, Ipv4Addr)> for RawPacketCodec<T> {
    type Error = std::io::Error;

    fn encode(&mut self, item: (T, Ipv4Addr), dst: &mut BytesMut) -> Result<(), Self::Error> {
        let (msg, dest_ip) = item;
        let mut payload = BytesMut::new();
        msg.encode(&mut payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let builder = etherparse::PacketBuilder::ethernet2(self.mac, [0xff; 6])
            .ipv4(self.source_ip.octets(), dest_ip.octets(), 64)
            .udp(self.source_port, self.dest_port);

        let packet_size = builder.size(payload.len());
        dst.reserve(packet_size);

        let mut writer = dst.writer();
        builder
            .write(&mut writer, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        Ok(())
    }
}

pub struct RawPacketIo {
    inner: AsyncFd<Socket>,
    ifindex: u32,
}

impl Clone for RawPacketIo {
    fn clone(&self) -> Self {
        let socket = self.inner.get_ref().try_clone().unwrap();
        Self {
            inner: AsyncFd::new(socket).unwrap(),
            ifindex: self.ifindex,
        }
    }
}

impl AsyncRead for RawPacketIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = futures::ready!(self.inner.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            let uninit_unfilled =
                unsafe { &mut *(unfilled as *mut [u8] as *mut [MaybeUninit<u8>]) };

            match guard.try_io(|inner| inner.get_ref().recv(uninit_unfilled)) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for RawPacketIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = futures::ready!(self.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
pub struct RawPacketSocket {
    io: RawPacketIo,
    mac: [u8; 6],
    client_port: u16,
    server_port: u16,
}

impl RawPacketSocket {
    pub fn new(
        iface_name: &str,
        ifindex: u32,
        mac: [u8; 6],
        client_port: u16,
        server_port: u16,
    ) -> std::io::Result<Self> {
        let protocol = (ETH_P_IP as u16).to_be() as i32;
        let socket = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(protocol)))
            .map_err(|e| {
                tracing::error!("Failed to create RAW socket: {:?}", e);
                e
            })?;

        socket.bind_device(Some(iface_name.as_bytes())).map_err(|e| {
            tracing::error!("Failed to bind to device {}: {:?}", iface_name, e);
            e
        })?;
        socket.set_nonblocking(true).map_err(|e| {
            tracing::error!("Failed to set nonblocking: {:?}", e);
            e
        })?;

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_ifindex = ifindex as i32;
        addr.sll_protocol = (ETH_P_IP as u16).to_be();

        let storage = unsafe {
            let mut s = std::mem::zeroed::<socket2::SockAddrStorage>();
            std::ptr::copy_nonoverlapping(&addr, &mut s as *mut _ as *mut libc::sockaddr_ll, 1);
            s
        };
        let sockaddr = unsafe {
            socket2::SockAddr::new(storage, std::mem::size_of::<libc::sockaddr_ll>() as u32)
        };

        socket.bind(&sockaddr).map_err(|e| {
            tracing::error!("Failed to bind sockaddr for ifindex {}: {:?}", ifindex, e);
            e
        })?;

        // 注入 BPF 过滤器：只允许 UDP 且目的端口为 client_port 的包进入。
        attach_dhcp_filter(&socket, client_port).map_err(|e| {
            tracing::error!("Failed to attach DHCP filter: {:?}", e);
            e
        })?;

        Ok(Self {
            io: RawPacketIo {
                inner: AsyncFd::new(socket).map_err(|e| {
                    tracing::error!("Failed to create AsyncFd: {:?}", e);
                    e
                })?,
                ifindex,
            },
            mac,
            client_port,
            server_port,
        })
    }

    pub fn into_framed(self) -> Framed<RawPacketIo, RawPacketCodec<DhcpV4Message>> {
        Framed::new(
            self.io,
            RawPacketCodec::new(
                self.mac,
                Ipv4Addr::UNSPECIFIED,
                self.client_port,
                self.server_port,
            ),
        )
    }

    pub async fn send_dhcp_packet(
        &self,
        msg: DhcpV4Message,
        dest_ip: Ipv4Addr,
    ) -> std::io::Result<()> {
        let mut payload = BytesMut::new();
        msg.encode(&mut payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let builder = etherparse::PacketBuilder::ethernet2(self.mac, [0xff; 6])
            .ipv4(Ipv4Addr::UNSPECIFIED.octets(), dest_ip.octets(), 64)
            .udp(self.client_port, self.server_port);

        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut packet, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = AF_PACKET as u16;
        addr.sll_ifindex = self.io.ifindex as i32;
        addr.sll_protocol = (ETH_P_IP as u16).to_be();
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

        let storage = unsafe {
            let mut s = std::mem::zeroed::<socket2::SockAddrStorage>();
            std::ptr::copy_nonoverlapping(&addr, &mut s as *mut _ as *mut libc::sockaddr_ll, 1);
            s
        };
        let dest = unsafe {
            socket2::SockAddr::new(storage, std::mem::size_of::<libc::sockaddr_ll>() as u32)
        };

        loop {
            let mut guard = self.io.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(&packet, &dest)) {
                Ok(result) => {
                    result?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

/// 挂载 BPF 过滤器，只通过 UDP 且目的端口为 client_port 的报文
fn attach_dhcp_filter(socket: &Socket, client_port: u16) -> std::io::Result<()> {
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
            use_std_os_fd(socket),
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            std::mem::size_of::<sock_fprog>() as libc::socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

/// 一个能够根据 DHCP 协议阶段动态切换底层 Socket (Raw/UDP) 的包装器。
/// 旨在解决 AF_PACKET 在 Bound 阶段的性能开销。
pub struct AdaptiveDhcpV4Socket {
    iface_name: String,
    ifindex: u32,
    mac_addr: [u8; 6],
    client_port: u16,
    server_port: u16,
    raw: Option<(RawPacketSocket, Framed<RawPacketIo, RawPacketCodec<DhcpV4Message>>)>,
    udp: Option<UdpSocket>,
}

impl AdaptiveDhcpV4Socket {
    pub fn new(
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

    /// 根据当前是否为初始化/广播阶段，切换底层 Socket
    pub async fn update_mode(&mut self, is_initial: bool) -> std::io::Result<()> {
        if is_initial {
            if self.raw.is_none() {
                tracing::info!("AdaptiveSocket: Switching to RAW mode (Broadcast/Init)");
                self.udp = None;
                match RawPacketSocket::new(
                    &self.iface_name,
                    self.ifindex,
                    self.mac_addr,
                    self.client_port,
                    self.server_port,
                ) {
                    Ok(raw) => {
                        self.raw = Some((raw.clone(), raw.into_framed()));
                    }
                    Err(e) => {
                        tracing::error!("Failed to initialize RAW socket: {:?}", e);
                        return Err(e);
                    }
                }
            }
        } else {
            if self.udp.is_none() {
                tracing::info!("AdaptiveSocket: Switching to UDP mode (Unicast/Bound)");
                self.raw = None;
                let socket = (|| -> std::io::Result<UdpSocket> {
                    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(
                        |e| {
                            tracing::error!("Failed to create UDP socket: {:?}", e);
                            e
                        },
                    )?;
                    s.set_reuse_address(true)?;
                    s.set_reuse_port(true)?;
                    s.set_nonblocking(true)?;
                    s.set_broadcast(true)?;
                    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.client_port);
                    s.bind(&addr.into()).map_err(|e| {
                        tracing::error!(
                            "Failed to bind UDP socket to port {}: {:?}",
                            self.client_port,
                            e
                        );
                        e
                    })?;
                    UdpSocket::from_std(s.into())
                })()?;
                self.udp = Some(socket);
            }
        }
        Ok(())
    }

    pub async fn send(&self, msg: DhcpV4Message, dest_ip: Ipv4Addr) -> std::io::Result<()> {
        if let Some(ref udp) = self.udp {
            let mut buf = BytesMut::new();
            msg.encode(&mut buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            udp.send_to(&buf, (dest_ip, self.server_port)).await?;
            Ok(())
        } else if let Some((ref raw, _)) = self.raw {
            raw.send_dhcp_packet(msg, dest_ip).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No active socket in AdaptiveDhcpV4Socket",
            ))
        }
    }

    pub async fn recv(&mut self) -> std::io::Result<(DhcpV4Message, SocketAddr)> {
        let mut udp_buf = [0u8; 2048];
        loop {
            tokio::select! {
                // 分支 1: 从 Raw 接收
                res = async {
                    if let Some((_, ref mut framed)) = self.raw {
                        use futures::StreamExt;
                        framed.next().await
                    } else {
                        futures::future::pending().await
                    }
                } => {
                    match res {
                        Some(Ok(msg)) => return Ok((msg, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.server_port))),
                        Some(Err(e)) => return Err(e),
                        None => continue,
                    }
                }

                // 分支 2: 从 UDP 接收
                res = async {
                    if let Some(ref s) = self.udp {
                        s.recv_from(&mut udp_buf).await
                    } else {
                        futures::future::pending().await
                    }
                } => {
                    let (len, addr) = res?;
                    let mut bytes = BytesMut::from(&udp_buf[..len]);
                    if let Ok(Some(msg)) = DhcpV4Message::decode(&mut bytes) {
                        return Ok((msg, addr));
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
fn use_std_os_fd(socket: &Socket) -> std::os::unix::io::RawFd {
    use std::os::unix::io::AsRawFd;
    socket.as_raw_fd()
}

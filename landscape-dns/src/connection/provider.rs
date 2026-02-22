use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::{future::Future, io, pin::Pin};

use hickory_resolver::{
    name_server::GenericConnector,
    proto::runtime::{
        iocompat::AsyncIoTokioAsStd, QuicSocketBinder, RuntimeProvider, TokioHandle, TokioTime,
    },
};

use landscape_common::dns::config::DnsBindConfig;
use libc::{setsockopt, SOL_SOCKET, SO_MARK, SO_RCVMARK};
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::net::{TcpSocket, TcpStream as TokioTcpStream};

pub type MarkConnectionProvider = GenericConnector<MarkRuntimeProvider>;

/// The Tokio Runtime for async execution
#[derive(Clone)]
pub struct MarkRuntimeProvider {
    handler: TokioHandle,
    mark_value: u32,
    bind_addr4: Option<Ipv4Addr>,
    bind_addr6: Option<Ipv6Addr>,
    quic_binder: MarkQuicSocketBinder,
}

impl fmt::Debug for MarkRuntimeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MarkRuntimeProvider")
            .field("mark_value", &self.mark_value)
            // .field("secret", &self.secret) // 手动跳过
            .finish()
    }
}

impl MarkRuntimeProvider {
    /// Create a Tokio runtime with a specific mark value
    pub fn new(mark_value: u32, bind_config: DnsBindConfig) -> Self {
        let DnsBindConfig { bind_addr4, bind_addr6 } = bind_config;
        MarkRuntimeProvider {
            handler: TokioHandle::default(),
            mark_value,
            bind_addr4,
            bind_addr6,
            quic_binder: MarkQuicSocketBinder { mark_value },
        }
    }
}

impl RuntimeProvider for MarkRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = TokioUdpSocket;
    type Tcp = AsyncIoTokioAsStd<TokioTcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handler.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let mark_value = self.mark_value;

        let (debug, bind_addr) = if server_addr.is_ipv4() {
            let bind_addr =
                self.bind_addr4.map(|addr| SocketAddr::new(IpAddr::V4(addr), 0)).or(bind_addr);

            (self.bind_addr4.is_some(), bind_addr)
        } else {
            let bind_addr =
                self.bind_addr6.map(|addr| SocketAddr::new(IpAddr::V6(addr), 0)).or(bind_addr);

            (self.bind_addr6.is_some(), bind_addr)
        };

        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            if debug {
                tracing::info!(
                    "Create tcp local_addr: {:?}, server_addr: {}, mark_value: {mark_value}",
                    bind_addr,
                    server_addr
                );
            }
            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }

            socket.set_nodelay(true)?;
            let fd = socket.as_raw_fd();
            set_socket_mark(fd, mark_value)?;

            let future = socket.connect(server_addr);
            let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));

            match tokio::time::timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let mark_value = self.mark_value;

        let (debug, socket_addr) = if server_addr.is_ipv4() {
            let socket_addr = self
                .bind_addr4
                .map(|addr| SocketAddr::new(IpAddr::V4(addr), 0))
                .unwrap_or(local_addr);

            (self.bind_addr4.is_some(), socket_addr)
        } else {
            let socket_addr = self
                .bind_addr6
                .map(|addr| SocketAddr::new(IpAddr::V6(addr), 0))
                .unwrap_or(local_addr);

            (self.bind_addr6.is_some(), socket_addr)
        };

        Box::pin(async move {
            if debug {
                tracing::info!(
                    "Create udp local_addr: {}, server_addr: {}, mark_value: {mark_value}",
                    socket_addr,
                    server_addr
                );
            }

            let socket = TokioUdpSocket::bind(socket_addr).await?;
            let fd = socket.as_raw_fd();
            set_socket_mark(fd, mark_value)?;
            socket.connect(server_addr).await?;

            Ok(socket)
        })
    }

    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(&self.quic_binder)
    }
}

#[derive(Clone)]
struct MarkQuicSocketBinder {
    mark_value: u32,
}

impl QuicSocketBinder for MarkQuicSocketBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        use quinn::Runtime;
        let socket = std::net::UdpSocket::bind(local_addr)?;
        set_socket_mark(socket.as_raw_fd(), self.mark_value)?;
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

#[allow(dead_code)]
pub fn set_socket_mark(fd: RawFd, mark_value: u32) -> io::Result<()> {
    // 设置 SO_MARK 选项
    let result = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_MARK,
            &mark_value as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
pub fn set_socket_income_mark(fd: RawFd, mark_value: u32) -> io::Result<()> {
    // 设置 SO_MARK 选项
    let result = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVMARK,
            &mark_value as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

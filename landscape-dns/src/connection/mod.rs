use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::{future::Future, io, pin::Pin};

use hickory_resolver::{
    name_server::GenericConnector,
    proto::runtime::{iocompat::AsyncIoTokioAsStd, RuntimeProvider, TokioHandle, TokioTime},
};

use libc::{setsockopt, SOL_SOCKET, SO_MARK};
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::net::{TcpSocket, TcpStream as TokioTcpStream};

pub type MarkConnectionProvider = GenericConnector<MarkRuntimeProvider>;

/// The Tokio Runtime for async execution
#[derive(Clone)]
pub struct MarkRuntimeProvider {
    handler: TokioHandle,
    mark_value: u32,
}

impl MarkRuntimeProvider {
    /// Create a Tokio runtime with a specific mark value
    pub fn new(mark_value: u32) -> Self {
        MarkRuntimeProvider { handler: TokioHandle::default(), mark_value }
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
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }

            socket.set_nodelay(true)?;

            let future = socket.connect(server_addr);
            let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));

            match tokio::time::timeout(wait_for, future).await {
                Ok(Ok(socket)) => {
                    let fd = socket.as_raw_fd();
                    set_socket_mark(fd, mark_value)?;
                    Ok(AsyncIoTokioAsStd(socket))
                }
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
        Box::pin(async move {
            let socket = TokioUdpSocket::bind(local_addr).await?;
            let fd = socket.as_raw_fd();
            set_socket_mark(fd, mark_value)?;
            tracing::info!("Create udp local_addr: {}, server_addr: {}", local_addr, server_addr);
            Ok(socket)
        })
    }
}

fn set_socket_mark(fd: RawFd, mark_value: u32) -> io::Result<()> {
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

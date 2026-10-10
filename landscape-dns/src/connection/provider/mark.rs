use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::dns::bind::DnsBindConfig;
use libc::{SO_MARK, SOL_SOCKET, setsockopt};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::net::{TcpSocket, TcpStream as TokioTcpStream};

/// Creates marked / source-bound sockets for upstream connections.
///
/// Every socket carries the DNS mark (the SO_MARK that selects the routing
/// table the upstream traffic must take) and, when configured, binds to the
/// upstream source address. The native transports call these methods directly;
/// the pool never touches socket creation.
#[derive(Clone)]
pub struct MarkRuntimeProvider {
    mark_value: u32,
    bind_addr4: Option<Ipv4Addr>,
    bind_addr6: Option<Ipv6Addr>,
}

impl fmt::Debug for MarkRuntimeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MarkRuntimeProvider").field("mark_value", &self.mark_value).finish()
    }
}

impl MarkRuntimeProvider {
    /// Create a provider applying `mark_value` (SO_MARK) and the optional
    /// source-address bindings to every socket it creates.
    pub fn new(mark_value: u32, bind_config: DnsBindConfig) -> Self {
        let DnsBindConfig { bind_addr4, bind_addr6 } = bind_config;
        MarkRuntimeProvider { mark_value, bind_addr4, bind_addr6 }
    }

    /// The local address a socket for `server_addr` should bind to: the
    /// configured source binding, or an ephemeral port on the unspecified
    /// address (letting the OS pick the source) when none is configured.
    fn bind_addr(&self, server_addr: SocketAddr) -> SocketAddr {
        match server_addr {
            SocketAddr::V4(_) => self
                .bind_addr4
                .map(|addr| SocketAddr::new(IpAddr::V4(addr), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            SocketAddr::V6(_) => self
                .bind_addr6
                .map(|addr| SocketAddr::new(IpAddr::V6(addr), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
        }
    }

    /// Connects a marked TCP socket to `server_addr`, waiting up to
    /// `wait_for` (default 5s) for the connect itself.
    pub async fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        wait_for: Option<Duration>,
    ) -> io::Result<TokioTcpStream> {
        let socket = match server_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }?;

        let bind_addr = self.bind_addr(server_addr);
        if self.bind_addr4.is_some() || self.bind_addr6.is_some() {
            tracing::info!(
                "Create tcp local_addr: {:?}, server_addr: {}, mark_value: {}",
                bind_addr,
                server_addr,
                self.mark_value
            );
        }
        socket.bind(bind_addr)?;

        socket.set_nodelay(true)?;
        set_socket_mark(socket.as_raw_fd(), self.mark_value)?;

        let future = socket.connect(server_addr);
        let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));

        match tokio::time::timeout(wait_for, future).await {
            Ok(Ok(socket)) => Ok(socket),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connection to {server_addr:?} timed out after {wait_for:?}"),
            )),
        }
    }

    /// Binds (and `connect`s) a marked UDP socket for `server_addr`.
    ///
    /// Deliberately `connect`ed: a connected UDP socket surfaces ICMP errors
    /// (e.g. port unreachable) as connection errors — an unreachable upstream
    /// becomes a detectable failure instead of a silent timeout — and the
    /// kernel drops datagrams from any source other than the peer.
    pub async fn bind_udp(&self, server_addr: SocketAddr) -> io::Result<TokioUdpSocket> {
        let bind_addr = self.bind_addr(server_addr);
        if self.bind_addr4.is_some() || self.bind_addr6.is_some() {
            tracing::debug!(
                "Create udp local_addr: {}, server_addr: {}, mark_value: {}",
                bind_addr,
                server_addr,
                self.mark_value
            );
        }

        let socket = TokioUdpSocket::bind(bind_addr).await?;
        set_socket_mark(socket.as_raw_fd(), self.mark_value)?;
        socket.connect(server_addr).await?;
        Ok(socket)
    }

    /// Binds a marked QUIC UDP socket for `server_addr`, honouring the
    /// upstream source-address binding the same way `connect_tcp` /
    /// `bind_udp` do.
    pub fn bind_quic(&self, server_addr: SocketAddr) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        use quinn::Runtime;
        let socket = self.bind_quic_socket(server_addr)?;
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }

    /// The marked, bound std UDP socket behind [`Self::bind_quic`]. Split
    /// out so the applied SO_MARK is observable in tests (the quinn wrapper
    /// does not expose the fd).
    fn bind_quic_socket(&self, server_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
        let bind_addr = self.bind_addr(server_addr);
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        set_socket_mark(socket.as_raw_fd(), self.mark_value)?;
        Ok(socket)
    }
}

/// Sets the SO_MARK option on a socket (the flow's routing identity).
pub fn set_socket_mark(fd: RawFd, mark_value: u32) -> io::Result<()> {
    let result = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_MARK,
            &mark_value as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if result == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the SO_MARK currently applied to the socket (0 = unmarked).
    fn read_socket_mark(fd: RawFd) -> u32 {
        let mut mark: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mut mark as *mut u32 as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(SO_MARK) failed: {}", std::io::Error::last_os_error());
        mark
    }

    /// An environment without CAP_NET_ADMIN cannot set SO_MARK, so the
    /// assertion is skipped there — but loudly, and never in a privileged
    /// CI (`LANDSCAPE_PRIVILEGED_CI=1`), where a missing capability is a
    /// real failure, not a skip.
    fn skip_without_net_admin(context: &str, e: &io::Error) {
        if std::env::var("LANDSCAPE_PRIVILEGED_CI").as_deref() == Ok("1") {
            panic!("{context} failed in privileged CI (LANDSCAPE_PRIVILEGED_CI=1): {e}");
        }
        eprintln!("skipping {context} (no CAP_NET_ADMIN): {e}");
    }

    /// The daemon's routing identity is the SO_MARK on the upstream sockets:
    /// this pins the mark actually applied by `MarkRuntimeProvider`.
    #[tokio::test]
    async fn udp_socket_carries_configured_mark() {
        let provider = MarkRuntimeProvider::new(0x8005, DnsBindConfig::default());
        let server: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let socket = match provider.bind_udp(server).await {
            Ok(socket) => socket,
            Err(e) => {
                skip_without_net_admin("SO_MARK assertion", &e);
                return;
            }
        };
        assert_eq!(read_socket_mark(socket.as_raw_fd()), 0x8005);
    }

    #[tokio::test]
    async fn tcp_socket_carries_configured_mark() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            socket
        });

        let provider = MarkRuntimeProvider::new(0x8005, DnsBindConfig::default());
        let stream = match provider.connect_tcp(server, None).await {
            Ok(stream) => stream,
            Err(e) => {
                skip_without_net_admin("SO_MARK assertion", &e);
                return;
            }
        };
        assert_eq!(read_socket_mark(stream.as_raw_fd()), 0x8005);
        let _ = accept.await;
    }

    /// The DoQ socket carries the mark too — it selects the routing table
    /// for QUIC traffic exactly like the TCP/UDP sockets do.
    #[test]
    fn quic_socket_carries_configured_mark() {
        let provider = MarkRuntimeProvider::new(0x8005, DnsBindConfig::default());
        let server: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let socket = match provider.bind_quic_socket(server) {
            Ok(socket) => socket,
            Err(e) => {
                skip_without_net_admin("SO_MARK assertion", &e);
                return;
            }
        };
        assert_eq!(read_socket_mark(socket.as_raw_fd()), 0x8005);
    }
}

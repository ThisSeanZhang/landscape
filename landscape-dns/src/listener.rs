use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::ServerFuture;
use rustls::server::ResolvesServerCert;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::server::handler::DnsRequestHandler;
use landscape_common::dns::DohRuntimeConfig;
use socket2::{Domain, Protocol, Socket, Type};

mod doh;

#[derive(Clone)]
pub struct DohTimeouts {
    pub handshake: Duration,
    pub request_body: Duration,
    pub idle_connection: Duration,
}

impl Default for DohTimeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(5),
            request_body: Duration::from_secs(5),
            idle_connection: Duration::from_secs(120),
        }
    }
}

#[derive(Clone)]
pub struct EffectiveDohListenerConfig {
    pub addr: SocketAddr,
    pub timeouts: DohTimeouts,
    pub server_cert_resolver: Arc<dyn ResolvesServerCert>,
    pub dns_hostname: Option<String>,
    pub http_endpoint: String,
}

#[derive(Clone)]
pub(crate) struct DohListenerStaticConfig {
    timeouts: DohTimeouts,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    dns_hostname: Option<String>,
}

#[derive(Clone)]
pub(crate) struct DohListenerState {
    pub(crate) static_config: DohListenerStaticConfig,
    /// DoH listen port/path are captured at process startup. Certificate/SNI
    /// domains hot-reload through the shared resolver, but changing the DoH
    /// endpoint itself requires restarting the process/listener.
    pub(crate) startup_config: DohRuntimeConfig,
}

impl DohListenerStaticConfig {
    pub(crate) fn build_effective_config(
        &self,
        doh_runtime: &DohRuntimeConfig,
    ) -> EffectiveDohListenerConfig {
        EffectiveDohListenerConfig {
            addr: SocketAddr::new(self.bind_addr(), doh_runtime.listen_port),
            timeouts: self.timeouts.clone(),
            server_cert_resolver: self.server_cert_resolver.clone(),
            dns_hostname: self.dns_hostname.clone(),
            http_endpoint: doh_runtime.http_endpoint.clone(),
        }
    }

    fn bind_addr(&self) -> std::net::IpAddr {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    }
}

impl DohListenerState {
    pub(crate) fn from_effective_config(value: EffectiveDohListenerConfig) -> Self {
        let startup_config = DohRuntimeConfig::from(&value);
        Self {
            static_config: DohListenerStaticConfig::from(value),
            startup_config,
        }
    }

    pub(crate) fn runtime_config(&self) -> DohRuntimeConfig {
        self.startup_config.clone()
    }

    pub(crate) fn build_effective_config(&self) -> EffectiveDohListenerConfig {
        self.static_config.build_effective_config(&self.startup_config)
    }
}

impl From<EffectiveDohListenerConfig> for DohListenerStaticConfig {
    fn from(value: EffectiveDohListenerConfig) -> Self {
        Self {
            timeouts: value.timeouts,
            server_cert_resolver: value.server_cert_resolver,
            dns_hostname: value.dns_hostname,
        }
    }
}

impl From<&EffectiveDohListenerConfig> for DohRuntimeConfig {
    fn from(value: &EffectiveDohListenerConfig) -> Self {
        Self {
            listen_port: value.addr.port(),
            http_endpoint: value.http_endpoint.clone(),
        }
    }
}

pub async fn create_udp_socket(address: SocketAddr) -> std::io::Result<(UdpSocket, i32)> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;

    let fd = socket.as_raw_fd();

    let udp_socket = UdpSocket::from_std(socket.into())?;
    Ok((udp_socket, fd))
}

pub fn create_tcp_listener(address: SocketAddr) -> std::io::Result<(tokio::net::TcpListener, i32)> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;

    let fd = socket.as_raw_fd();
    let listener: std::net::TcpListener = socket.into();
    let listener = tokio::net::TcpListener::from_std(listener)?;
    Ok((listener, fd))
}

pub async fn start_flow_dns_listener(
    flow_id: u32,
    addr: SocketAddr,
    doh: Option<EffectiveDohListenerConfig>,
    handler: DnsRequestHandler,
) -> CancellationToken {
    let Ok((udp, sock_fd)) = create_udp_socket(addr).await else {
        tracing::error!("[flow: {flow_id}]: create udp socket error");
        return cancelled_token();
    };

    attach_dns_socket(flow_id, sock_fd, false);

    let doh_handler = handler.clone();
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp);

    if let Some(doh) = doh {
        register_doh_listener(&mut server, flow_id, doh, doh_handler);
    }

    let token = server.shutdown_token().clone();
    let shutdown = token.clone();

    tokio::spawn(async move {
        let result = server.block_until_done().await;
        shutdown.cancel();

        if let Err(e) = result {
            tracing::error!("[flow: {flow_id}]: server down, error: {e:?}");
        } else {
            tracing::info!("[flow: {flow_id}]: server down");
        }
    });

    token
}

fn register_doh_listener(
    server: &mut ServerFuture<DnsRequestHandler>,
    flow_id: u32,
    doh: EffectiveDohListenerConfig,
    handler: DnsRequestHandler,
) {
    match create_tcp_listener(doh.addr) {
        Ok((listener, sock_fd)) => {
            attach_dns_socket(flow_id, sock_fd, true);
            doh::spawn_doh_listener(
                flow_id,
                listener,
                doh::DohListenerConfig {
                    timeouts: doh.timeouts,
                    server_cert_resolver: doh.server_cert_resolver.clone(),
                    dns_hostname: doh.dns_hostname.clone(),
                    http_endpoint: doh.http_endpoint,
                },
                handler,
                server.shutdown_token().clone(),
            );
        }
        Err(e) => {
            tracing::error!("[flow: {flow_id}]: create DoH listener error: {e}");
        }
    }
}

fn attach_dns_socket(flow_id: u32, sock_fd: i32, is_tcp: bool) {
    if is_tcp {
        landscape_ebpf::map_setting::dns::setting_dns_sock_map_tcp(sock_fd, flow_id);
    } else {
        landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd, flow_id);
    }
    landscape_ebpf::dns_dispatcher::attach_reuseport_ebpf(sock_fd).unwrap();
}

fn cancelled_token() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}

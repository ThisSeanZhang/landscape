use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use rustls::server::ResolvesServerCert;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::server::handler::DnsRequestHandler;
use landscape_common::dns::DohRuntimeConfig;
use landscape_common::flow::{DnsListenerRole, DnsSocketRegisterError, FlowSocketRegistrar};
use socket2::{Domain, Protocol, Socket, Type};
use tokio_util::task::TaskTracker;
use tracing::Instrument;

pub(crate) mod doh;
pub(crate) mod udp;
pub(crate) mod wire;

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

pub(crate) fn create_tcp_listener(
    address: SocketAddr,
) -> std::io::Result<(tokio::net::TcpListener, i32)> {
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

/// Start a flow's UDP and optional DoH DNS listeners.
///
/// `token` is a child of the service token: stopping the service tears the
/// listeners down, and UDP bind/registration failure cancels it so the flow is
/// marked failed. Both top-level tasks are tracked in `tracker`.
///
/// DoH startup failure (bind or sockmap registration) is best-effort: log it,
/// drop the DoH listener, and keep UDP serving. DoH is not retried until this
/// flow runtime is rebuilt. Unrecoverable runtime socket errors still cancel
/// the shared token so the whole flow is rebuilt.
pub(crate) async fn start_flow_dns_listener(
    flow_id: u32,
    addr: SocketAddr,
    doh: Option<EffectiveDohListenerConfig>,
    handler: DnsRequestHandler,
    socket_registrar: Arc<dyn FlowSocketRegistrar>,
    token: CancellationToken,
    tracker: TaskTracker,
) -> CancellationToken {
    let Ok((udp, sock_fd)) = create_udp_socket(addr).await else {
        tracing::error!("[flow: {flow_id}]: create udp socket error");
        token.cancel();
        return token;
    };

    if let Err(e) =
        attach_dns_socket(socket_registrar.as_ref(), flow_id, sock_fd, DnsListenerRole::Udp)
    {
        tracing::error!("[flow: {flow_id}]: register UDP DNS socket error: {e}");
        // Keep the unregistered listener closed so reuseport cannot send any
        // flow traffic to it. Mark the flow runtime failed as well.
        token.cancel();
        return token;
    }

    udp::spawn_udp_listener(flow_id, udp, handler.clone(), token.clone(), tracker.clone());

    if let Some(doh) = doh {
        register_doh_listener(
            flow_id,
            doh,
            handler,
            socket_registrar.clone(),
            token.clone(),
            tracker,
        );
    }

    token
}

/// 追踪式 spawn:与 [`landscape_common::concurrency::spawn_task`] 的
/// memtrack/tracing 语义一致,但任务注册进指定 [`TaskTracker`]。
pub(crate) fn spawn_tracked<Fut>(tracker: &TaskTracker, label: &'static str, future: Fut)
where
    Fut: std::future::Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let tag = landscape_common::memtrack::subsystem_from_task_label(label);
    tracker.spawn(
        landscape_common::memtrack::TaggedFuture::new(tag, future)
            .instrument(tracing::info_span!("task", task = label)),
    );
}

/// Fatal for a listening socket: the kernel-side association is gone and
/// every future accept/recv would fail identically. Anything else
/// (transient errors like `ConnectionReset`/`Interrupted`) is retried.
pub(crate) fn is_unrecoverable_socket_error(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::NotConnected | std::io::ErrorKind::ConnectionAborted)
}

fn register_doh_listener(
    flow_id: u32,
    doh: EffectiveDohListenerConfig,
    handler: DnsRequestHandler,
    socket_registrar: Arc<dyn FlowSocketRegistrar>,
    token: CancellationToken,
    tracker: TaskTracker,
) {
    match create_tcp_listener(doh.addr) {
        Ok((listener, sock_fd)) => {
            if let Err(e) =
                attach_dns_socket(socket_registrar.as_ref(), flow_id, sock_fd, DnsListenerRole::Doh)
            {
                tracing::error!("[flow: {flow_id}]: register DoH DNS socket error: {e}");
                // Drop the unregistered listener so reuseport cannot dispatch
                // DoH traffic to it; keep the flow alive on UDP. DoH is retried
                // only after the flow runtime is rebuilt.
                return;
            }
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
                token,
                tracker,
            );
        }
        Err(e) => {
            // Best-effort DoH: log and keep UDP serving; retried only on rebuild.
            tracing::error!("[flow: {flow_id}]: create DoH listener error: {e}");
        }
    }
}

fn attach_dns_socket(
    socket_registrar: &dyn FlowSocketRegistrar,
    flow_id: u32,
    sock_fd: i32,
    role: DnsListenerRole,
) -> Result<(), DnsSocketRegisterError> {
    socket_registrar.register_dns_socket(flow_id, sock_fd, role)
}

#[cfg(test)]
mod tests {
    use super::{attach_dns_socket, is_unrecoverable_socket_error};
    use landscape_common::flow::{DnsListenerRole, DnsSocketRegisterError, FlowSocketRegistrar};

    struct FailingRegistrar;

    impl FlowSocketRegistrar for FailingRegistrar {
        fn register_dns_socket(
            &self,
            _flow_id: u32,
            _sock_fd: i32,
            _role: DnsListenerRole,
        ) -> Result<(), DnsSocketRegisterError> {
            Err(DnsSocketRegisterError::MapUpdate("test failure".to_string()))
        }
    }

    #[test]
    fn dns_socket_registration_errors_are_propagated() {
        let err = attach_dns_socket(&FailingRegistrar, 7, -1, DnsListenerRole::Udp).unwrap_err();
        assert!(matches!(err, DnsSocketRegisterError::MapUpdate(_)));
    }

    #[test]
    fn classifies_unrecoverable_socket_errors() {
        assert!(is_unrecoverable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::NotConnected
        )));
        assert!(is_unrecoverable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionAborted
        )));
        assert!(!is_unrecoverable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(!is_unrecoverable_socket_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        )));
    }
}

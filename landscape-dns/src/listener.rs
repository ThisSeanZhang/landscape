use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::Server;
use rustls::server::ResolvesServerCert;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::server::handler::DnsRequestHandler;
use landscape_common::concurrency::task_label;
use landscape_common::dns::DohRuntimeConfig;
use landscape_common::flow::FlowSocketRegistrar;
use socket2::{Domain, Protocol, Socket, Type};
use tokio_util::task::TaskTracker;
use tracing::Instrument;

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

/// 启动单个 flow 的 DNS 监听(UDP + 可选 DoH)。
///
/// `token` 为服务运行 token 的 child:父 token 取消(服务停止)时本 flow
/// 监听随之终止;自身 bind 失败时自我取消以向上游标记失败。两个顶级任务
/// (UDP serve / DoH handler)均注册进 `tracker`,供停止侧确定性等待。
///
/// UDP 与 DoH 共用同一 token(同生共死):任一侧的致命错误都会取消整个
/// flow token 使另一半一并退出,由上层 refresh 感知死亡并整体重建。
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

    attach_dns_socket(socket_registrar.as_ref(), flow_id, sock_fd, false);

    let doh_handler = handler.clone();
    let mut server = Server::new(handler);
    server.register_socket(udp);

    if let Some(doh) = doh {
        register_doh_listener(
            flow_id,
            doh,
            doh_handler,
            socket_registrar.clone(),
            token.clone(),
            tracker.clone(),
        );
    }

    // hickory server 自身的关闭 token:父 token 触发时转发取消,
    // 让 server 停止 accept 并使 block_until_done 返回
    let server_shutdown = server.shutdown_token().clone();
    let serve_token = token.clone();

    spawn_tracked(&tracker, task_label::task::DNS_LISTENER_SERVE, async move {
        tokio::select! {
            result = server.block_until_done() => {
                if let Err(e) = result {
                    tracing::error!("[flow: {flow_id}]: server down, error: {e:?}");
                } else {
                    tracing::info!("[flow: {flow_id}]: server down");
                }
                // server 自身退出(如 socket 错误):标记本 flow 终止,
                // 同 token 的 DoH 监听一并退出
                serve_token.cancel();
            }
            () = serve_token.cancelled() => {
                // 服务停止/flow 替换:转发取消并等待 server 收尾
                server_shutdown.cancel();
                let _ = server.block_until_done().await;
            }
        }
    });

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
            attach_dns_socket(socket_registrar.as_ref(), flow_id, sock_fd, true);
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
            tracing::error!("[flow: {flow_id}]: create DoH listener error: {e}");
        }
    }
}

fn attach_dns_socket(
    socket_registrar: &dyn FlowSocketRegistrar,
    flow_id: u32,
    sock_fd: i32,
    is_tcp: bool,
) {
    socket_registrar.register_dns_socket(flow_id, sock_fd, is_tcp)
}

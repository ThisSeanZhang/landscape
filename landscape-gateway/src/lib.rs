pub mod proxy_service;
pub mod service;
pub mod sni_proxy;

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

use arc_swap::ArcSwap;
use landscape_common::config::gateway::config::GatewayRuntimeConfig;
use landscape_common::config::gateway::HttpUpstreamRuleConfig;

use landscape_common::service::{ServiceStatus, WatchService};
use pingora::apps::ServerApp;
use pingora::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Stream,
    TimingDigest, UniqueID, ALPN,
};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::{server::TlsStream as TokioTlsStream, TlsAcceptor};
use tokio_util::sync::CancellationToken;

use crate::sni_proxy::{parse_sni_from_client_hello, proxy_tls_passthrough, SniProxyRouter};

pub type SharedRules = Arc<ArcSwap<Vec<HttpUpstreamRuleConfig>>>;

#[derive(Debug, Clone)]
pub struct GatewayTlsConfig {
    pub server_config: Arc<ServerConfig>,
}

pub struct GatewayManager {
    rules: SharedRules,
    status: WatchService,
    state: Mutex<Option<GatewayRuntimeState>>,
    config: GatewayRuntimeConfig,
    tls_config: Option<GatewayTlsConfig>,
}

struct GatewayRuntimeState {
    thread: JoinHandle<()>,
    cancel: CancellationToken,
}

impl GatewayManager {
    pub fn new(
        initial_rules: Vec<HttpUpstreamRuleConfig>,
        config: GatewayRuntimeConfig,
        tls_config: Option<GatewayTlsConfig>,
    ) -> Self {
        Self {
            rules: Arc::new(ArcSwap::new(Arc::new(initial_rules))),
            status: WatchService::new(),
            state: Mutex::new(None),
            config,
            tls_config,
        }
    }

    pub fn shared_rules(&self) -> SharedRules {
        self.rules.clone()
    }

    pub fn reload_rules(&self, new_rules: Vec<HttpUpstreamRuleConfig>) {
        self.rules.store(Arc::new(new_rules));
        tracing::info!("Gateway rules reloaded ({} rules)", self.rules.load().len());
    }

    pub fn start(&self) {
        let mut state = self.state.lock().unwrap();
        if self.status.is_running() {
            tracing::warn!("Gateway is already running");
            return;
        }

        self.status.just_change_status(ServiceStatus::Staring);

        let rules = self.rules.clone();
        let http_port = self.config.http_port;
        let https_port = self.config.https_port;
        let tls_config = self.tls_config.clone();
        let status = self.status.clone();
        let cancel = CancellationToken::new();
        let thread_cancel = cancel.clone();

        let thread = std::thread::spawn(move || {
            run_pingora_server(
                rules,
                http_port,
                https_port,
                tls_config,
                status.clone(),
                thread_cancel,
            );
            status.just_change_status(ServiceStatus::Stop);
        });

        *state = Some(GatewayRuntimeState { thread, cancel });
        self.status.just_change_status(ServiceStatus::Running);
        if self.tls_config.is_some() {
            tracing::info!(
                "Gateway started on HTTP port {} and HTTPS port {}",
                self.config.http_port,
                self.config.https_port
            );
        } else {
            tracing::info!(
                "Gateway started on HTTP port {} (HTTPS listener disabled: no gateway certificate loaded)",
                self.config.http_port
            );
        }
    }

    /// Signal gateway to stop (non-blocking). The thread will actually be
    /// joined when the GatewayManager is dropped (or join() is called).
    pub fn shutdown(&self) {
        if self.status.is_exit() {
            return;
        }
        tracing::info!("Signalling gateway to stop...");
        self.status.just_change_status(ServiceStatus::Stopping);
        if let Some(state) = self.state.lock().unwrap().as_ref() {
            state.cancel.cancel();
        }
    }

    /// Block until the Pingora thread has exited. Call after shutdown().
    pub fn join(&self) {
        let mut state = self.state.lock().unwrap();
        if let Some(runtime_state) = state.take() {
            tracing::info!("Waiting for gateway thread to finish...");
            if let Err(e) = runtime_state.thread.join() {
                tracing::error!("Gateway thread panicked: {:?}", e);
            }
            tracing::info!("Gateway stopped");
        }
    }

    pub fn is_running(&self) -> bool {
        self.status.is_running()
    }

    pub fn status(&self) -> ServiceStatus {
        self.status.subscribe().borrow().clone()
    }

    pub fn watch_service(&self) -> WatchService {
        self.status.clone()
    }

    pub fn config(&self) -> &GatewayRuntimeConfig {
        &self.config
    }

    pub fn has_https_listener(&self) -> bool {
        self.tls_config.is_some()
    }
}

impl Drop for GatewayManager {
    fn drop(&mut self) {
        self.shutdown();
        if self.status.is_stop() {
            self.join();
            return;
        }

        if let Some(runtime_state) = self.state.lock().unwrap().take() {
            runtime_state.cancel.cancel();
            tracing::warn!(
                "Dropping gateway manager before gateway thread fully stopped; detaching thread"
            );
        }
    }
}

fn run_pingora_server(
    rules: SharedRules,
    http_port: u16,
    https_port: u16,
    tls_config: Option<GatewayTlsConfig>,
    status: WatchService,
    cancel: CancellationToken,
) {
    use pingora::server::Server;
    use proxy_service::LandscapeReverseProxy;

    let mut server = Server::new(None).expect("Failed to create Pingora server");
    server.bootstrap();
    let server_conf = server.configuration.clone();

    let proxy = LandscapeReverseProxy::new(rules.clone());
    let mut http_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    http_service.add_tcp(&format!("0.0.0.0:{http_port}"));
    server.add_service(http_service);

    let https_handle = tls_config.map(|tls_config| {
        let rules = rules.clone();
        let status = status.clone();
        let cancel = cancel.child_token();
        std::thread::spawn(move || {
            run_https_server(rules, https_port, tls_config, server_conf, status, cancel);
        })
    });

    let run_args = pingora::server::RunArgs {
        shutdown_signal: Box::new(ChannelShutdownWatch { status }),
    };
    server.run(run_args);

    if let Some(handle) = https_handle {
        if let Err(e) = handle.join() {
            tracing::error!("Gateway HTTPS thread panicked: {:?}", e);
        }
    }
}

fn run_https_server(
    rules: SharedRules,
    https_port: u16,
    tls_config: GatewayTlsConfig,
    server_conf: Arc<pingora::server::configuration::ServerConf>,
    status: WatchService,
    cancel: CancellationToken,
) {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .thread_name("landscape-gateway-https")
        .build()
        .expect("Failed to create gateway HTTPS runtime");

    runtime.block_on(async move {
        if let Err(e) =
            run_https_server_inner(rules, https_port, tls_config, server_conf, status, cancel).await
        {
            tracing::error!("Gateway HTTPS listener exited with error: {e}");
        }
    });
}

async fn run_https_server_inner(
    rules: SharedRules,
    https_port: u16,
    tls_config: GatewayTlsConfig,
    server_conf: Arc<pingora::server::configuration::ServerConf>,
    status: WatchService,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    use proxy_service::LandscapeReverseProxy;

    let listener = TcpListener::bind(("0.0.0.0", https_port)).await?;
    let acceptor = TlsAcceptor::from(tls_config.server_config);
    let sni_proxy_router = Arc::new(SniProxyRouter::new(rules.clone()));
    let app = Arc::new(pingora::proxy::http_proxy(&server_conf, LandscapeReverseProxy::new(rules)));

    let mut status_rx = status.subscribe();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    tracing::info!("Gateway HTTPS listener started on port {https_port}");

    loop {
        tokio::select! {
            changed = status_rx.changed() => {
                if changed.is_err() || matches!(*status_rx.borrow(), ServiceStatus::Stopping | ServiceStatus::Stop) {
                    let _ = shutdown_tx.send(true);
                    break;
                }
            }
            _ = cancel.cancelled() => {
                let _ = shutdown_tx.send(true);
                break;
            }
            accept_result = listener.accept() => {
                let (stream, peer_addr) = match accept_result {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!("Gateway HTTPS accept failed: {e}");
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let app = app.clone();
                let sni_proxy_router = sni_proxy_router.clone();
                let connection_shutdown = shutdown_rx.clone();
                let connection_cancel = cancel.child_token();

                tasks.spawn(async move {
                    if sni_proxy_router.has_sni_proxy_rules() {
                        let mut peek_buf = vec![0u8; 4096];
                        match tokio::select! {
                            _ = connection_cancel.cancelled() => return,
                            result = stream.peek(&mut peek_buf) => result,
                        } {
                            Ok(size) if size > 0 => {
                                if let Some(sni) = parse_sni_from_client_hello(&peek_buf[..size]) {
                                    if let Some(target) = sni_proxy_router.match_target(&sni) {
                                        tracing::info!(
                                            "Gateway HTTPS passthrough '{}' via rule '{}' -> {}:{}",
                                            target.sni,
                                            target.rule_name,
                                            target.target.address,
                                            target.target.port
                                        );
                                        if let Err(e) = proxy_tls_passthrough(stream, &target, connection_cancel.clone()).await {
                                            tracing::warn!(
                                                "Gateway TLS passthrough failed for '{}' via rule '{}': {}",
                                                target.sni,
                                                target.rule_name,
                                                e
                                            );
                                        }
                                        return;
                                    }
                                }
                            }
                            Ok(_) => return,
                            Err(e) => {
                                tracing::warn!("Gateway HTTPS peek failed from {peer_addr}: {e}");
                                return;
                            }
                        }
                    }

                    let tls_result = tokio::select! {
                        _ = connection_cancel.cancelled() => return,
                        result = tokio::time::timeout(Duration::from_secs(60), acceptor.accept(stream)) => result,
                    };
                    let tls_stream = match tls_result {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            tracing::warn!("Gateway HTTPS handshake failed from {peer_addr}: {e}");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!("Gateway HTTPS handshake timed out from {peer_addr}");
                            return;
                        }
                    };

                    let stream: Stream = Box::new(GatewayTlsStream::new(tls_stream));
                    tokio::select! {
                        _ = connection_cancel.cancelled() => {}
                        _ = app.process_new(stream, &connection_shutdown) => {}
                    }
                });
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    tracing::info!("Gateway HTTPS listener stopped on port {https_port}");
    Ok(())
}

struct GatewayTlsStream {
    inner: TokioTlsStream<TcpStream>,
    established_ts: SystemTime,
    socket_digest: Arc<SocketDigest>,
    unique_id: i32,
}

impl GatewayTlsStream {
    fn new(inner: TokioTlsStream<TcpStream>) -> Self {
        #[cfg(unix)]
        let raw_fd = inner.get_ref().0.as_raw_fd();

        Self {
            inner,
            established_ts: SystemTime::now(),
            #[cfg(unix)]
            socket_digest: Arc::new(SocketDigest::from_raw_fd(raw_fd)),
            #[cfg(windows)]
            socket_digest: Arc::new(SocketDigest::from_raw_socket(
                inner.get_ref().0.as_raw_socket(),
            )),
            #[cfg(unix)]
            unique_id: raw_fd,
            #[cfg(windows)]
            unique_id: inner.get_ref().0.as_raw_socket() as i32,
        }
    }
}

impl std::fmt::Debug for GatewayTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayTlsStream").field("unique_id", &self.unique_id).finish()
    }
}

impl AsyncRead for GatewayTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for GatewayTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait::async_trait]
impl Shutdown for GatewayTlsStream {
    async fn shutdown(&mut self) {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.inner).await;
    }
}

impl UniqueID for GatewayTlsStream {
    fn id(&self) -> pingora::protocols::UniqueIDType {
        self.unique_id
    }
}

impl pingora::protocols::Ssl for GatewayTlsStream {
    fn selected_alpn_proto(&self) -> Option<ALPN> {
        match self.inner.get_ref().1.alpn_protocol() {
            Some(b"h2") => Some(ALPN::H2),
            Some(b"http/1.1") => Some(ALPN::H1),
            _ => None,
        }
    }
}

impl GetTimingDigest for GatewayTlsStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        vec![Some(TimingDigest { established_ts: self.established_ts })]
    }
}

impl GetProxyDigest for GatewayTlsStream {
    fn get_proxy_digest(&self) -> Option<Arc<pingora::protocols::raw_connect::ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for GatewayTlsStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        Some(self.socket_digest.clone())
    }
}

#[async_trait::async_trait]
impl Peek for GatewayTlsStream {
    async fn try_peek(&mut self, _buf: &mut [u8]) -> std::io::Result<bool> {
        Ok(false)
    }
}

struct ChannelShutdownWatch {
    status: WatchService,
}

#[async_trait::async_trait]
impl pingora::server::ShutdownSignalWatch for ChannelShutdownWatch {
    async fn recv(&self) -> pingora::server::ShutdownSignal {
        if self.status.is_exit() {
            return pingora::server::ShutdownSignal::FastShutdown;
        }
        let mut rx = self.status.subscribe();
        loop {
            if rx.changed().await.is_err() {
                // Sender dropped, treat as fast shutdown
                return pingora::server::ShutdownSignal::FastShutdown;
            }
            if matches!(*rx.borrow(), ServiceStatus::Stopping | ServiceStatus::Stop) {
                return pingora::server::ShutdownSignal::FastShutdown;
            }
        }
    }
}

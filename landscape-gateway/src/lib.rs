mod http_listener;
pub mod proxy_service;
pub use landscape_common::sys_service::gateway::routes;
pub mod sni_proxy;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(test)]
use crate::routes::CompiledGatewayRoutes;
#[cfg(test)]
use arc_swap::ArcSwap;
use landscape_common::concurrency::{runtime_thread_name_fn, spawn_named_thread, thread_name};
use landscape_common::sys_config::GatewayRuntimeConfig;
use landscape_common::sys_service::gateway::GatewayError;

use landscape_common::service::{ServiceHandle, ServiceStatus};
use pingora::apps::ServerApp;
use pingora::protocols::{
    ALPN, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Stream,
    TimingDigest, UniqueID,
};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, server::TlsStream as TokioTlsStream};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::sni_proxy::{SniProxyRouter, parse_sni_from_client_hello, proxy_tls_passthrough};

pub use routes::SharedGatewayRoutes;

#[derive(Debug, Clone)]
pub struct GatewayTlsConfig {
    pub server_config: Arc<ServerConfig>,
}

pub struct GatewayServer {
    thread: Mutex<Option<JoinHandle<()>>>,
    done_rx: watch::Receiver<ServiceStatus>,
    run: RunState,
}

#[derive(Clone)]
struct RunState {
    cancel: CancellationToken,
    status: ServiceHandle,
    https_ready: Arc<AtomicBool>,
    cleanup_uncertain: Arc<AtomicBool>,
    error: Arc<OnceLock<String>>,
}

/// 网关一次运行的失败原因(线程未 panic 但组件异常退出)。
#[derive(Debug)]
enum GatewayRunFailure {
    HttpListenerFailed,
    /// HTTPS 驱动线程 panic,HTTPS 监听已不可用
    HttpsDriverPanicked,
    HttpsDriverFailed(GatewayHttpsRunError),
}

impl std::fmt::Display for GatewayRunFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpListenerFailed => write!(formatter, "HTTP listener exited unexpectedly"),
            Self::HttpsDriverPanicked => write!(formatter, "HTTPS driver thread panicked"),
            Self::HttpsDriverFailed(error) => {
                write!(formatter, "HTTPS listener {} failed: {}", error.bind_addr, error.source)
            }
        }
    }
}

impl GatewayServer {
    /// Start one gateway run. The caller owns route publication and replacement.
    pub fn spawn(
        routes: SharedGatewayRoutes,
        config: &GatewayRuntimeConfig,
        tls_config: Option<GatewayTlsConfig>,
    ) -> Self {
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);

        let http_port = config.http_port;
        let https_port = config.https_port;
        let (done_tx, done_rx) = watch::channel(ServiceStatus::Staring);
        let rt = tokio::runtime::Handle::try_current().ok();
        if rt.is_none() {
            status.just_change_status(ServiceStatus::Running);
        }
        let run = RunState {
            cancel: CancellationToken::new(),
            status,
            https_ready: Default::default(),
            cleanup_uncertain: Default::default(),
            error: Default::default(),
        };
        let worker = run.clone();

        let thread = spawn_named_thread(thread_name::fixed::GATEWAY_MAIN, move || {
            // catch_unwind:线程 panic 收敛为 Failed 终态,而非静默消失
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_pingora_server(routes, http_port, https_port, tls_config, rt, worker.clone())
            }));
            // Publish completion after the owning driver and its HTTPS child
            // have returned; a component failure remains visible as Failed.
            let terminal = match result {
                Ok(Ok(())) => ServiceStatus::Stop,
                Ok(Err(failure)) => {
                    let _ = worker.error.set(failure.to_string());
                    tracing::error!("Gateway run finished with failure: {failure}");
                    ServiceStatus::Failed
                }
                Err(panic) => {
                    let _ = worker.error.set("Gateway main thread panicked".into());
                    tracing::error!("Gateway main thread panicked: {panic:?}");
                    // Pingora may detach its runtime workers when run() unwinds.
                    // Keep this run owned: thread exit cannot prove port release.
                    worker.cleanup_uncertain.store(true, Ordering::Release);
                    ServiceStatus::Failed
                }
            };
            worker.cancel.cancel();
            worker.https_ready.store(false, Ordering::Release);
            worker.status.just_change_status(terminal.clone());
            let _ = done_tx.send(terminal);
        });
        let thread = match thread {
            Ok(thread) => Some(thread),
            Err(cause) => {
                let _ = run.error.set(cause.to_string());
                run.status.just_change_status(ServiceStatus::Failed);
                None
            }
        };
        Self { thread: Mutex::new(thread), run, done_rx }
    }

    pub async fn shutdown_and_wait(&self, timeout: Duration) -> Result<(), GatewayError> {
        self.run.cancel.cancel();
        if self.run.cleanup_uncertain.load(Ordering::Acquire) {
            return Err(GatewayError::StopFailed {
                reason: "gateway runtime cleanup could not be confirmed after a failure".into(),
            });
        }
        if self.thread.lock().unwrap().is_none() {
            return Ok(());
        }
        if !self.run.status.is_exit() {
            self.run.status.just_change_status(ServiceStatus::Stopping);
        }
        let wait = async {
            let mut done = self.done_rx.clone();
            done.wait_for(|status| matches!(status, ServiceStatus::Stop | ServiceStatus::Failed))
                .await
                .map_err(|_| GatewayError::StopFailed {
                    reason: "gateway completion channel closed without a terminal result".into(),
                })?;
            loop {
                {
                    let mut thread = self.thread.lock().unwrap();
                    let finished = thread.as_ref().is_none_or(JoinHandle::is_finished);
                    if self.run.cleanup_uncertain.load(Ordering::Acquire) {
                        return Err(GatewayError::StopFailed {
                            reason:
                                "gateway runtime cleanup could not be confirmed after a failure"
                                    .into(),
                        });
                    }
                    if finished {
                        if thread.take().is_some_and(|handle| handle.join().is_err()) {
                            self.run.cleanup_uncertain.store(true, Ordering::Release);
                            return Err(GatewayError::StopFailed {
                                reason: "gateway thread panicked".into(),
                            });
                        }
                        return Ok(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        tokio::time::timeout(timeout, wait).await.map_err(|_| GatewayError::StopTimeout {
            timeout_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
        })?
    }

    pub fn status(&self) -> ServiceStatus {
        self.run.status.current()
    }

    pub fn last_error(&self) -> Option<String> {
        self.run.error.get().cloned()
    }

    pub fn has_https_listener(&self) -> bool {
        !self.run.cancel.is_cancelled() && self.run.https_ready.load(Ordering::Acquire)
    }
}

impl Drop for GatewayServer {
    fn drop(&mut self) {
        self.run.cancel.cancel();
    }
}

/// Run Pingora and join the HTTPS driver, reporting its failures to the owner.
fn run_pingora_server(
    routes: SharedGatewayRoutes,
    http_port: u16,
    https_port: u16,
    tls_config: Option<GatewayTlsConfig>,
    rt: Option<tokio::runtime::Handle>,
    run: RunState,
) -> Result<(), GatewayRunFailure> {
    use proxy_service::LandscapeReverseProxy;
    let RunState {
        cancel,
        status,
        https_ready,
        cleanup_uncertain,
        error,
    } = run;

    let mut server = create_pingora_server();
    server.bootstrap();
    let server_conf = server.configuration.clone();

    // run() 之前完成 ExecutionPhase 订阅(broadcast 无接收者时发送被静默
    // 丢弃,必须先订阅后 run)并在网关线程内就地 spawn 转发任务
    if let Some(rt) = rt {
        let phases = server.watch_execution_phase();
        rt.spawn(forward_execution_phase(status.clone(), phases));
    }

    let proxy = LandscapeReverseProxy::new(routes.clone());
    let mut http_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    http_service.add_tcp(&format!("[::]:{http_port}"));
    let (http_service, http_shutdown) =
        http_listener::supervise(http_service, cancel.clone(), status.clone(), cleanup_uncertain);
    let http_shutdown = Arc::new(http_shutdown);
    server.add_service(http_service);

    // This guard cancels and joins HTTPS even when Pingora unwinds. Keeping
    // the child handle owned until join prevents an orphaned listening socket.
    let mut https_driver = HttpsDriver { thread: None, cancel: cancel.clone() };
    if let Some(tls_config) = tls_config {
        let routes = routes.clone();
        let driver_cancel = cancel.clone();
        https_driver.thread = Some(
            spawn_named_thread(thread_name::fixed::GATEWAY_HTTPS_DRIVER, move || {
                supervise_https_driver(
                    status,
                    driver_cancel.clone(),
                    https_ready.clone(),
                    &error,
                    || {
                        run_https_server(
                            routes,
                            https_port,
                            tls_config,
                            server_conf,
                            driver_cancel,
                            https_ready,
                        )
                    },
                )
            })
            .expect("failed to spawn gateway https driver thread"),
        );
    }

    let run_args = pingora::server::RunArgs {
        shutdown_signal: Box::new(TokenShutdownWatch {
            token: cancel,
            http: http_shutdown.clone(),
        }),
    };
    server.run(run_args);
    let https_result = https_driver.shutdown_and_join();
    if http_shutdown.failed() { Err(GatewayRunFailure::HttpListenerFailed) } else { https_result }
}

fn create_pingora_server() -> pingora::server::Server {
    pingora::server::Server::new(None).expect("Failed to create Pingora server")
}

struct HttpsDriver {
    thread: Option<JoinHandle<Result<(), GatewayRunFailure>>>,
    cancel: CancellationToken,
}

impl HttpsDriver {
    fn shutdown_and_join(&mut self) -> Result<(), GatewayRunFailure> {
        self.cancel.cancel();
        match self.thread.take().map(JoinHandle::join) {
            None | Some(Ok(Ok(()))) => Ok(()),
            Some(Ok(Err(error))) => Err(error),
            Some(Err(_)) => Err(GatewayRunFailure::HttpsDriverPanicked),
        }
    }
}

impl Drop for HttpsDriver {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown_and_join() {
            tracing::error!("Gateway HTTPS driver failed during cleanup: {error}");
        }
    }
}

fn supervise_https_driver(
    status: ServiceHandle,
    cancel: CancellationToken,
    https_ready: Arc<AtomicBool>,
    diagnostic: &OnceLock<String>,
    run: impl FnOnce() -> Result<(), GatewayHttpsRunError>,
) -> Result<(), GatewayRunFailure> {
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(GatewayRunFailure::HttpsDriverFailed(error)),
        Err(_) => Err(GatewayRunFailure::HttpsDriverPanicked),
    };
    https_ready.store(false, Ordering::Release);
    if let Err(error) = &result {
        let _ = diagnostic.set(error.to_string());
        tracing::error!("Gateway HTTPS driver failed: {error}");
        status.just_change_status(ServiceStatus::Failed);
        cancel.cancel();
    }
    result
}

/// Readiness belongs to the listener's lifetime, including unwind cleanup.
struct HttpsReadinessGuard(Arc<AtomicBool>);

impl Drop for HttpsReadinessGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// 将 pingora 的 ExecutionPhase 广播转发为服务状态:真正进入服务态才置
/// Running,进入关闭序列置 Stopping;状态到达退出态或广播关闭时结束。
async fn forward_execution_phase(
    forward_status: ServiceHandle,
    mut phases: tokio::sync::broadcast::Receiver<pingora::server::ExecutionPhase>,
) {
    loop {
        if forward_status.is_exit() {
            break;
        }
        match phases.recv().await {
            Ok(pingora::server::ExecutionPhase::Running) => {
                // pingora 真正进入服务态才置 Running
                if matches!(forward_status.current(), ServiceStatus::Staring) {
                    forward_status.just_change_status(ServiceStatus::Running);
                }
            }
            Ok(
                pingora::server::ExecutionPhase::GracefulTerminate
                | pingora::server::ExecutionPhase::ShutdownStarted
                | pingora::server::ExecutionPhase::ShutdownGracePeriod
                | pingora::server::ExecutionPhase::ShutdownRuntimes,
            ) => {
                if forward_status.is_active() {
                    forward_status.just_change_status(ServiceStatus::Stopping);
                }
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn run_https_server(
    routes: SharedGatewayRoutes,
    https_port: u16,
    tls_config: GatewayTlsConfig,
    server_conf: Arc<pingora::server::configuration::ServerConf>,
    cancel: CancellationToken,
    https_ready: Arc<AtomicBool>,
) -> Result<(), GatewayHttpsRunError> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .thread_name_fn(runtime_thread_name_fn(thread_name::prefix::GATEWAY_HTTPS_RUNTIME))
        .build()
        .map_err(|source| GatewayHttpsRunError {
            port: https_port,
            bind_addr: gateway_https_bind_addr(https_port),
            source,
            already_logged: false,
        })?;

    let result = runtime.block_on(run_https_server_inner(
        routes,
        https_port,
        tls_config,
        server_conf,
        cancel,
        https_ready,
    ));
    if let Err(error) = &result
        && !error.already_logged
    {
        tracing::error!(
            component = "gateway_https",
            event = "startup_failed",
            port = error.port,
            bind_addr = %error.bind_addr,
            error_kind = ?error.source.kind(),
            error = %error.source,
            "Gateway HTTPS listener exited with startup error"
        );
    }
    result
}

#[derive(Debug)]
struct GatewayHttpsRunError {
    port: u16,
    bind_addr: String,
    source: std::io::Error,
    already_logged: bool,
}

async fn run_https_server_inner(
    routes: SharedGatewayRoutes,
    https_port: u16,
    tls_config: GatewayTlsConfig,
    server_conf: Arc<pingora::server::configuration::ServerConf>,
    cancel: CancellationToken,
    https_ready: Arc<AtomicBool>,
) -> Result<(), GatewayHttpsRunError> {
    use proxy_service::LandscapeReverseProxy;

    let readiness = HttpsReadinessGuard(https_ready.clone());
    if cancel.is_cancelled() {
        return Ok(());
    }
    let bind_addr = gateway_https_bind_addr(https_port);
    tracing::info!(
        component = "gateway_https",
        event = "startup_begin",
        port = https_port,
        bind_addr = %bind_addr,
        "Starting Gateway HTTPS listener"
    );

    let listener = match TcpListener::bind(bind_addr.as_str()).await {
        Ok(listener) => listener,
        Err(source) => {
            tracing::error!(
                component = "gateway_https",
                event = "bind_failed",
                port = https_port,
                bind_addr = %bind_addr,
                error_kind = ?source.kind(),
                error = %source,
                diagnosis = gateway_https_bind_failure_diagnosis(source.kind()),
                "Gateway HTTPS listener failed to bind"
            );
            return Err(GatewayHttpsRunError {
                port: https_port,
                bind_addr,
                source,
                already_logged: true,
            });
        }
    };
    let acceptor = TlsAcceptor::from(tls_config.server_config);
    let sni_proxy_router = Arc::new(SniProxyRouter::new(routes.clone()));
    let app =
        Arc::new(pingora::proxy::http_proxy(&server_conf, LandscapeReverseProxy::new(routes)));

    if cancel.is_cancelled() {
        return Ok(());
    }
    https_ready.store(true, Ordering::Release);
    tracing::info!(
        component = "gateway_https",
        event = "bind_ok",
        port = https_port,
        bind_addr = %bind_addr,
        "Gateway HTTPS listener bound successfully"
    );

    let result = accept_https_connections(
        listener,
        &cancel,
        readiness,
        |stream, peer_addr, cancel, shutdown| {
            serve_https_connection(
                stream,
                peer_addr,
                cancel,
                shutdown,
                acceptor.clone(),
                sni_proxy_router.clone(),
                app.clone(),
            )
        },
    )
    .await;
    tracing::info!(
        component = "gateway_https",
        event = "listener_stopped",
        port = https_port,
        bind_addr = %bind_addr,
        "Gateway HTTPS listener stopped"
    );
    result.map_err(|source| GatewayHttpsRunError {
        port: https_port,
        bind_addr,
        source,
        already_logged: true,
    })
}

async fn accept_https_connections<Fut>(
    listener: TcpListener,
    cancel: &CancellationToken,
    readiness: HttpsReadinessGuard,
    serve: impl Fn(TcpStream, SocketAddr, CancellationToken, watch::Receiver<bool>) -> Fut,
) -> std::io::Result<()>
where
    Fut: Future<Output = ()> + Send + 'static,
{
    let tasks = TaskTracker::new();
    let connections = cancel.child_token().drop_guard();
    // Pingora uses a watch receiver for its per-connection shutdown signal.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let result = loop {
        let accepted = tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(()),
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer_addr)) => {
                let token = connections.token().child_token();
                tasks.spawn(serve(stream, peer_addr, token, shutdown_rx.clone()));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(error) => {
                tracing::error!("Gateway HTTPS accept failed: {error}");
                break Err(error);
            }
        }
    };

    drop(readiness);
    drop(listener);
    shutdown_tx.send_replace(true);
    drop(connections);
    tasks.close();
    tasks.wait().await;
    result
}

async fn serve_https_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    connection_cancel: CancellationToken,
    connection_shutdown: watch::Receiver<bool>,
    acceptor: TlsAcceptor,
    sni_proxy_router: Arc<SniProxyRouter>,
    app: Arc<pingora::proxy::HttpProxy<proxy_service::LandscapeReverseProxy>>,
) {
    if sni_proxy_router.has_sni_proxy_rules() {
        let mut peek_buf = vec![0u8; 4096];
        match tokio::select! {
            _ = connection_cancel.cancelled() => return,
            result = stream.peek(&mut peek_buf) => result,
        } {
            Ok(size) if size > 0 => {
                if let Some(sni) = parse_sni_from_client_hello(&peek_buf[..size])
                    && let Some(target) = sni_proxy_router.match_target(&sni)
                {
                    tracing::info!(
                        "Gateway HTTPS passthrough '{}' via rule '{}' -> {}:{}",
                        target.sni,
                        target.rule_name,
                        target.target.address,
                        target.target.port
                    );
                    if let Err(e) = proxy_tls_passthrough(stream, &target, connection_cancel).await
                    {
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
            Ok(_) => return,
            Err(e) => {
                tracing::warn!("Gateway HTTPS peek failed from {peer_addr}: {e}");
                return;
            }
        }
    }

    let handshake_start = Instant::now();
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

    let stream: Stream =
        Box::new(GatewayTlsStream::new(tls_stream, Some(handshake_start.elapsed())));
    tokio::select! {
        _ = connection_cancel.cancelled() => {}
        _ = app.process_new(stream, &connection_shutdown) => {}
    }
}

fn gateway_https_bind_addr(https_port: u16) -> String {
    format!("[::]:{https_port}")
}

fn gateway_https_bind_failure_diagnosis(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::AddrInUse => "port already in use",
        ErrorKind::PermissionDenied => "insufficient privilege to bind low port",
        _ => "unexpected bind failure",
    }
}

struct GatewayTlsStream {
    inner: TokioTlsStream<TcpStream>,
    established_ts: SystemTime,
    establishment_duration: Option<Duration>,
    socket_digest: Arc<SocketDigest>,
    unique_id: i32,
}

impl GatewayTlsStream {
    fn new(inner: TokioTlsStream<TcpStream>, establishment_duration: Option<Duration>) -> Self {
        #[cfg(unix)]
        let raw_fd = inner.get_ref().0.as_raw_fd();

        Self {
            inner,
            established_ts: SystemTime::now(),
            establishment_duration,
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
        vec![Some(TimingDigest {
            established_ts: self.established_ts,
            establishment_duration: self.establishment_duration,
            offload_wait_duration: None,
        })]
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

struct TokenShutdownWatch {
    token: CancellationToken,
    http: Arc<http_listener::HttpListenerShutdown>,
}

#[async_trait::async_trait]
impl pingora::server::ShutdownSignalWatch for TokenShutdownWatch {
    async fn recv(&self) -> pingora::server::ShutdownSignal {
        self.token.cancelled().await;
        // FastShutdown detaches Pingora runtime workers. First close and join
        // the HTTP accept loops so a subsequent run cannot overlap a listener.
        self.http.shutdown_and_wait().await;
        pingora::server::ShutdownSignal::FastShutdown
    }
}

#[cfg(test)]
mod lifecycle_tests;

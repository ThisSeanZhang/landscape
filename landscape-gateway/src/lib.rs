pub mod proxy_service;
pub mod service;
pub mod sni_proxy;

use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

use arc_swap::ArcSwap;
use landscape_common::concurrency::{runtime_thread_name_fn, spawn_named_thread, thread_name};
use landscape_common::sys_service::gateway::HttpUpstreamRuleConfig;
use landscape_common::sys_service::gateway::settings::GatewayRuntimeConfig;

use landscape_common::service::{ServiceStatus, WatchService};
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
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, server::TlsStream as TokioTlsStream};
use tokio_util::sync::CancellationToken;

use crate::sni_proxy::{SniProxyRouter, parse_sni_from_client_hello, proxy_tls_passthrough};

pub type SharedRules = Arc<ArcSwap<Vec<HttpUpstreamRuleConfig>>>;

#[derive(Debug, Clone)]
pub struct GatewayTlsConfig {
    pub server_config: Arc<ServerConfig>,
}

pub struct GatewayManager {
    rules: SharedRules,
    state: Mutex<Option<GatewayRun>>,
    /// 上一次运行的终态:无运行时对外展示(线程崩溃后可见 Failed)
    last_terminal: ArcSwap<ServiceStatus>,
    config: GatewayRuntimeConfig,
    tls_config: Option<GatewayTlsConfig>,
    /// 异步运行时句柄:用于 spawn Pingora ExecutionPhase 转发任务。
    /// 非异步上下文构造时为 None,状态回退为"线程 spawn 成功即 Running"。
    rt: Option<tokio::runtime::Handle>,
}

/// 一次网关运行:专用线程 + 自有取消信号 + 每轮新造的状态句柄(跨周期
/// 不复用)+ 完成通知。停止 = cancel → 线程收尾 → done 发送终态;
/// 等待侧 await done watch 即可,无需轮询状态。
struct GatewayRun {
    /// `Some` 直到被 `join()` 取出并阻塞等待;`Drop` 时若仍为 `Some`,
    /// 丢弃即 detach 线程。
    thread: Option<JoinHandle<()>>,
    cancel: CancellationToken,
    status: WatchService,
    done_rx: watch::Receiver<ServiceStatus>,
}

/// 网关一次运行的失败原因(线程未 panic 但组件异常退出)。
#[derive(Debug)]
enum GatewayRunFailure {
    /// HTTPS 驱动线程 panic,HTTPS 监听已不可用
    HttpsDriverPanicked,
}

impl GatewayManager {
    pub fn new(
        initial_rules: Vec<HttpUpstreamRuleConfig>,
        config: GatewayRuntimeConfig,
        tls_config: Option<GatewayTlsConfig>,
    ) -> Self {
        Self {
            rules: Arc::new(ArcSwap::new(Arc::new(initial_rules))),
            state: Mutex::new(None),
            last_terminal: ArcSwap::from_pointee(ServiceStatus::Stop),
            config,
            tls_config,
            rt: tokio::runtime::Handle::try_current().ok(),
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
        // 只要旧 run 尚未落终态(Staring/Running/Stopping)就拒绝覆盖:Stopping
        // 意味着线程仍在收尾、监听端口可能未释放,直接覆盖会 detached 旧线程
        // 并在同一端口上竞争 bind。仅在 Stop/Failed(线程已结束)时才允许替换。
        if let Some(run) = state.as_ref()
            && !run.status.is_stop()
        {
            tracing::warn!("Gateway is not stopped yet, refusing to start another run");
            return;
        }
        // 已终止的旧 run(线程已退出,JoinHandle drop 即 detach)直接覆盖

        // 每次启动创建全新运行实例:状态句柄跨周期不复用
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);

        let rules = self.rules.clone();
        let http_port = self.config.http_port;
        let https_port = self.config.https_port;
        let tls_config = self.tls_config.clone();
        let cancel = CancellationToken::new();
        let thread_cancel = cancel.clone();
        let (done_tx, done_rx) = watch::channel(ServiceStatus::Staring);
        let run_status = status.clone();
        // 异步句柄传入线程:ExecutionPhase 转发任务由网关线程在订阅后自行
        // spawn,主侧 start() 不阻塞等待交接
        let rt = self.rt.clone();

        let thread = spawn_named_thread(thread_name::fixed::GATEWAY_MAIN, move || {
            // catch_unwind:线程 panic 收敛为 Failed 终态,而非静默消失
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_pingora_server(
                    rules,
                    http_port,
                    https_port,
                    tls_config,
                    thread_cancel,
                    rt,
                    run_status.clone(),
                )
            }));
            // run() 返回 == pingora 完全停止(Terminated);子组件异常退出
            //(HTTPS 驱动线程 panic)同样收敛为 Failed,不谎报 Stop。
            let terminal = match result {
                Ok(Ok(())) => ServiceStatus::Stop,
                Ok(Err(failure)) => {
                    tracing::error!("Gateway run finished with failure: {failure:?}");
                    ServiceStatus::Failed
                }
                Err(panic) => {
                    tracing::error!("Gateway main thread panicked: {panic:?}");
                    ServiceStatus::Failed
                }
            };
            run_status.just_change_status(terminal.clone());
            let _ = done_tx.send(terminal);
        })
        .expect("failed to spawn gateway main thread");

        // 无异步运行时可用(非异步上下文构造):回退为线程 spawn 成功即
        // Running;否则状态由网关线程内 spawn 的 ExecutionPhase 转发任务驱动
        if self.rt.is_none() {
            status.just_change_status(ServiceStatus::Running);
        }

        *state = Some(GatewayRun { thread: Some(thread), cancel, status, done_rx });
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
        let state = self.state.lock().unwrap();
        if let Some(run) = state.as_ref() {
            if run.status.is_exit() {
                return;
            }
            tracing::info!("Signalling gateway to stop...");
            run.status.just_change_status(ServiceStatus::Stopping);
            run.cancel.cancel();
        }
    }

    /// Block until the gateway thread has exited. Call after shutdown().
    /// 线程终态会写入 last_terminal,供后续状态查询展示。
    pub fn join(&self) {
        let mut state = self.state.lock().unwrap();
        let Some(run) = state.as_mut() else {
            return;
        };
        tracing::info!("Waiting for gateway thread to finish...");
        // 持锁 join:期间并发 status() 会等待而不是读到「已 take 但尚未写入
        // last_terminal」的旧值;终态写入后再清空 state。
        if let Some(thread) = run.thread.take()
            && let Err(e) = thread.join()
        {
            tracing::error!("Gateway thread panicked: {:?}", e);
        }
        let terminal = run.status.current();
        self.last_terminal.store(Arc::new(terminal));
        *state = None;
        tracing::info!("Gateway stopped");
    }

    /// 当前运行的完成通知接收端:await 终态(Stop/Failed)替代轮询。
    pub fn done_receiver(&self) -> Option<watch::Receiver<ServiceStatus>> {
        self.state.lock().unwrap().as_ref().map(|run| run.done_rx.clone())
    }

    pub fn is_running(&self) -> bool {
        matches!(self.status(), ServiceStatus::Running)
    }

    pub fn status(&self) -> ServiceStatus {
        let state = self.state.lock().unwrap();
        match state.as_ref() {
            Some(run) => run.status.current(),
            None => (*self.last_terminal.load_full()).clone(),
        }
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
        let stopped = {
            let state = self.state.lock().unwrap();
            state.as_ref().is_some_and(|run| run.status.is_stop())
        };
        if stopped {
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

/// 运行 pingora 直到完全停止。正常返回 `Ok(())`;若 HTTPS 驱动线程 panic
/// 则返回 [`GatewayRunFailure::HttpsDriverPanicked`],由上层收敛为 Failed。
fn run_pingora_server(
    rules: SharedRules,
    http_port: u16,
    https_port: u16,
    tls_config: Option<GatewayTlsConfig>,
    cancel: CancellationToken,
    rt: Option<tokio::runtime::Handle>,
    status: WatchService,
) -> Result<(), GatewayRunFailure> {
    use pingora::server::Server;
    use proxy_service::LandscapeReverseProxy;

    let mut server = Server::new(None).expect("Failed to create Pingora server");
    server.bootstrap();
    let server_conf = server.configuration.clone();

    // run() 之前完成 ExecutionPhase 订阅(broadcast 无接收者时发送被静默
    // 丢弃,必须先订阅后 run)并在网关线程内就地 spawn 转发任务
    if let Some(rt) = rt {
        let phases = server.watch_execution_phase();
        rt.spawn(forward_execution_phase(status, phases));
    }

    let proxy = LandscapeReverseProxy::new(rules.clone());
    let mut http_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    http_service.add_tcp(&format!("[::]:{http_port}"));
    server.add_service(http_service);

    let https_handle = tls_config.map(|tls_config| {
        let rules = rules.clone();
        let cancel = cancel.child_token();
        spawn_named_thread(thread_name::fixed::GATEWAY_HTTPS_DRIVER, move || {
            run_https_server(rules, https_port, tls_config, server_conf, cancel);
        })
        .expect("failed to spawn gateway https driver thread")
    });

    let run_args = pingora::server::RunArgs {
        shutdown_signal: Box::new(TokenShutdownWatch { token: cancel }),
    };
    server.run(run_args);

    if let Some(handle) = https_handle
        && let Err(e) = handle.join()
    {
        tracing::error!("Gateway HTTPS thread panicked: {:?}", e);
        return Err(GatewayRunFailure::HttpsDriverPanicked);
    }
    Ok(())
}

/// 将 pingora 的 ExecutionPhase 广播转发为服务状态:真正进入服务态才置
/// Running,进入关闭序列置 Stopping;状态到达退出态或广播关闭时结束。
async fn forward_execution_phase(
    forward_status: WatchService,
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
    rules: SharedRules,
    https_port: u16,
    tls_config: GatewayTlsConfig,
    server_conf: Arc<pingora::server::configuration::ServerConf>,
    cancel: CancellationToken,
) {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .thread_name_fn(runtime_thread_name_fn(thread_name::prefix::GATEWAY_HTTPS_RUNTIME))
        .build()
        .expect("Failed to create gateway HTTPS runtime");

    runtime.block_on(async move {
        if let Err(error) =
            run_https_server_inner(rules, https_port, tls_config, server_conf, cancel).await
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
    });
}

#[derive(Debug)]
struct GatewayHttpsRunError {
    port: u16,
    bind_addr: String,
    source: std::io::Error,
    already_logged: bool,
}

async fn run_https_server_inner(
    rules: SharedRules,
    https_port: u16,
    tls_config: GatewayTlsConfig,
    server_conf: Arc<pingora::server::configuration::ServerConf>,
    cancel: CancellationToken,
) -> Result<(), GatewayHttpsRunError> {
    use proxy_service::LandscapeReverseProxy;

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
    let sni_proxy_router = Arc::new(SniProxyRouter::new(rules.clone()));
    let app = Arc::new(pingora::proxy::http_proxy(&server_conf, LandscapeReverseProxy::new(rules)));

    // Pingora's `ServerApp::process_new` requires a `watch::Receiver<bool>` as the
    // per-connection shutdown signal, so this channel is the token->watch bridge at
    // the pingora boundary; it is flipped when the manager's stop token fires.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    tracing::info!(
        component = "gateway_https",
        event = "bind_ok",
        port = https_port,
        bind_addr = %bind_addr,
        "Gateway HTTPS listener bound successfully"
    );

    loop {
        tokio::select! {
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
                                if let Some(sni) = parse_sni_from_client_hello(&peek_buf[..size])
                                    && let Some(target) = sni_proxy_router.match_target(&sni) {
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

                    let stream: Stream = Box::new(GatewayTlsStream::new(
                        tls_stream,
                        Some(handshake_start.elapsed()),
                    ));
                    tokio::select! {
                        _ = connection_cancel.cancelled() => {}
                        _ = app.process_new(stream, &connection_shutdown) => {}
                    }
                });
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    tracing::info!(
        component = "gateway_https",
        event = "listener_stopped",
        port = https_port,
        bind_addr = %bind_addr,
        "Gateway HTTPS listener stopped"
    );
    Ok(())
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
}

#[async_trait::async_trait]
impl pingora::server::ShutdownSignalWatch for TokenShutdownWatch {
    async fn recv(&self) -> pingora::server::ShutdownSignal {
        self.token.cancelled().await;
        pingora::server::ShutdownSignal::FastShutdown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stopping_run() -> GatewayRun {
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);
        status.just_change_status(ServiceStatus::Stopping);
        let (_done_tx, done_rx) = watch::channel(ServiceStatus::Stopping);
        GatewayRun {
            thread: Some(std::thread::spawn(|| {})),
            cancel: CancellationToken::new(),
            status,
            done_rx,
        }
    }

    #[test]
    fn start_refuses_while_previous_run_is_stopping() {
        let manager = GatewayManager::new(Vec::new(), GatewayRuntimeConfig::default(), None);
        *manager.state.lock().unwrap() = Some(stopping_run());

        manager.start();

        let state = manager.state.lock().unwrap();
        let run = state.as_ref().expect("previous run must be preserved, not overwritten");
        assert_eq!(run.status.current(), ServiceStatus::Stopping);
    }
}

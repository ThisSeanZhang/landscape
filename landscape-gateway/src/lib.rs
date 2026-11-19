mod client_hello;
mod health;
mod listener;
pub mod proxy_service;
mod upstream;
pub use landscape_common::sys_service::gateway::routes;
pub mod sni_proxy;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use std::os::fd::AsRawFd;

#[cfg(test)]
use crate::routes::CompiledGatewayRoutes;
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

use crate::client_hello::{ReplayTcpStream, TLS_HANDSHAKE_TIMEOUT, read_client_hello};
use crate::sni_proxy::{SniProxyRouter, proxy_prefixed_tls_passthrough};

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
    error: Arc<arc_swap::ArcSwapOption<String>>,
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
                RuntimeBuilder::new_multi_thread()
                    .enable_all()
                    .thread_name_fn(runtime_thread_name_fn(thread_name::prefix::GATEWAY_RUNTIME))
                    .build()?
                    .block_on(listener::run(routes, http_port, https_port, tls_config, &worker));
                std::io::Result::Ok(())
            }));
            // Completion includes runtime teardown and the release of all listeners.
            let terminal = match result {
                Ok(Ok(())) => ServiceStatus::Stop,
                Ok(Err(failure)) => {
                    worker.error.store(Some(Arc::new(failure.to_string())));
                    tracing::error!("Gateway run finished with failure: {failure}");
                    ServiceStatus::Failed
                }
                Err(panic) => {
                    worker.error.store(Some(Arc::new("Gateway main thread panicked".into())));
                    tracing::error!("Gateway main thread panicked: {panic:?}");
                    // Retain ownership if the driver could not finish its normal cleanup.
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
                run.error.store(Some(Arc::new(cause.to_string())));
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
        self.run.error.load_full().map(|message| (*message).clone())
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

/// Readiness belongs to the listener's lifetime, including unwind cleanup.
struct HttpsReadinessGuard(Arc<AtomicBool>);

impl Drop for HttpsReadinessGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn accept_connections<Fut>(
    http: TcpListener,
    https: Option<TcpListener>,
    cancel: &CancellationToken,
    readiness: HttpsReadinessGuard,
    serve: impl Fn(bool, TcpStream, SocketAddr, CancellationToken, watch::Receiver<bool>) -> Fut,
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
            accepted = listener::accept(&http, https.as_ref()) => accepted,
        };
        match accepted {
            Ok((tls, (stream, peer_addr))) => {
                let token = connections.token().child_token();
                tasks.spawn(serve(tls, stream, peer_addr, token, shutdown_rx.clone()));
            }
            Err(error) => {
                tracing::error!("Gateway accept failed: {error}");
                break Err(error);
            }
        }
    };

    drop(readiness);
    drop(http);
    drop(https);
    shutdown_tx.send_replace(true);
    drop(connections);
    tasks.close();
    tasks.wait().await;
    result
}

async fn serve_https_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    connection_cancel: CancellationToken,
    connection_shutdown: watch::Receiver<bool>,
    acceptor: TlsAcceptor,
    sni_proxy_router: Arc<SniProxyRouter>,
    app: Arc<pingora::proxy::HttpProxy<proxy_service::LandscapeReverseProxy>>,
) {
    let handshake_start = Instant::now();
    let deadline = tokio::time::Instant::now() + TLS_HANDSHAKE_TIMEOUT;
    let (prefix, target) = {
        let snapshot = sni_proxy_router.snapshot();
        if snapshot.has_sni_routes() {
            let result = tokio::select! {
                _ = connection_cancel.cancelled() => return,
                result = tokio::time::timeout_at(deadline, read_client_hello(&mut stream)) => result,
            };
            let Ok(Ok((bytes, sni))) = result else { return };
            let target = match sni {
                Some(name) => match sni_proxy_router.route(&snapshot, &name) {
                    Ok(target) => target,
                    Err(_) => return,
                },
                None => None,
            };
            (bytes, target)
        } else {
            (Vec::new(), None)
        }
    };
    let stream = ReplayTcpStream::new(stream, prefix);
    if let Some(target) = target {
        if let Err(error) = proxy_prefixed_tls_passthrough(stream, &target, connection_cancel).await
        {
            tracing::warn!(%peer_addr, %error, rule = %target.rule_name, "Gateway TLS passthrough failed");
        }
        return;
    }
    let tls_result = tokio::select! {
        _ = connection_cancel.cancelled() => return,
        result = tokio::time::timeout_at(deadline, acceptor.accept(stream)) => result,
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
    listener::serve_http(app, stream, connection_shutdown, connection_cancel).await;
}

struct GatewayTlsStream {
    inner: TokioTlsStream<ReplayTcpStream>,
    established_ts: SystemTime,
    establishment_duration: Option<Duration>,
    socket_digest: Arc<SocketDigest>,
    unique_id: i32,
}

impl GatewayTlsStream {
    fn new(
        inner: TokioTlsStream<ReplayTcpStream>,
        establishment_duration: Option<Duration>,
    ) -> Self {
        let raw_fd = inner.get_ref().0.as_raw_fd();
        Self {
            inner,
            established_ts: SystemTime::now(),
            establishment_duration,
            socket_digest: Arc::new(SocketDigest::from_raw_fd(raw_fd)),
            unique_id: raw_fd,
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

#[cfg(test)]
mod lifecycle_tests;

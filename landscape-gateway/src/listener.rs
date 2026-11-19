use super::*;
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream};
use pingora::protocols::http::{ServerSession, v2::server::H2Options};
use std::io;
use std::net::Ipv6Addr;
use tokio::net::TcpSocket;
use tokio_util::task::task_tracker::TaskTrackerToken;

// Preserve Pingora's listener queue size. Linux caps it at net.core.somaxconn.
const LISTEN_BACKLOG: u32 = 65_535;

pub(super) async fn accept(
    http: &TcpListener,
    https: Option<&TcpListener>,
) -> io::Result<(bool, (TcpStream, SocketAddr))> {
    loop {
        let result = if let Some(https) = https {
            tokio::select! {
                connection = http.accept() => connection.map(|s| (false, s)),
                connection = https.accept() => connection.map(|s| (true, s)),
            }
        } else {
            http.accept().await.map(|s| (false, s))
        };
        match result {
            Ok(connection) => return Ok(connection),
            Err(error) => {
                let Some(delay) = accept_retry_delay(&error) else { return Err(error) };
                if !delay.is_zero() {
                    tracing::warn!(%error, ?delay, "Gateway accept will retry");
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

fn accept_retry_delay(error: &io::Error) -> Option<Duration> {
    match error.raw_os_error() {
        // The descriptor is no longer a listening socket.
        Some(libc::EBADF | libc::ENOTSOCK | libc::EINVAL) => None,
        // Linux can surface the pending connection's network error from accept().
        Some(
            libc::EPROTO
            | libc::ENOPROTOOPT
            | libc::EHOSTDOWN
            | libc::ENONET
            | libc::EOPNOTSUPP
            | libc::EPERM,
        ) => Some(Duration::ZERO),
        _ => match error.kind() {
            io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::TimedOut
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown => Some(Duration::ZERO),
            // Resource errors such as EMFILE, ENFILE, ENOBUFS and ENOMEM can
            // repeat immediately. Leave established sessions running as they drain.
            _ => Some(Duration::from_secs(1)),
        },
    }
}

pub(super) async fn serve_http(
    app: Arc<pingora::proxy::HttpProxy<proxy_service::LandscapeReverseProxy>>,
    stream: Stream,
    shutdown: watch::Receiver<bool>,
    cancel: CancellationToken,
) {
    if matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) {
        serve_http2(app, stream, shutdown, cancel).await;
        return;
    }
    let mut next = Some(stream);
    while let Some(stream) = next {
        next = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            next = app.process_new(stream, &shutdown) => next,
        };
    }
}

// Pingora spawns an independent task holding this Arc for each HTTP/2 stream.
// The token stays alive until the last task drops its upstream session.
struct Http2Connection<A> {
    app: Arc<A>,
    cancel: CancellationToken,
    _lifetime: TaskTrackerToken,
}

#[async_trait::async_trait]
impl<A: HttpServerApp + Send + Sync + 'static> HttpServerApp for Http2Connection<A> {
    async fn process_new_http(
        self: &Arc<Self>,
        session: ServerSession,
        shutdown: &watch::Receiver<bool>,
    ) -> Option<ReusedHttpStream> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => None,
            result = self.app.process_new_http(session, shutdown) => result,
        }
    }

    fn h2_options(&self) -> Option<H2Options> {
        self.app.h2_options()
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        self.app.server_options()
    }
}

async fn serve_http2<A: HttpServerApp + Send + Sync + 'static>(
    app: Arc<A>,
    stream: Stream,
    shutdown: watch::Receiver<bool>,
    cancel: CancellationToken,
) {
    let streams = TaskTracker::new();
    let connection = Arc::new(Http2Connection {
        app,
        cancel: cancel.clone(),
        _lifetime: streams.token(),
    });
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {},
        _ = connection.process_new(stream, &shutdown) => {},
    }
    cancel.cancel();
    drop(connection);
    streams.close();
    streams.wait().await;
}

fn bind(protocol: &str, port: u16) -> io::Result<TcpListener> {
    let address = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port);
    let listener = TcpSocket::new_v6().and_then(|socket| {
        socket.set_reuseaddr(true)?;
        socket.bind(address)?;
        socket.listen(LISTEN_BACKLOG)
    });
    listener.map_err(|error| {
        io::Error::new(error.kind(), format!("binding gateway {protocol} at {address}: {error}"))
    })
}

pub(super) async fn run(
    routes: SharedGatewayRoutes,
    http_port: u16,
    https_port: u16,
    tls: Option<GatewayTlsConfig>,
    state: &RunState,
) {
    let health = crate::health::GatewayHealth::default();
    let serving =
        serve_listeners(routes.clone(), http_port, https_port, tls, state, health.clone());
    tokio::join!(serving, health.monitor(&routes, &state.cancel));
}

async fn serve_listeners(
    routes: SharedGatewayRoutes,
    http_port: u16,
    https_port: u16,
    tls: Option<GatewayTlsConfig>,
    state: &RunState,
    health: crate::health::GatewayHealth,
) {
    let app = Arc::new(pingora::proxy::http_proxy(
        &Arc::default(),
        proxy_service::LandscapeReverseProxy::with_health(routes.clone(), health.clone()),
    ));
    let router = Arc::new(SniProxyRouter::with_health(routes, health));
    let acceptor = tls.map(|tls| TlsAcceptor::from(tls.server_config));
    let mut delay = Duration::from_secs(1);
    while !state.cancel.is_cancelled() {
        state.status.just_change_status(ServiceStatus::Staring);
        let attempt = async {
            let http = bind("HTTP", http_port)?;
            let https = if acceptor.is_some() { Some(bind("HTTPS", https_port)?) } else { None };
            if state.cancel.is_cancelled() {
                return Ok(());
            }
            delay = Duration::from_secs(1);
            state.error.store(None);
            state.https_ready.store(https.is_some(), Ordering::Release);
            state.status.just_change_status(ServiceStatus::Running);
            accept_connections(
                http,
                https,
                &state.cancel,
                HttpsReadinessGuard(state.https_ready.clone()),
                |tls, stream, peer, token, shutdown| {
                    let app = app.clone();
                    let router = router.clone();
                    let acceptor = acceptor.clone();
                    async move {
                        let _ = stream.set_nodelay(true);
                        if tls {
                            if let Some(acceptor) = acceptor {
                                serve_https_connection(
                                    stream, peer, token, shutdown, acceptor, router, app,
                                )
                                .await;
                            }
                        } else {
                            let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
                            let mut stream = pingora::protocols::l4::stream::Stream::from(stream);
                            stream.set_socket_digest(digest);
                            serve_http(app, Box::new(stream), shutdown, token).await;
                        }
                    }
                },
            )
            .await
        };
        match attempt.await {
            Ok(()) => break,
            Err(error) => {
                tracing::warn!(%error, ?delay, "Gateway listener will retry");
                state.error.store(Some(Arc::new(error.to_string())));
                state.status.just_change_status(ServiceStatus::Failed);
            }
        }
        tokio::select! {
            _ = state.cancel.cancelled() => break,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(Duration::from_secs(30));
    }
    app.cleanup().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_retries_connections_and_backs_off_under_resource_pressure() {
        let retry = |errno| accept_retry_delay(&io::Error::from_raw_os_error(errno));
        for errno in [libc::EINTR, libc::ECONNRESET, libc::ENETUNREACH, libc::EPROTO] {
            assert_eq!(retry(errno), Some(Duration::ZERO));
        }
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(retry(errno).is_some_and(|delay| !delay.is_zero()));
        }
        for errno in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL] {
            assert_eq!(retry(errno), None);
        }
    }

    struct PendingRequests {
        options: HttpServerOptions,
        started: tokio::sync::Semaphore,
        active: TaskTracker,
    }

    #[async_trait::async_trait]
    impl HttpServerApp for PendingRequests {
        fn server_options(&self) -> Option<&HttpServerOptions> {
            Some(&self.options)
        }

        async fn process_new_http(
            self: &Arc<Self>,
            _session: ServerSession,
            _shutdown: &watch::Receiver<bool>,
        ) -> Option<ReusedHttpStream> {
            let _active = self.active.token();
            self.started.add_permits(1);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancelled_http2_connection_drains_all_in_flight_streams() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let mut options = HttpServerOptions::default();
            options.h2c = true;
            let app = Arc::new(PendingRequests {
                options,
                started: tokio::sync::Semaphore::new(0),
                active: TaskTracker::new(),
            });
            let (_shutdown_tx, shutdown) = watch::channel(false);
            let cancel = CancellationToken::new();
            let serving = tokio::spawn(serve_http2(
                app.clone(),
                Box::new(pingora::protocols::l4::stream::Stream::from(socket)),
                shutdown,
                cancel.clone(),
            ));
            let (mut client, connection) = h2::client::handshake(client).await.unwrap();
            let driver = tokio::spawn(connection);
            let mut responses = Vec::new();
            for _ in 0..2 {
                client = client.ready().await.unwrap();
                let request =
                    http::Request::builder().uri("http://gateway.example/").body(()).unwrap();
                responses.push(client.send_request(request, true).unwrap());
            }
            app.started.acquire_many(2).await.unwrap().forget();
            assert_eq!(app.active.len(), 2);
            cancel.cancel();
            serving.await.unwrap();
            assert!(app.active.is_empty());
            drop((responses, client));
            let _ = driver.await.unwrap();
        })
        .await
        .expect("HTTP/2 shutdown must finish with pending streams");
    }
}

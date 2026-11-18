use super::*;

struct ControlledRun {
    server: GatewayServer,
    release: Option<std::sync::mpsc::Sender<()>>,
    done: watch::Receiver<ServiceStatus>,
}

impl ControlledRun {
    fn new(status: ServiceStatus, early_terminal: bool, closed_completion: bool) -> Self {
        Self::with_uncertain_exit(status, early_terminal, closed_completion, false)
    }

    fn with_uncertain_exit(
        status: ServiceStatus,
        early_terminal: bool,
        closed_completion: bool,
        uncertain_exit: bool,
    ) -> Self {
        let handle = ServiceHandle::new();
        handle.just_change_status(ServiceStatus::Staring);
        handle.just_change_status(ServiceStatus::Running);
        handle.just_change_status(status.clone());
        let notification =
            if early_terminal { ServiceStatus::Stop } else { ServiceStatus::Staring };
        let (done_tx, done_rx) = watch::channel(notification);
        let done_tx = if closed_completion { None } else { Some(done_tx) };
        let (release, wait) = std::sync::mpsc::channel();
        let thread_status = handle.clone();
        let terminal = if status == ServiceStatus::Failed {
            ServiceStatus::Failed
        } else {
            ServiceStatus::Stop
        };
        let cleanup_uncertain = Arc::new(AtomicBool::new(false));
        let thread_cleanup_uncertain = cleanup_uncertain.clone();
        let thread = std::thread::spawn(move || {
            let _ = wait.recv();
            if uncertain_exit {
                thread_cleanup_uncertain.store(true, Ordering::Release);
            }
            thread_status.just_change_status(terminal.clone());
            if let Some(done_tx) = done_tx {
                let _ = done_tx.send(terminal);
            }
        });
        let server = GatewayServer {
            thread: Mutex::new(Some(thread)),
            done_rx: done_rx.clone(),
            run: RunState {
                cancel: CancellationToken::new(),
                status: handle,
                https_ready: Arc::new(AtomicBool::new(true)),
                cleanup_uncertain,
                error: Default::default(),
            },
        };
        Self { server, release: Some(release), done: done_rx }
    }

    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }

    fn assert_original_run(&self) {
        assert!(self.server.thread.lock().unwrap().is_some());
        assert!(self.server.done_rx.same_channel(&self.done));
    }
}

impl Drop for ControlledRun {
    fn drop(&mut self) {
        self.release();
    }
}

#[tokio::test]
async fn stop_timeout_retains_thread_and_prevents_restart() {
    let mut run = ControlledRun::new(ServiceStatus::Running, false, false);
    assert!(run.server.has_https_listener());
    let error = run.server.shutdown_and_wait(Duration::from_millis(10)).await.unwrap_err();
    assert!(matches!(error, GatewayError::StopTimeout { timeout_ms: 10 }));
    assert!(!run.server.has_https_listener());
    run.assert_original_run();

    run.release();
    run.server.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
    assert!(run.server.thread.lock().unwrap().is_none());
    assert_eq!(run.server.status(), ServiceStatus::Stop);
}

#[tokio::test]
async fn terminal_notification_still_waits_for_thread_exit() {
    let mut run = ControlledRun::new(ServiceStatus::Stop, true, false);
    assert!(matches!(
        run.server.shutdown_and_wait(Duration::from_millis(10)).await,
        Err(GatewayError::StopTimeout { .. })
    ));
    run.assert_original_run();
    run.release();
    run.server.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn closed_completion_channel_is_a_stop_failure() {
    let run = ControlledRun::new(ServiceStatus::Failed, false, true);
    assert!(matches!(
        run.server.shutdown_and_wait(Duration::from_secs(1)).await,
        Err(GatewayError::StopFailed { .. })
    ));
    run.assert_original_run();
    assert!(run.server.run.cancel.is_cancelled());
    assert!(!run.server.has_https_listener());
}

#[tokio::test]
async fn uncertain_panic_cleanup_keeps_failing_stop_and_refusing_restart() {
    let mut run = ControlledRun::new(ServiceStatus::Failed, false, false);
    run.server.run.cleanup_uncertain.store(true, Ordering::Release);
    run.release();
    for _ in 0..2 {
        assert!(matches!(
            run.server.shutdown_and_wait(Duration::from_secs(1)).await,
            Err(GatewayError::StopFailed { .. })
        ));
        run.assert_original_run();
        assert_eq!(run.server.status(), ServiceStatus::Failed);
        assert!(!run.server.has_https_listener());
    }
}

#[tokio::test]
async fn uncertainty_reported_after_early_notification_prevents_reaping() {
    let mut run = ControlledRun::with_uncertain_exit(ServiceStatus::Failed, true, false, true);
    run.release();
    assert!(matches!(
        run.server.shutdown_and_wait(Duration::from_secs(1)).await,
        Err(GatewayError::StopFailed { .. })
    ));
    run.assert_original_run();
}

#[test]
fn dropping_a_server_cancels_without_blocking_on_the_thread() {
    let mut run = ControlledRun::new(ServiceStatus::Failed, false, false);
    let release = run.release.take().unwrap();
    let cancel = run.server.run.cancel.clone();
    let (finished, wait) = std::sync::mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(run);
        finished.send(()).unwrap();
    });
    let result = wait.recv_timeout(Duration::from_secs(1));
    let _ = release.send(());
    dropper.join().unwrap();
    result.unwrap();
    assert!(cancel.is_cancelled());
}

#[tokio::test]
async fn safely_completed_failed_run_can_be_reaped() {
    let mut run = ControlledRun::new(ServiceStatus::Failed, false, false);
    run.release();
    run.server.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
    assert!(run.server.thread.lock().unwrap().is_none());
    assert_eq!(run.server.status(), ServiceStatus::Failed);
}

fn tls_config() -> GatewayTlsConfig {
    GatewayTlsConfig {
        server_config: Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())),
        ),
    }
}

fn empty_routes() -> SharedGatewayRoutes {
    Arc::new(ArcSwap::from_pointee(CompiledGatewayRoutes::default()))
}

#[tokio::test]
async fn https_readiness_tracks_bound_listener_and_cancellation() {
    let ready = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    let listener = tokio::spawn(run_https_server_inner(
        empty_routes(),
        0,
        tls_config(),
        Arc::new(pingora::server::configuration::ServerConf::default()),
        cancel.clone(),
        ready.clone(),
    ));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !ready.load(Ordering::Acquire) {
            assert!(!listener.is_finished(), "HTTPS listener exited before becoming ready");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), listener).await.unwrap().unwrap().unwrap();
    assert!(!ready.load(Ordering::Acquire));
}

#[test]
fn https_bind_failure_fails_and_cancels_the_run() {
    let occupied = std::net::TcpListener::bind("[::]:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let ready = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    let result = supervise_https_driver(
        status.clone(),
        cancel.clone(),
        ready.clone(),
        &OnceLock::new(),
        || {
            run_https_server(
                empty_routes(),
                port,
                tls_config(),
                Arc::new(pingora::server::configuration::ServerConf::default()),
                cancel.clone(),
                ready.clone(),
            )
        },
    );
    let Err(GatewayRunFailure::HttpsDriverFailed(error)) = result else {
        panic!("occupied HTTPS port must fail the run");
    };
    assert_eq!(error.source.kind(), std::io::ErrorKind::AddrInUse);
    assert_eq!(status.current(), ServiceStatus::Failed);
    assert!(cancel.is_cancelled());
    assert!(!ready.load(Ordering::Acquire));
}

#[tokio::test]
async fn https_accept_failure_drains_active_connections_before_returning() {
    use std::net::{Ipv4Addr, Shutdown};
    use std::os::fd::OwnedFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    // On Linux, shutting down the listening socket makes accept fail while
    // previously accepted connections remain usable.
    let control = std::net::TcpStream::from(OwnedFd::from(listener.try_clone().unwrap()));
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    let ready = Arc::new(AtomicBool::new(true));
    let readiness = HttpsReadinessGuard(ready.clone());
    let serving = tokio::spawn(async move {
        accept_https_connections(
            listener,
            &CancellationToken::new(),
            readiness,
            |mut stream, _, cancel, mut shutdown| async move {
                stream.write_u8(1).await.unwrap();
                cancel.cancelled().await;
                shutdown.wait_for(|stop| *stop).await.unwrap();
                stream.write_u8(2).await.unwrap();
                // The client controls when this connection may finish draining.
                assert_eq!(stream.read_u8().await.unwrap(), 3);
            },
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = TcpStream::connect(address).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), 1);
        control.shutdown(Shutdown::Both).unwrap();
        assert_eq!(client.read_u8().await.unwrap(), 2);
        assert!(!ready.load(Ordering::Acquire));
        assert!(!serving.is_finished(), "listener returned while a connection was draining");
        client.write_u8(3).await.unwrap();
        assert_eq!(serving.await.unwrap().unwrap_err().kind(), ErrorKind::InvalidInput);
    })
    .await
    .expect("listener must cancel and drain its connections after an accept failure");
}

#[test]
fn https_panic_clears_readiness_and_cancels_the_run() {
    let ready = Arc::new(AtomicBool::new(true));
    let cancel = CancellationToken::new();
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    let result = supervise_https_driver(
        status.clone(),
        cancel.clone(),
        ready.clone(),
        &OnceLock::new(),
        || panic!("injected HTTPS driver panic"),
    );
    assert!(matches!(result, Err(GatewayRunFailure::HttpsDriverPanicked)));
    assert_eq!(status.current(), ServiceStatus::Failed);
    assert!(cancel.is_cancelled());
    assert!(!ready.load(Ordering::Acquire));
}

#[test]
fn parent_unwind_cancels_and_joins_https_driver() {
    let cancel = CancellationToken::new();
    let child_cancel = cancel.clone();
    let child_exited = Arc::new(AtomicBool::new(false));
    let child_exited_flag = child_exited.clone();
    let result = std::panic::catch_unwind(move || {
        let _driver = HttpsDriver {
            cancel,
            thread: Some(std::thread::spawn(move || {
                while !child_cancel.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                child_exited_flag.store(true, Ordering::Release);
                Ok(())
            })),
        };
        panic!("injected main driver panic");
    });
    assert!(result.is_err());
    assert!(child_exited.load(Ordering::Acquire));
}

#[tokio::test]
async fn cancelled_start_does_not_bind_or_publish_https_readiness() {
    let occupied = std::net::TcpListener::bind("[::]:0").unwrap();
    let ready = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    cancel.cancel();
    run_https_server_inner(
        empty_routes(),
        occupied.local_addr().unwrap().port(),
        tls_config(),
        Arc::new(pingora::server::configuration::ServerConf::default()),
        cancel,
        ready.clone(),
    )
    .await
    .unwrap();
    assert!(!ready.load(Ordering::Acquire));
}

struct BlockedListenerService {
    bound: Option<std::sync::mpsc::Sender<std::net::SocketAddr>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

#[async_trait::async_trait]
impl pingora::services::Service for BlockedListenerService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora::server::ListenFds>,
        mut shutdown: pingora::server::ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        self.bound.take().unwrap().send(listener.local_addr().unwrap()).unwrap();
        // Intentionally block the async worker to expose shutdown_timeout(0)
        // detaching a work-stealing runtime before its listener is dropped.
        self.release.lock().unwrap().recv().unwrap();
        while !*shutdown.borrow() {
            shutdown.changed().await.unwrap();
        }
        drop(listener);
    }

    fn name(&self) -> &str {
        "gateway-stop-test"
    }
}

#[test]
fn fast_shutdown_waits_for_http_worker_to_release_its_listener() {
    let (bound_tx, bound_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let cancel = CancellationToken::new();
    let driver_cancel = cancel.clone();
    let driver = std::thread::spawn(move || {
        let mut server = create_pingora_server();
        server.bootstrap();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        let (service, http_shutdown) = http_listener::supervise(
            BlockedListenerService {
                bound: Some(bound_tx),
                release: Mutex::new(release_rx),
            },
            driver_cancel.clone(),
            status,
            Arc::new(AtomicBool::new(false)),
        );
        server.add_service(service);
        server.run(pingora::server::RunArgs {
            shutdown_signal: Box::new(TokenShutdownWatch {
                token: driver_cancel,
                http: Arc::new(http_shutdown),
            }),
        });
        done_tx.send(()).unwrap();
    });
    let address = bound_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    cancel.cancel();
    let early_completion = done_rx.recv_timeout(Duration::from_millis(50));
    release_tx.send(()).unwrap();
    if early_completion.is_err() {
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    driver.join().unwrap();
    assert!(matches!(early_completion, Err(std::sync::mpsc::RecvTimeoutError::Timeout)));
    std::net::TcpListener::bind(address).expect("HTTP listener must be released before completion");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_gateway_serves_requests_after_repeated_stop_and_start() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let reservation = std::net::TcpListener::bind("[::]:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let routes = empty_routes();
    for _ in 0..3 {
        let server = GatewayServer::spawn(
            routes.clone(),
            &GatewayRuntimeConfig { http_port: port, ..Default::default() },
            None,
        );
        let response = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = loop {
                match TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, port)).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::time::sleep(Duration::from_millis(2)).await,
                }
            };
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        })
        .await
        .expect("gateway must accept and answer requests after each restart");
        assert!(response.starts_with("HTTP/1.1 404"), "unexpected response: {response}");
        server.shutdown_and_wait(Duration::from_secs(5)).await.unwrap();
        assert!(server.thread.lock().unwrap().is_none());
    }
}

enum TestHttpService {
    WaitForStop,
    Return,
    Panic,
}

#[async_trait::async_trait]
impl pingora::services::Service for TestHttpService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora::server::ListenFds>,
        mut shutdown: pingora::server::ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        match self {
            Self::WaitForStop => shutdown.changed().await.unwrap(),
            Self::Return => (),
            Self::Panic => panic!("injected HTTP service panic"),
        }
    }

    fn name(&self) -> &str {
        "gateway-http-test"
    }
}

#[tokio::test]
async fn http_stop_before_start_is_observed_by_the_listener() {
    use pingora::services::Service;
    use std::future::Future;
    use std::task::Poll;

    let cancel = CancellationToken::new();
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    let uncertain = Arc::new(AtomicBool::new(false));
    let (mut service, shutdown) = http_listener::supervise(
        TestHttpService::WaitForStop,
        cancel.clone(),
        status,
        uncertain.clone(),
    );
    cancel.cancel();
    let waiting = shutdown.shutdown_and_wait();
    tokio::pin!(waiting);
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let (_unused_tx, unused_rx) = watch::channel(false);
    tokio::time::timeout(Duration::from_secs(1), service.start_service(None, unused_rx, 1))
        .await
        .unwrap();
    waiting.await;
    assert!(!shutdown.failed());
    assert!(!uncertain.load(Ordering::Acquire));
}

#[tokio::test]
async fn http_service_panic_reports_uncertain_cleanup_and_cancels_run() {
    use pingora::services::Service;

    let cancel = CancellationToken::new();
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    let uncertain = Arc::new(AtomicBool::new(false));
    let (mut service, shutdown) = http_listener::supervise(
        TestHttpService::Panic,
        cancel.clone(),
        status.clone(),
        uncertain.clone(),
    );
    let task = tokio::spawn(async move {
        let (_unused_tx, unused_rx) = watch::channel(false);
        service.start_service(None, unused_rx, 1).await;
    });
    assert!(task.await.unwrap_err().is_panic());
    shutdown.shutdown_and_wait().await;
    assert!(shutdown.failed());
    assert!(uncertain.load(Ordering::Acquire));
    assert!(cancel.is_cancelled());
    assert_eq!(status.current(), ServiceStatus::Failed);
}

#[tokio::test]
async fn unexpected_http_service_exit_fails_but_confirms_cleanup() {
    use pingora::services::Service;

    let cancel = CancellationToken::new();
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    let uncertain = Arc::new(AtomicBool::new(false));
    let (mut service, shutdown) = http_listener::supervise(
        TestHttpService::Return,
        cancel.clone(),
        status.clone(),
        uncertain.clone(),
    );
    let (_unused_tx, unused_rx) = watch::channel(false);
    service.start_service(None, unused_rx, 1).await;
    shutdown.shutdown_and_wait().await;
    assert!(shutdown.failed());
    assert!(!uncertain.load(Ordering::Acquire));
    assert!(cancel.is_cancelled());
    assert_eq!(status.current(), ServiceStatus::Failed);
}

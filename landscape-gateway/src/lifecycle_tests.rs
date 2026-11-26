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
    Arc::new(crate::routes::GatewayRoutes::new(CompiledGatewayRoutes::default()))
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
        accept_connections(
            listener,
            None,
            &CancellationToken::new(),
            readiness,
            |_, mut stream, _, cancel, mut shutdown| async move {
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
        assert_eq!(serving.await.unwrap().unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    })
    .await
    .expect("listener must cancel and drain its connections after an accept failure");
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

#[tokio::test]
async fn gateway_retries_occupied_listeners_and_releases_partial_binds() {
    for occupy_https in [false, true] {
        let first = std::net::TcpListener::bind("[::]:0").unwrap();
        let second = std::net::TcpListener::bind("[::]:0").unwrap();
        let http_port = first.local_addr().unwrap().port();
        let https_port = second.local_addr().unwrap().port();
        let occupied = if occupy_https {
            drop(first);
            second
        } else {
            drop(second);
            first
        };
        let server = GatewayServer::spawn(
            empty_routes(),
            &GatewayRuntimeConfig { enable: true, http_port, https_port },
            Some(tls_config()),
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.last_error().is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(!server.has_https_listener());
            if occupy_https {
                std::net::TcpListener::bind(("::", http_port))
                    .expect("partial HTTP listener was released");
            }
            drop(occupied);
            while !server.has_https_listener() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(server.last_error().is_none());
        })
        .await
        .expect("both listeners must recover without another restart");
        server.shutdown_and_wait(Duration::from_secs(2)).await.unwrap();
        assert!(!server.has_https_listener());
        std::net::TcpListener::bind(("::", https_port)).unwrap();
    }
}

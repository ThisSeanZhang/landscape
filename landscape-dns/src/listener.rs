use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::server::handler::DnsRequestHandler;
use landscape_common::flow::{DnsListenerRole, DnsSocketRegisterError, FlowSocketRegistrar};

use socket2::{Domain, Protocol, Socket, Type};
use tokio_util::task::TaskTracker;
use tracing::Instrument;

pub(crate) mod doh;
pub(crate) mod tcp;
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

mod transport;
pub use transport::DohSettings;
pub(crate) use transport::{DohReadiness, FlowListeners};

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

/// UDP owns the flow lifetime. TCP and DoH supervise their own sockets.
pub(crate) async fn start_flow_dns_listener(
    flow_id: u32,
    addr: SocketAddr,
    listeners: FlowListeners,
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

    // Bind DNS/TCP to the port the UDP socket actually got, so a port-0
    // address (tests) still yields one shared UDP/TCP port.
    let udp_addr = udp.local_addr().unwrap_or(addr);

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

    listeners.start(flow_id, udp_addr, handler, socket_registrar, &token, &tracker);
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::{
        FlowListeners, attach_dns_socket, create_udp_socket, is_unrecoverable_socket_error,
        start_flow_dns_listener,
    };
    use crate::server::handler::tests::redirect_test_handler;
    use landscape_common::flow::{DnsListenerRole, DnsSocketRegisterError, FlowSocketRegistrar};

    /// Records which listener roles a flow registered.
    #[derive(Default)]
    struct RecordingRegistrar {
        roles: Mutex<Vec<DnsListenerRole>>,
    }

    impl FlowSocketRegistrar for RecordingRegistrar {
        fn register_dns_socket(
            &self,
            _flow_id: u32,
            _sock_fd: i32,
            role: DnsListenerRole,
        ) -> Result<(), DnsSocketRegisterError> {
            self.roles.lock().unwrap().push(role);
            Ok(())
        }
    }

    fn query_bytes(id: u16) -> Vec<u8> {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("www.example.com.").unwrap(), RecordType::A));
        query.to_vec().unwrap()
    }

    async fn free_port() -> u16 {
        let (probe, _) = create_udp_socket("[::]:0".parse().unwrap()).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    }

    /// Each flow registers both plain DNS listeners on the same port.
    #[tokio::test]
    async fn serves_udp_and_tcp_on_one_port() {
        let port = free_port().await;
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let registrar = Arc::new(RecordingRegistrar::default());
        let handler =
            redirect_test_handler("www.example.com.", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 60);

        start_flow_dns_listener(
            1,
            addr,
            FlowListeners::default(),
            handler,
            registrar.clone(),
            token.clone(),
            tracker.clone(),
        )
        .await;

        let roles = registrar.roles.lock().unwrap().clone();
        assert!(roles.contains(&DnsListenerRole::Udp), "UDP role must be registered: {roles:?}");
        assert!(roles.contains(&DnsListenerRole::Tcp), "TCP role must be registered: {roles:?}");

        // TCP query on the shared port is answered by the same redirect rule.
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let query = query_bytes(0x4242);
        stream.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
        stream.write_all(&query).await.unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let mut payload = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut payload).await.unwrap();
        let response = Message::from_vec(&payload).unwrap();
        assert_eq!(response.id, 0x4242);
        assert_eq!(response.answers.len(), 1);

        token.cancel();
        tracker.close();
        let _ = tokio::time::timeout(Duration::from_secs(5), tracker.wait()).await;
    }

    #[tokio::test]
    async fn doh_rebinds_and_retries_while_plain_dns_keeps_serving() {
        tokio::time::timeout(Duration::from_secs(12), exercise_doh_rebind()).await.unwrap();
    }

    async fn exercise_doh_rebind() {
        use landscape_common::sys_config::DohRuntimeConfig;
        use rustls::{
            ClientConfig, RootCertStore, ServerConfig, crypto::ring, pki_types::PrivateKeyDer,
        };
        use tokio::net::{TcpListener, TcpStream, UdpSocket};
        let cert = rcgen::generate_simple_self_signed(vec!["dns.example".to_owned()]).unwrap();
        let provider = Arc::new(ring::default_provider());
        let server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let client = tokio_rustls::TlsConnector::from(Arc::new(client));

        let (desired, config) = tokio::sync::watch::channel(DohRuntimeConfig {
            listen_port: 0,
            http_endpoint: "/one".into(),
        });
        let listeners = FlowListeners {
            doh: Some(super::DohSettings { config, cert_resolver: server.cert_resolver }),
            ..Default::default()
        };
        let advertised = &listeners.readiness.advertised;
        let registrar = Arc::new(RecordingRegistrar::default());
        let handler =
            redirect_test_handler("www.example.com.", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 60);
        let owner = CancellationToken::new();
        let tasks = TaskTracker::new();
        let dns_port = free_port().await;
        for flow in 1..=2 {
            start_flow_dns_listener(
                flow,
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, dns_port)),
                listeners.clone(),
                handler.clone(),
                registrar.clone(),
                owner.child_token(),
                tasks.clone(),
            )
            .await;
        }
        tasks.close();
        let initial = advertised.load_full().unwrap();
        assert_ne!(initial.listen_port, 0);
        assert_eq!(doh_query(&client, initial.listen_port, "/one").await, http::StatusCode::OK);
        let mut tcp = TcpStream::connect(("::1", dns_port)).await.unwrap();

        // Force the new bind to fail. An existing TCP session and a new UDP query still work.
        let occupied = TcpListener::bind("[::]:0").await.unwrap();
        let new_port = occupied.local_addr().unwrap().port();
        desired.send_replace(DohRuntimeConfig {
            listen_port: new_port,
            http_endpoint: "/two".into(),
        });
        while listeners.doh_error.load().is_none() {
            tokio::task::yield_now().await;
        }
        assert!(advertised.load().is_none());
        let udp = UdpSocket::bind("[::1]:0").await.unwrap();
        let query = query_bytes(42);
        udp.send_to(&query, ("::1", dns_port)).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = udp.recv_from(&mut buf).await.unwrap();
        assert_eq!(Message::from_vec(&buf[..len]).unwrap().id, 42);
        tcp.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
        tcp.write_all(&query).await.unwrap();
        let len = tcp.read_u16().await.unwrap() as usize;
        tcp.read_exact(&mut buf[..len]).await.unwrap();
        assert_eq!(Message::from_vec(&buf[..len]).unwrap().id, 42);

        drop(occupied);
        while advertised.load().as_ref().is_none_or(|e| e.listen_port != new_port) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(doh_query(&client, new_port, "/two").await, http::StatusCode::OK);
        // A path-only edit also takes effect without re-registering UDP or TCP.
        desired.send_replace(DohRuntimeConfig {
            listen_port: new_port,
            http_endpoint: "/three".into(),
        });
        while advertised.load().as_ref().is_none_or(|e| e.http_endpoint != "/three") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(doh_query(&client, new_port, "/two").await, http::StatusCode::NOT_FOUND);
        assert_eq!(doh_query(&client, new_port, "/three").await, http::StatusCode::OK);
        for role in [DnsListenerRole::Udp, DnsListenerRole::Tcp] {
            assert_eq!(registrar.roles.lock().unwrap().iter().filter(|r| **r == role).count(), 2);
        }
        owner.cancel();
        tasks.wait().await;
        desired.send_replace((*initial).clone());
        assert!(advertised.load().is_none());
        assert!(TcpStream::connect(("::1", new_port)).await.is_err());
    }

    async fn doh_query(
        client: &tokio_rustls::TlsConnector,
        port: u16,
        path: &str,
    ) -> http::StatusCode {
        use base64::Engine;
        let tcp = tokio::net::TcpStream::connect(("::1", port)).await.unwrap();
        let tls = client.connect("dns.example".try_into().unwrap(), tcp).await.unwrap();
        let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
        let driver = tokio::spawn(connection);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query_bytes(42));
        let request = http::Request::get(format!("https://dns.example:{port}{path}?dns={encoded}"))
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        let status = response.status();
        if status.is_success() {
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            let answer = Message::from_vec(&bytes).unwrap();
            assert_eq!(answer.id, 42);
            assert_eq!(answer.answers.len(), 1);
        }
        driver.abort();
        status
    }

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

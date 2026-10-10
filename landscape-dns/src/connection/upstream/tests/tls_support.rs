//! Shared real-transport test harness: a self-signed TLS identity, an
//! authoritative hickory-server speaking DoT / DoH / DoQ, pool/connector
//! builders that trust the test certificate, and a minimal quinn DoQ echo
//! server.
//!
//! These live as unit tests (not `tests/` integration tests) because they
//! inject a `rustls::ClientConfig` through `UpstreamPool::new`, whose
//! `tls_config` parameter and `#[cfg(test)]` helpers are only visible inside
//! the crate. Production passes `None` (platform verifier); here a self-signed
//! cert is trusted instead.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::proto::op::{DnsRequestOptions, Message, Query};
use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use hickory_server::server::Server;
use hickory_server::zone_handler::Catalog;
use landscape_common::dns::bind::DnsBindConfig;
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;

use crate::connection::provider::MarkRuntimeProvider;
use crate::connection::upstream::UpstreamPool;
use crate::connection::upstream::native::build_connectors;
use crate::connection::upstream::pool_config::{PoolConfig, PoolSettings};
use crate::connection::upstream::traits::DnsConn;

/// A self-signed server certificate (SAN `ns.example.com`) plus the client
/// config that trusts it.
pub(super) struct TestTls {
    pub(super) cert_der: Vec<u8>,
    pub(super) key_der: Vec<u8>,
    pub(super) client_config: Arc<rustls::ClientConfig>,
}

pub(super) fn test_tls() -> TestTls {
    // Several rustls crypto providers are compiled into this workspace
    // (ring here, aws-lc-rs via rcgen elsewhere), so rustls needs an
    // explicit default provider before any config is built.
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let cert = rcgen::generate_simple_self_signed(vec!["ns.example.com".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone().to_vec();
    let key_der = cert.signing_key.serialize_der();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(cert_der.clone())).unwrap();
    let client_config = Arc::new(
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
    );
    TestTls { cert_der, key_der, client_config }
}

/// Serves the configured certificate for every handshake.
#[derive(Debug)]
struct FixedCertResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for FixedCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.certified_key.clone())
    }
}

fn certified_key(tls: &TestTls) -> Arc<rustls::sign::CertifiedKey> {
    let key =
        rustls::crypto::ring::sign::any_supported_type(&rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(tls.key_der.clone()),
        ))
        .unwrap();
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(tls.cert_der.clone())],
        key,
    ))
}

pub(super) enum TlsProtocol {
    Tls,
    Https,
    Quic,
}

/// Spawns an authoritative server for `example.com.` (A record
/// `www.example.com. -> 1.2.3.4`) on an ephemeral port, speaking the
/// requested encrypted protocol.
pub(super) async fn spawn_tls_server(
    protocol: TlsProtocol,
    tls: &TestTls,
) -> (u16, tokio::task::JoinHandle<()>) {
    let resolver: Arc<dyn rustls::server::ResolvesServerCert> =
        Arc::new(FixedCertResolver { certified_key: certified_key(tls) });

    let (origin, authority) = crate::connection::test_util::zone_authority(true);
    let mut catalog = Catalog::new();
    catalog.upsert(origin.into(), vec![authority]);
    let mut server = Server::new(catalog);

    let (port, handle) = match protocol {
        TlsProtocol::Tls => {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            server.register_tls_listener(listener, Duration::from_secs(5), resolver).unwrap();
            let handle = tokio::spawn(async move {
                let _ = server.block_until_done().await;
            });
            (port, handle)
        }
        TlsProtocol::Https => {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            server
                .register_https_listener(
                    listener,
                    Duration::from_secs(5),
                    resolver,
                    Some("ns.example.com".to_string()),
                    "/dns-query".to_string(),
                )
                .unwrap();
            let handle = tokio::spawn(async move {
                let _ = server.block_until_done().await;
            });
            (port, handle)
        }
        TlsProtocol::Quic => {
            let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
            let port = socket.local_addr().unwrap().port();
            // Since hickory-server 0.26.3 the quic handler also applies this
            // timeout as a "no new streams" idle limit and closes the
            // connection with DOQ_NO_ERROR(0) once it fires — client PING
            // keep-alives cannot prevent it. Keep it far above the client's
            // idle window so the keep-alive assertions below exercise the
            // QUIC transport idle timeout, not the server's stream-idle
            // close.
            server.register_quic_listener(socket, Duration::from_secs(30), resolver).unwrap();
            let handle = tokio::spawn(async move {
                let _ = server.block_until_done().await;
            });
            (port, handle)
        }
    };
    (port, handle)
}

/// Builds a pool for `mode` against `port`, trusting the test certificate.
pub(super) async fn tls_pool(port: u16, mode: DnsUpstreamMode, tls: &TestTls) -> Arc<UpstreamPool> {
    let upstream = DnsUpstreamConfig {
        remark: "test".into(),
        mode,
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        ..Default::default()
    };
    let provider = MarkRuntimeProvider::new(0x8000, DnsBindConfig::default());
    UpstreamPool::new(
        7,
        0x8000,
        &upstream,
        provider,
        &PoolSettings::default(),
        Some(tls.client_config.clone()),
    )
    .unwrap()
}

pub(super) async fn assert_www_answer(pool: &Arc<UpstreamPool>) {
    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
}

/// A bare DoQ connector (no pool) with explicit QUIC tuning, so keep-alive
/// behaviour can be observed without the pool's idle reaping interfering.
pub(super) fn quic_connector(
    port: u16,
    tls: &TestTls,
    idle_timeout: Duration,
    keep_alive: bool,
) -> Arc<dyn crate::connection::upstream::traits::DnsConnector> {
    quic_connector_at(IpAddr::V4(Ipv4Addr::LOCALHOST), port, tls, idle_timeout, keep_alive)
}

/// Like [`quic_connector`], but dialing the given upstream address (the
/// source-address binding on the connector follows the IP family).
pub(super) fn quic_connector_at(
    ip: IpAddr,
    port: u16,
    tls: &TestTls,
    idle_timeout: Duration,
    keep_alive: bool,
) -> Arc<dyn crate::connection::upstream::traits::DnsConnector> {
    let mode = DnsUpstreamMode::Quic { domain: "ns.example.com".into() };
    let mut config = PoolConfig::for_mode(&mode);
    config.idle_timeout = idle_timeout;
    config.keep_alive = keep_alive;
    let conns = build_connectors(
        &mode,
        &[ip],
        Some(port),
        MarkRuntimeProvider::new(0x8000, DnsBindConfig::default()),
        &config,
        Some(tls.client_config.clone()),
    );
    assert_eq!(conns.len(), 1);
    conns.into_iter().next().unwrap()
}

/// A bare single-endpoint connector for `mode` with an explicit in-flight
/// capacity, so saturation behaviour can be observed without the pool's
/// elastic scale-up interfering.
pub(super) fn connector_with_cap(
    mode: DnsUpstreamMode,
    port: u16,
    tls: &TestTls,
    max_active_requests: usize,
) -> Arc<dyn crate::connection::upstream::traits::DnsConnector> {
    let mut config = PoolConfig::for_mode(&mode);
    config.max_active_requests = max_active_requests;
    let conns = build_connectors(
        &mode,
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        Some(port),
        MarkRuntimeProvider::new(0x8000, DnsBindConfig::default()),
        &config,
        Some(tls.client_config.clone()),
    );
    assert_eq!(conns.len(), 1);
    conns.into_iter().next().unwrap()
}

/// A minimal DoH echo server: TLS with the h2 ALPN, one h2 connection per
/// TCP accept, one POST -> DNS response round-trip per stream, every
/// response delayed by `delay`. Fully received requests are counted on
/// `seen` (see [`spawn_quic_delayed_echo_server`]).
pub(super) async fn spawn_doh_echo_server(
    tls: &TestTls,
    delay: Duration,
) -> (u16, tokio::sync::watch::Receiver<u64>) {
    spawn_doh_echo_server_inner(tls, delay, None).await
}

/// Like [`spawn_doh_echo_server`], but advertising a
/// `SETTINGS_MAX_CONCURRENT_STREAMS` of `max_streams`: a peer limiting
/// concurrency below the client's own cap exercises the client's bounded
/// capacity wait inside `h2.ready()`.
pub(super) async fn spawn_doh_limited_echo_server(
    tls: &TestTls,
    max_streams: u32,
    delay: Duration,
) -> (u16, tokio::sync::watch::Receiver<u64>) {
    spawn_doh_echo_server_inner(tls, delay, Some(max_streams)).await
}

async fn spawn_doh_echo_server_inner(
    tls: &TestTls,
    delay: Duration,
    max_concurrent_streams: Option<u32>,
) -> (u16, tokio::sync::watch::Receiver<u64>) {
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        tls.key_der.clone(),
    ));
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(tls.cert_der.clone())], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::watch::channel(0u64);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let seen_tx = seen_tx.clone();
            let max_streams = max_concurrent_streams;
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else { return };
                let mut builder = h2::server::Builder::new();
                if let Some(max) = max_streams {
                    builder.max_concurrent_streams(max);
                }
                let Ok(mut h2) = builder.handshake::<_, bytes::Bytes>(stream).await else { return };
                while let Some(Ok((request, mut respond))) = h2.accept().await {
                    let seen_tx = seen_tx.clone();
                    tokio::spawn(async move {
                        let (_parts, mut body) = request.into_parts();
                        let mut buf = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            buf.extend_from_slice(&chunk);
                        }
                        seen_tx.send_modify(|count| *count += 1);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        let Ok(message) = Message::from_vec(&buf) else { return };
                        let mut response = message.into_response();
                        response.answers.push(Record::from_rdata(
                            Name::from_str("www.example.com.").unwrap(),
                            60,
                            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                        ));
                        let Ok(bytes) = response.to_vec() else { return };
                        let http_response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(http_response, false) else {
                            return;
                        };
                        let _ = send.send_data(bytes.into(), true);
                    });
                }
            });
        }
    });
    (port, seen_rx)
}

/// A DoH endpoint that completes the TLS handshake but never speaks h2
/// (no server preface, no SETTINGS): the client's h2 driver stays alive
/// while every `ready()` wait pends until its capacity timeout. The
/// returned counter tracks completed TLS accepts, so tests can observe
/// fresh dials.
pub(super) async fn spawn_doh_silent_server(
    tls: &TestTls,
) -> (u16, Arc<std::sync::atomic::AtomicU32>) {
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        tls.key_der.clone(),
    ));
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(tls.cert_der.clone())], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let task_accepts = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let accepts = task_accepts.clone();
            tokio::spawn(async move {
                let Ok(_tls_stream) = acceptor.accept(stream).await else { return };
                accepts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Wedged peer: never send the h2 server preface.
                std::future::pending::<()>().await;
            });
        }
    });
    (port, accepts)
}

/// A minimal quinn DoQ echo server (the hickory-net `test_quic_stream`
/// pattern: `QuicServer` + `server_responder`): accepts connections, reads
/// each framed query, and echoes it back as a response — optionally with a
/// mangled message id, to exercise the client's RFC 9250 id-0 validation.
pub(super) fn spawn_quic_echo_server(
    tls: &TestTls,
    bind_addr: IpAddr,
    mangle_response_id: bool,
) -> SocketAddr {
    spawn_quic_scripted_echo_server(tls, bind_addr, mangle_response_id, Duration::ZERO, None, None)
        .0
}

/// A DoQ echo server that delays every response by `delay` and counts fully
/// received requests on `seen`: the counter lets tests wait until a query is
/// provably in flight (occupying its capacity slot) before issuing the next.
pub(super) fn spawn_quic_delayed_echo_server(
    tls: &TestTls,
    delay: Duration,
) -> (SocketAddr, tokio::sync::watch::Receiver<u64>) {
    let (seen_tx, seen_rx) = tokio::sync::watch::channel(0u64);
    let (server, _) = spawn_quic_scripted_echo_server(
        tls,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        false,
        delay,
        Some(seen_tx),
        None,
    );
    (server, seen_rx)
}

/// Like [`spawn_quic_delayed_echo_server`], but advertising a
/// bidi-stream limit of `max_bidi` to the client: a peer limiting
/// concurrency below the client's own cap exercises the client's bounded
/// capacity wait inside `open_bi`.
pub(super) fn spawn_quic_limited_echo_server(
    tls: &TestTls,
    max_bidi: u32,
    delay: Duration,
) -> (SocketAddr, tokio::sync::watch::Receiver<u64>) {
    let (seen_tx, seen_rx) = tokio::sync::watch::channel(0u64);
    let (server, _) = spawn_quic_scripted_echo_server(
        tls,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        false,
        delay,
        Some(seen_tx),
        Some(max_bidi),
    );
    (server, seen_rx)
}

fn spawn_quic_scripted_echo_server(
    tls: &TestTls,
    bind_addr: IpAddr,
    mangle_response_id: bool,
    delay: Duration,
    seen: Option<tokio::sync::watch::Sender<u64>>,
    server_max_bidi: Option<u32>,
) -> (SocketAddr, Option<tokio::sync::watch::Receiver<u64>>) {
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        tls.key_der.clone(),
    ));
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(tls.cert_der.clone())], key)
        .unwrap();
    tls_config.alpn_protocols = vec![b"doq".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap(),
    ));
    if let Some(max_bidi) = server_max_bidi {
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(max_bidi));
        server_config.transport_config(Arc::new(transport));
    }
    let endpoint = quinn::Endpoint::server(server_config, SocketAddr::new(bind_addr, 0)).unwrap();
    let local = endpoint.local_addr().unwrap();
    let seen_rx = seen.as_ref().map(|tx| tx.subscribe());
    tokio::spawn(async move {
        while let Some(connecting) = endpoint.accept().await {
            // A failed handshake must not kill the accept loop (the task
            // owns the endpoint; its death would silently break the port).
            let Ok(connection) = connecting.await else { continue };
            let mangle = mangle_response_id;
            let seen = seen.clone();
            tokio::spawn(async move {
                while let Ok((send, recv)) = connection.accept_bi().await {
                    let mangle = mangle;
                    let seen = seen.clone();
                    // One task per stream: accepting must never stall behind a
                    // slow (or aborted) stream's handling, and a write failure on
                    // one stream must not end the accept loop (whose exit drops
                    // the connection handle and implicitly closes the connection).
                    tokio::spawn(async move {
                        let (mut send, mut recv) = (send, recv);
                        let mut len = [0u8; 2];
                        if recv.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let len = u16::from_be_bytes(len) as usize;
                        let mut body = vec![0u8; len];
                        if recv.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let Ok(message) = Message::from_vec(&body) else {
                            return;
                        };
                        if let Some(seen) = &seen {
                            seen.send_modify(|count| *count += 1);
                        }
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        let mut response = message.into_response();
                        // A real server answers: the bare echo is an empty
                        // NoError, which the pool treats as a negative answer.
                        response.answers.push(Record::from_rdata(
                            Name::from_str("www.example.com.").unwrap(),
                            60,
                            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                        ));
                        if mangle {
                            response.metadata.id = 7;
                        }
                        let Ok(bytes) = response.to_vec() else { return };
                        let len = (bytes.len() as u16).to_be_bytes();
                        // A client that aborted its query resets the stream: stop
                        // serving it instead of erroring the connection.
                        if send.write_all(&len).await.is_err() {
                            return;
                        }
                        if send.write_all(&bytes).await.is_err() {
                            return;
                        }
                        let _ = send.finish();
                    });
                }
            });
        }
    });
    (local, seen_rx)
}

pub(super) fn www_query() -> Query {
    Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A)
}

pub(super) fn request_options() -> DnsRequestOptions {
    let mut options = DnsRequestOptions::default();
    options.recursion_desired = true;
    options.use_edns = true;
    options
}

pub(super) async fn assert_www_query(conn: &dyn DnsConn) {
    let message = conn.query(&www_query(), &request_options()).await.unwrap();
    assert_eq!(message.answers.len(), 1);
    assert!(
        matches!(&message.answers[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4))
    );
}

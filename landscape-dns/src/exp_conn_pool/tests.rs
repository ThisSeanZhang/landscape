use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::pool_config::UpstreamPoolConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;

use crate::exp_conn_pool::PooledDnsResolver;

type Answers = HashMap<(&'static str, RecordType), Vec<Record>>;

fn a_record(name: &str, addr: Ipv4Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::parse(name, None).unwrap(), ttl, RData::A(A(addr)))
}

fn cname_record(name: &str, target: &str, ttl: u32) -> Record {
    Record::from_rdata(
        Name::parse(name, None).unwrap(),
        ttl,
        RData::CNAME(CNAME(Name::parse(target, None).unwrap())),
    )
}

#[derive(Default)]
struct MockStats {
    tcp_connections: AtomicUsize,
    udp_queries: AtomicUsize,
    tcp_queries: AtomicUsize,
}

struct MockUpstream {
    stats: Arc<MockStats>,
    _tcp: tokio::task::JoinHandle<()>,
    _udp: tokio::task::JoinHandle<()>,
    port: u16,
}

impl MockUpstream {
    async fn spawn(answers: Answers, response_code: ResponseCode) -> Arc<Self> {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp_listener.local_addr().unwrap().port();
        let udp_socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).await.unwrap();

        let stats = Arc::new(MockStats::default());
        let tcp = tokio::spawn({
            let stats = stats.clone();
            let answers = answers.clone();
            async move {
                loop {
                    let Ok((mut stream, _)) = tcp_listener.accept().await else { break };
                    stats.tcp_connections.fetch_add(1, Ordering::SeqCst);
                    let answers = answers.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut len_buf = [0u8; 2];
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                break;
                            }
                            let len = u16::from_be_bytes(len_buf) as usize;
                            let mut msg_buf = vec![0u8; len];
                            if stream.read_exact(&mut msg_buf).await.is_err() {
                                break;
                            }
                            stats.tcp_queries.fetch_add(1, Ordering::SeqCst);
                            let response =
                                respond(&msg_buf, &answers, response_code, Truncation::Off);
                            let mut out = Vec::with_capacity(response.len() + 2);
                            out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                            out.extend_from_slice(&response);
                            if stream.write_all(&out).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        });

        let udp = tokio::spawn({
            let stats = stats.clone();
            async move {
                let mut buf = [0u8; 4096];
                loop {
                    let Ok((len, peer)) = udp_socket.recv_from(&mut buf).await else { break };
                    stats.udp_queries.fetch_add(1, Ordering::SeqCst);
                    let response = respond(&buf[..len], &answers, response_code, Truncation::Off);
                    let _ = udp_socket.send_to(&response, peer).await;
                }
            }
        });

        Arc::new(Self { stats, _tcp: tcp, _udp: udp, port })
    }

    async fn spawn_tcp_only(answers: Answers, response_code: ResponseCode) -> Arc<Self> {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp_listener.local_addr().unwrap().port();
        let stats = Arc::new(MockStats::default());

        let tcp = tokio::spawn({
            let stats = stats.clone();
            async move {
                loop {
                    let Ok((mut stream, _)) = tcp_listener.accept().await else { break };
                    stats.tcp_connections.fetch_add(1, Ordering::SeqCst);
                    let answers = answers.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut len_buf = [0u8; 2];
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                break;
                            }
                            let len = u16::from_be_bytes(len_buf) as usize;
                            let mut msg_buf = vec![0u8; len];
                            if stream.read_exact(&mut msg_buf).await.is_err() {
                                break;
                            }
                            stats.tcp_queries.fetch_add(1, Ordering::SeqCst);
                            let response =
                                respond(&msg_buf, &answers, response_code, Truncation::Off);
                            let mut out = Vec::with_capacity(response.len() + 2);
                            out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                            out.extend_from_slice(&response);
                            if stream.write_all(&out).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        });

        Arc::new(Self {
            stats,
            _tcp: tcp,
            _udp: tokio::spawn(async {}),
            port,
        })
    }
}

#[derive(Clone, Copy)]
enum Truncation {
    Off,
    On,
}

fn respond(
    wire: &[u8],
    answers: &Answers,
    response_code: ResponseCode,
    truncation: Truncation,
) -> Vec<u8> {
    let request = Message::from_vec(wire).unwrap();
    let mut response = Message::response(request.id, request.op_code);
    response.queries = request.queries.clone();
    let matched = request.queries.first().and_then(|query| {
        answers.iter().find_map(|((name, qtype), records)| {
            (Name::parse(name, None).unwrap() == *query.name() && *qtype == query.query_type())
                .then(|| records.clone())
        })
    });
    match matched {
        Some(records) if !records.is_empty() => {
            response.answers = records;
        }
        _ => {
            response.metadata.response_code = response_code;
        }
    }
    if matches!(truncation, Truncation::On) {
        response.metadata.truncation = true;
    }
    let mut out = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut out);
        response.emit(&mut encoder).unwrap();
    }
    out
}
fn upstream_config(port: u16, experimental: bool) -> DnsUpstreamConfig {
    DnsUpstreamConfig {
        mode: DnsUpstreamMode::Plaintext,
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        use_experimental_pool: Some(experimental),
        ..DnsUpstreamConfig::default()
    }
}

fn fast_config() -> UpstreamPoolConfig {
    UpstreamPoolConfig {
        round_timeout: Duration::from_millis(500),
        ..UpstreamPoolConfig::default()
    }
}

#[tokio::test]
async fn tcp_connection_is_reused_across_queries() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);
    let mock = MockUpstream::spawn_tcp_only(answers, ResponseCode::NoError).await;
    let resolver = PooledDnsResolver::new(1, 0, &upstream_config(mock.port, true)).unwrap();
    for _ in 0..3 {
        let lookup = resolver.lookup("example.com.", RecordType::A).await.unwrap();
        assert_eq!(lookup.answers().len(), 1);
    }

    assert_eq!(mock.stats.tcp_connections.load(Ordering::SeqCst), 1);
    assert_eq!(mock.stats.tcp_queries.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn concurrency_opens_second_connection_instead_of_busy() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);
    let mock = MockUpstream::spawn_tcp_only(answers, ResponseCode::NoError).await;

    let config = UpstreamPoolConfig { max_inflight_per_conn: 1, ..fast_config() };
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(mock.port, true), config).unwrap();

    let lookups =
        (0..2).map(|_| resolver.lookup("example.com.", RecordType::A)).collect::<Vec<_>>();
    let results = futures_util::future::join_all(lookups).await;
    assert!(results.iter().all(|result| result.is_ok()));

    assert_eq!(mock.stats.tcp_connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn burst_acquires_respect_connection_capacity() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);
    let mock = MockUpstream::spawn_tcp_only(answers, ResponseCode::NoError).await;

    let config = UpstreamPoolConfig {
        max_inflight_per_conn: 1,
        max_conns_per_endpoint: 4,
        round_timeout: Duration::from_secs(2),
        ..fast_config()
    };
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(mock.port, true), config).unwrap();

    // A burst far beyond capacity: dials fill the pool to exactly
    // `max_conns_per_endpoint`; the rest wait and reuse — never a fifth
    // connection, never Busy failures.
    let lookups =
        (0..32).map(|_| resolver.lookup("example.com.", RecordType::A)).collect::<Vec<_>>();
    let results = futures_util::future::join_all(lookups).await;
    assert!(results.iter().all(|result| result.is_ok()), "every burst query must succeed");

    assert_eq!(mock.stats.tcp_connections.load(Ordering::SeqCst), 4);
    assert_eq!(mock.stats.tcp_queries.load(Ordering::SeqCst), 32);
}

#[tokio::test]
async fn server_closing_connection_triggers_transparent_redial() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let stats = Arc::new(MockStats::default());
    tokio::spawn({
        let stats = stats.clone();
        async move {
            loop {
                let Ok((mut stream, _)) = tcp_listener.accept().await else { break };
                stats.tcp_connections.fetch_add(1, Ordering::SeqCst);
                let answers = answers.clone();
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut msg_buf = vec![0u8; len];
                    if stream.read_exact(&mut msg_buf).await.is_err() {
                        return;
                    }
                    let response =
                        respond(&msg_buf, &answers, ResponseCode::NoError, Truncation::Off);
                    let mut out = Vec::with_capacity(response.len() + 2);
                    out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                    out.extend_from_slice(&response);
                    let _ = stream.write_all(&out).await;
                    let _ = stream.shutdown().await;
                });
            }
        }
    });

    let resolver = PooledDnsResolver::with_config(
        1,
        0,
        &upstream_config(port, true),
        UpstreamPoolConfig::default(),
    )
    .unwrap();

    for i in 0..3 {
        let lookup = resolver.lookup("example.com.", RecordType::A).await.unwrap();
        assert_eq!(lookup.answers().len(), 1, "query {i} must succeed");
    }
    assert_eq!(stats.tcp_connections.load(Ordering::SeqCst), 3);

    let samples = resolver.srtt_snapshot();
    let tcp = samples.iter().find(|sample| !sample.endpoint.protocol.is_datagram());
    assert!(
        tcp.is_some_and(|sample| sample.observations >= 3),
        "direct + redial exchanges must all record SRTT observations: {samples:?}"
    );
    assert_ne!(
        tcp.map(|sample| sample.srtt),
        Some(Duration::from_millis(10)),
        "recorded observations must move the estimate off its seed: {samples:?}"
    );
}

#[tokio::test]
async fn idle_connections_are_reaped_on_demand() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);
    let mock = MockUpstream::spawn_tcp_only(answers, ResponseCode::NoError).await;

    let config = UpstreamPoolConfig {
        idle_ttl: Duration::from_millis(80),
        ..fast_config()
    };
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(mock.port, true), config).unwrap();

    resolver.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(resolver.live_tcp_connection_count(), 1);

    tokio::time::sleep(Duration::from_millis(250)).await;
    // Eviction runs inline on the acquire path; the live-count helper does
    // not trigger it, so reap explicitly.
    resolver.sweep_idle();
    assert_eq!(resolver.live_tcp_connection_count(), 0, "idle connection must be reaped");
}

#[tokio::test]
async fn cname_chain_is_followed_and_preserved() {
    let answers: Answers = HashMap::from([
        (
            ("www.example.com.", RecordType::A),
            vec![cname_record("www.example.com.", "example.com.", 60)],
        ),
        (
            ("example.com.", RecordType::A),
            vec![a_record("example.com.", Ipv4Addr::new(9, 9, 9, 9), 300)],
        ),
    ]);
    let mock = MockUpstream::spawn(answers, ResponseCode::NoError).await;
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(mock.port, true), fast_config())
            .unwrap();

    let lookup = resolver.lookup("www.example.com.", RecordType::A).await.unwrap();
    let types: Vec<RecordType> =
        lookup.answers().iter().map(|record| record.record_type()).collect();
    assert!(types.contains(&RecordType::A), "final A record must be present: {types:?}");
    assert!(types.contains(&RecordType::CNAME), "CNAME intermediate must be preserved: {types:?}");
}

#[tokio::test]
async fn nxdomain_surfaces_as_no_records_found() {
    let mock = MockUpstream::spawn(HashMap::new(), ResponseCode::NXDomain).await;
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(mock.port, true), fast_config())
            .unwrap();

    let err = resolver.lookup("missing.example.com.", RecordType::A).await.unwrap_err();
    match err {
        hickory_resolver::net::NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(
            no_records,
        )) => assert_eq!(no_records.response_code, ResponseCode::NXDomain),
        other => panic!("expected NoRecordsFound, got {other:?}"),
    }
}

#[tokio::test]
async fn nxdomain_over_tcp_keeps_connection() {
    let mock = MockUpstream::spawn_tcp_only(HashMap::new(), ResponseCode::NXDomain).await;
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(mock.port, true), fast_config())
            .unwrap();

    for _ in 0..2 {
        let err = resolver.lookup("missing.example.com.", RecordType::A).await.unwrap_err();
        assert!(err.is_nx_domain());
    }

    // Negative answers are server responses, not faults: the TCP connection
    // is reused, not redialed.
    assert_eq!(mock.stats.tcp_connections.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.live_tcp_connection_count(), 1);
}

#[tokio::test]
async fn truncated_udp_falls_back_to_tcp() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let udp_socket =
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).await.unwrap();

    let answers: Answers = HashMap::from([(
        ("big.example.com.", RecordType::A),
        vec![a_record("big.example.com.", Ipv4Addr::new(1, 1, 1, 1), 300)],
    )]);

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = udp_socket.recv_from(&mut buf).await {
            let response =
                respond(&buf[..len], &HashMap::new(), ResponseCode::NoError, Truncation::On);
            let _ = udp_socket.send_to(&response, peer).await;
        }
    });

    let tcp_answers = answers.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp_listener.accept().await else { break };
            let answers = tcp_answers.clone();
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut msg_buf = vec![0u8; len];
                    if stream.read_exact(&mut msg_buf).await.is_err() {
                        break;
                    }
                    let response =
                        respond(&msg_buf, &answers, ResponseCode::NoError, Truncation::Off);
                    let mut out = Vec::with_capacity(response.len() + 2);
                    out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                    out.extend_from_slice(&response);
                    if stream.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let resolver = PooledDnsResolver::with_config(
        1,
        0,
        &upstream_config(port, true),
        UpstreamPoolConfig::default(),
    )
    .unwrap();

    let lookup = resolver.lookup("big.example.com.", RecordType::A).await.unwrap();
    assert_eq!(lookup.answers().len(), 1);
}

#[tokio::test]
async fn unreachable_upstream_times_out_with_transport_error() {
    let free_port = {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        port
    };
    let resolver = PooledDnsResolver::with_config(
        1,
        0,
        &upstream_config(free_port, true),
        UpstreamPoolConfig {
            round_timeout: Duration::from_millis(200),
            attempts: 2,
            ..UpstreamPoolConfig::default()
        },
    )
    .unwrap();

    let result = resolver.lookup("example.com.", RecordType::A).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn query_timeout_keeps_connection_alive() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let stats = Arc::new(MockStats::default());
    tokio::spawn({
        let stats = stats.clone();
        async move {
            loop {
                let Ok((mut stream, _)) = tcp_listener.accept().await else { break };
                stats.tcp_connections.fetch_add(1, Ordering::SeqCst);
                let answers = answers.clone();
                let mut first = true;
                tokio::spawn(async move {
                    loop {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut msg_buf = vec![0u8; len];
                        if stream.read_exact(&mut msg_buf).await.is_err() {
                            return;
                        }
                        if first {
                            first = false;
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                        let response =
                            respond(&msg_buf, &answers, ResponseCode::NoError, Truncation::Off);
                        let mut out = Vec::with_capacity(response.len() + 2);
                        out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                        out.extend_from_slice(&response);
                        if stream.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    });

    // Timeline: query 1 is sent at t=0 and times out at t=150ms; the mock
    // answers it at t=250ms (discarded, request gone). Query 2 rides the same
    // connection and answers instantly, within its own allowance at t=300ms.
    let config = UpstreamPoolConfig {
        round_timeout: Duration::from_millis(150),
        attempts: 1,
        ..UpstreamPoolConfig::default()
    };
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(port, true), config).unwrap();

    let first = resolver.lookup("example.com.", RecordType::A).await;
    assert!(first.is_err(), "stalled query must fail");
    assert_eq!(resolver.live_tcp_connection_count(), 1, "timeout must not kill the connection");

    let second = resolver.lookup("example.com.", RecordType::A).await;
    second.expect("retry on the same connection must succeed");

    assert_eq!(stats.tcp_connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn consecutive_timeouts_retire_connection() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp_listener.accept().await else { break };
            tokio::spawn(async move {
                let mut sink = [0u8; 4096];
                while stream.read_exact(&mut sink).await.is_ok() {}
            });
        }
    });

    let config = UpstreamPoolConfig {
        round_timeout: Duration::from_millis(100),
        attempts: 1,
        max_consecutive_timeouts: 2,
        ..UpstreamPoolConfig::default()
    };
    let resolver =
        PooledDnsResolver::with_config(1, 0, &upstream_config(port, true), config).unwrap();

    let first = resolver.lookup("example.com.", RecordType::A).await;
    assert!(first.is_err());
    assert_eq!(
        resolver.live_tcp_connection_count(),
        1,
        "one timeout (below the streak threshold) keeps the connection handout-eligible"
    );

    let second = resolver.lookup("example.com.", RecordType::A).await;
    assert!(second.is_err());
    assert_eq!(
        resolver.live_tcp_connection_count(),
        0,
        "the timeout streak threshold must retire the connection from handout"
    );
}

#[tokio::test]
async fn tls_upstream_resolves_and_reuses_connection() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);

    // Explicit crypto provider: nothing installs a process-level default
    // and tests must not depend on crate features enabled elsewhere.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified = rcgen::generate_simple_self_signed(vec!["dns.example".to_string()]).unwrap();
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .unwrap(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let tls_connections = Arc::new(AtomicUsize::new(0));
    let tls_queries = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let answers = answers.clone();
        let tls_connections = tls_connections.clone();
        let tls_queries = tls_queries.clone();
        async move {
            loop {
                let Ok((stream, _)) = tcp_listener.accept().await else { break };
                let Ok(mut stream) = acceptor.accept(stream).await else { continue };
                tls_connections.fetch_add(1, Ordering::SeqCst);
                let answers = answers.clone();
                let tls_queries = tls_queries.clone();
                tokio::spawn(async move {
                    loop {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut msg_buf = vec![0u8; len];
                        if stream.read_exact(&mut msg_buf).await.is_err() {
                            break;
                        }
                        tls_queries.fetch_add(1, Ordering::SeqCst);
                        let response =
                            respond(&msg_buf, &answers, ResponseCode::NoError, Truncation::Off);
                        let mut out = Vec::with_capacity(response.len() + 2);
                        out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                        out.extend_from_slice(&response);
                        if stream.write_all(&out).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let resolver = PooledDnsResolver::with_config_and_tls(
        1,
        0,
        &DnsUpstreamConfig {
            mode: DnsUpstreamMode::Tls { domain: "dns.example".to_string() },
            ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port: Some(port),
            use_experimental_pool: Some(true),
            ..DnsUpstreamConfig::default()
        },
        fast_config(),
        hickory_resolver::TlsConfig { config: client_config },
    )
    .unwrap();

    for _ in 0..2 {
        let lookup = resolver.lookup("example.com.", RecordType::A).await.unwrap();
        assert_eq!(lookup.answers().len(), 1);
    }

    assert_eq!(tls_connections.load(Ordering::SeqCst), 1, "both lookups reuse one DoT connection");
    assert_eq!(tls_queries.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn quic_upstream_resolves_and_reuses_connection() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);

    // Explicit crypto provider: nothing installs a process-level default
    // and tests must not depend on crate features enabled elsewhere.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified = rcgen::generate_simple_self_signed(vec!["dns.example".to_string()]).unwrap();
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .unwrap(),
        )
        .unwrap();
    // RFC 9250 §4.1: DoQ is identified by the "doq" ALPN.
    server_tls.alpn_protocols = vec![b"doq".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
    ));

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let port = endpoint.local_addr().unwrap().port();

    let quic_connections = Arc::new(AtomicUsize::new(0));
    let quic_queries = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let answers = answers.clone();
        let quic_connections = quic_connections.clone();
        let quic_queries = quic_queries.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                quic_connections.fetch_add(1, Ordering::SeqCst);
                let answers = answers.clone();
                let quic_queries = quic_queries.clone();
                tokio::spawn(async move {
                    loop {
                        // One bidirectional stream per query (RFC 9250 §4.2).
                        let Ok((mut send, mut recv)) = conn.accept_bi().await else { break };
                        let answers = answers.clone();
                        let quic_queries = quic_queries.clone();
                        tokio::spawn(async move {
                            let mut len_buf = [0u8; 2];
                            if recv.read_exact(&mut len_buf).await.is_err() {
                                return;
                            }
                            let len = u16::from_be_bytes(len_buf) as usize;
                            let mut msg_buf = vec![0u8; len];
                            if recv.read_exact(&mut msg_buf).await.is_err() {
                                return;
                            }
                            quic_queries.fetch_add(1, Ordering::SeqCst);
                            let response =
                                respond(&msg_buf, &answers, ResponseCode::NoError, Truncation::Off);
                            let mut out = Vec::with_capacity(response.len() + 2);
                            out.extend_from_slice(&(response.len() as u16).to_be_bytes());
                            out.extend_from_slice(&response);
                            if send.write_all(&out).await.is_err() {
                                return;
                            }
                            // FIN after the last response (RFC 9250 §4.2).
                            let _ = send.finish();
                        });
                    }
                });
            }
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let resolver = PooledDnsResolver::with_config_and_tls(
        1,
        0,
        &DnsUpstreamConfig {
            mode: DnsUpstreamMode::Quic { domain: "dns.example".to_string() },
            ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port: Some(port),
            use_experimental_pool: Some(true),
            ..DnsUpstreamConfig::default()
        },
        fast_config(),
        hickory_resolver::TlsConfig { config: client_config },
    )
    .unwrap();

    for _ in 0..2 {
        let lookup = resolver.lookup("example.com.", RecordType::A).await.unwrap();
        assert_eq!(lookup.answers().len(), 1);
    }

    // Both lookups ride one persistent QUIC connection; each query takes
    // its own stream.
    assert_eq!(quic_connections.load(Ordering::SeqCst), 1, "both lookups reuse one DoQ connection");
    assert_eq!(quic_queries.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn https_upstream_resolves_and_reuses_connection() {
    let answers: Answers = HashMap::from([(
        ("example.com.", RecordType::A),
        vec![a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
    )]);

    // Explicit crypto provider: nothing installs a process-level default
    // and tests must not depend on crate features enabled elsewhere.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified = rcgen::generate_simple_self_signed(vec!["dns.example".to_string()]).unwrap();
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .unwrap(),
        )
        .unwrap();
    // HTTP/2 DoH is negotiated with the "h2" ALPN.
    server_tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let https_connections = Arc::new(AtomicUsize::new(0));
    let https_queries = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let answers = answers.clone();
        let https_connections = https_connections.clone();
        let https_queries = https_queries.clone();
        async move {
            loop {
                let Ok((stream, _)) = tcp_listener.accept().await else { break };
                let Ok(tls) = acceptor.accept(stream).await else { continue };
                let Ok(mut connection) =
                    h2::server::Builder::new().handshake::<_, bytes::Bytes>(tls).await
                else {
                    continue;
                };
                https_connections.fetch_add(1, Ordering::SeqCst);
                let answers = answers.clone();
                let https_queries = https_queries.clone();
                tokio::spawn(async move {
                    while let Some(request) = futures_util::StreamExt::next(&mut connection).await {
                        let Ok((request, mut responder)) = request else { break };
                        let answers = answers.clone();
                        let https_queries = https_queries.clone();
                        tokio::spawn(async move {
                            let (_parts, mut body) = request.into_parts();
                            let mut msg_buf = Vec::new();
                            while let Some(Ok(chunk)) =
                                futures_util::StreamExt::next(&mut body).await
                            {
                                msg_buf.extend_from_slice(&chunk);
                            }
                            https_queries.fetch_add(1, Ordering::SeqCst);
                            let response =
                                respond(&msg_buf, &answers, ResponseCode::NoError, Truncation::Off);
                            let http_response = http::Response::builder()
                                .status(200)
                                .header(http::header::CONTENT_TYPE, "application/dns-message")
                                .header(http::header::CONTENT_LENGTH, response.len())
                                .body(())
                                .unwrap();
                            let mut send = responder.send_response(http_response, false).unwrap();
                            send.send_data(bytes::Bytes::from(response), true).unwrap();
                        });
                    }
                });
            }
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let resolver = PooledDnsResolver::with_config_and_tls(
        1,
        0,
        &DnsUpstreamConfig {
            mode: DnsUpstreamMode::Https {
                domain: "dns.example".to_string(),
                http_endpoint: None,
            },
            ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port: Some(port),
            use_experimental_pool: Some(true),
            ..DnsUpstreamConfig::default()
        },
        fast_config(),
        hickory_resolver::TlsConfig { config: client_config },
    )
    .unwrap();

    for _ in 0..2 {
        let lookup = resolver.lookup("example.com.", RecordType::A).await.unwrap();
        assert_eq!(lookup.answers().len(), 1);
    }

    // Both lookups ride one persistent HTTP/2 connection; each query takes
    // its own POST exchange.
    assert_eq!(
        https_connections.load(Ordering::SeqCst),
        1,
        "both lookups reuse one DoH connection"
    );
    assert_eq!(https_queries.load(Ordering::SeqCst), 2);
}

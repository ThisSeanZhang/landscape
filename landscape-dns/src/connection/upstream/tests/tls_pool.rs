//! Pool-level encrypted-transport tests: DoT / DoH / DoQ end-to-end against
//! a local hickory-server, plus warm-up, certificate rejection, and
//! source-address binding.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use hickory_server::proto::rr::RecordType;
use landscape_common::dns::bind::DnsBindConfig;
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;

use super::UpstreamError;
use super::UpstreamPool;
use super::pool_config::PoolSettings;
use super::tls_support::*;
use crate::connection::provider::MarkRuntimeProvider;

#[tokio::test]
async fn dot_lookup_answers_from_local_server() {
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Tls, &tls).await;
    let pool = tls_pool(port, DnsUpstreamMode::Tls { domain: "ns.example.com".into() }, &tls).await;
    assert_www_answer(&pool).await;
}

#[tokio::test]
async fn doh_lookup_answers_from_local_server() {
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Https, &tls).await;
    let pool = tls_pool(
        port,
        DnsUpstreamMode::Https {
            domain: "ns.example.com".into(),
            http_endpoint: Some("/dns-query".into()),
        },
        &tls,
    )
    .await;
    assert_www_answer(&pool).await;
}

#[tokio::test]
async fn doq_lookup_answers_from_local_server() {
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Quic, &tls).await;
    let pool =
        tls_pool(port, DnsUpstreamMode::Quic { domain: "ns.example.com".into() }, &tls).await;
    assert_www_answer(&pool).await;
}

#[tokio::test]
async fn encrypted_upstream_warms_up_connection_at_build() {
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Tls, &tls).await;
    let upstream = DnsUpstreamConfig {
        remark: "test".into(),
        mode: DnsUpstreamMode::Tls { domain: "ns.example.com".into() },
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        ..Default::default()
    };
    let provider = MarkRuntimeProvider::new(0x8000, DnsBindConfig::default());
    let pool = UpstreamPool::new(
        7,
        0x8000,
        &upstream,
        provider,
        &PoolSettings::default(),
        Some(tls.client_config.clone()),
    )
    .unwrap();

    // The warm-up runs on a background task; wait for the TLS handshake to
    // land before asserting a pooled connection exists.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while pool.conn_count() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(pool.conn_count(), 1);
    assert_www_answer(&pool).await;
    // The warm connection served the query; no extra dial happened.
    assert_eq!(pool.conn_count(), 1);
}

#[tokio::test]
async fn untrusted_certificate_rejected_fast_without_pooling() {
    // Production passes `None`, so the verifier trusts only the system/webpki
    // roots — the server's self-signed cert must be rejected with a clean
    // transport-level error: no hang, no panic, no connection pooled.
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Tls, &tls).await;
    let upstream = DnsUpstreamConfig {
        remark: "test".into(),
        mode: DnsUpstreamMode::Tls { domain: "ns.example.com".into() },
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        ..Default::default()
    };
    let provider = MarkRuntimeProvider::new(0x8000, DnsBindConfig::default());
    let pool =
        UpstreamPool::new(7, 0x8000, &upstream, provider, &PoolSettings::default(), None).unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        pool.lookup("www.example.com.", RecordType::A),
    )
    .await
    .expect("an untrusted certificate must fail fast, not hang");
    let err = result.unwrap_err();
    // The handshake failure surfaces as the permanent TLS class (not a
    // bogus protocol answer, and not a budget-exhaustion Timeout).
    assert!(matches!(err, UpstreamError::Tls(_)), "got {err:?}");
    // The failed handshake never produced a poolable connection.
    assert_eq!(pool.conn_count(), 0);
}

#[tokio::test]
async fn doq_honours_bind_config_source_address() {
    // The QUIC socket must be bound to the configured source address
    // (127.0.0.1) instead of an unspecified one; the lookup still works.
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Quic, &tls).await;
    let upstream = DnsUpstreamConfig {
        remark: "test".into(),
        mode: DnsUpstreamMode::Quic { domain: "ns.example.com".into() },
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        bind_config: DnsBindConfig {
            bind_addr4: Some(Ipv4Addr::LOCALHOST),
            bind_addr6: None,
        },
        ..Default::default()
    };
    let provider = MarkRuntimeProvider::new(0x8000, upstream.bind_config.clone());
    let pool = UpstreamPool::new(
        7,
        0x8000,
        &upstream,
        provider,
        &PoolSettings::default(),
        Some(tls.client_config.clone()),
    )
    .unwrap();
    assert_www_answer(&pool).await;
}

#[tokio::test]
async fn doq_unassignable_bind_source_fails_fast() {
    // 192.0.2.1 (TEST-NET-1) is not assigned to any local interface: the
    // QUIC socket bind() fails locally, so the lookup must fail fast with a
    // transport-level error instead of hanging or answering.
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Quic, &tls).await;
    let upstream = DnsUpstreamConfig {
        remark: "test".into(),
        mode: DnsUpstreamMode::Quic { domain: "ns.example.com".into() },
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        bind_config: DnsBindConfig {
            bind_addr4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            bind_addr6: None,
        },
        ..Default::default()
    };
    let provider = MarkRuntimeProvider::new(0x8000, upstream.bind_config.clone());
    let pool = UpstreamPool::new(
        7,
        0x8000,
        &upstream,
        provider,
        &PoolSettings::default(),
        Some(tls.client_config.clone()),
    )
    .unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        pool.lookup("www.example.com.", RecordType::A),
    )
    .await
    .expect("an unassignable source address must fail fast, not hang");
    let err = result.unwrap_err();
    // The local bind failure surfaces as an internal transport error (not
    // a bogus protocol answer, and not a budget-exhaustion Timeout).
    assert!(matches!(err, UpstreamError::Internal(_)), "got {err:?}");
    // The failed socket never produced a poolable connection.
    assert_eq!(pool.conn_count(), 0);
}

/// A DoH upstream whose TLS handshake completes but which never speaks h2:
/// the h2 driver resolves stream opens optimistically (no peer SETTINGS is
/// not a ready() blocker), so every query burns its full `query_timeout`
/// waiting for a response. That timeout is *health-counted* — crucially not
/// the capacity class — so the wedged connection accumulates the two stream
/// failures it needs to be retired, and the pool recovers by dialling
/// fresh instead of fast-failing every query forever.
#[tokio::test]
async fn doh_connection_with_wedged_h2_peer_is_retired_and_redialled() {
    let tls = test_tls();
    let (port, accepts) = spawn_doh_silent_server(&tls).await;
    let upstream = DnsUpstreamConfig {
        remark: "test".into(),
        mode: DnsUpstreamMode::Https {
            domain: "ns.example.com".into(),
            http_endpoint: Some("/dns-query".into()),
        },
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        ..Default::default()
    };
    let settings = PoolSettings { attempts: Some(1), ..PoolSettings::default() };
    let pool = UpstreamPool::new(
        7,
        0x8000,
        &upstream,
        MarkRuntimeProvider::new(0x8000, DnsBindConfig::default()),
        &settings,
        Some(tls.client_config.clone()),
    )
    .unwrap();

    // Two lookups against the wedged connection: health-counted timeouts
    // (never `NoConnections`, which would strand the pool permanently),
    // the second of which crosses the stream retirement threshold.
    for _ in 0..2 {
        let err = pool.lookup("www.example.com.", RecordType::A).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Timeout), "got {err:?}");
    }

    // The third lookup dials fresh: the retired connection is gone and the
    // wedged peer accepts a new TLS connection.
    let _ = pool.lookup("www.example.com.", RecordType::A).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while accepts.load(std::sync::atomic::Ordering::Relaxed) < 2
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        accepts.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "the wedged connection must be retired and redialled"
    );
    assert_eq!(pool.conn_count(), 1, "the fresh connection is pooled");
}

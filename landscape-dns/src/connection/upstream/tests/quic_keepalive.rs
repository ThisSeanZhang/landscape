//! DoQ keep-alive / idle-timeout behaviour and stream multiplexing, against
//! a local hickory-server.

use std::net::Ipv4Addr;
use std::time::Duration;

use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::{RData, RecordType};
use landscape_common::dns::upstream::DnsUpstreamMode;

use super::tls_support::*;
use super::traits::DnsConnError;

/// With keep-alives on, a DoQ connection survives an idle period longer than
/// the negotiated idle timeout (min(client 3s, server quinn-default 30s) =
/// 3s): the same connection still answers afterwards.
#[tokio::test]
async fn doq_keep_alive_keeps_connection_alive() {
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Quic, &tls).await;
    let connector = quic_connector(port, &tls, Duration::from_secs(3), true);

    let conn = connector.connect().await.unwrap();
    assert_www_query(conn.as_ref()).await;
    // Keep-alives fire every 1s (idle_timeout/3, floored at 1s), far below
    // the 3s idle timeout: the connection must not die while idle.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_www_query(conn.as_ref()).await;
}

/// Without keep-alives the connection dies on its negotiated idle timeout;
/// the next query on it fails at the transport level instead of answering.
#[tokio::test]
async fn doq_without_keep_alive_dies_on_idle_timeout() {
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Quic, &tls).await;
    let connector = quic_connector(port, &tls, Duration::from_secs(3), false);

    let conn = connector.connect().await.unwrap();
    assert_www_query(conn.as_ref()).await;
    // 5s idle vs a 3s negotiated idle timeout: the connection idles out and
    // the next query fails (quinn reports the idle timeout at the transport
    // level) instead of answering.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let result =
        tokio::time::timeout(Duration::from_secs(5), conn.query(&www_query(), &request_options()))
            .await
            .expect("a query on an idled-out connection must fail, not hang");
    match result {
        Err(DnsConnError::Timeout | DnsConnError::Io(_)) => {}
        Ok(_) => panic!("expected the idled-out connection to fail, got an answer"),
        Err(other) => panic!("expected a transport-level error, got {other:?}"),
    }
}

/// Concurrent lookups multiplex on the single pooled DoQ connection: quinn
/// opens one bidi stream per query, so a burst of client lookups must ride
/// one connection (streams 0, 4, 8, ...) instead of serializing or dialing
/// more.
#[tokio::test]
async fn doq_connection_multiplexes_concurrent_lookups() {
    let tls = test_tls();
    let (port, _server) = spawn_tls_server(TlsProtocol::Quic, &tls).await;
    let pool =
        tls_pool(port, DnsUpstreamMode::Quic { domain: "ns.example.com".into() }, &tls).await;
    // Wait for the build-time warm-up to pool its connection deterministically
    // (a burst of concurrent cold lookups would legitimately race fresh
    // dials, which is pool behaviour, not what this test asserts).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while pool.conn_count() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(pool.conn_count(), 1);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(
            async move { pool.lookup("www.example.com.", RecordType::A).await },
        ));
    }
    for handle in handles {
        let records = handle.await.unwrap().unwrap();
        assert_eq!(records.len(), 1);
        assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
    }
    // Every query rode the one warm connection.
    assert_eq!(pool.conn_count(), 1);
}

//! P0 regression: DoH and DoQ must surface saturation as the capacity class
//! (`NoConnections`) — exactly like the TCP/DoT multiplexer — instead of
//! queueing silently inside `h2.ready()` / `open_bi()` until the query
//! timeout, which the pool would misread as a connectivity failure and
//! count towards the upstream's offline flip.

use std::time::Duration;

use super::tls_support::*;
use super::traits::DnsConnError;
use crate::connection::upstream::{PoolConfig, UpstreamPool};
use hickory_proto::rr::RecordType;
use landscape_common::dns::upstream::DnsUpstreamMode;

/// With a one-slot cap and a slow peer, the second concurrent DoQ query
/// fails fast with the capacity class while the first is still in flight;
/// the first still completes once the delayed response arrives.
#[tokio::test]
async fn doq_saturation_surfaces_capacity_class() {
    let tls = test_tls();
    let (server, mut seen) = spawn_quic_delayed_echo_server(&tls, Duration::from_millis(500));
    let connector = connector_with_cap(
        DnsUpstreamMode::Quic { domain: "ns.example.com".into() },
        server.port(),
        &tls,
        1,
    );
    let conn = connector.connect().await.unwrap();

    let first = {
        let conn = conn.clone();
        let query = www_query();
        let options = request_options();
        tokio::spawn(async move { conn.query(&query, &options).await })
    };
    // Wait until the first query is provably on the wire (its capacity
    // slot is held), so the second query is guaranteed to hit the cap.
    seen.changed().await.unwrap();
    seen.borrow_and_update();

    let err = conn.query(&www_query(), &request_options()).await.unwrap_err();
    assert!(matches!(err, DnsConnError::NoConnections), "expected NoConnections, got {err:?}");

    // The slot frees when the first response lands: the first query
    // succeeded, and a follow-up query rides the connection again.
    assert!(first.await.unwrap().is_ok());
    let message = conn.query(&www_query(), &request_options()).await.unwrap();
    assert_eq!(message.answers.len(), 1);
}

/// Same contract over DoH: a one-slot h2 connection surfaces the second
/// concurrent query as the capacity class instead of queuing it.
#[tokio::test]
async fn doh_saturation_surfaces_capacity_class() {
    let tls = test_tls();
    let (port, mut seen) = spawn_doh_echo_server(&tls, Duration::from_millis(500)).await;
    let connector = connector_with_cap(
        DnsUpstreamMode::Https {
            domain: "ns.example.com".into(),
            http_endpoint: None,
        },
        port,
        &tls,
        1,
    );
    let conn = connector.connect().await.unwrap();

    let first = {
        let conn = conn.clone();
        let query = www_query();
        let options = request_options();
        tokio::spawn(async move { conn.query(&query, &options).await })
    };
    seen.changed().await.unwrap();
    seen.borrow_and_update();

    let err = conn.query(&www_query(), &request_options()).await.unwrap_err();
    assert!(matches!(err, DnsConnError::NoConnections), "expected NoConnections, got {err:?}");

    assert!(first.await.unwrap().is_ok());
    let message = conn.query(&www_query(), &request_options()).await.unwrap();
    assert_eq!(message.answers.len(), 1);
}

/// A caller that gives up on a DoQ query (dropped future) releases its
/// capacity slot immediately: the next query proceeds instead of
/// fast-failing with the capacity error.
#[tokio::test]
async fn doq_dropped_query_releases_capacity_slot() {
    let tls = test_tls();
    let (server, mut seen) = spawn_quic_delayed_echo_server(&tls, Duration::from_millis(500));
    let connector = connector_with_cap(
        DnsUpstreamMode::Quic { domain: "ns.example.com".into() },
        server.port(),
        &tls,
        1,
    );
    let conn = connector.connect().await.unwrap();

    let dropped = {
        let conn = conn.clone();
        let query = www_query();
        let options = request_options();
        tokio::spawn(async move { conn.query(&query, &options).await })
    };
    seen.changed().await.unwrap();
    seen.borrow_and_update();
    dropped.abort();
    // Awaiting the aborted task guarantees its future (and the capacity
    // permit it holds) is dropped before the next query runs.
    let _ = dropped.await;

    // The slot freed on drop: this query rides the connection (the
    // capacity path would have failed it instantly).
    let message = conn.query(&www_query(), &request_options()).await.unwrap();
    assert_eq!(message.answers.len(), 1);
}

/// Same cancellation contract over DoH.
#[tokio::test]
async fn doh_dropped_query_releases_capacity_slot() {
    let tls = test_tls();
    let (port, mut seen) = spawn_doh_echo_server(&tls, Duration::from_millis(500)).await;
    let connector = connector_with_cap(
        DnsUpstreamMode::Https {
            domain: "ns.example.com".into(),
            http_endpoint: None,
        },
        port,
        &tls,
        1,
    );
    let conn = connector.connect().await.unwrap();

    let dropped = {
        let conn = conn.clone();
        let query = www_query();
        let options = request_options();
        tokio::spawn(async move { conn.query(&query, &options).await })
    };
    seen.changed().await.unwrap();
    seen.borrow_and_update();
    dropped.abort();
    let _ = dropped.await;

    let message = conn.query(&www_query(), &request_options()).await.unwrap();
    assert_eq!(message.answers.len(), 1);
}

/// A burst larger than the per-connection cap: exactly `cap` queries ride
/// the connection (and complete), the overflow fails fast with the
/// capacity class, and nothing degrades into a spurious timeout.
#[tokio::test]
async fn doq_burst_beyond_cap_splits_into_answers_and_capacity_errors() {
    let tls = test_tls();
    let (server, mut seen) = spawn_quic_delayed_echo_server(&tls, Duration::from_millis(500));
    const CAP: usize = 32;
    const BURST: usize = CAP + 8;
    let connector = connector_with_cap(
        DnsUpstreamMode::Quic { domain: "ns.example.com".into() },
        server.port(),
        &tls,
        CAP,
    );
    let conn = connector.connect().await.unwrap();

    let tasks: Vec<_> = (0..BURST)
        .map(|_| {
            let conn = conn.clone();
            let query = www_query();
            let options = request_options();
            tokio::spawn(async move { conn.query(&query, &options).await })
        })
        .collect();
    // Wait until every slot is provably occupied on the wire.
    loop {
        if *seen.borrow_and_update() >= CAP as u64 {
            break;
        }
        seen.changed().await.unwrap();
    }

    let mut answered = 0;
    let mut capacity = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(message) => {
                assert_eq!(message.answers.len(), 1);
                answered += 1;
            }
            Err(DnsConnError::NoConnections) => capacity += 1,
            Err(other) => panic!("burst must fail fast with the capacity class, got {other:?}"),
        }
    }
    assert_eq!(answered, CAP, "exactly the cap rides the connection");
    assert_eq!(capacity, BURST - CAP, "the overflow hits the cap");
}

/// A peer advertising a bidi-stream limit below the client-side cap is the
/// residual saturation path (our semaphore cannot see it): the query
/// parked inside `open_bi` must surface the capacity class after the
/// bounded wait instead of aging into a health-counted Timeout once the
/// slow first stream finally completes.
#[tokio::test]
async fn doq_peer_stream_limit_surfaces_capacity_class() {
    let tls = test_tls();
    let (server, mut seen) = spawn_quic_limited_echo_server(&tls, 1, Duration::from_secs(2));
    let connector = connector_with_cap(
        DnsUpstreamMode::Quic { domain: "ns.example.com".into() },
        server.port(),
        &tls,
        32,
    );
    let conn = connector.connect().await.unwrap();

    let first = {
        let conn = conn.clone();
        let query = www_query();
        let options = request_options();
        tokio::spawn(async move { conn.query(&query, &options).await })
    };
    // The first query provably occupies the only peer stream slot.
    seen.changed().await.unwrap();
    seen.borrow_and_update();

    let err = conn.query(&www_query(), &request_options()).await.unwrap_err();
    assert!(matches!(err, DnsConnError::NoConnections), "expected NoConnections, got {err:?}");

    first.abort();
    let _ = first.await;
}

/// Same residual over DoH: a server advertising
/// `SETTINGS_MAX_CONCURRENT_STREAMS` below the client cap parks the excess
/// caller inside `h2.ready()`; the bounded wait surfaces the capacity
/// class instead of a Timeout.
#[tokio::test]
async fn doh_peer_stream_limit_surfaces_capacity_class() {
    let tls = test_tls();
    let (port, mut seen) = spawn_doh_limited_echo_server(&tls, 1, Duration::from_secs(2)).await;
    let connector = connector_with_cap(
        DnsUpstreamMode::Https {
            domain: "ns.example.com".into(),
            http_endpoint: None,
        },
        port,
        &tls,
        32,
    );
    let conn = connector.connect().await.unwrap();

    let first = {
        let conn = conn.clone();
        let query = www_query();
        let options = request_options();
        tokio::spawn(async move { conn.query(&query, &options).await })
    };
    seen.changed().await.unwrap();
    seen.borrow_and_update();

    let err = conn.query(&www_query(), &request_options()).await.unwrap_err();
    assert!(matches!(err, DnsConnError::NoConnections), "expected NoConnections, got {err:?}");

    first.abort();
    let _ = first.await;
}

/// The DoH burst analogue of
/// [`doq_burst_beyond_cap_splits_into_answers_and_capacity_errors`]: the
/// cap rides and completes, the overflow fails fast with the capacity
/// class.
#[tokio::test]
async fn doh_burst_beyond_cap_splits_into_answers_and_capacity_errors() {
    let tls = test_tls();
    let (port, mut seen) = spawn_doh_echo_server(&tls, Duration::from_millis(500)).await;
    const CAP: usize = 32;
    const BURST: usize = CAP + 8;
    let connector = connector_with_cap(
        DnsUpstreamMode::Https {
            domain: "ns.example.com".into(),
            http_endpoint: None,
        },
        port,
        &tls,
        CAP,
    );
    let conn = connector.connect().await.unwrap();

    let tasks: Vec<_> = (0..BURST)
        .map(|_| {
            let conn = conn.clone();
            let query = www_query();
            let options = request_options();
            tokio::spawn(async move { conn.query(&query, &options).await })
        })
        .collect();
    loop {
        if *seen.borrow_and_update() >= CAP as u64 {
            break;
        }
        seen.changed().await.unwrap();
    }

    let mut answered = 0;
    let mut capacity = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(message) => {
                assert_eq!(message.answers.len(), 1);
                answered += 1;
            }
            Err(DnsConnError::NoConnections) => capacity += 1,
            Err(other) => panic!("burst must fail fast with the capacity class, got {other:?}"),
        }
    }
    assert_eq!(answered, CAP, "exactly the cap rides the connection");
    assert_eq!(capacity, BURST - CAP, "the overflow hits the cap");
}

/// The steady-state counterpart of
/// [`doh_peer_stream_limit_surfaces_capacity_class`]: once the server's
/// SETTINGS are applied, h2-0.4.x parks excess streams *client-side* — no
/// REFUSED_STREAM, and a per-query handle clone's `ready()` is always
/// Ready — so the pre-send in-flight check is the only remaining capacity
/// signal. The connection is settled first (past the pre-SETTINGS window)
/// so the test cannot pass by winning that race.
#[tokio::test]
async fn doh_steady_state_peer_limit_surfaces_capacity_class() {
    let tls = test_tls();
    let (port, mut seen) = spawn_doh_limited_echo_server(&tls, 1, Duration::from_secs(2)).await;
    let connector = connector_with_cap(
        DnsUpstreamMode::Https {
            domain: "ns.example.com".into(),
            http_endpoint: None,
        },
        port,
        &tls,
        32,
    );
    let conn = connector.connect().await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let first = {
        let conn = conn.clone();
        let query = www_query();
        let options = request_options();
        tokio::spawn(async move { conn.query(&query, &options).await })
    };
    // The first query provably occupies the only stream the peer allows.
    seen.changed().await.unwrap();
    seen.borrow_and_update();

    let started = std::time::Instant::now();
    let err = conn.query(&www_query(), &request_options()).await.unwrap_err();
    assert!(matches!(err, DnsConnError::NoConnections), "expected NoConnections, got {err:?}");
    // The pre-send check refuses immediately; a parked stream would only
    // surface as a Timeout after the full query budget.
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "capacity must fail fast, took {:?}",
        started.elapsed()
    );

    first.abort();
    let _ = first.await;
}

/// End-to-end dial-around: the pool (not a bare connection) answers a
/// capacity error by dialing a second connection to the same peer instead
/// of failing the query — the whole point of the capacity class.
#[tokio::test]
async fn doq_capacity_error_dials_second_pool_connection() {
    let tls = test_tls();
    let (server, mut seen) = spawn_quic_limited_echo_server(&tls, 1, Duration::from_millis(500));
    let mode = DnsUpstreamMode::Quic { domain: "ns.example.com".into() };
    let connector = connector_with_cap(mode.clone(), server.port(), &tls, 32);
    let pool = UpstreamPool::with_connectors(vec![connector], PoolConfig::for_mode(&mode));

    let first = {
        let pool = pool.clone();
        tokio::spawn(async move { pool.lookup("www.example.com.", RecordType::A).await })
    };
    // The first lookup provably occupies the peer's only bidi stream.
    seen.changed().await.unwrap();
    seen.borrow_and_update();

    // The second lookup hits the capacity class on conn 1, the pool dials
    // around it, and the query still answers within its budget.
    let second = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(second.len(), 1);
    assert!(first.await.unwrap().is_ok());
    assert!(
        pool.conn_count() >= 2,
        "pool must have dialed around, conn_count={}",
        pool.conn_count()
    );
}

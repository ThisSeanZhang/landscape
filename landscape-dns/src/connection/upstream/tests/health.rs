//! Upstream health tests: the offline flip, fast-fail while offline, and
//! revival through the probe loop (positive and protocol answers). The
//! probe loop is detached from client queries, so queries themselves never
//! probe — they only fast-fail or (when online) reset the failure streak.

use super::*;

#[tokio::test]
async fn offline_upstream_fast_fails_until_revival_probe_succeeds() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    // Three consecutive failed lookups (3 attempts each) flip the
    // upstream offline.
    for _ in 0..3 {
        connector.push(Err(DnsConnError::Timeout));
        let _ = pool.lookup("example.com.", RecordType::A).await;
    }
    assert!(pool.health.offline.load(Ordering::Relaxed));

    // While offline every query fast-fails with the explicit Offline error
    // (distinct from the capacity-bound NoConnections) without touching
    // any connection — probing is the revival loop's job, so a dropped
    // client query can never strand the health state.
    connector.push(Ok(ok_answer()));
    let before = connector.queries();
    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Offline));
    assert_eq!(connector.queries(), before, "offline queries must not reach the upstream");

    // The revival probe succeeds and the upstream revives. The probe
    // consumed the pushed outcome, so the next lookup needs its own.
    pool.revival_probe().await;
    assert!(!pool.health.offline.load(Ordering::Relaxed));
    connector.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn offline_upstream_fast_fails_every_concurrent_query() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    for _ in 0..3 {
        connector.push(Err(DnsConnError::Timeout));
        let _ = pool.lookup("example.com.", RecordType::A).await;
    }
    assert!(pool.health.offline.load(Ordering::Relaxed));

    // Every concurrent query fast-fails without piling onto the dead
    // upstream: not a single *client* query is touched while offline.
    // (The revival loop spawned at flip time probes once in the
    // background; that query is its own, bounded at one.)
    let before = connector.queries();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let pool = pool.clone();
            tokio::spawn(async move { pool.lookup("example.com.", RecordType::A).await })
        })
        .collect();
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(matches!(result, Err(UpstreamError::Offline)), "got {result:?}");
    }
    assert!(
        connector.queries() <= before + 1,
        "only the revival loop's own probe may reach the upstream"
    );
}

#[tokio::test]
async fn revival_probe_with_protocol_answer_revives_offline_upstream() {
    // The revival criterion matches client lookups: an explicit protocol
    // answer (NXDomain) proves the upstream is alive, so the probe revives
    // it even without a positive response.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    for _ in 0..3 {
        connector.push(Err(DnsConnError::Timeout));
        let _ = pool.lookup("example.com.", RecordType::A).await;
    }
    assert!(pool.health.offline.load(Ordering::Relaxed));

    connector.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    pool.revival_probe().await;
    assert!(!pool.health.offline.load(Ordering::Relaxed));

    // Subsequent lookups go through normally.
    connector.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn failed_revival_probe_keeps_upstream_offline() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    for _ in 0..3 {
        connector.push(Err(DnsConnError::Timeout));
        let _ = pool.lookup("example.com.", RecordType::A).await;
    }
    assert!(pool.health.offline.load(Ordering::Relaxed));

    // A failed probe consumes its outcome and must not change the offline
    // state; the loop simply re-probes after the interval.
    for _ in 0..3 {
        connector.push(Err(DnsConnError::Timeout));
    }
    pool.revival_probe().await;
    assert!(pool.health.offline.load(Ordering::Relaxed));

    // Lookups still fast-fail, so the dead upstream is not hammered.
    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Offline));
}

#[tokio::test(start_paused = true)]
async fn revival_probe_loop_probes_on_interval_until_revival() {
    // The spawned loop probes immediately at flip time and then once per
    // interval, exiting on its own once the upstream answers. Time starts
    // paused so the interval pacing is deterministic.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 1);

    pool.health.offline.store(true, Ordering::Relaxed);
    connector.push(Err(DnsConnError::Timeout));
    pool.spawn_revival_probes();

    // The first probe runs immediately and fails: still offline.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert!(pool.health.offline.load(Ordering::Relaxed));
    assert_eq!(connector.queries(), 1, "the loop probes immediately at flip time");

    // The next probe fires after the interval and revives.
    connector.push(Ok(ok_answer()));
    tokio::time::advance(pool.config.probe_interval).await;
    for _ in 0..200 {
        if !pool.health.offline.load(Ordering::Relaxed) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!pool.health.offline.load(Ordering::Relaxed), "the loop must revive the upstream");
    assert_eq!(connector.queries(), 2);
}

#[tokio::test]
async fn partial_failure_sequence_never_flips_offline() {
    // A success between failures resets the failure streak: only
    // consecutive failures count towards the offline flip.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 1);

    connector.push(Err(DnsConnError::Timeout));
    assert!(pool.lookup("example.com.", RecordType::A).await.is_err());
    connector.push(Err(DnsConnError::Timeout));
    assert!(pool.lookup("example.com.", RecordType::A).await.is_err());
    assert!(!pool.health.offline.load(Ordering::Relaxed));

    // The success resets the streak: two more failures cannot flip the
    // upstream (they only reach a streak of two).
    connector.push(Ok(ok_answer()));
    assert!(pool.lookup("example.com.", RecordType::A).await.is_ok());
    connector.push(Err(DnsConnError::Timeout));
    assert!(pool.lookup("example.com.", RecordType::A).await.is_err());
    connector.push(Err(DnsConnError::Timeout));
    assert!(pool.lookup("example.com.", RecordType::A).await.is_err());
    assert!(!pool.health.offline.load(Ordering::Relaxed));

    // A third consecutive failure completes the streak of three.
    connector.push(Err(DnsConnError::Timeout));
    assert!(pool.lookup("example.com.", RecordType::A).await.is_err());
    assert!(pool.health.offline.load(Ordering::Relaxed));
}

#[tokio::test]
async fn dial_failures_count_towards_offline_flip() {
    // Dial (I/O) failures surface as Internal errors and count as
    // connectivity failures: three consecutive ones flip the upstream
    // offline, not just query timeouts.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 1);

    connector.fail_next_dial(3);
    for _ in 0..3 {
        let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Internal(_)));
    }
    assert!(pool.health.offline.load(Ordering::Relaxed));
}

#[tokio::test]
async fn no_connections_failures_never_flip_upstream_offline() {
    // A pool with no usable connectors returns NoConnections — a capacity
    // condition, not a connectivity failure: it must never count towards
    // the offline flip (only Timeout/Io failures do).
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![], config);

    for _ in 0..6 {
        let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
        assert!(matches!(err, UpstreamError::NoConnections));
    }
    assert!(!pool.health.offline.load(Ordering::Relaxed));
}

#[tokio::test]
async fn tls_failures_never_flip_offline() {
    // Permanent TLS failures (bad certificate) are config-level problems:
    // retrying or probing cannot fix them, so they never count towards
    // the offline flip.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 1);

    for _ in 0..6 {
        connector.push(Err(DnsConnError::Tls("bad certificate".into())));
        let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Tls(_)));
    }
    assert!(!pool.health.offline.load(Ordering::Relaxed));
}

//! Connection lifecycle tests: acquisition, reuse, racing, warm-up,
//! maintenance, and connection-level failure retirement.

use super::*;

#[tokio::test]
async fn race_fresh_dial_hang_defers_to_stale_verdict() {
    // A fresh dial that outlives `connect_timeout` is abandoned (the race
    // converts the timeout into `std::future::pending`): the stale
    // connection's own verdict must decide, and nothing of the abandoned
    // dial may be pooled or leaked.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.stale_conn_age = Duration::from_millis(1);
    config.connect_timeout = Duration::from_millis(50);
    let pool = UpstreamPool::with_connectors(vec![connector.clone()], config);

    // First lookup dials and pools a connection.
    connector.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);

    // Age it and script a dial slower than the connect budget: the race's
    // fresh leg times out into `pending`, so the stale conn's (instant)
    // answer wins the race.
    age_all(&pool);
    connector.set_dial_delay_ms(200);
    connector.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);

    // The abandoned dial never completed: nothing extra was pooled or
    // registered with the connector.
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(connector.alive_conns(), 1);
    assert_eq!(connector.dials(), 2);
}

#[tokio::test]
async fn stream_connection_retired_after_two_consecutive_failures() {
    // Stream connections amortize an expensive handshake: a single timeout
    // is not enough to retire one (CONN_FAILURE_THRESHOLD_STREAM = 2) — the
    // next attempt reuses the same conn; the second consecutive failure
    // retires it and the following attempt dials a fresh one.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Err(DnsConnError::Timeout));
    connector.push(Err(DnsConnError::Timeout));
    connector.push(Ok(ok_answer()));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.dials(), 2);
    assert_eq!(connector.queries(), 3);
}

#[tokio::test]
async fn tls_error_does_not_retire_connection() {
    // Permanent TLS failures (bad certificate) would fail on any
    // connection: retiring this one would only trigger a pointless
    // re-dial. The connection stays pooled across repeated Tls errors.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 1);

    for _ in 0..4 {
        connector.push(Err(DnsConnError::Tls("bad certificate".into())));
        let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Tls(_)));
    }
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(connector.dials(), 1);
    assert_eq!(connector.shutdowns(), 0);
}

#[tokio::test]
async fn each_udp_failure_retires_connection() {
    // UDP sockets are cheap to replace: a single failure retires the socket
    // (CONN_FAILURE_THRESHOLD_UDP = 1), so every attempt dials a fresh one.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    connector.push(Err(DnsConnError::Timeout));
    connector.push(Err(DnsConnError::Timeout));
    connector.push(Ok(ok_answer()));
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![connector.clone()], config);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.dials(), 3);
    assert_eq!(connector.queries(), 3);
}

#[tokio::test]
async fn concurrent_lookups_share_connections_up_to_cap() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.max_conns = 2;
    let pool = UpstreamPool::with_connectors(vec![connector.clone()], config);
    for _ in 0..20 {
        connector.push(Ok(ok_answer()));
    }

    let mut handles = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            pool.lookup("example.com.", RecordType::A).await.unwrap().len()
        }));
    }
    for handle in handles {
        assert_eq!(handle.await.unwrap(), 1);
    }
    assert_eq!(connector.queries(), 8);
    // Pool size never exceeds max_conns even under a dial race (extras
    // are dropped on insertion); tasks must have reused connections —
    // otherwise every lookup would have dialed its own (use-then-drop).
    assert!(pool.conn_count() <= 2);
    assert!(connector.dials() >= 1);
    assert!(connector.dials() < 8, "connections were not shared: {} dials", connector.dials());
    // Leak invariant: every dialed connection is either pooled or shut
    // down (no dial is left dangling).
    assert_eq!(connector.dials() as usize, pool.conn_count() + connector.shutdowns() as usize);
}

#[tokio::test]
async fn connection_reused_across_query_types() {
    // The same pooled connection serves A and AAAA lookups (old
    // hickory-resolver `test_multi_use_conns` scenario): no redial between
    // query types.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![a_record([1, 2, 3, 4])])));
    connector
        .push(Ok(answer_with(vec![aaaa_record([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888])])));
    let pool = stream_pool(connector.clone(), 3);

    let a_records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(a_records.len(), 1);
    let aaaa_records = pool.lookup("example.com.", RecordType::AAAA).await.unwrap();
    assert_eq!(aaaa_records.len(), 1);
    // One connection served both queries.
    assert_eq!(connector.dials(), 1);
    assert_eq!(connector.queries(), 2);
}

#[tokio::test]
async fn maintain_reaps_idle_connections_and_keeps_min_warm() {
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "example.com".into() });
    config.min_conns = 1;
    config.idle_timeout = Duration::from_millis(50);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    // Dial two connections (one per endpoint), both idle.
    pool.acquire(a.as_ref()).await.unwrap();
    pool.acquire(b.as_ref()).await.unwrap();
    assert_eq!(pool.conn_count(), 2);

    // Age endpoint A's connection beyond the idle timeout.
    {
        let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
        conns[0].last_used_ms.store(0, Ordering::Relaxed);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    pool.maintain().await;

    // Idle conn on endpoint A reaped (with an explicit shutdown); min_conns
    // = 1 keeps B's conn.
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(a.alive_conns(), 1);
    assert_eq!(a.shutdowns(), 1);
}

#[tokio::test]
async fn fresh_connection_does_not_race() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    pool.acquire(connector.as_ref()).await.unwrap();
    connector.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // A recently used conn is trusted: no raced dial.
    assert_eq!(connector.dials(), 1);
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn stale_race_old_transport_failure_keeps_dialed_fresh_conn() {
    // The stale conn fails at the transport level while the raced fresh
    // dial has already completed (its query is still running and gets
    // cancelled): the healthy fresh conn must be kept for the retry
    // instead of being shut down and re-dialed.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = race_pool(connector.clone(), 3);

    pool.acquire(connector.as_ref()).await.unwrap();
    age_all(&pool);

    // The raced fresh dial is polled first (`biased;`), so it takes the
    // first (slow) outcome; the stale conn takes the second (a fast
    // transport failure), deciding the race while the fresh query is still
    // in flight and gets cancelled.
    connector.push_after(Duration::from_millis(500), Ok(ok_answer()));
    connector.push(Err(DnsConnError::Timeout));
    connector.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // 1 initial + 2 raced dials (the retry races again). The raced conn
    // from the first race was pooled instead of being shut down, so the
    // pool holds the stale conn plus it; the second race's fresh conn was
    // closed because the stale conn answered successfully.
    assert_eq!(connector.dials(), 3);
    assert_eq!(pool.conn_count(), 2);
    assert_eq!(connector.shutdowns(), 1);
}

#[tokio::test]
async fn stale_connection_race_old_wins_when_alive() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = race_pool(connector.clone(), 3);

    pool.acquire(connector.as_ref()).await.unwrap();
    age_all(&pool);

    // The stale conn answers instantly; the raced fresh dial is still
    // sleeping when the race resolves, so it is abandoned unqueried
    // (the pool's race select is `biased`, so the fresh leg is polled
    // first and must not be ready for the stale branch to win).
    connector.set_dial_delay_ms(50);
    connector.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // The raced dial may or may not have started before the race
    // resolved (select can short-circuit on the already-ready stale
    // conn); either way at most one dial happened and the stale conn
    // stayed in the pool un-replaced.
    assert!(connector.dials() <= 2);
    assert_eq!(connector.queries(), 1);
    assert_eq!(pool.conn_count(), 1);
}

#[tokio::test]
async fn stale_connection_race_fresh_wins_when_old_is_dead() {
    // The scenario the race exists for: the server silently dropped our
    // idle connection. The stale conn would burn the whole 1s query
    // budget, but the raced fresh dial answers immediately.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = race_pool(connector.clone(), 3);

    pool.acquire(connector.as_ref()).await.unwrap();
    age_all(&pool);

    connector.push_after(Duration::from_millis(100), Err(DnsConnError::Timeout));
    connector.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // 1 initial + 1 raced dial.
    assert_eq!(connector.dials(), 2);
    // The stale conn was retired and the fresh one took its place (which of
    // the two race legs wins is poll-order dependent, so shutdown counts
    // are asserted in the dedicated retire_and_pool test).
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(connector.queries(), 2);
}

#[tokio::test]
async fn warm_up_to_min_dials_across_all_stream_endpoints() {
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "example.com".into() });
    config.min_conns = 2;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    pool.warm_up_to_min().await;

    // One warm connection per endpoint, dialed round-robin.
    assert_eq!(pool.conn_count(), 2);
    assert_eq!(a.dials(), 1);
    assert_eq!(b.dials(), 1);
}

#[tokio::test]
async fn warm_up_continues_past_a_failed_endpoint() {
    // Endpoint A's first dial fails outright: the warm-up must move on
    // and still dial B instead of abandoning the pass (a permanently
    // dead first endpoint used to starve every other endpoint of a warm
    // connection).
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "example.com".into() });
    config.min_conns = 2;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);
    a.fail_next_dial(1);

    pool.warm_up_to_min().await;

    // A's dial failed, but B was still warmed up.
    assert_eq!(a.dials(), 1);
    assert_eq!(b.dials(), 1);
    assert_eq!(pool.conn_count(), 1);
}

#[tokio::test]
async fn stale_connection_race_fresh_query_failure_defers_to_stale_conn() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = race_pool(connector.clone(), 3);

    pool.acquire(connector.as_ref()).await.unwrap();
    age_all(&pool);

    // The raced dial is slowed so the stale conn always pops its outcome
    // (200ms) before the fresh leg's query starts (its dial takes 100ms):
    // tokio::select! polls branches in random order, so without the dial
    // skew the fresh leg could steal the stale conn's slow answer from
    // the shared outcome queue. The fresh leg then fails fast at the
    // transport level, proving nothing about the stale conn — the stale
    // verdict must win and the failed fresh dial must not be pooled.
    connector.set_dial_delay_ms(100);
    connector.push_after(Duration::from_millis(200), Ok(ok_answer()));
    connector.push(Err(DnsConnError::Timeout));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // The stale conn survived and the failed fresh one was abandoned.
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(connector.dials(), 2);

    // The surviving stale conn must serve the next query. Stamp its
    // last-used marker in the future so the 1ms stale threshold cannot
    // race a spurious second dial across a millisecond boundary.
    {
        let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
        conns[0].last_used_ms.store(pool.clock.now_ms() + 60_000, Ordering::Relaxed);
    }
    connector.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.dials(), 2);
}

#[tokio::test]
async fn stale_connection_race_dial_failure_defers_to_stale_conn() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = race_pool(connector.clone(), 3);

    pool.acquire(connector.as_ref()).await.unwrap();
    age_all(&pool);

    // The raced fresh dial fails outright (server unreachable): the stale
    // conn's own verdict decides the race instead of an error. The stale
    // conn answers slowly, so the raced dial actually gets started.
    connector.fail_next_dial(1);
    connector.push_after(Duration::from_millis(100), Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.dials(), 2);
    assert_eq!(pool.conn_count(), 1);
}

#[tokio::test]
async fn stale_connection_race_both_fail_then_redials_fresh() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.stale_conn_age = Duration::from_millis(1);
    // A frozen clock pins the raced-fresh conn's later staleness check: it
    // is pooled at `now` and re-examined at the same `now`, so a
    // millisecond boundary under the real clock cannot flip it stale and
    // spawn a spurious extra race (the historical under-load flake made
    // the dial/query counts wander).
    let pool = UpstreamPool::with_connectors_and_clock(
        vec![connector.clone()],
        config,
        Arc::new(TestClock::new(10_000)),
    );

    pool.acquire(connector.as_ref()).await.unwrap();
    age_all(&pool);

    // Both legs fail: the raced fresh dial of attempt 1 pops the delayed
    // outcome (the biased select polls the fresh leg first, so both raced
    // dials provably start) and is still sleeping when the stale conn's
    // instant Timeout wins the race; attempt 2 repeats this on the LRU
    // stale conn, whose second failure retires it. The conn survives one
    // failure (stream threshold 2) but is retired on the second. The
    // raced fresh conn of attempt 1 was kept (its query was cancelled,
    // the conn is healthy), so the final attempt reuses it instead of
    // dialing again.
    connector.push_after(Duration::from_millis(100), Err(DnsConnError::Timeout));
    connector.push(Err(DnsConnError::Timeout));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Timeout));
    // Deterministic under the frozen clock: setup dial + the two raced
    // dials (attempt 1 and attempt 2), nothing else — the final attempt
    // reuses the kept fresh conn.
    assert_eq!(connector.dials(), 3, "dials");
    // Stale conn ×2 (attempts 1-2), raced fresh of attempt 1 (cancelled),
    // raced fresh of attempt 2 (transport failure), kept conn (final
    // attempt, queue empty → instant Timeout).
    assert_eq!(connector.queries(), 5, "queries");
    // The attempt-2 raced fresh dial (transport failure, never pooled) and
    // the twice-failed stale conn retired by the final attempt's purge.
    assert_eq!(connector.shutdowns(), 2, "shutdowns");
    // The pool holds the kept fresh connection.
    assert_eq!(pool.conn_count(), 1);
}

#[tokio::test]
async fn race_fresh_wins_replaces_stale_under_cap_pressure() {
    // Two endpoints, max_conns = 2: when the raced fresh conn wins, the
    // stale conn is retired and the fresh one takes its place (the pool
    // still fits under the cap); the third endpoint is blocked from
    // dialing by the cap and its leg falls back to NoConnections without
    // touching the wire. The fan-out also queries B, so its leg is
    // scripted to stay in flight (slower than A's answer) and aborted.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let c = MockConnector::new([10, 0, 0, 3], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.max_conns = 2;
    config.stale_conn_age = Duration::from_millis(1);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone(), c.clone()], config);

    pool.acquire(a.as_ref()).await.unwrap();
    pool.acquire(b.as_ref()).await.unwrap();
    age_all(&pool);

    // Stale conn on A is slow and dead; the raced fresh dial answers. The
    // dial delay makes the fresh dial slow enough that the stale conn's
    // query pops the slow outcome first (the race polls the fresh branch
    // first), so the fresh leg still wins the race with the good answer.
    a.set_dial_delay_ms(50);
    a.push_after(Duration::from_millis(100), Err(DnsConnError::Timeout));
    a.push(Ok(ok_answer()));
    // B answers slowly too, so A's fresh answer wins the selection and
    // aborts it before it completes.
    b.push_after(Duration::from_millis(500), Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(a.dials(), 2);
    // The stale A conn was retired (shutdown) and the fresh one pooled in
    // its place; B's conn completes the pair at the cap.
    assert_eq!(pool.conn_count(), 2);
    assert_eq!(a.shutdowns(), 1);
    // The cap blocked C's dial entirely: its leg reported NoConnections.
    assert_eq!(c.dials(), 0);
}

#[tokio::test]
async fn concurrent_dials_respect_cap_serving_transient_conn() {
    // Two tasks dial simultaneously against max_conns = 1: one insertion
    // wins; the other, seeing the cap full, serves its query with the
    // freshly dialed connection without pooling it (use-then-drop) instead
    // of failing with NoConnections — and must never be handed a
    // connection to the other endpoint.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    a.set_dial_delay_ms(50);
    b.set_dial_delay_ms(50);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.max_conns = 1;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    let pa = pool.acquire(a.as_ref());
    let pb = pool.acquire(b.as_ref());
    let (ra, rb) = tokio::join!(pa, pb);
    let ra = ra.unwrap().expect("cap pressure must not fail the query");
    let rb = rb.unwrap().expect("cap pressure must not fail the query");

    // Both tasks get a usable connection to *their own* endpoint; exactly
    // one of them is pooled, the other is transient.
    assert_eq!(ra.conn.ip(), a.ip());
    assert_eq!(rb.conn.ip(), b.ip());
    assert_eq!(a.dials(), 1);
    assert_eq!(b.dials(), 1);
    assert_eq!(pool.conn_count(), 1);
    // The transient (use-then-drop) connection is closed by `PooledConn`'s
    // Drop once the caller releases it — the shutdown contract holds for it
    // too.
    drop(ra);
    drop(rb);
    assert_eq!(a.shutdowns() + b.shutdowns(), 1);
    // Leak invariant: every dialed connection is either pooled or shut down.
    assert_eq!(
        a.dials() as usize + b.dials() as usize,
        pool.conn_count() + (a.shutdowns() + b.shutdowns()) as usize
    );
}

#[tokio::test]
async fn acquire_purges_dead_connections_calling_shutdown() {
    // A dead connection left in the pool is purged on the next acquire; the
    // purge must call shutdown() on it (same contract as maintain).
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    let conn = pool.acquire(connector.as_ref()).await.unwrap().unwrap();
    {
        let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
        conns[0].dead.store(true, Ordering::Relaxed);
    }
    drop(conn);

    let fresh = pool.acquire(connector.as_ref()).await.unwrap().unwrap();
    assert!(!fresh.dead.load(Ordering::Relaxed));
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(connector.shutdowns(), 1);
    assert_eq!(connector.dials(), 2);
}

#[tokio::test]
async fn retire_and_pool_shuts_down_the_retired_connection() {
    // The raced fresh conn winning must retire the stale one via
    // shutdown(), and the pool must hold exactly the fresh conn.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    let old = pool.acquire(connector.as_ref()).await.unwrap().unwrap();
    let fresh = connector.connect().await.unwrap();
    let winner = pool.retire_and_pool(&old, fresh);

    assert!(!Arc::ptr_eq(&old, &winner));
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(connector.shutdowns(), 1);
}

#[tokio::test]
async fn udp_connection_reused_and_never_races() {
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp.clone()], config);

    udp.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    udp.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(udp.dials(), 1);
    assert_eq!(udp.queries(), 2);

    // Even when aged beyond the stale threshold, UDP never races (no
    // handshake to amortize, so a race would be pure waste).
    age_all(&pool);
    udp.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(udp.dials(), 1);
}

#[tokio::test]
async fn maintain_prunes_dead_and_reaps_idle_calling_shutdown() {
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.min_conns = 0;
    config.idle_timeout = Duration::from_millis(0);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    pool.acquire(a.as_ref()).await.unwrap();
    pool.acquire(b.as_ref()).await.unwrap();
    assert_eq!(pool.conn_count(), 2);

    {
        let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
        conns[0].dead.store(true, Ordering::Relaxed);
        conns[1].last_used_ms.store(0, Ordering::Relaxed);
        conns[1].last_borrow_ms.store(0, Ordering::Relaxed);
    }

    pool.maintain().await;
    assert_eq!(pool.conn_count(), 0);
    // Both retired connections were shut down explicitly (dead prune +
    // idle reap).
    assert_eq!(a.shutdowns() + b.shutdowns(), 2);
}

#[tokio::test]
async fn maintain_keeps_all_conns_when_idle_count_at_or_below_min() {
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.min_conns = 2;
    config.idle_timeout = Duration::from_millis(0);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    pool.acquire(a.as_ref()).await.unwrap();
    pool.acquire(b.as_ref()).await.unwrap();
    age_all(&pool);

    pool.maintain().await;

    // Both conns are idle but min_conns = 2 forbids reaping any of them.
    assert_eq!(pool.conn_count(), 2);
    assert_eq!(a.shutdowns() + b.shutdowns(), 0);
}

#[tokio::test]
async fn race_protocol_error_does_not_retire_connection() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = race_pool(connector.clone(), 3);

    pool.acquire(connector.as_ref()).await.unwrap();
    age_all(&pool);

    // The fresh leg wins the race with an NXDomain: the stale conn is
    // replaced, but the fresh one is an *answer*, not a failure — it must
    // survive to serve the next query.
    connector.push_after(Duration::from_millis(100), Err(DnsConnError::Timeout));
    connector.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    assert_eq!(pool.conn_count(), 1);

    // The surviving conn must be reused by the next query. Stamp its
    // last-used marker far in the future: a `now_ms()` stamp can fall on
    // the far side of the 1ms stale threshold mid-test, racing a spurious
    // dial across a millisecond boundary.
    {
        let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
        conns[0].last_used_ms.store(pool.clock.now_ms() + 60_000, Ordering::Relaxed);
    }
    connector.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // The surviving conn was reused: no additional dial.
    assert_eq!(connector.dials(), 2);
}

#[tokio::test]
async fn maintenance_survives_panicking_connector() {
    // The maintenance task is the pool's only reaper, warmer and prober,
    // and it dials connectors inline (`acquire` -> `connect`): a panicking
    // pass must be caught and logged instead of silently killing the task
    // — otherwise idle connections leak forever and an offline upstream is
    // never probed again for the pool's remaining lifetime.
    let healthy = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.min_conns = 1;
    let pool = UpstreamPool::with_connectors(
        vec![
            Arc::new(PanicConnector {
                ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            }),
            healthy.clone(),
        ],
        config,
    );

    // Two guarded passes both survive the panicking warm-up dial; the
    // second proves the loop kept ticking instead of dying.
    pool.maintain_guarded().await;
    pool.maintain_guarded().await;

    // The pool still serves queries through the healthy connector.
    healthy.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn cold_start_dial_failure_retries_next_attempt() {
    // The first dial fails outright (server temporarily unreachable);
    // the retry dials a fresh conn and succeeds. Dial failures must be
    // treated as transient, not final.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.fail_next_dial(1);
    connector.push(Ok(ok_answer()));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.dials(), 2);
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn dial_failure_on_one_endpoint_falls_through_to_next() {
    // IP1 refuses connections, IP2 answers: the same attempt must move on
    // to IP2 instead of aborting, so one broken endpoint does not cost a
    // full retry cycle.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    a.fail_next_dial(1);
    b.push(Ok(ok_answer()));
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // Exactly one dial per endpoint.
    assert_eq!(a.dials(), 1);
    assert_eq!(b.dials(), 1);
}

#[tokio::test]
async fn aborted_leg_failures_are_not_recorded() {
    // A dead connection on one endpoint whose leg keeps losing the fan-out
    // (a healthy endpoint answers instantly, so the positive answer aborts
    // the dead leg mid-flight) never has its failures recorded: the failure
    // threshold cannot retire it. This locks the accepted behaviour — the
    // backstop is the stale race (see stale_connection_race_*): aborted
    // legs never update `last_used_ms`, so the connection goes stale and
    // the next query races it against a fresh dial instead.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    // A's connection is dead (its query only fails after a long timeout);
    // B answers instantly, aborting A's leg. Three lookups = three aborted
    // A-legs; had the aborted failures been recorded, the stream threshold
    // of two would have retired the connection.
    for _ in 0..3 {
        a.push_after(Duration::from_millis(500), Err(DnsConnError::Timeout));
        b.push(Ok(ok_answer()));
    }
    for _ in 0..3 {
        let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
        assert_eq!(records.len(), 1);
    }

    // The dead conn is still pooled and never re-dialed: the aborted legs
    // did not count towards its retirement threshold.
    assert_eq!(a.dials(), 1);
    assert_eq!(a.shutdowns(), 0);
    assert_eq!(pool.conn_count(), 2);
}

#[tokio::test]
async fn concurrent_same_endpoint_acquires_share_one_dial() {
    // Two concurrent acquires on the SAME endpoint coalesce into a single
    // dial (the cold-dial gate serializes them): the waiter reuses the
    // first dialer's pooled connection instead of racing it over the cap.
    // The historical cap-excess outcome this test replaced (the loser's
    // fresh dial closed at insert time) is now structurally prevented one
    // step earlier; the cross-endpoint cap race keeps its coverage in
    // `concurrent_dials_respect_cap_serving_transient_conn`.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    a.set_dial_delay_ms(50);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.max_conns = 1;
    let pool = UpstreamPool::with_connectors(vec![a.clone()], config);

    let p1 = pool.acquire(a.as_ref());
    let p2 = pool.acquire(a.as_ref());
    let (r1, r2) = tokio::join!(p1, p2);
    let c1 = r1.unwrap().expect("coalescing must not fail the query");
    let c2 = r2.unwrap().expect("coalescing must not fail the query");

    assert_eq!(c1.conn.ip(), a.ip());
    assert_eq!(c2.conn.ip(), a.ip());
    // Exactly one dial, one pooled connection, nothing closed.
    assert_eq!(a.dials(), 1);
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(a.shutdowns(), 0);
}

#[tokio::test]
async fn maintain_reaps_all_idle_when_non_idle_meets_min() {
    // The reaping math `removable = idle − (min_conns − non_idle)`: with
    // min_conns = 1 and one recently used conn, every idle conn beyond the
    // min is reaped even though idle > min.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let c = MockConnector::new([10, 0, 0, 3], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.min_conns = 1;
    config.idle_timeout = Duration::from_millis(0);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone(), c.clone()], config);

    pool.acquire(a.as_ref()).await.unwrap();
    pool.acquire(b.as_ref()).await.unwrap();
    pool.acquire(c.as_ref()).await.unwrap();
    assert_eq!(pool.conn_count(), 3);

    // A stays recent; B and C go idle.
    {
        let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
        for pooled in conns.iter() {
            if pooled.conn.ip() == b.ip() || pooled.conn.ip() == c.ip() {
                pooled.last_used_ms.store(0, Ordering::Relaxed);
                pooled.last_borrow_ms.store(0, Ordering::Relaxed);
            }
        }
    }

    pool.maintain().await;

    // Both idle conns were reaped (with shutdown); A is kept for
    // min_conns = 1.
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(a.shutdowns() + b.shutdowns() + c.shutdowns(), 2);
}

#[tokio::test]
async fn acquire_connect_timeout_returns_timeout_error() {
    // A dial slower than the connect budget must surface as a Timeout
    // instead of hanging the query on the handshake.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.set_dial_delay_ms(50);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.connect_timeout = Duration::from_millis(1);
    let pool = UpstreamPool::with_connectors(vec![connector.clone()], config);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Timeout));
    assert_eq!(connector.dials(), 1);
}

#[tokio::test]
async fn no_connections_query_errors_never_retire_connection_or_flip_offline() {
    // A saturated multiplexer surfaces as NoConnections (capacity): it must
    // not retire the pooled connection nor count towards the offline flip,
    // no matter how often it recurs (the `Busy` mapping in `map_net_error`).
    // Instead of failing forever it grows the pool (elastic scale-up).
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    let pool = UpstreamPool::with_connectors(vec![connector.clone()], config);

    for _ in 0..4 {
        connector.push(Err(DnsConnError::NoConnections));
        let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
        assert!(matches!(err, UpstreamError::NoConnections));
    }
    // The first Busy dialed at least one extra connection; the later ones
    // were served by the new connection or capped. Whatever the exact count,
    // nothing was retired (zero shutdowns) and the upstream never flipped
    // offline (3+ transport failures would be required).
    assert!(connector.dials() >= 2, "Busy must trigger elastic scale-up");
    assert_eq!(connector.shutdowns(), 0);
    assert!(pool.conn_count() >= 2);
    assert!(!pool.health.offline.load(Ordering::Relaxed));
}

#[tokio::test]
async fn busy_triggers_elastic_scale_up_and_recovers() {
    // A connection at its in-flight cap (Busy -> NoConnections) is marked
    // used so the LRU picker favours other connections, and one extra
    // connection is dialed for the endpoint. The next query then succeeds
    // on the fresh connection instead of failing forever.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.set_dial_delay_ms(50);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.query_timeout = Duration::from_millis(200);
    config.connect_timeout = Duration::from_millis(500);
    let pool = UpstreamPool::with_connectors(vec![connector.clone()], config);

    connector.push(Err(DnsConnError::NoConnections));
    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::NoConnections));

    // While the scale-up dial is in flight, another Busy on the same
    // connection must not start a second dial (one at a time).
    connector.push(Err(DnsConnError::NoConnections));
    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::NoConnections));
    assert_eq!(connector.dials(), 2);

    // The fresh connection lands in the pool; the next query uses it.
    connector.push(Ok(ok_answer()));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while pool.conn_count() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(pool.conn_count(), 2);
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.dials(), 2);
    assert_eq!(connector.shutdowns(), 0);
}

#[tokio::test]
async fn warm_up_stops_at_stream_cap() {
    // Two endpoints, min_conns = 2 but max_conns = 1: the warm-up must stop
    // at the cap instead of dialing past it (the cap is a hard budget).
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "example.com".into() });
    config.min_conns = 2;
    config.max_conns = 1;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    pool.warm_up_to_min().await;

    // Only the first endpoint was dialed; the cap stopped the pass.
    assert_eq!(pool.conn_count(), 1);
    assert_eq!(a.dials() + b.dials(), 1);
}

#[tokio::test]
async fn warm_up_with_min_above_endpoint_count_stops() {
    // min_conns > stream endpoint count: the warm-up is bounded by the
    // endpoint count (one multiplexed connection per endpoint serves all
    // queries) instead of dialing the same endpoint repeatedly.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "example.com".into() });
    config.min_conns = 4;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    pool.warm_up_to_min().await;

    assert_eq!(pool.conn_count(), 2);
    assert_eq!(a.dials(), 1);
    assert_eq!(b.dials(), 1);
}

#[tokio::test]
async fn warm_up_survives_multiple_failed_endpoints() {
    // Endpoints A and C fail their first dial: the warm-up must keep moving
    // and still dial B instead of abandoning the pass.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let c = MockConnector::new([10, 0, 0, 3], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "example.com".into() });
    config.min_conns = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone(), c.clone()], config);
    a.fail_next_dial(1);
    c.fail_next_dial(1);

    pool.warm_up_to_min().await;

    // A and C failed; B was warmed up.
    assert_eq!(a.dials(), 1);
    assert_eq!(b.dials(), 1);
    assert_eq!(c.dials(), 1);
    assert_eq!(pool.conn_count(), 1);
}

/// A cold-start burst of concurrent lookups must coalesce into a single
/// dial per endpoint: C parallel handshakes against the same peer would
/// trip handshake rate limiters and surface the duplicates as
/// health-counted `Io` failures (3 flip the upstream offline from
/// cold-start pressure alone).
#[tokio::test]
async fn cold_start_burst_coalesces_into_single_dial() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 2);
    // A dial latency wide enough that every lookup of the burst is
    // provably waiting in `acquire` before the first dial lands.
    connector.set_dial_delay_ms(100);
    for _ in 0..8 {
        connector.push(Ok(ok_answer()));
    }

    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let pool = pool.clone();
            tokio::spawn(async move { pool.lookup("example.com.", RecordType::A).await })
        })
        .collect();
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap().len(), 1);
    }
    assert_eq!(connector.dials(), 1, "the burst must share one dial");
    assert_eq!(pool.conn_count(), 1);
}

#[tokio::test]
async fn maintain_reaps_idle_udp_entries() {
    // UDP pool entries are bookkeeping over stateless per-query sockets:
    // every idle entry must be reaped (no `min_conns` protection), or a
    // cold-start burst that raced `find_reusable` would leave entries
    // behind forever and degrade every hot-path scan under the pool lock.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.idle_timeout = Duration::from_millis(50);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    pool.acquire(a.as_ref()).await.unwrap();
    pool.acquire(b.as_ref()).await.unwrap();
    assert_eq!(pool.conn_count(), 2);

    // Age both entries beyond the idle timeout.
    {
        let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
        for pooled in conns.iter() {
            pooled.last_used_ms.store(0, Ordering::Relaxed);
            pooled.last_borrow_ms.store(0, Ordering::Relaxed);
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    pool.maintain().await;

    assert_eq!(pool.conn_count(), 0, "idle UDP entries must be reaped");
}

#[tokio::test]
async fn maintain_does_not_reap_an_in_flight_borrow() {
    // `last_used_ms` must be stamped when a connection is *borrowed*, not
    // only when its query completes: a query in flight on an almost-idle
    // connection otherwise races the reaper, which retires the connection
    // (and for DoQ, whose `shutdown` actively closes, kills the in-flight
    // query and counts the failure against upstream health).
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.idle_timeout = Duration::from_millis(50);
    let clock = TestClock::new(1_000);
    let pool = UpstreamPool::with_connectors_and_clock(
        vec![connector.clone()],
        config,
        Arc::new(clock.clone()),
    );

    pool.acquire(connector.as_ref()).await.unwrap();
    assert_eq!(pool.conn_count(), 1);

    // Age the entry past the idle timeout, then borrow it again: the borrow
    // renews the stamp (the query starts here and runs for a while).
    clock.advance(100);
    let _borrowed = pool.acquire(connector.as_ref()).await.unwrap().unwrap();
    assert_eq!(pool.conn_count(), 1);

    // The query is in flight for 10ms (well under the idle timeout) when
    // the maintenance pass runs: the borrow stamp must protect it.
    clock.advance(10);
    pool.maintain().await;
    assert_eq!(pool.conn_count(), 1, "an in-flight borrow must not be reaped");
    assert_eq!(connector.shutdowns(), 0, "the borrowed connection must not be closed");

    // Without another use the entry ages out normally.
    clock.advance(100);
    pool.maintain().await;
    assert_eq!(pool.conn_count(), 0, "the entry must still be reaped once idle again");
}

#[tokio::test]
async fn gate_queue_timeout_surfaces_capacity_not_timeout() {
    // A waiter queued behind a cold dial that outlived the connect budget
    // is congestion, not a connectivity verdict: `acquire` must surface the
    // capacity class (`Ok(None)` → `NoConnections`, which the pool never
    // counts against the upstream's health), not a `Timeout` that would
    // let a healthy-but-slow endpoint be voted offline by its own queue.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "example.com".into() });
    config.connect_timeout = Duration::from_millis(50);
    let pool = UpstreamPool::with_connectors(vec![connector.clone()], config);

    // Hold the cold-dial gate ourselves: every `acquire` becomes a queued
    // waiter with a 50ms budget.
    let slot = pool.dial_slot_for(connector.ip(), connector.transport());
    let _holder = slot.gate.lock().await;

    let outcome = pool.acquire(connector.as_ref()).await.unwrap();
    assert!(
        outcome.is_none(),
        "queue timeout must surface as the capacity class (None), got {outcome:?}"
    );
    assert!(!pool.health.offline.load(Ordering::Relaxed));
}

#[tokio::test]
async fn scale_up_dials_survive_a_panicking_connector() {
    // The elastic-growth dial runs on a background task; a connector that
    // panics mid-dial must not leave the in-flight counter stuck (which
    // would silently disable every future scale-up). The guard makes the
    // counter panic-proof, so the dial after the panicking one still runs.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.panic_dials_over(2);
    // One attempt per lookup: every lookup consumes exactly one `Busy`
    // outcome and fires exactly one scale-up dial.
    let pool = stream_pool(connector.clone(), 1);
    let slot = pool.dial_slot_for(connector.ip(), connector.transport());

    // Every lookup: cold dial, the conn reports Busy (`NoConnections`),
    // the pool scales up with one background dial. The third dial panics.
    for _ in 0..3 {
        connector.push(Err(DnsConnError::NoConnections));
    }
    for expected_dials in [2, 3, 4] {
        let _ = pool.lookup("example.com.", RecordType::A).await;
        // The scale-up dial runs on a background task: wait for it.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while connector.dials() < expected_dials && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(connector.dials(), expected_dials, "scale-up must keep dialing");
        assert_eq!(
            slot.background_dial.load(Ordering::Relaxed),
            0,
            "the slot's dial counter must restore after every dial (including a panicking one)"
        );
    }
}

//! Fan-out response-selection tests: concurrent legs, negative grace,
//! truncation preference, and the UDP → stream fallback.

use super::*;

#[tokio::test]
async fn truncated_udp_answer_falls_back_to_stream() {
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    udp.push(Ok(truncated_answer()));
    let stream = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    stream.push(Ok(ok_answer()));
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // UDP answered once (truncated); the answer came from the stream conn.
    assert_eq!(stream.queries(), 1);
    assert_eq!(udp.queries(), 1);
}

#[tokio::test]
async fn contested_negative_after_grace_has_clamped_soa_ttl() {
    // A negative that wins only after the grace window (another endpoint
    // still in flight) may be stale: its SOA TTL is clamped so the negative
    // caching it drives (RFC 2308) expires quickly instead of poisoning the
    // domain.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    b.set_dial_delay_ms(150);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    let soa = Record::from_rdata(
        Name::from_str("example.com.").unwrap(),
        300,
        RData::SOA(hickory_proto::rr::rdata::SOA::new(
            Name::from_str("example.com.").unwrap(),
            Name::from_str("ns.example.com.").unwrap(),
            1,
            1,
            1,
            1,
            60,
        )),
    );
    a.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, Some(Box::new(soa)))));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    match err {
        UpstreamError::Protocol(code, soa) => {
            assert_eq!(code, ResponseCode::NXDomain);
            let soa = soa.expect("contested negative must carry its SOA");
            assert_eq!(soa.ttl, pool_config::CONTESTED_NEGATIVE_TTL);
        }
        other => panic!("expected Protocol(NXDomain, clamped soa), got {other:?}"),
    }
}

#[tokio::test]
async fn consensual_negative_keeps_full_soa_ttl() {
    // All endpoints answer NXDomain quickly: the negative is a consensus
    // (no grace wait) and its SOA TTL is untouched.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);

    let soa_of = || {
        Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_str("example.com.").unwrap(),
                Name::from_str("ns.example.com.").unwrap(),
                1,
                1,
                1,
                1,
                60,
            )),
        )
    };
    a.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, Some(Box::new(soa_of())))));
    b.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, Some(Box::new(soa_of())))));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    match err {
        UpstreamError::Protocol(code, soa) => {
            assert_eq!(code, ResponseCode::NXDomain);
            let soa = soa.expect("negative must carry its SOA");
            assert_eq!(soa.ttl, 300);
        }
        other => panic!("expected Protocol(NXDomain, full-ttl soa), got {other:?}"),
    }
}

#[tokio::test]
async fn nxdomain_not_overwritten_by_later_connector_timeout() {
    // Multi-IP: an explicit negative answer must not be overwritten by a
    // concurrent leg's transient failure (it used to become a retried
    // Timeout, hiding the NXDomain).
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(50);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);
    a.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    b.push(Err(DnsConnError::Timeout));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    // Both legs were queried concurrently (fan-out), but the negative
    // answer won the selection over IP2's timeout.
    assert_eq!(a.queries(), 1);
    assert_eq!(b.dials(), 1);
}

#[tokio::test]
async fn plaintext_nxdomain_over_udp_does_not_touch_tcp() {
    // Single-IP plaintext has UDP + TCP connectors: an NXDomain over UDP
    // is final and must not dial the TCP connector (old resolver returned
    // the negative answer directly).
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let tcp = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(50);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), tcp.clone()], config);
    udp.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    assert_eq!(tcp.dials(), 0);
    assert_eq!(tcp.queries(), 0);
    // The answering UDP socket survives (protocol answers never retire a
    // connection) and is reused on the next lookup.
    udp.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    assert_eq!(udp.dials(), 1);
}

#[tokio::test]
async fn fanout_fastest_leg_wins() {
    // Both IPs are queried concurrently; the faster one wins and the slow
    // leg is aborted mid-dial.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    a.set_dial_delay_ms(100);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);
    a.push(Ok(answer_with(vec![a_record([1, 1, 1, 1])])));
    b.push(Ok(answer_with(vec![a_record([8, 8, 8, 8])])));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(8, 8, 8, 8)));
    // Both legs were dialed concurrently; the slow one was aborted.
    assert_eq!(a.dials(), 1);
    assert_eq!(b.dials(), 1);
}

#[tokio::test]
async fn fanout_negative_waits_grace_for_positive() {
    // IP1 answers NXDomain instantly; IP2 answers positively within the
    // 100ms negative grace: the positive answer wins.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);
    a.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    b.push_after(Duration::from_millis(50), Ok(answer_with(vec![a_record([8, 8, 8, 8])])));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(8, 8, 8, 8)));
}

#[tokio::test]
async fn fanout_negative_returned_after_grace_when_no_positive() {
    // IP1 answers NXDomain; IP2 is still dialing when the grace window
    // expires: the negative is returned and IP2's leg is aborted before
    // it can query.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    b.set_dial_delay_ms(150);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);
    a.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    // The slow leg was aborted after the grace window, before querying.
    assert_eq!(b.dials(), 1);
    assert_eq!(b.queries(), 0);
}

#[tokio::test]
async fn fanout_truncated_udp_loses_to_positive() {
    // One UDP leg truncates, the other answers positively: the truncated
    // answer must never win over a complete one.
    let a_udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let b_udp = MockConnector::new([10, 0, 0, 2], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a_udp.clone(), b_udp.clone()], config);
    a_udp.push(Ok(truncated_answer()));
    b_udp.push(Ok(answer_with(vec![a_record([8, 8, 8, 8])])));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(8, 8, 8, 8)));
}

#[tokio::test]
async fn fanout_truncated_answer_wins_over_negative() {
    // One endpoint truncates (the answer exists, it just does not fit
    // over UDP), the other answers NXDomain: the truncated answer must
    // trigger the stream retry instead of surfacing the negative, so the
    // TCP leg can recover the full answer.
    let udp1 = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let udp2 = MockConnector::new([10, 0, 0, 2], DnsTransport::Udp);
    let tcp = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp1.clone(), udp2.clone(), tcp.clone()], config);
    udp1.push(Ok(truncated_answer()));
    udp2.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    tcp.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // The negative did not short-circuit the truncation: TCP was queried
    // and its answer returned.
    assert_eq!(tcp.queries(), 1);
    assert_eq!(tcp.dials(), 1);
}

#[tokio::test]
async fn fanout_truncated_answer_wins_over_negative_during_grace() {
    // Same preference while other legs are still in flight: IP2's
    // negative opens the grace window, IP3 is still dialing, and the
    // truncated answer from IP1 must win when the window expires.
    let udp1 = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let udp2 = MockConnector::new([10, 0, 0, 2], DnsTransport::Udp);
    let udp3 = MockConnector::new([10, 0, 0, 3], DnsTransport::Udp);
    let tcp = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(500);
    let pool = UpstreamPool::with_connectors(
        vec![udp1.clone(), udp2.clone(), udp3.clone(), tcp.clone()],
        config,
    );
    udp1.push(Ok(truncated_answer()));
    udp2.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    // IP3 is still dialing when the grace window expires, so its leg is
    // aborted before it can answer.
    udp3.set_dial_delay_ms(150);
    udp3.push_after(Duration::from_millis(400), Ok(ok_answer()));
    tcp.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(tcp.queries(), 1);
    // IP3's leg was aborted mid-dial; it never got to query.
    assert_eq!(udp3.queries(), 0);
}

#[tokio::test]
async fn fanout_nxdomain_skips_tcp_phase() {
    // A negative UDP answer is final: the TCP phase must not run even
    // though the UDP phase "failed" (negatively).
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let tcp = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), tcp.clone()], config);
    udp.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    assert_eq!(tcp.dials(), 0);
}

#[tokio::test]
async fn fanout_cap_limits_concurrent_legs() {
    // Three IPs with fanout capped at 2: only two legs are queried per
    // lookup. (Rotation of the excluded endpoint across attempts is covered
    // by `fanout_rotates_legs_across_attempts_and_recovers` — here the
    // first attempt already answers, so no rotation happens.)
    let udp1 = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let udp2 = MockConnector::new([10, 0, 0, 2], DnsTransport::Udp);
    let udp3 = MockConnector::new([10, 0, 0, 3], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.fanout = 2;
    let pool =
        UpstreamPool::with_connectors(vec![udp1.clone(), udp2.clone(), udp3.clone()], config);
    for udp in [&udp1, &udp2, &udp3] {
        udp.push(Ok(ok_answer()));
    }

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(udp1.queries() + udp2.queries() + udp3.queries(), 2);
}

#[tokio::test]
async fn fanout_servfail_loses_to_negative() {
    // IP1 answers NXDomain, IP2 answers ServFail: ServFail is an explicit
    // code (final, like every explicit answer — never retried), not a
    // negative — but when no positive arrives, the negative wins the
    // selection over the ServFail after the grace window.
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);
    a.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    b.push(Err(DnsConnError::Protocol(ResponseCode::ServFail, None)));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    // Both legs were queried concurrently; the negative outranked the
    // ServFail once the grace window expired.
    assert_eq!(a.queries(), 1);
    assert_eq!(b.queries(), 1);
}

#[tokio::test]
async fn fanout_slow_positive_after_grace_does_not_beat_negative() {
    // The negative grace window is the commitment point: a positive that
    // would arrive after the window is not waited for — the negative is
    // returned once the window expires (a client retry can pick the other
    // endpoint next time).
    let a = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(500);
    let pool = UpstreamPool::with_connectors(vec![a.clone(), b.clone()], config);
    a.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    // IP2's positive arrives at 150ms — after the 100ms grace window, so
    // it must not beat the negative (its leg is aborted at the expiry).
    b.push_after(Duration::from_millis(150), Ok(answer_with(vec![a_record([8, 8, 8, 8])])));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    // The slow leg was aborted at the grace expiry; its answer never
    // materialized (the query started but was cut short mid-delay).
    assert_eq!(b.queries(), 1);
}

#[tokio::test]
async fn fanout_rotates_legs_across_attempts_and_recovers() {
    // Three IPs, fanout capped at 2: attempt 1 queries two of them (both
    // scripted to fail), attempt 2 rotates — and because every endpoint
    // answers on its second query, whichever two legs are picked the
    // lookup recovers across attempts.
    let udp1 = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let udp2 = MockConnector::new([10, 0, 0, 2], DnsTransport::Udp);
    let udp3 = MockConnector::new([10, 0, 0, 3], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 2;
    config.fanout = 2;
    config.query_timeout = Duration::from_millis(50);
    let pool =
        UpstreamPool::with_connectors(vec![udp1.clone(), udp2.clone(), udp3.clone()], config);
    for udp in [&udp1, &udp2, &udp3] {
        udp.push(Err(DnsConnError::Timeout));
        udp.push(Ok(ok_answer()));
    }

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // 2 legs per attempt × 2 attempts. Every attempt-1 UDP socket was
    // retired by its single failure (UDP threshold 1), so attempt 2
    // redials both legs it picks: 2 + 2 dials, 2 + 2 queries.
    assert_eq!(udp1.queries() + udp2.queries() + udp3.queries(), 4);
    assert_eq!(udp1.dials() + udp2.dials() + udp3.dials(), 4);
}

#[tokio::test]
async fn multi_ip_connectors_iterated_with_per_ip_reuse() {
    let a_udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let a_tcp = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let b_udp = MockConnector::new([10, 0, 0, 2], DnsTransport::Udp);
    let b_tcp = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(
        vec![a_udp.clone(), a_tcp.clone(), b_udp.clone(), b_tcp.clone()],
        config,
    );

    // Lookup 1: the fan-out queries both UDP legs concurrently; UDP@IP1
    // answers and the (possibly started) UDP@IP2 leg is aborted. TCP is
    // never touched while a UDP leg succeeds.
    a_udp.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(a_tcp.dials(), 0);
    assert_eq!(b_tcp.dials(), 0);

    // Lookup 2: UDP@IP1 reused (one socket for the whole test).
    a_udp.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(a_udp.dials(), 1);

    // Lookup 3: both UDP legs time out → the attempt falls through to
    // the stream (TCP) phase, where TCP@IP1 answers.
    a_udp.push(Err(DnsConnError::Timeout));
    b_udp.push(Err(DnsConnError::Timeout));
    a_tcp.push(Ok(ok_answer()));
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(a_udp.queries(), 3);
    assert_eq!(a_tcp.dials(), 1);
}

#[tokio::test]
async fn failed_fallback_does_not_mask_connectivity_error() {
    // The UDP phase times out (connectivity-class) and the stream fallback
    // hits the cap (NoConnections, capacity-class): the reported error must
    // be the Timeout — the more informative one — independent of which
    // phase finishes last. The same selection also keeps the health
    // accounting honest: connectivity failures flip the upstream offline,
    // whereas a surfaced NoConnections would have been ignored.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.max_conns = 0;
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    for _ in 0..3 {
        udp.push(Err(DnsConnError::Timeout));
    }
    for _ in 0..3 {
        let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Timeout));
    }
    // Three consecutive Timeouts flip the upstream offline (a masked
    // NoConnections would have left it online forever).
    assert!(pool.health.offline.load(Ordering::Relaxed));
    // The stream connector was never dialed: max_conns = 0 refuses every
    // dial before it can reach the network.
    assert_eq!(stream.dials(), 0);
}

#[tokio::test]
async fn fanout_panicked_leg_does_not_poison_selection() {
    // A leg task that panics mid-query (e.g. an internal invariant
    // violation in a transport) must not take down the fan-out: it counts
    // as no outcome and the healthy leg's answer wins.
    let healthy = MockConnector::new([10, 0, 0, 2], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    let pool = UpstreamPool::with_connectors(
        vec![
            Arc::new(PanicConnector {
                ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            }),
            healthy.clone(),
        ],
        config,
    );
    healthy.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(healthy.queries(), 1);
    assert_eq!(pool.conn_count(), 1);
}

//! Lookup retry-loop tests: error taxonomy, attempt budgets, truncation
//! fallback, and the leg-rotation helper.

use super::*;

#[tokio::test]
async fn protocol_negative_answers_are_final() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    let pool = stream_pool(connector.clone(), 3);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    // No retry for negative answers (old RetryDnsHandle behaviour).
    assert_eq!(connector.queries(), 1);
    // Protocol answers prove the connection is alive: it survives.
    assert_eq!(connector.dials(), 1);
}

#[tokio::test]
async fn noerror_empty_answer_is_negative_and_final() {
    // A NoData answer (NoError, no records) is a negative answer: it must
    // be surfaced as Protocol(NoError) without retrying.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut message = Message::response(0, hickory_proto::op::OpCode::Query);
    message.metadata.response_code = ResponseCode::NoError;
    connector.push(Ok(message));
    let pool = stream_pool(connector.clone(), 3);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NoError, _)));
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn nxdomain_with_authority_soa_is_negative() {
    // A negative answer usually carries the zone SOA in the authority
    // section; it must still be treated as a final negative answer.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut message = Message::response(0, hickory_proto::op::OpCode::Query);
    message.metadata.response_code = ResponseCode::NXDomain;
    message.authorities.push(Record::from_rdata(
        Name::from_str("example.com.").unwrap(),
        60,
        RData::SOA(hickory_proto::rr::rdata::SOA::new(
            Name::from_str("ns.example.com.").unwrap(),
            Name::from_str("admin.example.com.").unwrap(),
            1,
            3600,
            600,
            86400,
            300,
        )),
    ));
    connector.push(Ok(message));
    let pool = stream_pool(connector.clone(), 3);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn server_error_codes_are_final() {
    // An explicit protocol answer (ServFail) means the server is alive and
    // answering: matching the old hickory RetryDnsHandle, which never
    // retried response-code errors, it is final after one attempt instead
    // of burning the retry budget on a deterministic answer (which would
    // amplify load and latency on an erroring upstream). Endpoint
    // diversity within that one attempt still comes from the fan-out.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Err(DnsConnError::Protocol(ResponseCode::ServFail, None)));
    let pool = stream_pool(connector.clone(), 3);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::ServFail, _)));
    assert_eq!(connector.queries(), 1);
    assert_eq!(connector.dials(), 1);
}

#[tokio::test]
async fn all_attempts_fail_with_timeout() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Err(DnsConnError::Timeout));
    let pool = stream_pool(connector.clone(), 3);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Timeout));
    assert_eq!(connector.queries(), 3);
    // The first failure keeps the conn (stream threshold 2), the second
    // retires it, and the final attempt dials a fresh one.
    assert_eq!(connector.dials(), 2);
}

#[tokio::test]
async fn lookup_total_budget_bounds_phased_attempts() {
    // A UDP truncation forces a stream retry, and every stream dial is
    // cold and slow: without the lookup-level budget the three attempts
    // would run dial + query each (300 + 400 + 300 per attempt after the
    // truncation), far past the 3 × query_timeout + connect_timeout
    // deadline. The deadline must cut the last attempt short.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(300);
    config.connect_timeout = Duration::from_millis(500);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);
    // Attempt 1: a truncated UDP answer arrives within the query budget.
    udp.push_after(Duration::from_millis(250), Ok(truncated_answer()));
    // Attempts 2-3: slow cold dials plus queries that would outlive the
    // deadline.
    stream.set_dial_delay_ms(400);
    for _ in 0..3 {
        stream.push_after(Duration::from_millis(500), Err(DnsConnError::Timeout));
    }

    let started = tokio::time::Instant::now();
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    let elapsed = started.elapsed();

    // The deadline cut the last attempt short; the truncated answer from
    // attempt 1 surfaces once the stream retries cannot complete in time
    // (B1: a truncated answer outranks a fabricated internal error).
    assert_eq!(records.len(), 1);
    // Deadline = 3 × 300ms + 500ms = 1400ms. Without the deadline the
    // third attempt would run its full dial + query (700ms more). The
    // bands are generous for CI scheduling noise.
    assert!(elapsed < Duration::from_millis(2000), "lookup took {elapsed:?}");
    // And the budget was actually used: attempts really ran (not a
    // degenerate early exit).
    assert!(elapsed > Duration::from_millis(1150), "lookup took {elapsed:?}");
}

#[tokio::test]
async fn stream_truncated_answer_retried_then_returned_as_is() {
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    // A truncated response on a stream transport is retried exactly once
    // (the retry switches to stream-only connectors, which is already
    // what this pool uses), then the partial answer is returned as-is
    // instead of looping for the remaining attempts.
    connector.push(Ok(truncated_answer()));
    connector.push(Ok(truncated_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.queries(), 2);
}

#[tokio::test]
async fn force_stream_without_stream_connectors_returns_truncated_answer() {
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    udp.push(Ok(truncated_answer()));
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp.clone()], config);

    // No stream connector exists: the stream-only retries have nothing to
    // run, so the truncated answer itself is surfaced (the data exists).
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(udp.queries(), 1);
}

#[test]
fn rotate_capped_respects_cap_and_rotates() {
    use std::collections::HashSet;

    let legs = vec![0usize, 1, 2, 3];
    // Cap >= len: every leg exactly once.
    let mut all = rotate_capped(&legs, 4);
    all.sort();
    assert_eq!(all, legs);
    // Cap < len: exactly cap distinct legs.
    let capped = rotate_capped(&legs, 2);
    assert_eq!(capped.len(), 2);
    assert!(capped.iter().all(|i| legs.contains(i)));
    // Empty inputs.
    assert!(rotate_capped(&[], 4).is_empty());
    assert!(rotate_capped(&legs, 0).is_empty());
    // Random rotation: with a cap of 1 the chosen leg varies across
    // draws (P(all 64 draws identical) ~ (1/4)^63).
    let seen: HashSet<usize> = (0..64).map(|_| rotate_capped(&legs, 1)[0]).collect();
    assert!(seen.len() > 1);
}

#[tokio::test]
async fn truncation_on_final_attempt_gets_extra_stream_attempt() {
    // Attempts 1-2: the UDP legs fail and the in-attempt stream fallback
    // fails too. Attempt 3 (the final one): the UDP leg answers truncated —
    // the extra stream-only attempt then runs and recovers the full answer.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(200);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    udp.push(Err(DnsConnError::Timeout));
    udp.push(Err(DnsConnError::Timeout));
    udp.push(Ok(truncated_answer()));
    stream.push(Err(DnsConnError::Timeout));
    stream.push(Err(DnsConnError::Timeout));
    stream.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // Attempts 1-2 each ran one stream fallback query; the extra
    // post-truncation attempt dialed a fresh conn (the fallback conn was
    // retired after its second failure) and recovered the full answer.
    assert_eq!(stream.queries(), 3);
    assert_eq!(stream.dials(), 2);
}

#[tokio::test]
async fn lookup_keeps_pool_alive_when_caller_drops_its_arc() {
    // The pool's `lookup` borrows the caller's `Arc` (it is invoked through
    // the rule runtime, which holds the only external reference). When that
    // reference goes away mid-lookup — e.g. a `ResolvePool` sweep reclaims
    // the map entry while a query is in flight — the in-flight future must
    // still complete: the lookup path itself holds a strong reference for
    // its duration.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);
    connector.push(Ok(ok_answer()));

    let handle = tokio::spawn({
        let pool = pool.clone();
        async move { pool.lookup("example.com.", RecordType::A).await }
    });
    // The caller drops its only reference while the lookup is pending: the
    // spawned task's clone keeps the pool (and its maintenance task) alive.
    drop(pool);

    let records = handle.await.unwrap().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn truncation_on_final_attempt_with_failed_stream_returns_truncated() {
    // Same setup, but every stream retry (including the extra attempt)
    // fails: the truncated answer is returned as-is instead of a
    // fabricated internal error.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(200);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    udp.push(Err(DnsConnError::Timeout));
    udp.push(Err(DnsConnError::Timeout));
    udp.push(Ok(truncated_answer()));
    stream.push(Err(DnsConnError::Timeout));
    stream.push(Err(DnsConnError::Timeout));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    // The truncated answer carries the A record of `ok_answer()`.
    assert_eq!(records.len(), 1);
    // Two fallback queries (attempts 1-2) + the extra attempt's fresh conn
    // (its scripted queue is exhausted, so it times out) — the truncated
    // answer surfaces once every stream retry is spent.
    assert_eq!(stream.queries(), 3);
    assert_eq!(stream.dials(), 2);
}

#[tokio::test]
async fn truncation_with_single_attempt_recovers_over_stream() {
    // attempts = 1: the truncated UDP answer consumes the only attempt, yet
    // the pool still runs one stream-only retry under the remaining
    // deadline and returns the recovered full answer.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.query_timeout = Duration::from_millis(200);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    udp.push(Ok(truncated_answer()));
    stream.push(Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(stream.queries(), 1);
}

#[tokio::test]
async fn force_stream_failure_does_not_repeat_stream_phase() {
    // Plaintext pool: after a UDP truncation forces stream-only retries, a
    // failed stream attempt must not fall through to a second stream
    // fan-out within the same attempt.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(100);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    udp.push(Ok(truncated_answer()));
    stream.push(Err(DnsConnError::Timeout));
    stream.push(Err(DnsConnError::Timeout));

    // Once the stream retries are spent, the truncated answer surfaces.
    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // Attempts 2-3 each ran exactly one stream query, plus the extra
    // post-truncation attempt: 3 queries and 2 dials (the stream conn was
    // retired after its second consecutive failure). A repeated stream
    // phase per attempt would have queried 4 times.
    assert_eq!(stream.queries(), 3);
    assert_eq!(stream.dials(), 2);
}

#[tokio::test]
async fn truncated_udp_stream_retry_nxdomain_beats_partial_answer() {
    // A truncated UDP answer only surfaces when the stream retry fails at
    // the transport level. An explicit negative from the stream retry is
    // more authoritative: the NXDomain wins over the partial UDP answer
    // (old hickory-resolver semantics).
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    udp.push(Ok(truncated_answer()));
    stream.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    // One truncated UDP query; the stream retry answered the negative and
    // the partial answer was discarded (no further attempts).
    assert_eq!(udp.queries(), 1);
    assert_eq!(stream.queries(), 1);
    assert_eq!(stream.dials(), 1);
}

#[tokio::test]
async fn truncated_empty_udp_answer_not_surfaced_as_success() {
    // A truncated response with NO answers must not surface as an empty
    // success: the caller would serve an empty NOERROR and cache it as a
    // negative for a domain that demonstrably exists. When the stream
    // retry also fails, the transport error is returned instead.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    config.query_timeout = Duration::from_millis(100);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    let mut empty_truncated = Message::response(0, hickory_proto::op::OpCode::Query);
    empty_truncated.metadata.truncation = true;
    udp.push(Ok(empty_truncated));
    stream.push(Err(DnsConnError::Timeout));
    stream.push(Err(DnsConnError::Timeout));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Timeout));
}

#[tokio::test]
async fn extra_stream_attempt_cut_by_deadline_surfaces_truncated_answer() {
    // The extra post-truncation stream attempt is bounded by the remaining
    // deadline: when the deadline fires mid-attempt (the tokio-timeout
    // branch, not a leg error), a truncated answer that carries data still
    // surfaces.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.query_timeout = Duration::from_millis(50);
    config.connect_timeout = Duration::from_millis(120);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    udp.push_after(Duration::from_millis(40), Ok(truncated_answer()));
    // The stream dial is slow enough that acquire (110ms) + query-timeout
    // (50ms) outlives the remaining deadline (50+120-40 = 130ms), so the
    // deadline fires mid-attempt instead of a leg error.
    stream.set_dial_delay_ms(110);
    stream.push_after(Duration::from_millis(500), Ok(ok_answer()));

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(stream.dials(), 1);
}

#[tokio::test]
async fn partial_truncated_answer_surfaces_truncated_flag() {
    // A partial (truncated) answer that surfaces after a failed stream
    // retry carries the truncated flag: the caller must not cache it as a
    // complete answer and must serve it with the TC bit.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let stream = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    config.query_timeout = Duration::from_millis(100);
    config.connect_timeout = Duration::from_millis(120);
    let pool = UpstreamPool::with_connectors(vec![udp.clone(), stream.clone()], config);

    udp.push(Ok(truncated_answer()));
    stream.push(Err(DnsConnError::Timeout));

    let answer = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert!(answer.truncated);
    assert_eq!(answer.records.len(), 1);
}

#[tokio::test]
async fn full_answer_is_not_truncated() {
    // A complete answer never sets the truncated flag.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    let pool = UpstreamPool::with_connectors(vec![udp.clone()], config);

    udp.push(Ok(ok_answer()));
    let answer = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert!(!answer.truncated);
    assert_eq!(answer.records.len(), 1);
}

#[tokio::test]
async fn negative_soa_survives_lookup() {
    // A negative answer's authority-section SOA travels with the protocol
    // error: the chain layer needs it for RFC 2308 negative caching.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 1;
    let pool = UpstreamPool::with_connectors(vec![udp.clone()], config);

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
    udp.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, Some(Box::new(soa)))));

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    match err {
        UpstreamError::Protocol(code, soa) => {
            assert_eq!(code, ResponseCode::NXDomain);
            let soa = soa.expect("SOA must be preserved");
            assert_eq!(soa.ttl, 300);
            assert!(matches!(soa.data, RData::SOA(_)));
        }
        other => panic!("expected Protocol(NXDomain, soa), got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_domain_returns_internal_error() {
    // A label longer than 63 bytes cannot be a valid DNS name: the pool
    // rejects it before touching any connection.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let pool = stream_pool(connector.clone(), 3);

    let err = pool.lookup(&"a".repeat(64), RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Internal(msg) if msg.contains("invalid domain")));
    assert_eq!(connector.queries(), 0);
    assert_eq!(connector.dials(), 0);
}

#[test]
fn request_options_sets_recursion_edns_and_payload() {
    let options = request_options();
    assert!(options.recursion_desired);
    assert!(options.use_edns);
    assert_eq!(options.edns_payload_len, hickory_proto::op::DEFAULT_MAX_PAYLOAD_LEN);
}

#[tokio::test]
async fn empty_truncated_stream_answer_preserves_the_udp_partial() {
    // Attempt 1 (UDP): a truncated answer carrying data. Attempt 2 (TCP,
    // forced by the truncation): a degenerate TC-only, record-less answer.
    // The stored non-empty UDP partial must win over the error the stream
    // answer degenerated to — discarding it would turn a demonstrably
    // existing domain into an intermittent SERVFAIL.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let tcp = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    udp.push(Ok(truncated_answer()));
    tcp.push(Ok(empty_truncated_answer()));
    tcp.push(Ok(empty_truncated_answer()));
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp, tcp.clone()], config);

    let answer = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert!(answer.truncated, "the partial must keep the TC flag so the client retries over TCP");
    assert_eq!(answer.records.len(), 1);
    assert!(matches!(&answer.records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(tcp.queries(), 2, "stream phase runs in-loop and once more post-loop");
}

#[tokio::test]
async fn protocol_answer_from_udp_legs_skips_tcp_fallback() {
    // An explicit ServFail from every UDP leg is a final answer (the
    // upstream is alive and said no): the UDP→TCP fallback must not
    // re-query the same server — that doubles latency and load for nothing.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let tcp = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    udp.push(Err(DnsConnError::Protocol(ResponseCode::ServFail, None)));
    // Would satisfy the query if the (wrong) TCP fallback ran.
    tcp.push(Ok(ok_answer()));
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 3;
    let pool = UpstreamPool::with_connectors(vec![udp, tcp.clone()], config);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::ServFail, _)));
    assert_eq!(tcp.queries(), 0, "a protocol answer is final: no TCP fallback");
    assert_eq!(tcp.dials(), 0);
}

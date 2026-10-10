//! CNAME chain-following tests: follow-up queries for unresolved targets,
//! in-band chain detection, error propagation, and depth bounding.

use super::*;

#[tokio::test]
async fn cname_only_answer_follows_chain_with_follow_up_query() {
    // The upstream answers the A query with just a CNAME (chain not
    // resolved in-band): the pool must issue a follow-up query for the
    // target and accumulate both hops (old hickory-resolver behaviour).
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![cname_record("example.com.", "www.example.com.")])));
    connector.push(Ok(answer_with(vec![a_record([1, 2, 3, 4])])));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    // CNAME + final A, in chain order.
    assert_eq!(records.len(), 2);
    assert!(matches!(&records[0].data, RData::CNAME(_)));
    assert!(matches!(&records[1].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(connector.queries(), 2);
    // The follow-up reuses the same connection.
    assert_eq!(connector.dials(), 1);
}

#[tokio::test]
async fn cname_resolved_in_single_response_is_not_requeried() {
    // Recursive resolvers usually return the full chain (CNAME + final
    // records) in one response: no follow-up query must be issued.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![
        cname_record("example.com.", "www.example.com."),
        a_record_named("www.example.com.", [1, 2, 3, 4]),
    ])));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn cname_chain_follow_up_error_propagates() {
    // The follow-up hop answers NXDomain: the whole lookup fails with
    // the protocol error (old resolver chain semantics), without
    // retrying the negative answer.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![cname_record("example.com.", "missing.example.com.")])));
    connector.push(Err(DnsConnError::Protocol(ResponseCode::NXDomain, None)));
    let pool = stream_pool(connector.clone(), 3);

    let err = pool.lookup("example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Protocol(ResponseCode::NXDomain, _)));
    assert_eq!(connector.queries(), 2);
}

#[tokio::test]
async fn cname_chain_follow_up_transient_error_is_retried() {
    // The follow-up hop's first attempt fails transiently (timeout); the
    // chain query gets its own attempt budget and recovers the final
    // records — a single hiccup must not abandon the chain.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![cname_record("example.com.", "www.example.com.")])));
    connector.push(Err(DnsConnError::Timeout));
    connector.push(Ok(answer_with(vec![a_record([1, 2, 3, 4])])));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    // CNAME + final A, in chain order.
    assert_eq!(records.len(), 2);
    assert!(matches!(&records[1].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
    // 1 chain response + 2 follow-up attempts; the same connection served
    // both (one stream failure is below the retirement threshold).
    assert_eq!(connector.queries(), 3);
    assert_eq!(connector.dials(), 1);
}

#[tokio::test]
async fn cname_loop_is_bounded_by_max_depth() {
    // A CNAME loop (a → b → a) must terminate instead of hanging: the
    // accumulated chain is returned once the depth limit is reached.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![cname_record("example.com.", "loop.example.com.")])));
    // The loop bounces example.com ↔ loop.example.com; each follow-up
    // query must get the CNAME matching its own owner, alternating.
    for i in 0..pool_config::MAX_CNAME_DEPTH {
        let record = if i % 2 == 0 {
            cname_record("loop.example.com.", "example.com.")
        } else {
            cname_record("example.com.", "loop.example.com.")
        };
        connector.push(Ok(answer_with(vec![record])));
    }
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    // 1 initial response + MAX_CNAME_DEPTH follow-ups, all accumulated.
    assert_eq!(records.len(), pool_config::MAX_CNAME_DEPTH as usize + 1);
    assert_eq!(connector.queries() as usize, pool_config::MAX_CNAME_DEPTH as usize + 1);
}

#[tokio::test]
async fn cname_query_type_returns_records_without_chasing() {
    // A CNAME-typed query must be answered as-is (hickory parity): chasing
    // the target would typically answer NXDomain and discard the CNAME
    // records we already have.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![cname_record("example.com.", "www.example.com.")])));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::CNAME).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(&records[0].data, RData::CNAME(_)));
    // No follow-up query was issued for the target.
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn cname_chain_out_of_order_in_one_response_still_resolves() {
    // Answers chained out of order (mid→final before orig→mid): the fold
    // runs to a fixpoint, so the chain is completed without a redundant
    // follow-up query.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![
        cname_record("mid.example.com.", "final.example.com."),
        cname_record("example.com.", "mid.example.com."),
        a_record_named("final.example.com.", [1, 2, 3, 4]),
    ])));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn cname_cycle_within_one_response_terminates() {
    // A self-referential pair inside a single response must not hang the
    // fixpoint fold: it terminates (bounded by the CNAME record count) and
    // returns the records as-is.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    connector.push(Ok(answer_with(vec![
        cname_record("example.com.", "loop.example.com."),
        cname_record("loop.example.com.", "example.com."),
    ])));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(connector.queries(), 1);
}

#[tokio::test]
async fn cname_chain_truncated_follow_up_hop_keeps_truncated_flag() {
    // Hop 0: the complete CNAME alias -> target. Hop 1 (querying the
    // target): a truncated partial answer. The accumulated chain must
    // surface with the truncated flag: reporting the partial data as
    // complete would let the caller cache it, and the cut-off tail may
    // hold exactly the missing records.
    let udp = MockConnector::new([10, 0, 0, 1], DnsTransport::Udp);
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = 2;
    let pool = UpstreamPool::with_connectors(vec![udp.clone()], config);

    udp.push(Ok(answer_with(vec![cname_record("example.com.", "www.example.com.")])));
    udp.push(Ok(truncated_answer()));

    let answer = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert!(answer.truncated, "a truncated follow-up hop must surface the flag");
    // Exactly the chain accumulated: hop-0 CNAME plus the hop-1 partial
    // record (an exact count also guards against a double-append).
    assert_eq!(answer.records.len(), 2);
    assert!(matches!(&answer.records[0].data, RData::CNAME(_)));
    assert_eq!(udp.queries(), 2);
}

#[tokio::test]
async fn cname_completed_from_additional_section_keeps_the_final_records() {
    // The completing A record lives in the additional section (the
    // chain-completeness check deliberately scans authority/additional
    // too): the chain is complete — no follow-up query — and the final
    // records must still reach the client, not just the CNAME chain.
    let connector = MockConnector::new([10, 0, 0, 1], DnsTransport::Stream);
    let mut message = answer_with(vec![cname_record("example.com.", "www.example.com.")]);
    message.additionals.push(a_record_named("www.example.com.", [1, 2, 3, 4]));
    connector.push(Ok(message));
    let pool = stream_pool(connector.clone(), 3);

    let records = pool.lookup("example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 2, "CNAME plus the additional-section A record");
    assert!(matches!(&records[0].data, RData::CNAME(_)));
    assert!(matches!(&records[1].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(connector.queries(), 1);
}

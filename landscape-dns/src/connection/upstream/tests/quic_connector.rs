//! Native quinn DoQ connector tests against a minimal echo peer (the
//! hickory-net `test_quic_stream` pattern): round-trip fidelity, the RFC 9250
//! id-0 validation, stream reuse across sequential queries, and IPv6.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::RData;
use hickory_server::proto::rr::rdata::A;

use super::tls_support::*;
use super::traits::DnsConnError;

/// Full round-trip fidelity against a minimal quinn echo peer (the
/// hickory-net `test_quic_stream` assertion, `*response ==
/// message.into_response()`): the response must echo the question, carry the
/// served answer, and reset the id to 0 (RFC 9250).
#[tokio::test]
async fn doq_native_connector_round_trips_message() {
    let tls = test_tls();
    let server = spawn_quic_echo_server(&tls, IpAddr::V4(Ipv4Addr::LOCALHOST), false);
    let connector = quic_connector(server.port(), &tls, Duration::from_secs(60), true);

    let conn = connector.connect().await.unwrap();
    let message = conn.query(&www_query(), &request_options()).await.unwrap();

    assert_eq!(message.metadata.id, 0);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.queries, vec![www_query()]);
    assert_eq!(message.answers.len(), 1);
    assert!(
        matches!(&message.answers[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4))
    );
}

/// RFC 9250 §4.2.1: a response with a non-zero message id must be rejected —
/// the stream mapping makes the id redundant, so a non-zero one marks a
/// broken peer. The echo server mangles the id to exercise the validation.
#[tokio::test]
async fn doq_native_connector_rejects_nonzero_response_id() {
    let tls = test_tls();
    let server = spawn_quic_echo_server(&tls, IpAddr::V4(Ipv4Addr::LOCALHOST), true);
    let connector = quic_connector(server.port(), &tls, Duration::from_secs(60), true);

    let conn = connector.connect().await.unwrap();
    let err = conn.query(&www_query(), &request_options()).await.unwrap_err();
    assert!(matches!(err, DnsConnError::Io(_)), "expected an I/O error, got {err:?}");
}

/// Sequential queries ride one connection, each on a fresh QUIC stream
/// (stream ids 0, 4, 8, ...) — the hickory-net `SEND_RECV_TIMES` loop.
#[tokio::test]
async fn doq_native_connector_reuses_connection_across_queries() {
    let tls = test_tls();
    let server = spawn_quic_echo_server(&tls, IpAddr::V4(Ipv4Addr::LOCALHOST), false);
    let connector = quic_connector(server.port(), &tls, Duration::from_secs(60), true);

    let conn = connector.connect().await.unwrap();
    for _ in 0..4 {
        let message = conn.query(&www_query(), &request_options()).await.unwrap();
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.metadata.id, 0);
    }
}

/// IPv6 path: the connector binds its QUIC socket on the v6 unspecified
/// address and dials `::1` (hickory-net runs its TCP tests on both stacks;
/// the v6 branch of the connector's bind-address logic needs real coverage).
#[tokio::test]
async fn doq_native_connector_round_trips_over_ipv6() {
    let tls = test_tls();
    let server = spawn_quic_echo_server(&tls, IpAddr::V6(Ipv6Addr::LOCALHOST), false);
    let connector = quic_connector_at(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        server.port(),
        &tls,
        Duration::from_secs(60),
        true,
    );

    let conn = connector.connect().await.unwrap();
    let message = conn.query(&www_query(), &request_options()).await.unwrap();
    assert_eq!(message.answers.len(), 1);
}

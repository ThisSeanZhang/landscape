//! Real-transport failure-mode coverage against a scripted plaintext peer
//! (see [`crate::connection::test_util::ScriptedDnsServer`]): explicit
//! error codes over the wire, restarts on the same port, TCP RSTs,
//! spoofed/late frames, blackholes, and a flapping upstream. These are the
//! conditions under which a resolver bug turns into "the user lost
//! internet", so they run against the actual UDP/TCP transport paths.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hickory_proto::op::DnsRequestOptions;
use hickory_proto::op::Query;
use hickory_proto::rr::Name;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::RData;
use hickory_server::proto::rr::RecordType;
use hickory_server::proto::rr::rdata::A;
use landscape_common::dns::bind::DnsBindConfig;
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;
use std::str::FromStr;

use crate::connection::provider::MarkRuntimeProvider;
use crate::connection::test_util::{ScriptedAction, ScriptedDnsServer};
use crate::connection::upstream::UpstreamPool;
use crate::connection::upstream::native::build_connectors;
use crate::connection::upstream::pool_config;
use crate::connection::upstream::pool_config::PoolConfig;
use crate::connection::upstream::pool_config::PoolSettings;
use crate::connection::upstream::traits::DnsTransport;

/// One dead-phase script per transport: enough drops for every attempt of
/// a fully-blackholed lookup (`DEFAULT_ATTEMPTS`), plus margin so a
/// scheduling hiccup can never run the queue dry — the dry-script default
/// is `Answer`, which would silently flip a dead phase into a success.
fn push_dead_phase(server: &ScriptedDnsServer) {
    for _ in 0..(pool_config::DEFAULT_ATTEMPTS as usize + 1) {
        server.push_udp(ScriptedAction::Drop);
        server.push_tcp(ScriptedAction::Drop);
    }
}

/// A plaintext pool against `port` with the fixed default settings.
fn plaintext_pool(port: u16) -> Arc<UpstreamPool> {
    let upstream = DnsUpstreamConfig {
        remark: "scripted".into(),
        mode: DnsUpstreamMode::Plaintext,
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        ..Default::default()
    };
    UpstreamPool::new(
        7,
        0x8000,
        &upstream,
        MarkRuntimeProvider::new(0x8000, DnsBindConfig::default()),
        &PoolSettings::default(),
        None,
    )
    .unwrap()
}

/// P0-B1 end-to-end lock: an upstream answering SERVFAIL over the real
/// TCP/UDP wire must surface as `Protocol(ServFail)` — never as a
/// successful empty answer (which the chain layer would cache as a
/// NOERROR negative for the domain). A protocol answer also proves the
/// upstream is alive: no offline flip.
#[tokio::test]
async fn servfail_over_real_transports_surfaces_as_protocol() {
    let server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    // An explicit protocol code is final after the first attempt, so one
    // scripted SERVFAIL per transport suffices (a second is pushed as
    // margin; the dry-script default would be Answer, never an error).
    for _ in 0..2 {
        server.push_udp(ScriptedAction::Code(ResponseCode::ServFail));
        server.push_tcp(ScriptedAction::Code(ResponseCode::ServFail));
    }
    let pool = plaintext_pool(server.port());

    let err = pool.lookup("www.example.com.", RecordType::A).await.unwrap_err();
    assert!(
        matches!(
            err,
            crate::connection::upstream::UpstreamError::Protocol(ResponseCode::ServFail, _)
        ),
        "expected Protocol(ServFail), got {err:?}"
    );
    assert!(!pool.health.offline.load(std::sync::atomic::Ordering::Relaxed));
}

/// An upstream that dies and comes back on the same port: queries fail
/// while it is gone and recover without rebuilding the pool.
#[tokio::test]
async fn upstream_restart_on_same_port_recovers() {
    let mut server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let pool = plaintext_pool(server.port());

    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(server.queries() >= 1, "the first lookup must have reached the server");

    server.kill();
    assert!(pool.lookup("www.example.com.", RecordType::A).await.is_err());

    server.restart_on_same_port().await;
    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
}

/// A TCP RST mid-query fails the lookup (nothing satisfies it with a
/// garbage answer); the pool redials and the next query succeeds.
#[tokio::test]
async fn tcp_reset_fails_query_then_next_query_redials() {
    let server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let pool = plaintext_pool(server.port());

    // First lookup: UDP blackholed, every TCP attempt reset.
    for _ in 0..(pool_config::DEFAULT_ATTEMPTS as usize + 1) {
        server.push_udp(ScriptedAction::Drop);
        server.push_tcp(ScriptedAction::Reset);
    }
    assert!(pool.lookup("www.example.com.", RecordType::A).await.is_err());

    // The next lookup dials fresh and succeeds.
    server.push_udp(ScriptedAction::Answer);
    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
}

/// Spoofed frames arriving before the real answer (a wrong-id frame and a
/// wrong-question frame, each carrying an enticing answer) must be dropped
/// by the client's validators — the real answer still completes the query.
/// Both transports of the pool are exercised: the UDP leg sees the spoof
/// sequence, the TCP legs are kept dead so success can only come from UDP.
#[tokio::test]
async fn udp_spoofed_frames_do_not_satisfy_query() {
    let server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let pool = plaintext_pool(server.port());

    server.push_udp(ScriptedAction::SpoofThenAnswer);
    for _ in 0..(pool_config::DEFAULT_ATTEMPTS as usize + 1) {
        server.push_tcp(ScriptedAction::Drop);
    }

    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    // The spoofed frames answered 6.6.6.6: only the real answer (1.2.3.4)
    // proves the spoof attempts were discarded instead of believed.
    assert!(
        matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)),
        "the spoofed answer must not satisfy the query, got {:?}",
        records[0].data
    );
}

/// The stream-mux counterpart of [`udp_spoofed_frames_do_not_satisfy_query`]:
/// the same spoof sequence over TCP exercises the multiplexer's wire-path
/// validators (dispatch by id, then question-section echo) instead of only
/// the in-process unit tests — a spoofed frame with the right id but a
/// foreign question must be re-queued, never delivered as the answer.
/// Connector-level (no pool) so the verdict is the mux's alone.
#[tokio::test]
async fn tcp_spoofed_frames_do_not_satisfy_query() {
    let server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;

    let connectors = build_connectors(
        &DnsUpstreamMode::Plaintext,
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        Some(server.port()),
        MarkRuntimeProvider::new(0x8000, DnsBindConfig::default()),
        &PoolConfig::for_mode(&DnsUpstreamMode::Plaintext),
        None,
    );
    let tcp = connectors
        .into_iter()
        .find(|c| c.transport() == DnsTransport::Stream)
        .expect("plaintext builds a TCP connector");
    let conn = tcp.connect().await.expect("TCP dial against the scripted peer");

    server.push_tcp(ScriptedAction::SpoofThenAnswer);
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    let message = conn.query(&query, &DnsRequestOptions::default()).await.expect("real answer");
    assert_eq!(message.answers.len(), 1);
    assert!(
        matches!(&message.answers[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)),
        "the spoofed answer must not satisfy the query, got {:?}",
        message.answers[0].data
    );
}

/// A blackholed upstream (queries dropped on both transports) surfaces as
/// an error after the attempt budget, and recovers as soon as it answers
/// again.
#[tokio::test]
async fn blackholed_upstream_times_out_then_recovers() {
    let server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let pool = plaintext_pool(server.port());

    push_dead_phase(&server);
    assert!(pool.lookup("www.example.com.", RecordType::A).await.is_err());

    server.push_udp(ScriptedAction::Answer);
    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
}

/// A flapping upstream (answers, dies, answers, ...) keeps serving through
/// the pool: each good phase answers, each dead phase errors, and the
/// health tracker never wedges the pool (two consecutive failed lookups
/// stay below the offline threshold; the final lookup still succeeds).
#[tokio::test]
async fn flapping_upstream_keeps_serving() {
    let server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    let pool = plaintext_pool(server.port());

    // Good.
    server.push_udp(ScriptedAction::Answer);
    assert_eq!(pool.lookup("www.example.com.", RecordType::A).await.unwrap().len(), 1);
    // Dead.
    push_dead_phase(&server);
    assert!(pool.lookup("www.example.com.", RecordType::A).await.is_err());
    // Good again.
    server.push_udp(ScriptedAction::Answer);
    assert_eq!(pool.lookup("www.example.com.", RecordType::A).await.unwrap().len(), 1);
    // Dead again.
    push_dead_phase(&server);
    assert!(pool.lookup("www.example.com.", RecordType::A).await.is_err());
    // Good again — never wedged.
    server.push_udp(ScriptedAction::Answer);
    assert_eq!(pool.lookup("www.example.com.", RecordType::A).await.unwrap().len(), 1);
    assert!(!pool.health.offline.load(std::sync::atomic::Ordering::Relaxed));
}

/// A half-open upstream (TCP established, but the peer read the request and
/// never answers, never closes): the client's query timeout fires, the
/// connection accumulates the two stream failures it needs to be retired,
/// and the next lookup redials fresh and recovers. The UDP leg is kept
/// dead throughout so success can only come from the TCP path.
#[tokio::test]
async fn half_open_tcp_connection_times_out_is_retired_and_redialled() {
    let server = ScriptedDnsServer::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    // One attempt per lookup (UDP blackhole + TCP fallback both run inside
    // a single attempt) keeps the test under a few seconds.
    let upstream = DnsUpstreamConfig {
        remark: "scripted".into(),
        mode: DnsUpstreamMode::Plaintext,
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(server.port()),
        ..Default::default()
    };
    let settings = PoolSettings { attempts: Some(1), ..PoolSettings::default() };
    let pool = UpstreamPool::new(
        7,
        0x8000,
        &upstream,
        MarkRuntimeProvider::new(0x8000, DnsBindConfig::default()),
        &settings,
        None,
    )
    .unwrap();

    // Both lookups: UDP drops, TCP holds open. The first lookup costs the
    // held-open connection one failure, the second its second (retirement)
    // failure.
    for _ in 0..3 {
        server.push_udp(ScriptedAction::Drop);
    }
    server.push_tcp(ScriptedAction::HoldOpen);
    assert!(pool.lookup("www.example.com.", RecordType::A).await.is_err());
    assert!(pool.lookup("www.example.com.", RecordType::A).await.is_err());

    // Third lookup: the retired connection is gone; the fresh TCP dial is
    // served by the (now empty) script default `Answer`.
    server.push_udp(ScriptedAction::Drop);
    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
}

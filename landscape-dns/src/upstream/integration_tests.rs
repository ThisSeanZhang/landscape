//! End-to-end tests of the native upstream pool against loopback UDP and TCP servers.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crate::upstream::native::UpstreamPool;
use crate::upstream::native::mark::MarkRuntimeProvider;
use crate::upstream::native::pool_config::PoolSettings;
use crate::upstream::test_util::{
    ScriptedAction, ScriptedDnsServer, mark_supported_or_fail, spawn_plaintext_server,
};
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::{RData, RecordType};
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;

/// Builds the pool the same way `create_resolver` does for a
/// `use_experimental_pool` upstream under the `pool-native` feature.
fn make_pool(flow_id: u32, mark: u32, upstream: &DnsUpstreamConfig) -> Arc<UpstreamPool> {
    UpstreamPool::new(
        flow_id,
        mark,
        upstream,
        MarkRuntimeProvider::new(mark, upstream.bind_config.clone()),
        &PoolSettings::default(),
        None,
    )
    .expect("build upstream pool")
}

async fn spawn_test_server() -> (u16, tokio::task::JoinHandle<()>) {
    spawn_plaintext_server(Ipv4Addr::LOCALHOST, true).await
}

fn plaintext_upstream(port: u16) -> DnsUpstreamConfig {
    DnsUpstreamConfig {
        remark: "test".into(),
        mode: DnsUpstreamMode::Plaintext,
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        port: Some(port),
        ..Default::default()
    }
}

#[tokio::test]
async fn plaintext_lookup_via_pool_answers_from_local_server() {
    if !mark_supported_or_fail() {
        return;
    }
    let (port, _server) = spawn_test_server().await;
    let upstream = plaintext_upstream(port);
    let pool = make_pool(7, 0x8000, &upstream);

    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type(), RecordType::A);
    assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
}

#[tokio::test]
async fn plaintext_lookup_reuses_connection_across_queries() {
    if !mark_supported_or_fail() {
        return;
    }
    let (port, _server) = spawn_test_server().await;
    let upstream = plaintext_upstream(port);
    let pool = make_pool(7, 0x8000, &upstream);

    for _ in 0..3 {
        let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
        assert_eq!(records.len(), 1);
    }
    // One UDP socket and one TCP connection should have been dialed in total.
    assert!(pool.conn_count() <= 2);
}

#[tokio::test]
async fn cname_alias_resolves_through_pool() {
    if !mark_supported_or_fail() {
        return;
    }
    // The authoritative server resolves the alias chain in-band, returning
    // the CNAME in the answer section and the target's A record in the
    // ADDITIONAL section. The pool's completion check scans all sections
    // (hickory parity — the old `caching_client` scanned `all_sections()`),
    // so it recognizes the chain as complete without a follow-up query —
    // and since the completion check reads all sections, the final records
    // they carry must be returned too: a "complete" answer that omitted
    // the target's A record would leave the client with an unresolvable
    // CNAME chain.
    let (port, _server) = spawn_test_server().await;
    let upstream = plaintext_upstream(port);
    let pool = make_pool(7, 0x8000, &upstream);

    let records = pool.lookup("alias.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 2, "CNAME plus the additional-section A record");
    assert_eq!(records[0].record_type(), RecordType::CNAME);
    assert_eq!(records[1].record_type(), RecordType::A);
}

#[tokio::test]
async fn plaintext_nxdomain_passes_through() {
    if !mark_supported_or_fail() {
        return;
    }
    let (port, _server) = spawn_test_server().await;
    let upstream = plaintext_upstream(port);
    let pool = make_pool(7, 0x8000, &upstream);

    let err = pool.lookup("missing.example.com.", RecordType::A).await.unwrap_err();
    match err {
        crate::upstream::native::UpstreamError::Protocol(
            hickory_server::proto::op::ResponseCode::NXDomain,
            soa,
        ) => {
            // The authority-section SOA travels with the negative answer for
            // RFC 2308 negative caching (this zone's SOA: TTL 3600, MINIMUM
            // 300).
            let soa = soa.expect("NXDomain must carry its authority SOA");
            assert_eq!(soa.ttl, 3600);
            assert!(matches!(soa.data, RData::SOA(_)));
        }
        other => panic!("expected Protocol(NXDomain, soa), got {other:?}"),
    }
}

#[tokio::test]
async fn udp_truncation_falls_back_to_tcp_end_to_end() {
    if !mark_supported_or_fail() {
        return;
    }
    // The big TXT answer exceeds the client's EDNS payload (1232), so the
    // UDP response carries the TC bit and the pool retries over TCP — the
    // real-transport path of the truncation fallback.
    let (port, _server) = spawn_test_server().await;
    let upstream = plaintext_upstream(port);
    let pool = make_pool(7, 0x8000, &upstream);

    let result = pool.lookup("big.example.com.", RecordType::TXT).await;
    let records = result.unwrap();
    assert_eq!(records.len(), 1);
    let RData::TXT(txt) = &records[0].data else {
        panic!("expected a TXT answer, got {:?}", records[0].data);
    };
    let joined: String = txt.txt_data.iter().flat_map(|s| s.iter()).map(|b| *b as char).collect();
    assert_eq!(joined.len(), 2000);
    assert!(joined.chars().all(|c| c == 'x'));
    // The truncated UDP attempt must have been followed by a TCP connection.
    assert!(pool.conn_count() >= 2);
}

#[tokio::test]
async fn multi_ip_fanout_prefers_positive_over_nxdomain_endpoint() {
    if !mark_supported_or_fail() {
        return;
    }
    let empty_ip = Ipv4Addr::new(127, 0, 0, 2);
    // Not every container binds the whole 127.0.0.0/8 range; skip instead
    // of failing when the second loopback IP is unavailable.
    if std::net::UdpSocket::bind((empty_ip, 0)).is_err() {
        eprintln!("skipping: cannot bind {empty_ip} (127.0.0.0/8 restricted)");
        return;
    }
    let content = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
    let empty = ScriptedDnsServer::spawn_on_port(empty_ip.into(), content.port()).await;
    let release_answer = Arc::new(tokio::sync::Notify::new());
    let nxdomain = ScriptedAction::Negative {
        code: ResponseCode::NXDomain,
        soa: Some((3600, 300)),
        alias_ttl: None,
    };
    content.push_udp(ScriptedAction::AnswerOn(release_answer.clone()));
    empty.push_udp(nxdomain.clone());

    let upstream = DnsUpstreamConfig {
        remark: "multi-ip".into(),
        mode: DnsUpstreamMode::Plaintext,
        ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V4(empty_ip)],
        port: Some(content.port()),
        ..Default::default()
    };
    let pool = make_pool(7, 0x8000, &upstream);

    // Let the positive endpoint reply only once the other endpoint has received the query.
    let (result, ()) = tokio::join!(pool.lookup("www.example.com.", RecordType::A), async {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while empty.queries() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("NXDOMAIN endpoint did not receive the fan-out query");
        release_answer.notify_one();
    });
    let records = result.unwrap();
    assert_eq!([content.queries(), empty.queries()], [1, 1]);
    assert_eq!(records.len(), 1);
    assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));

    // A name neither endpoint has answers NXDomain after the fan-out.
    content.push_udp(nxdomain.clone());
    empty.push_udp(nxdomain);
    let err = pool.lookup("missing.example.com.", RecordType::A).await.unwrap_err();
    assert!(matches!(
        err,
        crate::upstream::native::UpstreamError::Protocol(ResponseCode::NXDomain, Some(_))
    ));
    assert_eq!([content.queries(), empty.queries()], [2, 2]);
}

#[tokio::test]
async fn plaintext_lookup_over_ipv6() {
    if !mark_supported_or_fail() {
        return;
    }
    // The v6 branches of the socket-creation paths (UDP bind/connect, TCP
    // bind/connect, source-address family selection) need real coverage;
    // skip instead of failing when the environment has no IPv6 loopback.
    let bind_ip = std::net::Ipv6Addr::LOCALHOST;
    if tokio::net::UdpSocket::bind((bind_ip, 0)).await.is_err() {
        eprintln!("skipping: no IPv6 loopback available");
        return;
    }
    let (port, _server) =
        crate::upstream::test_util::spawn_plaintext_server_at(std::net::IpAddr::V6(bind_ip), true)
            .await;

    let upstream = DnsUpstreamConfig {
        remark: "test-v6".into(),
        mode: DnsUpstreamMode::Plaintext,
        ips: vec![std::net::IpAddr::V6(bind_ip)],
        port: Some(port),
        ..Default::default()
    };
    let pool = make_pool(7, 0x8000, &upstream);

    let records = pool.lookup("www.example.com.", RecordType::A).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(&records[0].data, RData::A(A(ip)) if *ip == Ipv4Addr::new(1, 2, 3, 4)));
}

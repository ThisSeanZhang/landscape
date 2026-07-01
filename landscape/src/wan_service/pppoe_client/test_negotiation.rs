use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio::time::Duration;

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::{PPPOption, PointToPoint};
use landscape_common::net_proto::pppoe::PPPoEFrame;
use landscape_common::service::{ServiceStatus, WatchService};

use crate::pppoe_client::PPPoEClientConfig;

use super::error::PppoeError;
use super::lcp::LcpPhaseResult;
use super::negotiation::run;
use super::negotiation::NegotiationResult;
use super::{DEFAULT_TIMEOUT, ETH_P_PPOES, LCP_ECHO_INTERVAL};

fn ensure_test_env() {
    std::env::set_var("LANDSCAPE_IGNORE_CLI_ARGS", "1");
}

fn test_config() -> PPPoEClientConfig {
    PPPoEClientConfig::new(
        1,
        "eth0".into(),
        MacAddr::new(0x02, 0x03, 0x04, 0x05, 0x06, 0x07),
        "testuser".into(),
        "testpass".into(),
        false,
        1492,
    )
}

const SERVER_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

fn mock_lcp(auth_type: u16) -> LcpPhaseResult {
    LcpPhaseResult {
        session_id: 0x0042,
        server_mac: SERVER_MAC.to_vec(),
        mru: 1492,
        magic_number: 0xDEAD_BEEF,
        auth_type,
        peer_mru: 1492,
        peer_magic: 0xFEED_FACE,
    }
}

fn wrap_eth(dst: &[u8], src: &[u8], ethertype: u16, payload: Vec<u8>) -> Box<Vec<u8>> {
    let mut packet = dst.to_vec();
    packet.extend(src);
    packet.extend(ethertype.to_be_bytes());
    packet.extend(payload);
    Box::new(packet)
}

fn send_session(to_client: &mpsc::Sender<Box<Vec<u8>>>, sid: u16, ppp_payload: Vec<u8>) {
    let frame = PPPoEFrame {
        ver: 1,
        t: 1,
        code: 0,
        sid,
        length: ppp_payload.len() as u16,
        payload: ppp_payload,
    };
    let raw = wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOES, frame.convert_to_payload());
    to_client.try_send(raw).expect("send session packet");
}

fn extract_ppp(raw: &[u8], session_id: u16) -> Option<PointToPoint> {
    if raw.len() < 16 {
        return None;
    }
    if u16::from_be_bytes([raw[12], raw[13]]) != ETH_P_PPOES {
        return None;
    }
    let frame = PPPoEFrame::new(&raw[14..])?;
    if frame.sid != session_id {
        return None;
    }
    PointToPoint::new(&frame.payload)
}

// ── packet builders (using PointToPoint struct + convert_to_payload) ──

fn pap_pkt(code: u8, id: u8) -> Vec<u8> {
    PointToPoint {
        protocol: 0xc023,
        code,
        id,
        length: 4,
        payload: vec![],
    }
    .convert_to_payload()
}

fn chap_challenge(id: u8, challenge: &[u8]) -> Vec<u8> {
    let mut payload = vec![challenge.len() as u8];
    payload.extend(challenge);
    payload.extend(b"test-server");
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0xc223,
        code: 1,
        id,
        length: len,
        payload,
    }
    .convert_to_payload()
}

fn chap_status(code: u8, id: u8) -> Vec<u8> {
    PointToPoint {
        protocol: 0xc223,
        code,
        id,
        length: 4,
        payload: vec![],
    }
    .convert_to_payload()
}

fn ipcp_ack(id: u8, ip: Ipv4Addr) -> Vec<u8> {
    let octets = ip.octets();
    let payload = [3, 6, octets[0], octets[1], octets[2], octets[3]];
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0x8021,
        code: 2,
        id,
        length: len,
        payload: payload.to_vec(),
    }
    .convert_to_payload()
}

fn ipcp_nak(id: u8, suggested_ip: Ipv4Addr) -> Vec<u8> {
    let octets = suggested_ip.octets();
    let payload = [3, 6, octets[0], octets[1], octets[2], octets[3]];
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0x8021,
        code: 3,
        id,
        length: len,
        payload: payload.to_vec(),
    }
    .convert_to_payload()
}

fn ipcp_request(id: u8, ip: Ipv4Addr) -> Vec<u8> {
    let octets = ip.octets();
    let payload = [3, 6, octets[0], octets[1], octets[2], octets[3]];
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0x8021,
        code: 1,
        id,
        length: len,
        payload: payload.to_vec(),
    }
    .convert_to_payload()
}

fn ipcp_reject(id: u8) -> Vec<u8> {
    PointToPoint {
        protocol: 0x8021,
        code: 4,
        id,
        length: 4,
        payload: vec![],
    }
    .convert_to_payload()
}

fn ipv6cp_ack(id: u8, iface_id: &[u8]) -> Vec<u8> {
    let mut payload = vec![1u8, 0x0a];
    payload.extend(iface_id);
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0x8057,
        code: 2,
        id,
        length: len,
        payload,
    }
    .convert_to_payload()
}

fn ipv6cp_request(id: u8, iface_id: &[u8]) -> Vec<u8> {
    let mut payload = vec![1u8, 0x0a];
    payload.extend(iface_id);
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0x8057,
        code: 1,
        id,
        length: len,
        payload,
    }
    .convert_to_payload()
}

fn ipv6cp_reject(id: u8) -> Vec<u8> {
    PointToPoint {
        protocol: 0x8057,
        code: 4,
        id,
        length: 4,
        payload: vec![],
    }
    .convert_to_payload()
}

fn lcp_proto_reject(id: u8, proto: u16) -> Vec<u8> {
    let payload = proto.to_be_bytes().to_vec();
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0xc021,
        code: 8,
        id,
        length: len,
        payload,
    }
    .convert_to_payload()
}

fn lcp_terminate_request(id: u8) -> Vec<u8> {
    let payload = b"User request".to_vec();
    let len = (payload.len() + 4) as u16;
    PointToPoint {
        protocol: 0xc021,
        code: 5,
        id,
        length: len,
        payload,
    }
    .convert_to_payload()
}

// ── test helpers ──────────────────────────────────────────────────────

fn spawn_nego(
    config: PPPoEClientConfig,
    lcp: LcpPhaseResult,
    mut client_tx: mpsc::Sender<Box<Vec<u8>>>,
    mut client_rx: mpsc::Receiver<Box<Vec<u8>>>,
    status: &WatchService,
) -> tokio::task::JoinHandle<Result<NegotiationResult, PppoeError>> {
    let status_c = status.clone();
    tokio::spawn(async move { run(&config, &lcp, &mut client_tx, &mut client_rx, &status_c).await })
}

/// Complete PAP auth: read PAP Request, send Ack.
/// Returns after auth is done (IPCP/IPv6CP requests will have been triggered).
async fn do_pap_auth(
    from_client: &mut mpsc::Receiver<Box<Vec<u8>>>,
    to_client: &mpsc::Sender<Box<Vec<u8>>>,
    sid: u16,
) {
    let pap_req = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
        .await
        .unwrap()
        .expect("expected PAP Request");
    let ppp = extract_ppp(&pap_req, sid).expect("valid PAP packet");
    assert!(ppp.is_pap_auth());
    let req_id = ppp.id;

    send_session(to_client, sid, pap_pkt(2, req_id)); // Ack

    // Drain the immediate Echo-Request sent at entry of negotiation::run()
    let _echo = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
        .await
        .unwrap()
        .expect("expected immediate Echo-Request after PAP auth");
}

/// Complete PAP auth, drain both NCP requests.
/// Returns (IPCP request, IPv6CP request).
async fn do_pap_and_read_ncp_requests(
    from: &mut mpsc::Receiver<Box<Vec<u8>>>,
    to: &mpsc::Sender<Box<Vec<u8>>>,
    sid: u16,
) -> (PointToPoint, PointToPoint) {
    do_pap_auth(from, to, sid).await;
    let a = tokio::time::timeout(Duration::from_secs(2), from.recv())
        .await
        .unwrap()
        .expect("expected NCP request 1");
    let b = tokio::time::timeout(Duration::from_secs(2), from.recv())
        .await
        .unwrap()
        .expect("expected NCP request 2");
    let pa = extract_ppp(&a, sid).unwrap();
    let pb = extract_ppp(&b, sid).unwrap();
    if pa.is_ipcp() {
        (pa, pb)
    } else {
        (pb, pa)
    }
}

mod auth_tests {
    use super::*;

    #[tokio::test]
    async fn test_pap_success_triggers_ipcp() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);

        // PAP Request already sent. Read + Ack (also drains immediate Echo-Request).
        do_pap_auth(&mut from_client, &to_client, lcp.session_id).await;

        // After auth, should see IPCP Request (0.0.0.0)
        let ipcp_req = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected IPCP Request after auth");
        let ppp = extract_ppp(&ipcp_req, lcp.session_id).unwrap();
        assert!(ppp.is_ipcp());
        assert!(ppp.is_request(), "should be IPCP Config-Request");

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_pap_failed() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);

        // Read PAP Request
        let pap_req = from_client.recv().await.expect("expected PAP Request");
        let ppp = extract_ppp(&pap_req, lcp.session_id).unwrap();
        let req_id = ppp.id;

        // Send PAP Nak → should fail
        send_session(&to_client, lcp.session_id, pap_pkt(3, req_id));

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(matches!(result, Err(PppoeError::AuthFailed(_))));
    }

    #[tokio::test]
    async fn test_chap_success_triggers_ipcp() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc223);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);

        // Drain immediate Echo-Request sent at entry
        let _echo = from_client.recv().await.unwrap();

        // CHAP: server sends Challenge first
        let challenge = b"randomchallenge12345678";
        send_session(&to_client, lcp.session_id, chap_challenge(0x01, challenge));

        // Read CHAP Response
        let chap_resp = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected CHAP Response");
        let ppp = extract_ppp(&chap_resp, lcp.session_id).unwrap();
        assert!(ppp.is_chap());
        let resp_id = ppp.id;
        assert_eq!(resp_id, 0x01);

        // Send CHAP Success
        send_session(&to_client, lcp.session_id, chap_status(3, resp_id));

        // Should see IPCP Request after auth
        let ipcp_req = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected IPCP after CHAP auth");
        assert!(extract_ppp(&ipcp_req, lcp.session_id).unwrap().is_ipcp());

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_chap_failed() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc223);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);

        // Send Challenge
        send_session(&to_client, lcp.session_id, chap_challenge(1, b"test-challenge"));
        let resp = from_client.recv().await.unwrap();
        let ppp = extract_ppp(&resp, lcp.session_id).unwrap();

        // Send CHAP Failure
        send_session(&to_client, lcp.session_id, chap_status(4, ppp.id));

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(matches!(result, Err(PppoeError::AuthFailed(_))));
    }

    #[tokio::test]
    async fn test_unsupported_auth_type() {
        ensure_test_env();

        let (mut client_tx, _from_client) = mpsc::channel(2);
        let (_to_client, mut client_rx) = mpsc::channel(2);
        let config = test_config();
        let lcp = mock_lcp(0x9999); // invalid
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let result = run(&config, &lcp, &mut client_tx, &mut client_rx, &status).await;
        assert!(matches!(result, Err(PppoeError::UnsupportedAuthType(0x9999))));
    }
}

mod ipcp_tests {
    use super::*;

    #[tokio::test]
    async fn test_ipcp_nak_then_ack_returns_correct_ip() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);

        let sid = lcp.session_id;
        // do_pap_and_read_ncp_requests internally drains the immediate Echo-Request
        let (ipcp_ppp, _v6_ppp) =
            do_pap_and_read_ncp_requests(&mut from_client, &to_client, sid).await;

        let ipcp_id = ipcp_ppp.id;
        let mut req_ip = Ipv4Addr::UNSPECIFIED;
        for op in PPPOption::from_bytes(&ipcp_ppp.payload) {
            if op.t == 3 && op.data.len() >= 4 {
                req_ip = Ipv4Addr::new(op.data[0], op.data[1], op.data[2], op.data[3]);
            }
        }
        assert_eq!(req_ip, Ipv4Addr::UNSPECIFIED, "first IPCP request is 0.0.0.0");

        // Send Nak suggesting 10.0.0.100
        let suggested = Ipv4Addr::new(10, 0, 0, 100);
        send_session(&to_client, sid, ipcp_nak(ipcp_id, suggested));

        // Read adjusted IPCP Request
        let adj = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected adjusted IPCP Request");
        let adj_ppp = extract_ppp(&adj, sid).unwrap();
        assert!(adj_ppp.is_request());
        let mut adj_ip = Ipv4Addr::UNSPECIFIED;
        for op in PPPOption::from_bytes(&adj_ppp.payload) {
            if op.t == 3 && op.data.len() >= 4 {
                adj_ip = Ipv4Addr::new(op.data[0], op.data[1], op.data[2], op.data[3]);
            }
        }
        assert_eq!(adj_ip, suggested, "adjusted request should use suggested IP");

        // Send Ack
        send_session(&to_client, sid, ipcp_ack(adj_ppp.id, suggested));

        // Server sends IPCP Config-Request to announce its IP
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);
        send_session(&to_client, sid, ipcp_request(0x10, server_ip));

        // Read client's Ack to server
        let ack_raw = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected IPCP Ack to server");
        let ack_ppp = extract_ppp(&ack_raw, sid).unwrap();
        assert!(ack_ppp.is_ipcp() && ack_ppp.is_ack());

        // Complete IPv6CP using the already-drained request
        let server_v6_id = [0x01u8, 2, 3, 4, 5, 6, 7, 8];
        send_session(&to_client, sid, ipv6cp_ack(_v6_ppp.id, &_v6_ppp.payload[2..]));
        send_session(&to_client, sid, ipv6cp_request(0x01, &server_v6_id));
        let _v6_ack = from_client.recv().await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .expect("negotiation should succeed");
        assert_eq!(result.client_ip, suggested);
        assert_eq!(result.server_ip, server_ip);
    }

    #[tokio::test]
    async fn test_ipcp_rejected() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);

        let sid = lcp.session_id;
        let (ipcp_ppp, _v6) = do_pap_and_read_ncp_requests(&mut from_client, &to_client, sid).await;

        // Send IPCP Reject
        send_session(&to_client, sid, ipcp_reject(ipcp_ppp.id));

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(matches!(result, Err(PppoeError::IpRequiredButRejected)));
    }
}

mod ipv6cp_tests {
    use super::*;

    #[tokio::test]
    async fn test_proto_reject_ipv6cp_non_fatal_should_complete() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // PAP + get both NCP requests (do_pap_auth internally drains the immediate Echo-Request)
        do_pap_auth(&mut from_client, &to_client, sid).await;

        // After PAP, read both NCP requests
        let raw1 = from_client.recv().await.unwrap();
        let raw2 = from_client.recv().await.unwrap();
        let p1 = extract_ppp(&raw1, sid).unwrap();
        let p2 = extract_ppp(&raw2, sid).unwrap();

        // One is IPCP, one is IPv6CP
        let (ipcp_ppp, v6_ppp) = if p1.is_ipcp() { (p1, p2) } else { (p2, p1) };
        assert!(ipcp_ppp.is_ipcp() && ipcp_ppp.is_request());
        assert!(v6_ppp.is_ipv6cp() && v6_ppp.is_request());

        // Ack IPCP
        send_session(&to_client, sid, ipcp_ack(ipcp_ppp.id, Ipv4Addr::new(10, 0, 0, 1)));
        // Server IP
        send_session(&to_client, sid, ipcp_request(0x01, Ipv4Addr::new(10, 0, 0, 254)));
        let _server_ack = from_client.recv().await.unwrap();

        // Send Proto-Reject for IPv6CP
        send_session(&to_client, sid, lcp_proto_reject(v6_ppp.id, 0x8057));

        // Negotiation should complete
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(result.is_ok(), "proto-reject IPv6CP should not be fatal: {:?}", result.err());
        assert!(result.unwrap().ipv6cp_server_id.is_none());
    }
}

mod integration {
    use super::*;

    #[tokio::test]
    async fn test_full_pap_ipcp_ipv6cp() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // PAP (do_pap_auth internally drains the immediate Echo-Request)
        do_pap_auth(&mut from_client, &to_client, sid).await;

        // After PAP, both IPCP and IPv6CP requests are sent.
        // Read them in order (IPCP first, then IPv6CP).
        let ipcp_raw = from_client.recv().await.unwrap();
        let v6_raw = from_client.recv().await.unwrap();

        // Identify which is which
        let (ipcp_ppp, v6_ppp) = {
            let a = extract_ppp(&ipcp_raw, sid).unwrap();
            let b = extract_ppp(&v6_raw, sid).unwrap();
            if a.is_ipcp() {
                (a, b)
            } else {
                (b, a)
            }
        };
        assert!(ipcp_ppp.is_request(), "IPCP is a request");
        assert!(v6_ppp.is_ipv6cp() && v6_ppp.is_request(), "IPv6CP is a request");

        // Ack IPCP
        send_session(&to_client, sid, ipcp_ack(ipcp_ppp.id, Ipv4Addr::new(10, 0, 0, 100)));
        // Server IP
        send_session(&to_client, sid, ipcp_request(0x01, Ipv4Addr::new(10, 0, 0, 254)));
        let _server_ack = from_client.recv().await.unwrap();

        // Handle IPv6CP
        let server_v6_id = [0x01u8, 2, 3, 4, 5, 6, 7, 8];
        send_session(&to_client, sid, ipv6cp_ack(v6_ppp.id, &v6_ppp.payload[2..]));
        send_session(&to_client, sid, ipv6cp_request(0x01, &server_v6_id));
        let _v6_ack = from_client.recv().await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .expect("full negotiation should succeed");

        assert_eq!(result.client_ip, Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(result.server_ip, Ipv4Addr::new(10, 0, 0, 254));
        assert_eq!(result.ipv6cp_server_id, Some(server_v6_id.to_vec()));
    }

    #[tokio::test]
    async fn test_peer_terminated_during_auth() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Read PAP Request (client sends it at entry)
        let _pap = from_client.recv().await.unwrap();

        // Drain immediate Echo-Request sent at entry
        let _echo = from_client.recv().await.unwrap();

        // Send Terminate-Request
        send_session(&to_client, sid, lcp_terminate_request(0x42));

        // Read Terminate-Ack
        let ack_raw = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected Terminate-Ack");
        let ack_ppp = extract_ppp(&ack_raw, sid).unwrap();
        assert!(ack_ppp.is_lcp_config());
        assert!(ack_ppp.is_termination_ack());

        // Task should return PeerTerminated
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(matches!(result, Err(PppoeError::PeerTerminated)));
    }

    #[tokio::test]
    async fn test_proto_reject_ipv6cp_non_fatal() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // PAP + get both NCP requests
        let (ipcp_ppp, v6_ppp) =
            do_pap_and_read_ncp_requests(&mut from_client, &to_client, sid).await;

        // Ack IPCP
        send_session(&to_client, sid, ipcp_ack(ipcp_ppp.id, Ipv4Addr::new(10, 0, 0, 1)));
        // Server IP
        send_session(&to_client, sid, ipcp_request(0x01, Ipv4Addr::new(10, 0, 0, 254)));
        let _ = from_client.recv().await.unwrap(); // server ack

        // Send Proto-Reject for IPv6CP
        send_session(&to_client, sid, lcp_proto_reject(v6_ppp.id, 0x8057));

        // Negotiation should complete (IPCP already done, IPv6CP rejected)
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(result.is_ok(), "proto-reject IPv6CP should not be fatal");
        assert!(result.unwrap().ipv6cp_server_id.is_none());
    }

    #[tokio::test]
    async fn test_proto_reject_ipcp_fatal() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // PAP
        do_pap_auth(&mut from_client, &to_client, sid).await;

        // Read first NCP request (could be IPCP or IPv6CP)
        let raw = from_client.recv().await.unwrap();
        let ppp = extract_ppp(&raw, sid).unwrap();

        if ppp.is_ipcp() {
            // Send Proto-Reject for IPCP
            send_session(&to_client, sid, lcp_proto_reject(ppp.id, 0x8021));
        } else {
            // IPv6CP came first, Ack it, wait for IPCP
            send_session(&to_client, sid, ipv6cp_reject(ppp.id));
            let ipcp_raw = from_client.recv().await.unwrap();
            let ipcp_ppp = extract_ppp(&ipcp_raw, sid).unwrap();
            send_session(&to_client, sid, lcp_proto_reject(ipcp_ppp.id, 0x8021));
        }

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(matches!(result, Err(PppoeError::IpRequiredButRejected)));
    }

    #[tokio::test]
    async fn test_proto_reject_pap_fatal() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Complete PAP auth (also drains the immediate echo request)
        do_pap_auth(&mut from_client, &to_client, sid).await;

        // Send LCP Protocol-Reject for PAP
        send_session(&to_client, sid, lcp_proto_reject(0x01, 0xc023));

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(matches!(result, Err(PppoeError::AuthFailed(_))));
    }

    #[tokio::test]
    async fn test_service_stopped() {
        ensure_test_env();

        let (mut client_tx, _from_client) = mpsc::channel(16);
        let (_to_client, mut client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let status2 = status.clone();
        let handle = tokio::spawn(async move {
            run(&config, &lcp, &mut client_tx, &mut client_rx, &status2).await
        });

        // Trigger service stop
        status.0.send_if_modified(|s| {
            *s = ServiceStatus::Stopping;
            true
        });

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap();
        assert!(matches!(result, Err(PppoeError::ServiceStopped)));
    }

    #[tokio::test]
    async fn test_channel_closed() {
        ensure_test_env();

        let (mut client_tx, _from_client) = mpsc::channel(2);
        let (to_client, mut client_rx) = mpsc::channel(2);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        drop(to_client);
        let result = run(&config, &lcp, &mut client_tx, &mut client_rx, &status).await;
        assert!(matches!(result, Err(PppoeError::ChannelClosed)));
    }

    #[tokio::test]
    async fn test_echo_request_from_peer_triggers_echo_reply() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Read PAP Request
        let _pap = from_client.recv().await.unwrap();

        // Drain immediate Echo-Request sent at entry
        let _echo = from_client.recv().await.unwrap();

        // Send LCP Echo-Request from peer
        let echo_req = PointToPoint::gen_echo_request_with_magic(0xAB, lcp.magic_number);
        send_session(&to_client, sid, echo_req);

        // Read Echo-Reply from client
        let reply_raw = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected Echo-Reply");
        let ppp = extract_ppp(&reply_raw, sid).expect("valid LCP packet");
        assert!(ppp.is_lcp_config());
        assert!(ppp.is_echo_reply(), "should be Echo-Reply");
        assert_eq!(ppp.id, 0xAB, "Echo-Reply preserves request id");

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_echo_reply_received_resets_counter() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Drain immediate Echo-Request sent at entry
        // PAP request is sent first by client. Read and Ack it.
        let pap_raw = from_client.recv().await.unwrap();
        let pap_ppp = extract_ppp(&pap_raw, sid).expect("valid PAP packet");
        assert!(pap_ppp.is_pap_auth());
        send_session(&to_client, sid, pap_pkt(2, pap_ppp.id));

        // Drain immediate Echo-Request sent at entry of negotiation::run()
        let _echo = from_client.recv().await.unwrap();

        // Drain NCP requests triggered by auth success
        let _raw1 = from_client.recv().await.unwrap();
        let _raw2 = from_client.recv().await.unwrap();

        // Send LCP Echo-Request from peer → should trigger Echo-Reply
        let echo_req = PointToPoint::gen_echo_request_with_magic(0x01, lcp.magic_number);
        send_session(&to_client, sid, echo_req);

        // Read Echo-Reply
        let reply = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected Echo-Reply");
        let ppp = extract_ppp(&reply, sid).unwrap();
        assert!(ppp.is_lcp_config());
        assert!(ppp.is_echo_reply(), "should be Echo-Reply");
        assert_eq!(ppp.id, 0x01);

        // Send another Echo-Request — echo_failures within the client should reset
        let echo_req2 = PointToPoint::gen_echo_request_with_magic(0x02, lcp.magic_number);
        send_session(&to_client, sid, echo_req2);

        // Read Echo-Reply with id 0x02
        let reply2 = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected second Echo-Reply");
        let ppp2 = extract_ppp(&reply2, sid).unwrap();
        assert!(ppp2.is_echo_reply());
        assert_eq!(ppp2.id, 0x02);

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_client_sends_echo_request_after_lcp_open() {
        ensure_test_env();
        tokio::time::pause();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Complete PAP
        let pap_raw = from_client.recv().await.unwrap();
        let pap_ppp = extract_ppp(&pap_raw, sid).unwrap();
        send_session(&to_client, sid, pap_pkt(2, pap_ppp.id));

        // Drain initial NCP requests
        from_client.recv().await.unwrap();
        from_client.recv().await.unwrap();

        // Advance in small steps, responding to IPCP to keep timeouts reset.
        // Echo timer fires at LCP_ECHO_INTERVAL (20 s).
        let mut echo_found: Option<PointToPoint> = None;
        let mut elapsed = 0u64;

        while echo_found.is_none() && elapsed < super::LCP_ECHO_INTERVAL + 10 {
            tokio::time::advance(Duration::from_secs(2)).await;
            elapsed += 2;

            // Drain all buffered packets (try_recv is non-blocking, works with pause())
            loop {
                match from_client.try_recv() {
                    Ok(raw) => {
                        let Some(ppp) = extract_ppp(&raw, sid) else { continue };
                        if ppp.is_lcp_config() && ppp.is_echo_request() {
                            echo_found = Some(ppp);
                            break;
                        }
                        if ppp.is_ipcp() && ppp.is_request() {
                            let ip = Ipv4Addr::new(10, 0, 0, (elapsed as u8 % 100) + 1);
                            send_session(&to_client, sid, ipcp_nak(ppp.id, ip));
                        }
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
        }

        assert!(echo_found.is_some(), "client should send LCP Echo-Request after {elapsed}s");
        assert_eq!(echo_found.unwrap().protocol, 0xc021, "protocol is LCP");

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_packet_with_wrong_session_id_ignored() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Read PAP Request
        let _pap = from_client.recv().await.unwrap();

        // Drain immediate Echo-Request sent at entry
        let _echo = from_client.recv().await.unwrap();

        // Send PAP Ack with WRONG session ID — should be silently ignored
        let frame = PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid: 0xDEAD, // wrong!
            length: pap_pkt(2, 1).len() as u16,
            payload: pap_pkt(2, 1),
        };
        let raw = wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOES, frame.convert_to_payload());
        to_client.send(raw).await.unwrap();

        // Verify no response to the wrong-SID packet (short timeout, should be empty)
        let response = tokio::time::timeout(Duration::from_millis(200), from_client.recv()).await;
        assert!(response.is_err(), "no response expected for wrong session ID");

        // Send correct PAP Ack to make progress and confirm client is still alive
        send_session(&to_client, sid, pap_pkt(2, 1));

        // After correct Ack, NCP requests should arrive normally
        let ncp = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("NCP request after correct PAP Ack");
        assert!(extract_ppp(&ncp, sid).is_some());

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_echo_timeout_returns_echo_failed() {
        ensure_test_env();
        tokio::time::pause();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Drain immediate Echo-Request sent at entry
        let _immediate_echo = from_client.recv().await.unwrap();

        // Complete PAP
        let pap_raw = from_client.recv().await.unwrap();
        send_session(&to_client, sid, pap_pkt(2, extract_ppp(&pap_raw, sid).unwrap().id));

        // Drain initial NCP requests
        from_client.recv().await.unwrap();
        from_client.recv().await.unwrap();

        // Advance past MAX_ECHO_FAILURES × LCP_ECHO_INTERVAL
        // (first echo already sent, echo_failures=1, need 5 more timer fires)
        // Keep IPCP alive with Nak responses to prevent NCP timeout.
        let total =
            super::super::negotiation::MAX_ECHO_FAILURES as u64 * super::LCP_ECHO_INTERVAL + 1;
        let mut elapsed = 0u64;

        while elapsed < total {
            tokio::time::advance(Duration::from_secs(2)).await;
            elapsed += 2;

            loop {
                match from_client.try_recv() {
                    Ok(raw) => {
                        if let Some(ppp) = extract_ppp(&raw, sid) {
                            if ppp.is_ipcp() && ppp.is_request() {
                                send_session(
                                    &to_client,
                                    sid,
                                    ipcp_nak(
                                        ppp.id,
                                        Ipv4Addr::new(10, 0, 0, (elapsed as u8 % 100) + 1),
                                    ),
                                );
                            }
                        }
                    }
                    _ => break,
                }
            }
        }

        let result = handle.await.expect("negotiation should have exited");

        assert!(matches!(result, Err(PppoeError::EchoFailed(_))));
    }

    #[tokio::test]
    async fn test_auth_timeout_returns_auth_failed() {
        ensure_test_env();
        tokio::time::pause();

        let (mut client_tx, _from_client) = mpsc::channel(16);
        let (_to_client, mut client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &lcp, &mut client_tx, &mut client_rx, &status).await
        });

        // PAP request is sent, but we never respond.
        // Advance past MAX_AUTH_RETRIES × DEFAULT_TIMEOUT.
        let total = (super::super::negotiation::MAX_AUTH_RETRIES as u64 + 1) * DEFAULT_TIMEOUT;
        tokio::time::advance(Duration::from_secs(total + 1)).await;

        let result = handle.await.expect("negotiation should have exited");
        assert!(matches!(result, Err(PppoeError::AuthFailed(_))));
    }

    #[tokio::test]
    async fn test_unknown_protocol_ignored() {
        ensure_test_env();

        let (client_tx, mut from_client) = mpsc::channel(16);
        let (to_client, client_rx) = mpsc::channel(16);
        let config = test_config();
        let lcp = mock_lcp(0xc023);
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = spawn_nego(config.clone(), lcp.clone(), client_tx, client_rx, &status);
        let sid = lcp.session_id;

        // Read PAP Request
        let _pap = from_client.recv().await.unwrap();

        // Drain immediate Echo-Request sent at entry
        let _echo = from_client.recv().await.unwrap();

        // Send an unknown PPP protocol packet (e.g., CCP = 0x80FD)
        let unknown = PointToPoint {
            protocol: 0x80FD,
            code: 1,
            id: 0,
            length: 4,
            payload: vec![],
        };
        send_session(&to_client, sid, unknown.convert_to_payload());

        // Verify no response (short timeout, should be empty)
        let response = tokio::time::timeout(Duration::from_millis(200), from_client.recv()).await;
        assert!(response.is_err(), "no response expected for unknown protocol");

        // Client should still be functioning normally
        send_session(&to_client, sid, pap_pkt(2, 1));
        let ncp = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("NCP request after correct PAP Ack");
        assert!(extract_ppp(&ncp, sid).is_some());

        drop(to_client);
        drop(handle);
    }
}

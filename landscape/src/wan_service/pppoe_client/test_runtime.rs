use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::PointToPoint;
use landscape_common::net_proto::pppoe::PPPoEFrame;
use landscape_common::service::{ServiceHandle, ServiceStatus};

use super::PPPoEClientConfig;
use super::error::PppoeError;
use super::lcp::LcpPhaseResult;
use super::runtime::keepalive;

fn ensure_test_env() {
    unsafe { std::env::set_var("LANDSCAPE_IGNORE_CLI_ARGS", "1") };
}

fn test_config(echo_interval: Option<u64>) -> PPPoEClientConfig {
    let mut config = PPPoEClientConfig::new(
        uuid::Uuid::new_v4(),
        1,
        "eth0".into(),
        MacAddr::new(0x02, 0x03, 0x04, 0x05, 0x06, 0x07),
        "testuser".into(),
        "testpass".into(),
        false,
        1492,
        None,
    );
    config.lcp_echo_interval = echo_interval;
    config
}

const SERVER_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const SID: u16 = 0x0042;

fn mock_lcp() -> LcpPhaseResult {
    LcpPhaseResult {
        session_id: SID,
        server_mac: SERVER_MAC.to_vec(),
        mru: 1492,
        magic_number: 0xDEAD_BEEF,
        auth_type: 0xc023,
        auth_algorithm: None,
        peer_mru: 1492,
        peer_magic: 0xFEED_FACE,
    }
}

/// A session established with CHAP/MD5 (RFC 1994 §4.1).
fn mock_chap_lcp() -> LcpPhaseResult {
    LcpPhaseResult {
        auth_type: 0xc223,
        auth_algorithm: Some(0x05),
        ..mock_lcp()
    }
}

fn wrap_eth(ethertype: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut packet = SERVER_MAC.to_vec();
    packet.extend(SERVER_MAC);
    packet.extend(ethertype.to_be_bytes());
    packet.extend(payload);
    packet
}

fn send_session_frame(to_client: &mpsc::Sender<Vec<u8>>, ppp_payload: Vec<u8>) {
    let frame = PPPoEFrame {
        ver: 1,
        t: 1,
        code: 0,
        sid: SID,
        length: ppp_payload.len() as u16,
        payload: ppp_payload,
    };
    to_client.try_send(wrap_eth(0x8864, frame.convert_to_payload())).expect("send session packet");
}

/// PADT travels on the discovery ethertype (0x8863) per RFC 2516 §5.6.
fn send_padt(to_client: &mpsc::Sender<Vec<u8>>, sid: u16) {
    let frame = PPPoEFrame::get_padt(sid);
    to_client.try_send(wrap_eth(0x8863, frame.convert_to_payload())).expect("send PADT");
}

fn echo_reply_packet(magic: u32) -> Vec<u8> {
    PointToPoint {
        protocol: 0xc021,
        code: 10,
        id: 1,
        length: 8,
        payload: magic.to_be_bytes().to_vec(),
    }
    .convert_to_payload()
}

fn echo_request_packet(id: u8, magic: u32) -> Vec<u8> {
    PointToPoint {
        protocol: 0xc021,
        code: 9,
        id,
        length: 8,
        payload: magic.to_be_bytes().to_vec(),
    }
    .convert_to_payload()
}

fn lcp_config_request_packet(id: u8, mru: u16, magic: u32) -> Vec<u8> {
    let mut payload = vec![1, 4];
    payload.extend(mru.to_be_bytes());
    payload.extend([3, 4, 0xc0, 0x23]);
    payload.extend([5, 6]);
    payload.extend(magic.to_be_bytes());
    lcp_config_request_with_payload(id, payload)
}

/// Config-Request with a caller-supplied Authentication-Protocol option
/// (MRU matches the established config, magic is fresh).
fn lcp_config_request_with_auth(id: u8, auth_option: &[u8], magic: u32) -> Vec<u8> {
    let mut payload = vec![1, 4];
    payload.extend(mock_lcp().peer_mru.to_be_bytes());
    payload.extend(auth_option);
    payload.extend([5, 6]);
    payload.extend(magic.to_be_bytes());
    lcp_config_request_with_payload(id, payload)
}

fn termination_ack_packet(id: u8) -> Vec<u8> {
    PointToPoint {
        protocol: 0xc021,
        code: 6,
        id,
        length: 4,
        payload: vec![],
    }
    .convert_to_payload()
}

/// Extract a PPP packet the client sent, or a PADT frame (`None` marks a
/// PADT on 0x8863 which carries no PPP payload).
fn extract_client_frame(raw: &[u8]) -> Option<(u16, Option<PointToPoint>)> {
    assert!(raw.len() >= 14, "frame too short: {raw:?}");
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    let frame = PPPoEFrame::new(&raw[14..]).expect("valid PPPoE frame");
    assert_eq!(frame.sid, SID, "client must send with the session id");
    if ethertype == 0x8863 {
        assert_eq!(frame.code, 0xa7, "0x8863 from client must be PADT");
        return Some((ethertype, None));
    }
    assert_eq!(ethertype, 0x8864);
    Some((ethertype, PointToPoint::new(&frame.payload)))
}

struct KeepaliveHarness {
    to_client: mpsc::Sender<Vec<u8>>,
    from_client: mpsc::Receiver<Vec<u8>>,
    status: ServiceHandle,
    handle: JoinHandle<Result<(), PppoeError>>,
}

fn spawn_keepalive(config: PPPoEClientConfig, lcp: LcpPhaseResult) -> KeepaliveHarness {
    let (client_tx, from_client) = mpsc::channel(16);
    let (to_client, client_rx) = mpsc::channel(16);
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    status.just_change_status(ServiceStatus::Running);

    let task_status = status.clone();
    let handle = tokio::spawn(async move {
        keepalive(&config, &lcp, 0, &mut client_tx.clone(), &mut { client_rx }, &task_status).await
    });

    KeepaliveHarness { to_client, from_client, status, handle }
}

/// Drain frames until one carries a PPP packet (skips the periodic
/// echo requests the client sends).
async fn next_ppp_from_client(h: &mut KeepaliveHarness) -> PointToPoint {
    loop {
        let raw = tokio::time::timeout(Duration::from_secs(5), h.from_client.recv())
            .await
            .expect("timed out waiting for client frame")
            .expect("client channel closed");
        if let Some((_, Some(ppp))) = extract_client_frame(&raw) {
            return ppp;
        }
    }
}

// ── PADT detection ────────────────────────────────────────────────────────

#[tokio::test]
async fn padt_immediately_detected() {
    ensure_test_env();
    // Long echo interval: the PADT must be acted on long before any timer.
    let h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    send_padt(&h.to_client, SID);

    let result = tokio::time::timeout(Duration::from_secs(5), h.handle)
        .await
        .expect("keepalive finished")
        .unwrap();
    assert!(
        matches!(result, Err(PppoeError::PadtReceived)),
        "expected PadtReceived, got {result:?}"
    );
}

/// RFC 2516 §5.6: a PADT's session id MUST NOT be zero, and pppd matches
/// the sid strictly — a broadcast PADT (sid 0) must be ignored, even from
/// the established peer's MAC.
#[tokio::test]
async fn broadcast_padt_with_sid_zero_ignored() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    send_padt(&h.to_client, 0);

    // The client must keep the session: answer its initial echo request and
    // observe a normal echo reply exchange afterwards.
    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request(), "client should still send echo requests");
    send_session_frame(&h.to_client, echo_reply_packet(0xFEED_FACE));

    send_session_frame(&h.to_client, echo_request_packet(7, 0xFEED_FACE));
    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_echo_reply(), "session must still be alive");

    h.status.just_change_status(ServiceStatus::Stopping);
    let result = tokio::time::timeout(Duration::from_secs(5), h.handle)
        .await
        .expect("keepalive finished")
        .unwrap();
    assert!(matches!(result, Err(PppoeError::ServiceStopped)));
}

#[tokio::test]
async fn padt_for_other_session_ignored() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    send_padt(&h.to_client, 0x7777);

    // The client must keep the session: answer its initial echo request and
    // observe a normal echo reply exchange afterwards.
    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request(), "client should still send echo requests");
    send_session_frame(&h.to_client, echo_reply_packet(0xFEED_FACE));

    send_session_frame(&h.to_client, echo_request_packet(7, 0xFEED_FACE));
    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_echo_reply(), "session must still be alive");

    h.status.just_change_status(ServiceStatus::Stopping);
    let result = tokio::time::timeout(Duration::from_secs(5), h.handle)
        .await
        .expect("keepalive finished")
        .unwrap();
    assert!(matches!(result, Err(PppoeError::ServiceStopped)));
}

// ── echo liveness validation ──────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn echo_reply_with_own_magic_is_not_liveness() {
    ensure_test_env();
    // RFC 1661 §6.4: a reply carrying our own magic means a looped link and
    // must not reset the failure count.
    let h = spawn_keepalive(test_config(Some(1)), mock_lcp());

    // Keep feeding looped replies forever; the client must still fail.
    let feeder = {
        let to_client = h.to_client.clone();
        tokio::spawn(async move {
            loop {
                if to_client
                    .try_send(wrap_eth(0x8864, {
                        let frame = PPPoEFrame {
                            ver: 1,
                            t: 1,
                            code: 0,
                            sid: SID,
                            length: echo_reply_packet(0xDEAD_BEEF).len() as u16,
                            payload: echo_reply_packet(0xDEAD_BEEF),
                        };
                        frame.convert_to_payload()
                    }))
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    };

    let result = tokio::time::timeout(Duration::from_secs(30), h.handle)
        .await
        .expect("keepalive failed")
        .unwrap();
    assert!(
        matches!(result, Err(PppoeError::EchoFailed(_))),
        "looped replies must not keep the session alive, got {result:?}"
    );
    feeder.abort();
}

/// An Echo-Reply without a well-formed Magic-Number is malformed and must
/// not count as liveness (RFC 1661 §5.4): the session must still fail on
/// echo timeouts.
#[tokio::test(start_paused = true)]
async fn malformed_echo_reply_is_not_liveness() {
    ensure_test_env();
    let h = spawn_keepalive(test_config(Some(1)), mock_lcp());

    let malformed_reply = {
        let ppp = PointToPoint {
            protocol: 0xc021,
            code: 10,
            id: 1,
            length: 4,
            payload: vec![],
        }
        .convert_to_payload();
        let frame = PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid: SID,
            length: ppp.len() as u16,
            payload: ppp,
        };
        wrap_eth(0x8864, frame.convert_to_payload())
    };

    // Keep feeding malformed replies forever; the client must still fail.
    let feeder = {
        let to_client = h.to_client.clone();
        let packet = malformed_reply;
        tokio::spawn(async move {
            loop {
                if to_client.try_send(packet.clone()).is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    };

    let result = tokio::time::timeout(Duration::from_secs(30), h.handle)
        .await
        .expect("keepalive should fail")
        .unwrap();
    assert!(
        matches!(result, Err(PppoeError::EchoFailed(_))),
        "malformed replies must not keep the session alive, got {result:?}"
    );
    feeder.abort();
}

/// A peer Echo-Request proves the peer is alive but not that it can hear
/// us: only valid replies to our own Echo-Requests count as liveness
/// (pppd semantics). The session must still fail on echo timeouts when
/// the peer never answers our requests.
#[tokio::test(start_paused = true)]
async fn peer_echo_request_alone_keeps_failure_count() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(1)), mock_lcp());

    let feeder = {
        let to_client = h.to_client.clone();
        tokio::spawn(async move {
            loop {
                if to_client
                    .try_send(wrap_eth(0x8864, {
                        let payload = echo_request_packet(7, 0xFEED_FACE);
                        let frame = PPPoEFrame {
                            ver: 1,
                            t: 1,
                            code: 0,
                            sid: SID,
                            length: payload.len() as u16,
                            payload,
                        };
                        frame.convert_to_payload()
                    }))
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    };

    // Drain the client's own echoes and its replies to the peer's requests
    // so the bounded channel never blocks the keepalive.
    let result = loop {
        tokio::select! {
            biased;
            result = &mut h.handle => break result.expect("task should not panic"),
            _ = h.from_client.recv() => {}
        }
    };

    assert!(
        matches!(result, Err(PppoeError::EchoFailed(_))),
        "peer echo requests alone must not keep the session alive, got {result:?}"
    );
    feeder.abort();
}

#[tokio::test]
async fn echo_reply_with_peer_magic_keeps_session() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());
    send_session_frame(&h.to_client, echo_reply_packet(0xFEED_FACE));

    // No error: the client answers a peer echo request instead.
    send_session_frame(&h.to_client, echo_request_packet(7, 0xFEED_FACE));
    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_echo_reply(), "expected echo reply, got code {}", reply.code);
    assert_eq!(
        reply.payload,
        0xDEAD_BEEF_u32.to_be_bytes().to_vec(),
        "reply must carry our own magic"
    );
    assert_eq!(reply.id, 7, "reply must mirror the request id");

    h.status.just_change_status(ServiceStatus::Stopping);
    let result = tokio::time::timeout(Duration::from_secs(5), h.handle)
        .await
        .expect("keepalive finished")
        .unwrap();
    assert!(matches!(result, Err(PppoeError::ServiceStopped)));
}

// ── LCP renegotiation while Established ───────────────────────────────────

#[tokio::test]
async fn lcp_config_request_matching_is_acked() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(
        &h.to_client,
        lcp_config_request_packet(3, mock_lcp().peer_mru, mock_lcp().peer_magic),
    );

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_ack(), "matching renegotiation must be acked, code={}", reply.code);
    assert_eq!(reply.id, 3);

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

#[tokio::test]
async fn lcp_config_request_mismatch_is_naked() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(&h.to_client, lcp_config_request_packet(4, 1400, mock_lcp().peer_magic));

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_nak(), "differing options must be naked, code={}", reply.code);
    assert_eq!(reply.id, 4);
    assert!(reply.payload.starts_with(&[1, 4]), "nak options must start with MRU");
    assert_eq!(
        u16::from_be_bytes([reply.payload[2], reply.payload[3]]),
        mock_lcp().peer_mru,
        "nak must suggest the established MRU"
    );

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

fn lcp_config_request_with_payload(id: u8, payload: Vec<u8>) -> Vec<u8> {
    PointToPoint {
        protocol: 0xc021,
        code: 1,
        id,
        length: payload.len() as u16 + 4,
        payload,
    }
    .convert_to_payload()
}

/// RFC 1661 §5.4: options we do not recognize must be refused with a
/// Configure-Reject that echoes the offending options — not Acked.
#[tokio::test]
async fn lcp_config_request_with_unknown_option_is_rejected() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    // MRU matching the established config + an unrecognized option (type 11)
    let mut payload = vec![1, 4];
    payload.extend(mock_lcp().peer_mru.to_be_bytes());
    payload.extend([0x0b, 4, 0xaa, 0xbb]);
    send_session_frame(&h.to_client, lcp_config_request_with_payload(5, payload));

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_reject(), "unknown option must be rejected, code={}", reply.code);
    assert_eq!(reply.id, 5);
    assert_eq!(
        reply.payload,
        vec![0x0b, 4, 0xaa, 0xbb],
        "reject must echo the unrecognized option"
    );

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// A recognized option with an illegal length is malformed and must also be
/// refused with a Configure-Reject echoing the option as received.
#[tokio::test]
async fn lcp_config_request_with_malformed_known_option_is_rejected() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    // MRU option (type 1) with a bogus length of 3 (must be 4)
    send_session_frame(&h.to_client, lcp_config_request_with_payload(6, vec![1, 3, 0x05]));

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_reject(), "malformed option must be rejected, code={}", reply.code);
    assert_eq!(reply.id, 6);
    assert_eq!(reply.payload, vec![1, 3, 0x05], "reject must echo the malformed option");

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

// ── CHAP renegotiation (pppd lcp.c:1618-1663) ─────────────────────────────

/// pppd semantics: a well-formed CHAP Authentication-Protocol option (3
/// data bytes: protocol + algorithm) requesting the established auth must
/// be Acked — it must not be rejected just because its data is longer
/// than PAP's.
#[tokio::test]
async fn chap_renegotiation_matching_is_acked() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_chap_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(
        &h.to_client,
        lcp_config_request_with_auth(3, &[3, 5, 0xc2, 0x23, 0x05], 0x1234_5678),
    );

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_ack(), "matching CHAP renegotiation must be acked, code={}", reply.code);
    assert_eq!(reply.id, 3);

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// A CHAP request with a different algorithm cannot be honored mid-session
/// (authentication already ran): Naked suggesting the established values in
/// the 5-byte CHAP form (pppd `CILEN_CHAP`).
#[tokio::test]
async fn chap_renegotiation_different_algorithm_is_naked() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_chap_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(
        &h.to_client,
        lcp_config_request_with_auth(4, &[3, 5, 0xc2, 0x23, 0x81], 0x1234_5678),
    );

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_nak(), "changed CHAP algorithm must be naked, code={}", reply.code);
    assert_eq!(reply.id, 4);
    assert_eq!(
        reply.payload,
        vec![3, 5, 0xc2, 0x23, 0x05],
        "nak must suggest the established CHAP auth in 5-byte form"
    );

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// PAP requested on a CHAP-established session: Naked suggesting CHAP,
/// including the algorithm byte (pppd lcp.c:1626-1628).
#[tokio::test]
async fn pap_renegotiation_on_chap_session_is_naked_suggesting_chap() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_chap_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(
        &h.to_client,
        lcp_config_request_with_auth(5, &[3, 4, 0xc0, 0x23], 0x1234_5678),
    );

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_nak(), "PAP on a CHAP session must be naked, code={}", reply.code);
    assert_eq!(reply.id, 5);
    assert_eq!(
        reply.payload,
        vec![3, 5, 0xc2, 0x23, 0x05],
        "nak must suggest CHAP in its 5-byte form"
    );

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// A CHAP option without the algorithm byte is malformed (RFC 1994 §4.1)
/// and must be refused with a Configure-Reject echoing the option.
#[tokio::test]
async fn chap_option_without_algorithm_is_rejected() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_chap_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(
        &h.to_client,
        lcp_config_request_with_auth(6, &[3, 4, 0xc2, 0x23], 0x1234_5678),
    );

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_reject(), "CHAP without algorithm must be rejected, code={}", reply.code);
    assert_eq!(reply.id, 6);
    assert_eq!(reply.payload, vec![3, 4, 0xc2, 0x23], "reject must echo the option");

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// An auth option too short to carry the protocol is malformed and must be
/// refused with a Configure-Reject (pppd rejects `cilen < CILEN_SHORT`).
#[tokio::test]
async fn auth_option_without_protocol_is_rejected() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(&h.to_client, lcp_config_request_with_auth(7, &[3, 2], 0x1234_5678));

    let reply = next_ppp_from_client(&mut h).await;
    assert!(
        reply.is_reject(),
        "auth option without protocol must be rejected, code={}",
        reply.code
    );
    assert_eq!(reply.id, 7);
    assert_eq!(reply.payload, vec![3, 2], "reject must echo the option");

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// pppd semantics (lcp.c:1727-1749): a peer renegotiating with a fresh
/// random Magic-Number must be Acked. Only a magic equal to our own
/// (looped link, RFC 1661 §6.4) is Naked.
#[tokio::test]
async fn renegotiation_with_fresh_peer_magic_is_acked() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(
        &h.to_client,
        lcp_config_request_packet(3, mock_lcp().peer_mru, 0x1234_5678),
    );

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_ack(), "fresh peer magic must be acked, code={}", reply.code);
    assert_eq!(reply.id, 3);

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// RFC 1661 §6.4: a peer magic equal to our own means the link is
/// looped-back. The request must be Naked with a suggested magic
/// different from our own.
#[tokio::test]
async fn renegotiation_with_own_magic_is_naked() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    send_session_frame(
        &h.to_client,
        lcp_config_request_packet(4, mock_lcp().peer_mru, mock_lcp().magic_number),
    );

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_nak(), "own-magic collision must be naked, code={}", reply.code);
    assert_eq!(reply.id, 4);
    assert_eq!(
        reply.payload,
        [vec![5, 6], (!mock_lcp().magic_number | 1).to_be_bytes().to_vec()].concat(),
        "nak must suggest a magic different from our own"
    );

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// pppd excludes Magic-Number from the reject_if_disagree escalation
/// (lcp.c:1824-1826): even past MAX_NAK_LOOPS a magic collision keeps
/// being Naked, never Rejected.
#[tokio::test]
async fn magic_collision_never_escalates_to_reject() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    let rounds = super::MAX_NAK_LOOPS + 2;
    for i in 1..=rounds {
        send_session_frame(
            &h.to_client,
            lcp_config_request_packet(i, mock_lcp().peer_mru, mock_lcp().magic_number),
        );

        let reply = next_ppp_from_client(&mut h).await;
        assert!(
            reply.is_nak(),
            "magic collision must stay a nak in round {i}, code={}",
            reply.code
        );
        assert_eq!(reply.id, i);
    }

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

/// pppd-aligned anti-ping-pong (RFC 1661 §4.5 loop avoidance): after
/// MAX_NAK_LOOPS consecutive Naks the client escalates disagreeing options
/// to Configure-Reject instead of Naking forever. A compliant peer then
/// drops the option and the next matching request is Acked. No
/// Terminate-Request is ever sent for this. The disagreement is driven by
/// MRU — Magic-Number never escalates (see magic_collision_never_* above).
#[tokio::test]
async fn renegotiation_nak_escalates_to_reject() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    let peer_mru = mock_lcp().peer_mru;
    let peer_auth = mock_lcp().auth_type;

    // Disagreeing MRU plus a fresh (acceptable) peer magic each round.
    let request_with_mru = |id: u8, mru: u16, magic: u32| {
        let mut payload = vec![1, 4];
        payload.extend(mru.to_be_bytes());
        payload.extend([3, 4]);
        payload.extend(peer_auth.to_be_bytes());
        payload.extend([5, 6]);
        payload.extend(magic.to_be_bytes());
        lcp_config_request_with_payload(id, payload)
    };

    for i in 1..=super::MAX_NAK_LOOPS {
        let mru = 1400 + u16::from(i);
        send_session_frame(&h.to_client, request_with_mru(i, mru, 0x1111_0000 + u32::from(i)));

        let reply = next_ppp_from_client(&mut h).await;
        assert!(reply.is_nak(), "request {i} within the cap must be Naked, code={}", reply.code);
        assert_eq!(reply.id, i);
        assert_eq!(
            reply.payload,
            [vec![1, 4], peer_mru.to_be_bytes().to_vec()].concat(),
            "nak must only carry the established MRU"
        );
    }

    for i in 0..2u8 {
        let mru = 1300 + u16::from(i);
        send_session_frame(&h.to_client, request_with_mru(10 + i, mru, 0x2222_0000 + u32::from(i)));

        let reply = next_ppp_from_client(&mut h).await;
        assert!(
            reply.is_reject(),
            "request past the Nak cap must be rejected, code={}",
            reply.code
        );
        assert_eq!(reply.id, 10 + i);
        assert_eq!(
            reply.payload,
            [vec![1, 4], mru.to_be_bytes().to_vec()].concat(),
            "reject must echo the disagreeing MRU option as received"
        );
    }

    send_session_frame(&h.to_client, lcp_config_request_packet(20, peer_mru, 0x3333_0000));

    let reply = next_ppp_from_client(&mut h).await;
    assert!(reply.is_ack(), "matching request after the cap must be Acked, code={}", reply.code);
    assert_eq!(reply.id, 20);

    h.status.just_change_status(ServiceStatus::Stopping);
    let _ = tokio::time::timeout(Duration::from_secs(5), h.handle).await;
}

// ── graceful stop sends Terminate + PADT ─────────────────────────────────

#[tokio::test]
async fn graceful_stop_sends_terminate_then_padt() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());
    send_session_frame(&h.to_client, echo_reply_packet(0xFEED_FACE));

    h.status.just_change_status(ServiceStatus::Stopping);

    let term = next_ppp_from_client(&mut h).await;
    assert!(term.is_termination(), "expected Terminate-Request, code={}", term.code);

    send_session_frame(&h.to_client, termination_ack_packet(term.id));
    loop {
        let raw = tokio::time::timeout(Duration::from_secs(5), h.from_client.recv())
            .await
            .expect("timed out waiting for PADT")
            .expect("client channel closed");
        if let Some((ethertype, ppp)) = extract_client_frame(&raw) {
            assert_eq!(ethertype, 0x8863, "expected PADT ethertype");
            assert!(ppp.is_none(), "PADT carries no PPP payload");
            break;
        }
    }

    let result = tokio::time::timeout(Duration::from_secs(5), h.handle)
        .await
        .expect("keepalive finished")
        .unwrap();
    assert!(matches!(result, Err(PppoeError::ServiceStopped)));
}

// ── peer LCP termination still works ──────────────────────────────────────

#[tokio::test]
async fn peer_termination_request_is_acked() {
    ensure_test_env();
    let mut h = spawn_keepalive(test_config(Some(600)), mock_lcp());

    let echo = next_ppp_from_client(&mut h).await;
    assert!(echo.is_echo_request());

    let term_req = PointToPoint {
        protocol: 0xc021,
        code: 5,
        id: 9,
        length: 4,
        payload: vec![],
    }
    .convert_to_payload();
    send_session_frame(&h.to_client, term_req);

    let ack = next_ppp_from_client(&mut h).await;
    assert!(ack.is_termination_ack());
    assert_eq!(ack.id, 9);

    let result = tokio::time::timeout(Duration::from_secs(5), h.handle)
        .await
        .expect("keepalive finished")
        .unwrap();
    assert!(matches!(result, Err(PppoeError::PeerTerminated)));
}

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::{PPPOption, PointToPoint};
use landscape_common::net_proto::pppoe::{PPPoEFrame, PPPoETag};
use landscape_common::service::{ServiceStatus, WatchService};

use crate::pppoe_client::PPPoEClientConfig;

use super::{PppoeResult, DEFAULT_TIMEOUT, ETH_P_PPOED, ETH_P_PPOES, MAX_DISCOVERY_RETRIES, MAX_LCP_RETRIES};
use super::lcp::{LcpPhaseResult, run};

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
const TEST_HOST_UNIQ: u32 = 0x12345678;

fn wrap_eth(dst: &[u8], src: &[u8], ethertype: u16, payload: Vec<u8>) -> Box<Vec<u8>> {
    let mut packet = dst.to_vec();
    packet.extend(src);
    packet.extend(ethertype.to_be_bytes());
    packet.extend(payload);
    Box::new(packet)
}

fn build_pado(host_uniq: u32) -> Box<Vec<u8>> {
    let frame = PPPoEFrame::get_offer_with_host_uniq(host_uniq);
    wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload())
}

fn build_pads(host_uniq: u32, session_id: u16) -> Box<Vec<u8>> {
    let mut frame = PPPoEFrame {
        ver: 1, t: 1, code: 0x65, sid: session_id, length: 0, payload: vec![],
    };
    frame.payload.extend(PPPoETag::HostUniq(host_uniq).decode_options());
    frame.length = frame.payload.len() as u16;
    wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload())
}

fn build_pppoe_session(sid: u16, ppp_payload: Vec<u8>) -> Box<Vec<u8>> {
    let frame = PPPoEFrame {
        ver: 1, t: 1, code: 0, sid, length: ppp_payload.len() as u16, payload: ppp_payload,
    };
    wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOES, frame.convert_to_payload())
}

fn build_lcp_config_request(id: u8, mru: u16, magic: u32, auth_type: u16) -> Vec<u8> {
    PointToPoint::request_mru_with_auth(id, mru, magic, auth_type)
}

fn build_lcp_config_ack(id: u8, mru: u16, magic: u32) -> Vec<u8> {
    PointToPoint::ack_mru(id, mru, magic)
}

fn build_lcp_config_nak(id: u8, mru: u16, magic: u32) -> Vec<u8> {
    PointToPoint::nak_mru(id, mru, magic)
}

fn extract_host_uniq(packet: &[u8]) -> Option<u32> {
    if packet.len() < 20 { return None; }
    let frame = PPPoEFrame::new(&packet[14..])?;
    for tag in PPPoETag::from_bytes(&frame.payload) {
        if let PPPoETag::HostUniq(id) = tag { return Some(id); }
    }
    None
}

fn extract_pppoe_code(packet: &[u8]) -> Option<u8> {
    if packet.len() < 15 { return None; }
    Some(packet[14 + 1])
}

fn extract_lcp_packet(packet: &[u8], expect_sid: u16) -> Option<PointToPoint> {
    if packet.len() < 16 { return None; }
    if u16::from_be_bytes([packet[12], packet[13]]) != ETH_P_PPOES { return None; }
    let frame = PPPoEFrame::new(&packet[14..])?;
    if frame.sid != expect_sid { return None; }
    PointToPoint::new(&frame.payload)
}

fn extract_sid_from_pads(packet: &[u8]) -> Option<u16> {
    if packet.len() < 14 { return None; }
    let frame = PPPoEFrame::new(&packet[14..])?;
    if frame.code != 0x65 { return None; }
    Some(frame.sid)
}

// ── unit tests ──────────────────────────────────────────────────────────

mod unit {
    use super::*;

    #[test]
    fn parse_lcp_mru_magic_options_full() {
        ensure_test_env();
        let payload = [1, 4, 0x05, 0xd4, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let (mru, magic) = super::super::lcp::parse_lcp_mru_magic_options(&payload);
        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
    }

    #[test]
    fn parse_lcp_mru_magic_options_empty() {
        ensure_test_env();
        let (mru, magic) = super::super::lcp::parse_lcp_mru_magic_options(&[]);
        assert_eq!(mru, None);
        assert_eq!(magic, None);
    }

    #[test]
    fn parse_lcp_mru_magic_options_mru_only() {
        ensure_test_env();
        let payload = [1, 4, 0x05, 0xd4];
        let (mru, magic) = super::super::lcp::parse_lcp_mru_magic_options(&payload);
        assert_eq!(mru, Some(1492));
        assert_eq!(magic, None);
    }

    #[test]
    fn parse_lcp_request_options_full() {
        ensure_test_env();
        let payload = [1, 4, 0x05, 0xd4, 3, 4, 0xc0, 0x23, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let (mru, magic, auth, count) = super::super::lcp::parse_lcp_request_options(&payload);
        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
        assert_eq!(auth, Some(0xc023));
        assert_eq!(count, 3);
    }

    #[test]
    fn parse_lcp_request_options_missing_auth() {
        ensure_test_env();
        let payload = [1, 4, 0x05, 0xd4, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let (mru, magic, auth, count) = super::super::lcp::parse_lcp_request_options(&payload);
        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
        assert_eq!(auth, None);
        assert_eq!(count, 2);
    }

    #[test]
    fn extract_l2_valid() {
        ensure_test_env();
        // dst(6) + src(6) + ethertype(2) + payload(2) = 16 bytes
        let data: Vec<u8> = [0xFFu8; 6].into_iter()     // dst
            .chain([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) // src
            .chain([0x88, 0x63])                          // ethertype
            .chain([0xaa, 0xbb])                          // payload
            .collect();
        let (src, payload) = super::super::lcp::extract_l2(&data).unwrap();
        assert_eq!(src, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(payload, &[0x88, 0x63, 0xaa, 0xbb]);
    }

    #[test]
    fn extract_l2_too_short() {
        ensure_test_env();
        assert!(super::super::lcp::extract_l2(&[0u8; 10]).is_none());
    }
}

// ── async integration tests ─────────────────────────────────────────────

mod integration {
    use super::*;

    #[tokio::test]
    async fn test_discovery_success() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // 1. Read PADI
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADI");
        assert_eq!(extract_pppoe_code(&padi), Some(0x09), "should be PADI");
        let host_uniq = extract_host_uniq(&padi).expect("PADI must have HostUniq");

        // 2. Send PADO
        to_client.send(build_pado(host_uniq)).await.unwrap();

        // 3. Read PADR
        let padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADR");
        assert_eq!(extract_pppoe_code(&padr), Some(0x19), "should be PADR");

        // 4. Send PADS
        to_client.send(build_pads(host_uniq, 0x0042)).await.unwrap();

        // Verify PADR/PADS exchange done — LCP phase would begin next.
        // We stop here to avoid needing LCP packet response.
        // Drop and let task die.
        drop(to_client);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn test_discovery_wrong_host_uniq_ignored() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // Read PADI to get host_uniq
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADI");
        let real_uniq = extract_host_uniq(&padi).unwrap();

        // Send PADO with WRONG HostUniq — should be ignored
        to_client.send(build_pado(real_uniq.wrapping_add(1))).await.unwrap();

        // There should be NO PADR in response (verify with a short timeout)
        let result = tokio::time::timeout(Duration::from_millis(200), from_client.recv()).await;
        assert!(result.is_err() || result.unwrap().is_none(),
            "PADR should NOT be sent for wrong HostUniq");

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_discovery_timeout() {
        ensure_test_env();
        tokio::time::pause();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // Each timeout is DEFAULT_TIMEOUT seconds. After (MAX_DISCOVERY_RETRIES + 1)
        // send attempts without PADO, it should fail with DiscoveryTimeout.
        // Total advance: (MAX_DISCOVERY_RETRIES + 1) * DEFAULT_TIMEOUT + some margin.
        let total_timeout = Duration::from_secs(
            (MAX_DISCOVERY_RETRIES as u64 + 2) * DEFAULT_TIMEOUT
        );

        // Advance time in chunks to let intermediate timeout fires process
        for _ in 0..(MAX_DISCOVERY_RETRIES + 2) {
            tokio::time::advance(Duration::from_secs(DEFAULT_TIMEOUT + 1)).await;
        }

        let result = handle.await.expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::DiscoveryTimeout)));
    }

    #[tokio::test]
    async fn test_full_lcp_success() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // Discovery
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();

        let padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADR");
        assert_eq!(extract_pppoe_code(&padr), Some(0x19));

        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        // LCP: send peer Config-Request
        let peer_mru = 1492u16;
        let peer_magic = 0xDEAD_BEEFu32;
        let auth_type = 0xc023u16;
        let lcp_req = build_lcp_config_request(1, peer_mru, peer_magic, auth_type);
        to_client.send(build_pppoe_session(session_id, lcp_req)).await.unwrap();

        // Read our LCP Ack to peer's Request
        let our_ack = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected our LCP Ack");
        let ack_ppp = extract_lcp_packet(&our_ack, session_id).expect("valid LCP Ack packet");
        assert!(ack_ppp.is_lcp_config());
        assert!(ack_ppp.is_ack());

        // Read our LCP Config-Request
        let our_req = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected our LCP Config-Request");
        let req_ppp = extract_lcp_packet(&our_req, session_id).expect("valid LCP Request packet");
        assert!(req_ppp.is_request());
        let our_req_id = req_ppp.id;

        // Send Ack to our Config-Request
        let ack_to_us = build_lcp_config_ack(our_req_id, 1492, 0xDEAD_0000);
        to_client.send(build_pppoe_session(session_id, ack_to_us)).await.unwrap();

        // Wait for lcp::run to complete
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");

        let lcp_result = result.expect("LCP phase should succeed");
        assert_eq!(lcp_result.session_id, session_id);
        assert_eq!(lcp_result.server_mac, SERVER_MAC.to_vec());
        assert_eq!(lcp_result.mru, 1492);
        assert_eq!(lcp_result.auth_type, auth_type);
    }

    #[tokio::test]
    async fn test_lcp_config_rejected() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // Discovery
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();

        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        // Send peer Config-Request
        let lcp_req = build_lcp_config_request(1, 1492, 0xDEAD_BEEF, 0xc023);
        to_client.send(build_pppoe_session(session_id, lcp_req)).await.unwrap();

        // Read our Ack + our Config-Request
        let _our_ack = from_client.recv().await.unwrap();
        let our_req = from_client.recv().await.unwrap();
        let req_ppp = extract_lcp_packet(&our_req, session_id).unwrap();
        let our_req_id = req_ppp.id;

        // Send LCP Config-Reject
        let reject = [
            0xc0u8, 0x21, 4, our_req_id, 0, 4,
        ];
        to_client.send(build_pppoe_session(session_id, reject.to_vec())).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await.expect("task should complete").expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::LcpConfigRejected)));
    }

    #[tokio::test]
    async fn test_lcp_config_nak_then_ack() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // Discovery
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();

        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        // Send peer Config-Request
        let lcp_req = build_lcp_config_request(1, 1492, 0xDEAD_BEEF, 0xc023);
        to_client.send(build_pppoe_session(session_id, lcp_req)).await.unwrap();

        // Read our Ack + our Config-Request
        let _our_ack = from_client.recv().await.unwrap();
        let our_req = from_client.recv().await.unwrap();
        let req_ppp = extract_lcp_packet(&our_req, session_id).unwrap();
        let our_req_id = req_ppp.id;

        // Send Config-Nak with suggested MRU=1400, magic=0xCAFE
        let nak = build_lcp_config_nak(our_req_id, 1400, 0xCAFE_0000);
        to_client.send(build_pppoe_session(session_id, nak)).await.unwrap();

        // Read our adjusted Config-Request (should use min(1492, 1400) = 1400)
        let our_adj_req = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected adjusted Config-Request");
        let adj_ppp = extract_lcp_packet(&our_adj_req, session_id).unwrap();
        assert!(adj_ppp.is_request());

        let (mru, _, _, _) = super::super::lcp::parse_lcp_request_options(&adj_ppp.payload);
        assert_eq!(mru, Some(1400), "MRU should be min(1492, 1400) = 1400");

        // Send Ack to adjusted request
        let ack = build_lcp_config_ack(our_req_id + 1, 1400, 0xCAFE_0000);
        to_client.send(build_pppoe_session(session_id, ack)).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await.expect("task should complete").expect("task should not panic");

        let lcp_result = result.expect("LCP phase should succeed after Nak");
        assert_eq!(lcp_result.mru, 1400);
    }

    #[tokio::test]
    async fn test_channel_closed() {
        ensure_test_env();

        let (mut client_tx, _from_client) = mpsc::channel::<Box<Vec<u8>>>(2);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(2);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        // Drop the sender — rx.recv() will return None
        drop(to_client);

        let result = tokio::time::timeout(Duration::from_secs(2),
            run(&config, &mut client_tx, &mut client_rx, &status)
        ).await.expect("should complete quickly");

        assert!(matches!(result, Err(super::super::error::PppoeError::ChannelClosed)));
    }

    #[tokio::test]
    async fn test_service_stopped_during_discovery() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let status_for_spawn = status.clone();
        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status_for_spawn).await
        });

        // Wait for PADI
        let _padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await.unwrap().expect("expected PADI");

        // Simulate service stop
        status.just_change_status(ServiceStatus::Stopping);

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await.expect("task should complete").expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::ServiceStopped)));
    }

    #[tokio::test]
    async fn test_lcp_timeout_after_discovery() {
        ensure_test_env();
        tokio::time::pause();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // Complete discovery quickly
        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();
        to_client.send(build_pads(host_uniq, 0x0042)).await.unwrap();

        // Advance past all LCP retries (no LCP response sent)
        for _ in 0..(MAX_LCP_RETRIES + 2) {
            tokio::time::advance(Duration::from_secs(DEFAULT_TIMEOUT + 1)).await;
        }

        let result = handle.await.expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::LcpTimeout)));
    }

    #[tokio::test]
    async fn test_discovery_retry_then_succeed() {
        ensure_test_env();
        tokio::time::pause();

        let (mut client_tx, mut from_client) = mpsc::channel::<Box<Vec<u8>>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Box<Vec<u8>>>(16);
        let config = test_config();
        let status = WatchService::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status).await
        });

        // First PADI (will timeout)
        let padi1 = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi1).unwrap();

        // Advance past first timeout → PADI resent
        tokio::time::advance(Duration::from_secs(DEFAULT_TIMEOUT + 1)).await;
        let padi2 = from_client.recv().await.unwrap();
        assert_eq!(extract_host_uniq(&padi2), Some(host_uniq), "same HostUniq on retry");

        // Now send PADO to the retry
        to_client.send(build_pado(host_uniq)).await.unwrap();

        // Verify PADR follows
        let padr = from_client.recv().await.expect("expected PADR after PADO");
        assert_eq!(extract_pppoe_code(&padr), Some(0x19));

        drop(to_client);
        drop(handle);
    }
}

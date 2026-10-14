use tokio::sync::mpsc;
use tokio::time::Duration;

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::PointToPoint;
use landscape_common::net_proto::pppoe::{PPPoEFrame, PPPoETag};
use landscape_common::service::{ServiceHandle, ServiceStatus};

use super::PPPoEClientConfig;

use super::lcp::run;
use super::{DEFAULT_TIMEOUT, ETH_P_PPOED, ETH_P_PPOES, MAX_DISCOVERY_RETRIES, MAX_LCP_RETRIES};

fn ensure_test_env() {
    unsafe { std::env::set_var("LANDSCAPE_IGNORE_CLI_ARGS", "1") };
}

fn test_config() -> PPPoEClientConfig {
    PPPoEClientConfig::new(
        uuid::Uuid::new_v4(),
        1,
        "eth0".into(),
        MacAddr::new(0x02, 0x03, 0x04, 0x05, 0x06, 0x07),
        "testuser".into(),
        "testpass".into(),
        false,
        1492,
        None,
    )
}

const SERVER_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
fn wrap_eth(dst: &[u8], src: &[u8], ethertype: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut packet = dst.to_vec();
    packet.extend(src);
    packet.extend(ethertype.to_be_bytes());
    packet.extend(payload);
    packet
}

fn build_pado(host_uniq: u32) -> Vec<u8> {
    let frame = PPPoEFrame::get_offer_with_host_uniq(host_uniq);
    wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload())
}

fn build_pado_with_ac_name(host_uniq: u32, ac_name: &str) -> Vec<u8> {
    let mut frame = PPPoEFrame::get_offer_with_host_uniq(host_uniq);
    frame.payload.extend(PPPoETag::AcName(ac_name.as_bytes().to_vec()).decode_options());
    frame.length = frame.payload.len() as u16;
    wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload())
}

fn build_pads(host_uniq: u32, session_id: u16) -> Vec<u8> {
    let mut frame = PPPoEFrame {
        ver: 1,
        t: 1,
        code: 0x65,
        sid: session_id,
        length: 0,
        payload: vec![],
    };
    frame.payload.extend(PPPoETag::HostUniq(host_uniq).decode_options());
    frame.length = frame.payload.len() as u16;
    wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload())
}

fn build_pppoe_session(sid: u16, ppp_payload: Vec<u8>) -> Vec<u8> {
    let frame = PPPoEFrame {
        ver: 1,
        t: 1,
        code: 0,
        sid,
        length: ppp_payload.len() as u16,
        payload: ppp_payload,
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

/// LCP Config-Request with a caller-supplied Authentication-Protocol
/// option (MRU and Magic-Number are always included).
fn build_lcp_config_request_auth(id: u8, mru: u16, magic: u32, auth_option: &[u8]) -> Vec<u8> {
    let mut payload = vec![1, 4];
    payload.extend(mru.to_be_bytes());
    payload.extend(auth_option);
    payload.extend([5, 6]);
    payload.extend(magic.to_be_bytes());
    PointToPoint {
        protocol: 0xc021,
        code: 1,
        id,
        length: payload.len() as u16 + 4,
        payload,
    }
    .convert_to_payload()
}

fn extract_host_uniq(packet: &[u8]) -> Option<u32> {
    if packet.len() < 20 {
        return None;
    }
    let frame = PPPoEFrame::new(&packet[14..])?;
    for tag in PPPoETag::from_bytes(&frame.payload) {
        if let PPPoETag::HostUniq(id) = tag {
            return Some(id);
        }
    }
    None
}

fn extract_pppoe_code(packet: &[u8]) -> Option<u8> {
    if packet.len() < 15 {
        return None;
    }
    Some(packet[14 + 1])
}

fn extract_lcp_packet(packet: &[u8], expect_sid: u16) -> Option<PointToPoint> {
    if packet.len() < 16 {
        return None;
    }
    if u16::from_be_bytes([packet[12], packet[13]]) != ETH_P_PPOES {
        return None;
    }
    let frame = PPPoEFrame::new(&packet[14..])?;
    if frame.sid != expect_sid {
        return None;
    }
    PointToPoint::new(&frame.payload)
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
        let (mru, magic, auth, algorithm, count) =
            super::super::lcp::parse_lcp_request_options(&payload);
        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
        assert_eq!(auth, Some(0xc023));
        assert_eq!(algorithm, None, "PAP carries no algorithm byte");
        assert_eq!(count, 3);
    }

    #[test]
    fn parse_lcp_request_options_chap_algorithm() {
        ensure_test_env();
        let payload = [1, 4, 0x05, 0xd4, 3, 5, 0xc2, 0x23, 0x05, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let (mru, magic, auth, algorithm, count) =
            super::super::lcp::parse_lcp_request_options(&payload);
        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
        assert_eq!(auth, Some(0xc223));
        assert_eq!(algorithm, Some(0x05), "CHAP algorithm byte must be recorded");
        assert_eq!(count, 3);
    }

    #[test]
    fn parse_lcp_request_options_missing_auth() {
        ensure_test_env();
        let payload = [1, 4, 0x05, 0xd4, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let (mru, magic, auth, algorithm, count) =
            super::super::lcp::parse_lcp_request_options(&payload);
        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
        assert_eq!(auth, None);
        assert_eq!(algorithm, None);
        assert_eq!(count, 2);
    }

    #[test]
    fn discovery_tag_error_formats_reason() {
        ensure_test_env();
        assert_eq!(
            super::super::lcp::discovery_tag_error(&PPPoETag::ServiceNameError(
                b"no such service".to_vec()
            ))
            .as_deref(),
            Some("Service-Name-Error: no such service")
        );
        // An empty message degrades to the bare tag name
        assert_eq!(
            super::super::lcp::discovery_tag_error(&PPPoETag::ACSystemError(vec![])).as_deref(),
            Some("AC-System-Error")
        );
        // Non-error tags are not errors
        assert_eq!(super::super::lcp::discovery_tag_error(&PPPoETag::AcName(vec![])), None);
        assert_eq!(super::super::lcp::discovery_tag_error(&PPPoETag::HostUniq(1)), None);
    }

    #[test]
    fn extract_l2_valid() {
        ensure_test_env();
        // dst(6) + src(6) + ethertype(2) + payload(2) = 16 bytes
        let data: Vec<u8> = [0xFFu8; 6]
            .into_iter() // dst
            .chain([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) // src
            .chain([0x88, 0x63]) // ethertype
            .chain([0xaa, 0xbb]) // payload
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

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // 1. Read PADI
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
        assert_eq!(extract_pppoe_code(&padi), Some(0x09), "should be PADI");
        let host_uniq = extract_host_uniq(&padi).expect("PADI must have HostUniq");

        // 2. Send PADO
        to_client.send(build_pado(host_uniq)).await.unwrap();

        // 3. Read PADR
        let padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADR");
        assert_eq!(extract_pppoe_code(&padr), Some(0x19), "should be PADR");

        // 4. Send PADS
        to_client.send(build_pads(host_uniq, 0x0042)).await.unwrap();

        // Verify PADR/PADS exchange done — LCP phase would begin next.
        // We stop here to avoid needing LCP packet response.
        // Drop and let task die.
        drop(to_client);
        drop(handle);
    }

    /// pppd semantics (lcp.c:1618-1663): a CHAP request with an algorithm
    /// this client cannot run (only MD5 is implemented) is answered with a
    /// Configure-Nak suggesting CHAP/MD5 in its 5-byte form; the peer's
    /// retry with MD5 is then Acked and the negotiation continues.
    #[tokio::test]
    async fn test_unsupported_chap_algorithm_naked_then_md5_acked() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();
        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        // CHAP with SHA-256 (algorithm 0x81): must be Naked
        let req = build_lcp_config_request_auth(1, 1492, 0xDEAD_BEEF, &[3, 5, 0xc2, 0x23, 0x81]);
        to_client.send(build_pppoe_session(session_id, req)).await.unwrap();

        let nak = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected Nak for unsupported algorithm");
        let nak_ppp = extract_lcp_packet(&nak, session_id).unwrap();
        assert!(nak_ppp.is_nak(), "code {}", nak_ppp.code);
        assert_eq!(nak_ppp.id, 1, "nak must mirror the request id");
        assert_eq!(
            nak_ppp.payload,
            vec![3, 5, 0xc2, 0x23, 0x05],
            "nak must suggest CHAP/MD5 in its 5-byte form"
        );

        // Retry with MD5: must be Acked (and our own Config-Request follows)
        let req = build_lcp_config_request_auth(2, 1492, 0xDEAD_BEEF, &[3, 5, 0xc2, 0x23, 0x05]);
        to_client.send(build_pppoe_session(session_id, req)).await.unwrap();

        let ack = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected Ack for CHAP/MD5");
        let ack_ppp = extract_lcp_packet(&ack, session_id).unwrap();
        assert!(ack_ppp.is_ack(), "code {}", ack_ppp.code);
        assert_eq!(ack_ppp.id, 2);

        drop(to_client);
        drop(handle);
    }

    /// A CHAP option without the algorithm byte is unusable (RFC 1994
    /// §4.1) and an unknown authentication protocol (e.g. EAP) cannot run
    /// either: both are Naked suggesting CHAP/MD5.
    #[tokio::test]
    async fn test_chap_without_algorithm_and_eap_are_naked() {
        ensure_test_env();

        // CHAP without the algorithm byte (RFC 1994 §4.1 violation), and
        // EAP (0xc227) — an authentication this client cannot run.
        for auth_option in [vec![3, 4, 0xc2, 0x23], vec![3, 4, 0xc2, 0x27]] {
            let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
            let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
            let config = test_config();
            let status = ServiceHandle::new();
            status.just_change_status(ServiceStatus::Staring);
            status.just_change_status(ServiceStatus::Running);

            let handle =
                tokio::spawn(
                    async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
                );

            let padi = from_client.recv().await.unwrap();
            let host_uniq = extract_host_uniq(&padi).unwrap();
            to_client.send(build_pado(host_uniq)).await.unwrap();
            let _padr = from_client.recv().await.unwrap();
            let session_id = 0x0042u16;
            to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

            let req = build_lcp_config_request_auth(7, 1492, 0xDEAD_BEEF, &auth_option);
            to_client.send(build_pppoe_session(session_id, req)).await.unwrap();

            let nak = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
                .await
                .unwrap()
                .expect("expected Nak");
            let nak_ppp = extract_lcp_packet(&nak, session_id).unwrap();
            assert!(nak_ppp.is_nak(), "auth {auth_option:?} must be naked");
            assert_eq!(nak_ppp.payload, vec![3, 5, 0xc2, 0x23, 0x05]);

            drop(to_client);
            drop(handle);
        }
    }

    /// pppd nakloops bound: a peer that keeps requesting an unsupported
    /// authentication gets at most MAX_NAK_LOOPS Naks before the phase
    /// fails instead of ping-ponging forever.
    #[tokio::test]
    async fn test_unsupported_auth_nak_cap_fails_lcp() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();
        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        let rounds = super::super::MAX_NAK_LOOPS;
        for i in 1..=rounds {
            let req =
                build_lcp_config_request_auth(i, 1492, 0xDEAD_BEEF, &[3, 5, 0xc2, 0x23, 0x81]);
            to_client.send(build_pppoe_session(session_id, req)).await.unwrap();

            let nak = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
                .await
                .unwrap()
                .expect("expected Nak");
            assert!(extract_lcp_packet(&nak, session_id).unwrap().is_nak());
        }

        // Past the cap the phase fails fatally instead of naking again.
        let req = build_lcp_config_request_auth(9, 1492, 0xDEAD_BEEF, &[3, 5, 0xc2, 0x23, 0x81]);
        to_client.send(build_pppoe_session(session_id, req)).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");
        assert!(matches!(result, Err(super::super::error::PppoeError::LcpConfigRejected)));
    }

    /// RFC 2516 §5.4: a PADO carrying Service-Name-Error fails the
    /// discovery immediately (pppd parsePADOTags) instead of waiting for
    /// the discovery timeouts.
    #[tokio::test]
    async fn test_pado_service_name_error_rejected() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();

        let mut frame = PPPoEFrame::get_offer_with_host_uniq(host_uniq);
        frame
            .payload
            .extend(PPPoETag::ServiceNameError(b"no such service".to_vec()).decode_options());
        frame.length = frame.payload.len() as u16;
        to_client
            .send(wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload()))
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");
        assert!(
            matches!(
                &result,
                Err(super::super::error::PppoeError::DiscoveryRejected(reason))
                    if reason.contains("Service-Name-Error")
            ),
            "expected DiscoveryRejected, got {:?}",
            result.err()
        );
    }

    /// RFC 2516 §5.4: a PADS carrying an error tag means the AC denied the
    /// session — fail fast instead of grinding through the LCP timeouts.
    #[tokio::test]
    async fn test_pads_generic_error_rejected() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();

        let mut frame = PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0x65,
            sid: 0,
            length: 0,
            payload: vec![],
        };
        frame.payload.extend(PPPoETag::HostUniq(host_uniq).decode_options());
        frame.payload.extend(PPPoETag::GenericError(b"no resources".to_vec()).decode_options());
        frame.length = frame.payload.len() as u16;
        to_client
            .send(wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload()))
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");
        assert!(
            matches!(
                &result,
                Err(super::super::error::PppoeError::DiscoveryRejected(reason))
                    if reason.contains("Generic-Error")
            ),
            "expected DiscoveryRejected, got {:?}",
            result.err()
        );
    }

    /// RFC 2516 §5.4 + shared medium: another AC's error-tagged PADO with a
    /// mismatched Host-Uniq is not addressed to us and must not fail the
    /// discovery — a later PADO from the target AC still establishes the
    /// flow (answered with a PADR).
    #[tokio::test]
    async fn test_pado_error_tag_with_wrong_host_uniq_ignored() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();

        let mut frame = PPPoEFrame::get_offer_with_host_uniq(host_uniq.wrapping_add(1));
        frame
            .payload
            .extend(PPPoETag::ServiceNameError(b"no such service".to_vec()).decode_options());
        frame.length = frame.payload.len() as u16;
        to_client
            .send(wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload()))
            .await
            .unwrap();

        // The error-tagged PADO is not for us: the client keeps discovering
        // and a matching PADO is still answered with a PADR.
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .expect("discovery should survive a foreign error-tagged PADO")
            .expect("channel should stay open");

        drop(to_client);
        drop(handle);
    }

    /// RFC 2516 §5.4: an error-tagged PADS with a mismatched Host-Uniq is
    /// not addressed to us and is ignored — a later correct PADS still
    /// enters the LCP phase.
    #[tokio::test]
    async fn test_pads_error_tag_with_wrong_host_uniq_ignored() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();

        let mut frame = PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0x65,
            sid: 0,
            length: 0,
            payload: vec![],
        };
        frame.payload.extend(PPPoETag::HostUniq(host_uniq.wrapping_add(1)).decode_options());
        frame.payload.extend(PPPoETag::GenericError(b"no resources".to_vec()).decode_options());
        frame.length = frame.payload.len() as u16;
        to_client
            .send(wrap_eth(&SERVER_MAC, &SERVER_MAC, ETH_P_PPOED, frame.convert_to_payload()))
            .await
            .unwrap();

        // The error-tagged PADS is not for us: a correct PADS still enters
        // the LCP phase, proven by answering a peer Config-Request with an
        // Ack.
        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        let lcp_req = build_lcp_config_request(1, 1492, 0xDEAD_BEEF, 0xc023);
        to_client.send(build_pppoe_session(session_id, lcp_req)).await.unwrap();

        let ack = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .expect("LCP phase should start after a foreign error-tagged PADS")
            .expect("channel should stay open");
        let ppp = extract_lcp_packet(&ack, session_id).unwrap();
        assert!(ppp.is_lcp_config() && ppp.is_ack());

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_discovery_wrong_host_uniq_ignored() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Read PADI to get host_uniq
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
        let real_uniq = extract_host_uniq(&padi).unwrap();

        // Send PADO with WRONG HostUniq — should be ignored
        to_client.send(build_pado(real_uniq.wrapping_add(1))).await.unwrap();

        // There should be NO PADR in response (verify with a short timeout)
        let result = tokio::time::timeout(Duration::from_millis(200), from_client.recv()).await;
        assert!(
            result.is_err() || result.unwrap().is_none(),
            "PADR should NOT be sent for wrong HostUniq"
        );

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_discovery_timeout() {
        ensure_test_env();
        tokio::time::pause();

        let (mut client_tx, _from_client) = mpsc::channel::<Vec<u8>>(16);
        let (_to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Each timeout is DEFAULT_TIMEOUT seconds. After (MAX_DISCOVERY_RETRIES + 1)
        // send attempts without PADO, it should fail with DiscoveryTimeout.
        // Total advance: (MAX_DISCOVERY_RETRIES + 1) * DEFAULT_TIMEOUT + some margin.
        let _total_timeout =
            Duration::from_secs((MAX_DISCOVERY_RETRIES as u64 + 2) * DEFAULT_TIMEOUT);

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

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Discovery
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();

        let padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADR");
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
            .await
            .unwrap()
            .expect("expected our LCP Ack");
        let ack_ppp = extract_lcp_packet(&our_ack, session_id).expect("valid LCP Ack packet");
        assert!(ack_ppp.is_lcp_config());
        assert!(ack_ppp.is_ack());

        // Read our LCP Config-Request
        let our_req = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected our LCP Config-Request");
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

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Discovery
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
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
        let reject = [0xc0u8, 0x21, 4, our_req_id, 0, 4];
        to_client.send(build_pppoe_session(session_id, reject.to_vec())).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::LcpConfigRejected)));
    }

    #[tokio::test]
    async fn test_lcp_request_missing_auth_type_rejected() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Discovery
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();

        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        // Build a peer LCP Config-Request with only MRU + magic (no auth-type option)
        // Header: 0xc0 0x21 code=1 id=1 length=14
        // Options: MRU(1,4,0x05d4) + magic-number(5,6,0xDEADBEEF)
        let partial_request: Vec<u8> = [
            0xc0u8, 0x21, 1, 1, // protocol + code + id
            0x00, 14, // length = 4(header) + 4(MRU) + 6(magic) = 14
            1, 4, 0x05, 0xd4, // MRU = 1492
            5, 6, 0xDE, 0xAD, 0xBE, 0xEF, // magic number
        ]
        .to_vec();
        to_client.send(build_pppoe_session(session_id, partial_request)).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::LcpConfigRejected)));
    }

    #[tokio::test]
    async fn test_lcp_config_nak_then_ack() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Discovery
        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
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
            .await
            .unwrap()
            .expect("expected adjusted Config-Request");
        let adj_ppp = extract_lcp_packet(&our_adj_req, session_id).unwrap();
        assert!(adj_ppp.is_request());

        let (mru, _, _, _, _) = super::super::lcp::parse_lcp_request_options(&adj_ppp.payload);
        assert_eq!(mru, Some(1400), "MRU should be min(1492, 1400) = 1400");

        // Send Ack to adjusted request
        let ack = build_lcp_config_ack(our_req_id + 1, 1400, 0xCAFE_0000);
        to_client.send(build_pppoe_session(session_id, ack)).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");

        let lcp_result = result.expect("LCP phase should succeed after Nak");
        assert_eq!(lcp_result.mru, 1400);
    }

    #[tokio::test]
    async fn test_channel_closed() {
        ensure_test_env();

        let (mut client_tx, _from_client) = mpsc::channel::<Vec<u8>>(2);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(2);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        // Drop the sender — rx.recv() will return None
        drop(to_client);

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run(&config, &mut client_tx, &mut client_rx, &status),
        )
        .await
        .expect("should complete quickly");

        assert!(matches!(result, Err(super::super::error::PppoeError::ChannelClosed)));
    }

    #[tokio::test]
    async fn test_service_stopped_during_discovery() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (_to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let status_for_spawn = status.clone();
        let handle = tokio::spawn(async move {
            run(&config, &mut client_tx, &mut client_rx, &status_for_spawn).await
        });

        // Wait for PADI
        let _padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");

        // Simulate service stop
        status.just_change_status(ServiceStatus::Stopping);

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::ServiceStopped)));
    }

    #[tokio::test]
    async fn test_lcp_timeout_after_discovery() {
        ensure_test_env();
        tokio::time::pause();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

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

    /// A PADT (RFC 2516 §5.6) after PADS must terminate the LCP negotiation
    /// phase immediately with `PadtReceived` instead of grinding through the
    /// LCP retransmission timeouts.
    #[tokio::test]
    async fn test_padt_during_lcp_negotiation() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Discovery up to the LCP negotiation state
        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();
        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        // Server tears the not-yet-negotiated session down via PADT
        let padt = wrap_eth(
            &SERVER_MAC,
            &SERVER_MAC,
            ETH_P_PPOED,
            PPPoEFrame::get_padt(session_id).convert_to_payload(),
        );
        to_client.send(padt).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should complete")
            .expect("task should not panic");

        assert!(matches!(result, Err(super::super::error::PppoeError::PadtReceived)));
    }

    /// A PADT for a different session id must not disturb our negotiation.
    #[tokio::test]
    async fn test_padt_wrong_sid_ignored_during_lcp_negotiation() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        // Discovery up to the LCP negotiation state
        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();
        let session_id = 0x0042u16;
        to_client.send(build_pads(host_uniq, session_id)).await.unwrap();

        // PADT for another session: ignored
        let padt = wrap_eth(
            &SERVER_MAC,
            &SERVER_MAC,
            ETH_P_PPOED,
            PPPoEFrame::get_padt(session_id + 1).convert_to_payload(),
        );
        to_client.send(padt).await.unwrap();

        // The LCP negotiation still works: peer Config-Request gets an Ack
        let lcp_req = build_lcp_config_request(1, 1492, 0xDEAD_BEEF, 0xc023);
        to_client.send(build_pppoe_session(session_id, lcp_req)).await.unwrap();

        let ack = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected LCP Ack after unrelated PADT");
        let ppp = extract_lcp_packet(&ack, session_id).unwrap();
        assert!(ppp.is_lcp_config() && ppp.is_ack());

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_discovery_retry_then_succeed() {
        ensure_test_env();
        tokio::time::pause();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

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

    #[tokio::test]
    async fn test_pads_wrong_host_uniq_ignored() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle = tokio::spawn(async move {
            let _ = run(&config, &mut client_tx, &mut client_rx, &status).await;
        });

        // Discovery: read PADI, send PADO, read PADR
        let padi = from_client.recv().await.unwrap();
        let host_uniq = extract_host_uniq(&padi).unwrap();
        to_client.send(build_pado(host_uniq)).await.unwrap();
        let _padr = from_client.recv().await.unwrap();

        // Send PADS with WRONG HostUniq — should be ignored
        to_client.send(build_pads(host_uniq.wrapping_add(1), 0x0042)).await.unwrap();

        // No state change expected. Wait briefly and verify no LCP request arrives.
        let response = tokio::time::timeout(Duration::from_millis(200), from_client.recv()).await;
        assert!(response.is_err(), "no LCP activity expected for wrong PADS HostUniq");

        // Send correct PADS — should enter LCP phase
        to_client.send(build_pads(host_uniq, 0x0042)).await.unwrap();

        // LCP phase would begin — verify by sending peer Config-Request and reading Ack
        let lcp_req = build_lcp_config_request(1, 1492, 0xDEAD_BEEF, 0xc023);
        to_client.send(build_pppoe_session(0x0042, lcp_req)).await.unwrap();

        let ack = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected LCP Ack after correct PADS");
        let ppp = extract_lcp_packet(&ack, 0x0042).unwrap();
        assert!(ppp.is_lcp_config() && ppp.is_ack());

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_ac_name_matching() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let mut config = test_config();
        config.ac_name = Some("desired-ac".into());
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).expect("PADI must have HostUniq");

        to_client.send(build_pado_with_ac_name(host_uniq, "desired-ac")).await.unwrap();

        let padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADR for matching AC name");
        assert_eq!(extract_pppoe_code(&padr), Some(0x19), "should be PADR");

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_ac_name_mismatch_ignored() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let mut config = test_config();
        config.ac_name = Some("desired-ac".into());
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).expect("PADI must have HostUniq");

        to_client.send(build_pado_with_ac_name(host_uniq, "wrong-ac")).await.unwrap();

        let result = tokio::time::timeout(Duration::from_millis(200), from_client.recv()).await;
        assert!(
            result.is_err() || result.unwrap().is_none(),
            "PADR should NOT be sent for mismatched AC name"
        );

        to_client.send(build_pado_with_ac_name(host_uniq, "desired-ac")).await.unwrap();

        let padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADR for matching AC name after mismatch");
        assert_eq!(extract_pppoe_code(&padr), Some(0x19));

        drop(to_client);
        drop(handle);
    }

    #[tokio::test]
    async fn test_ac_name_not_configured_any_accepted() {
        ensure_test_env();

        let (mut client_tx, mut from_client) = mpsc::channel::<Vec<u8>>(16);
        let (to_client, mut client_rx) = mpsc::channel::<Vec<u8>>(16);
        let config = test_config();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        status.just_change_status(ServiceStatus::Running);

        let handle =
            tokio::spawn(
                async move { run(&config, &mut client_tx, &mut client_rx, &status).await },
            );

        let padi = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADI");
        let host_uniq = extract_host_uniq(&padi).expect("PADI must have HostUniq");

        to_client.send(build_pado_with_ac_name(host_uniq, "any-ac")).await.unwrap();

        let padr = tokio::time::timeout(Duration::from_secs(2), from_client.recv())
            .await
            .unwrap()
            .expect("expected PADR when AC name not configured");
        assert_eq!(extract_pppoe_code(&padr), Some(0x19));

        drop(to_client);
        drop(handle);
    }
}

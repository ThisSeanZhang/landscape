use std::process;

use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, sleep};

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::{PPPOption, PointToPoint};
use landscape_common::net_proto::pppoe::{PPPoEFrame, PPPoETag};
use landscape_common::service::ServiceHandle;

use super::PPPoEClientConfig;

use super::error::PppoeError;
use super::{
    DEFAULT_TIMEOUT, ETH_P_PPOED, ETH_P_PPOES, MAX_DISCOVERY_RETRIES, MAX_LCP_RETRIES,
    MAX_NAK_LOOPS, OPT_AUTH, PppoeResult, SessionPacket, parse_session_packet,
};

/// CHAP with MD5 (RFC 1994 §4.1): the only digest this client runs.
pub(crate) const CHAP_ALGORITHM_MD5: u8 = 0x05;
/// PAP (RFC 1334): Authentication-Protocol 0xc023.
pub(crate) const AUTH_PROTO_PAP: u16 = 0xc023;
/// CHAP (RFC 1994): Authentication-Protocol 0xc223.
pub(crate) const AUTH_PROTO_CHAP: u16 = 0xc223;

#[derive(Clone)]
pub(crate) struct LcpPhaseResult {
    pub session_id: u16,
    pub server_mac: Vec<u8>,
    pub mru: u16,
    pub magic_number: u32,
    pub auth_type: u16,
    /// CHAP algorithm byte from the peer's Authentication-Protocol option
    /// (`None` for PAP, or when the peer's option omitted it). Recorded so
    /// a mid-session LCP renegotiation can Nak with the established
    /// 5-byte CHAP form (RFC 1994 §4.1), like pppd does.
    pub auth_algorithm: Option<u8>,
    pub peer_mru: u16,
    pub peer_magic: u32,
}

enum Phase1State {
    Discovering,
    ReuqestSession {
        server_mac: Vec<u8>,
        ac_cookie: Option<Vec<u8>>,
    },
    LcpNegotiating {
        server_mac: Vec<u8>,
        session_id: u16,
        our_mru: u16,
        our_magic: u32,
        cfg_req_id: u8,
        our_config_acked: bool,
        peer_mru: u16,
        peer_magic: u32,
        auth_type: u16,
        auth_algorithm: Option<u8>,
        /// Consecutive unanswered auth Naks sent while answering the peer's
        /// LCP Config-Request (pppd `nakloops`): bounds a peer that keeps
        /// requesting an authentication we cannot run.
        auth_nak_loops: u8,
        peer_config_received: bool,
    },
}

pub(crate) async fn run(
    config: &PPPoEClientConfig,
    tx: &mut mpsc::Sender<Vec<u8>>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    status_rx: &ServiceHandle,
) -> PppoeResult<LcpPhaseResult> {
    let host_uniq = process::id().swap_bytes();
    let magic_number = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut state = Phase1State::Discovering;
    send_padi(config, host_uniq, tx).await?;

    let mut discovery_retries: u8 = 0;
    let mut lcp_retries: u8 = 0;
    let stop_token = status_rx.stop_token();

    let timeout_sleep = sleep(Duration::from_secs(0));
    tokio::pin!(timeout_sleep);
    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));

    loop {
        tokio::select! {
            _ = stop_token.cancelled() => {
                return Err(PppoeError::ServiceStopped);
            }
            received = rx.recv() => {
                let Some(raw) = received else {
                    return Err(PppoeError::ChannelClosed);
                };

                // A PADT for the session being negotiated (RFC 2516 §5.6)
                // closes it immediately instead of grinding through the
                // LCP retransmission timeouts below.
                if let Phase1State::LcpNegotiating { session_id, server_mac, .. } = &state
                    && matches!(
                        parse_session_packet(&raw, *session_id, server_mac),
                        Some(SessionPacket::Padt)
                    )
                {
                    tracing::warn!(
                        iface = %config.iface_name,
                        session_id = *session_id,
                        "received PADT during LCP negotiation, session terminated by peer"
                    );
                    return Err(PppoeError::PadtReceived);
                }

                match &mut state {
                    Phase1State::Discovering => {
                        if let Some(next) = handle_discovery(&raw, config, host_uniq)? {
                            state = next;
                            discovery_retries = 0;
                            // Send PADR immediately on transition
                            if let Phase1State::ReuqestSession { server_mac, ac_cookie } = &state {
                                send_padr(config, host_uniq, server_mac, ac_cookie.clone(), tx).await?;
                            }
                            timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                        }
                    }
                    Phase1State::ReuqestSession { server_mac, ac_cookie: _ } => {
                        if let Some(next) = handle_session_confirm(&raw, config, host_uniq, server_mac.clone())? {
                            state = next;
                            discovery_retries = 0;
                            timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                        }
                    }
                    Phase1State::LcpNegotiating { .. } => {
                        if let Some(result) = handle_lcp_packet(
                            &raw, &mut state, config, magic_number, tx,
                        ).await? {
                            return Ok(result);
                        }
                    }
                }
            }
            _ = &mut timeout_sleep => {
                match &mut state {
                    Phase1State::Discovering => {
                        discovery_retries += 1;
                        if discovery_retries > MAX_DISCOVERY_RETRIES {
                            return Err(PppoeError::DiscoveryTimeout);
                        }
                        send_padi(config, host_uniq, tx).await?;
                        timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                    }
                    Phase1State::ReuqestSession { server_mac, ac_cookie } => {
                        discovery_retries += 1;
                        if discovery_retries > MAX_DISCOVERY_RETRIES {
                            return Err(PppoeError::DiscoveryTimeout);
                        }
                        send_padr(config, host_uniq, server_mac, ac_cookie.clone(), tx).await?;
                        timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                    }
                    Phase1State::LcpNegotiating {
                        server_mac, session_id, our_mru, our_magic,
                        cfg_req_id, our_config_acked, ..
                    } => {
                        lcp_retries += 1;
                        if lcp_retries > MAX_LCP_RETRIES {
                            return Err(PppoeError::LcpTimeout);
                        }
                        if !*our_config_acked {
                            *cfg_req_id = cfg_req_id.wrapping_add(1);
                            send_lcp_config_request(config, *session_id, *cfg_req_id, *our_mru, *our_magic, server_mac, tx).await?;
                        }
                        timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT * (lcp_retries as u64 + 1)));
                    }
                }
            }
        }
    }
}

pub(crate) fn extract_l2(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 14 {
        return None;
    }
    Some((&data[6..12], &data[12..]))
}

/// RFC 2516 §5.4: a PADO/PADS carrying one of the error tags means the AC
/// refuses to serve the request (Service-Name mismatch, no resources, ...).
/// pppd (discovery.c `parsePADOTags`/`parsePADSTags`) fails the discovery
/// immediately on them instead of waiting for the negotiation timeouts.
pub(crate) fn discovery_tag_error(tag: &PPPoETag) -> Option<String> {
    let (name, msg): (&str, &Vec<u8>) = match tag {
        PPPoETag::ServiceNameError(msg) => ("Service-Name-Error", msg),
        PPPoETag::ACSystemError(msg) => ("AC-System-Error", msg),
        PPPoETag::GenericError(msg) => ("Generic-Error", msg),
        _ => return None,
    };
    Some(if msg.is_empty() {
        name.to_string()
    } else {
        format!("{name}: {}", String::from_utf8_lossy(msg))
    })
}

fn handle_discovery(
    raw: &[u8],
    config: &PPPoEClientConfig,
    host_uniq: u32,
) -> Result<Option<Phase1State>, PppoeError> {
    let Some((src_mac, eth_payload)) = extract_l2(raw) else {
        return Ok(None);
    };
    if eth_payload.len() < 4 || u16::from_be_bytes([eth_payload[0], eth_payload[1]]) != ETH_P_PPOED
    {
        return Ok(None);
    }
    let Some(frame) = PPPoEFrame::new(&eth_payload[2..]) else {
        return Ok(None);
    };
    if !frame.is_offer() {
        return Ok(None);
    }

    let mut ac_cookie = None;
    let mut ac_name = None;
    let mut matched = host_uniq == 0;
    let mut error_tag = None;
    for tag in PPPoETag::from_bytes(&frame.payload) {
        if error_tag.is_none() {
            error_tag = discovery_tag_error(&tag);
        }
        match tag {
            PPPoETag::HostUniq(id) => matched = id == host_uniq,
            PPPoETag::AcCookie(cookie) => ac_cookie = Some(cookie),
            PPPoETag::AcName(name) => ac_name = Some(name),
            _ => {}
        }
    }

    if !matched {
        tracing::warn!(
            iface = %config.iface_name,
            "received PADO with mismatched Host-Uniq"
        );
        return Ok(None);
    }

    // Only an error-tagged PADO addressed to us (matching Host-Uniq) may
    // fail the discovery: on a shared medium another AC can answer our
    // broadcast PADI with an error of its own (RFC 2516 §5.4), and that
    // must not abort the discovery while the target AC could still serve
    // us. pppd only sees unicast PADOs for itself here, so its
    // parsePADOTags fail-fast stays compatible with this gate.
    if let Some(reason) = error_tag {
        tracing::warn!(
            iface = %config.iface_name,
            %reason,
            "PADO carries an error tag, the AC refuses to serve this request"
        );
        return Err(PppoeError::DiscoveryRejected(reason));
    }

    if let Some(ref allowed) = config.ac_name
        && !allowed.is_empty()
    {
        let received = ac_name.as_ref().map(|n| String::from_utf8_lossy(n).into_owned());
        if received.as_deref() != Some(allowed.as_str()) {
            tracing::info!(
                iface = %config.iface_name,
                expected_ac = %allowed,
                ?received,
                "ignoring PADO from non-matching AC"
            );
            return Ok(None);
        }
    }

    tracing::info!(
        iface = %config.iface_name,
        "received matching PADO"
    );

    Ok(Some(Phase1State::ReuqestSession { server_mac: src_mac.to_vec(), ac_cookie }))
}

fn handle_session_confirm(
    raw: &[u8],
    config: &PPPoEClientConfig,
    host_uniq: u32,
    server_mac: Vec<u8>,
) -> Result<Option<Phase1State>, PppoeError> {
    let Some((_src, eth_payload)) = extract_l2(raw) else {
        return Ok(None);
    };
    if eth_payload.len() < 4 || u16::from_be_bytes([eth_payload[0], eth_payload[1]]) != ETH_P_PPOED
    {
        return Ok(None);
    }
    let Some(frame) = PPPoEFrame::new(&eth_payload[2..]) else {
        return Ok(None);
    };
    if !frame.is_confirm() {
        return Ok(None);
    }

    let mut matched = host_uniq == 0;
    let mut error_tag = None;
    for tag in PPPoETag::from_bytes(&frame.payload) {
        if error_tag.is_none() {
            error_tag = discovery_tag_error(&tag);
        }
        if let PPPoETag::HostUniq(id) = tag {
            matched = id == host_uniq;
        }
    }

    if !matched {
        tracing::warn!(
            iface = %config.iface_name,
            "received PADS with mismatched Host-Uniq"
        );
        return Ok(None);
    }

    // Same gate as the PADO path above: only an error-tagged PADS addressed
    // to us (matching Host-Uniq) fails the discovery.
    if let Some(reason) = error_tag {
        tracing::warn!(
            iface = %config.iface_name,
            %reason,
            "PADS carries an error tag, the AC denied the session"
        );
        return Err(PppoeError::DiscoveryRejected(reason));
    }

    // RFC 2516: the session id MUST NOT be 0 or 0xffff. pppd only
    // complains and stays compatible with a violating AC, so do the same.
    if frame.sid == 0 || frame.sid == 0xffff {
        tracing::error!(
            iface = %config.iface_name,
            session_id = frame.sid,
            "access concentrator used a forbidden session id (RFC 2516)"
        );
    }

    tracing::info!(
        iface = %config.iface_name,
        session_id = frame.sid,
        "received matching PADS, session established"
    );

    Ok(Some(Phase1State::LcpNegotiating {
        server_mac,
        session_id: frame.sid,
        our_mru: config.requested_mru,
        our_magic: 0,
        cfg_req_id: 0,
        our_config_acked: false,
        peer_mru: 0,
        peer_magic: 0,
        auth_type: 0,
        auth_algorithm: None,
        auth_nak_loops: 0,
        peer_config_received: false,
    }))
}

async fn handle_lcp_packet(
    raw: &[u8],
    state: &mut Phase1State,
    config: &PPPoEClientConfig,
    generated_magic: u32,
    tx: &mut mpsc::Sender<Vec<u8>>,
) -> Result<Option<LcpPhaseResult>, PppoeError> {
    let &mut Phase1State::LcpNegotiating {
        ref server_mac,
        ref mut session_id,
        ref mut our_mru,
        ref mut our_magic,
        ref mut cfg_req_id,
        ref mut our_config_acked,
        ref mut peer_mru,
        ref mut peer_magic,
        ref mut auth_type,
        ref mut auth_algorithm,
        ref mut auth_nak_loops,
        ref mut peer_config_received,
    } = state
    else {
        return Ok(None);
    };

    let Some((_src_mac, eth_payload)) = extract_l2(raw) else {
        return Ok(None);
    };
    if eth_payload.len() < 4 || u16::from_be_bytes([eth_payload[0], eth_payload[1]]) != ETH_P_PPOES
    {
        return Ok(None);
    }
    let Some(mut frame) = PPPoEFrame::new(&eth_payload[2..]) else {
        return Ok(None);
    };
    if frame.sid != *session_id {
        return Ok(None);
    }
    let Some(lcp) = PointToPoint::new(&frame.payload) else {
        return Ok(None);
    };
    if !lcp.is_lcp_config() {
        return Ok(None);
    }

    if lcp.is_request() {
        let (mru, magic, at, alg, _count) = parse_lcp_request_options(&lcp.payload);
        let (Some(mru), Some(magic), Some(at)) = (mru, magic, at) else {
            tracing::warn!(iface = %config.iface_name, "peer LCP Config-Request missing required options");
            return Err(PppoeError::LcpConfigRejected);
        };

        // pppd semantics (lcp.c:1618-1663): an authentication we cannot run
        // (CHAP with anything but MD5, or an unknown protocol such as EAP)
        // is answered with a Configure-Nak suggesting CHAP/MD5 in its
        // 5-byte form, so the peer can retry with a workable auth instead
        // of failing the CHAP exchange opaquely later.
        let auth_supported =
            at == AUTH_PROTO_PAP || (at == AUTH_PROTO_CHAP && alg == Some(CHAP_ALGORITHM_MD5));
        if !auth_supported {
            if *auth_nak_loops >= MAX_NAK_LOOPS {
                tracing::error!(
                    iface = %config.iface_name,
                    auth_type = format!("0x{at:04x}"),
                    "peer keeps requesting an unsupported authentication"
                );
                return Err(PppoeError::LcpConfigRejected);
            }
            *auth_nak_loops += 1;
            let nak = lcp.gen_nak(
                [
                    OPT_AUTH,
                    5,
                    (AUTH_PROTO_CHAP >> 8) as u8,
                    AUTH_PROTO_CHAP as u8,
                    CHAP_ALGORITHM_MD5,
                ]
                .to_vec(),
            );
            super::send_pppoe_session_frame(server_mac, config.iface_mac, *session_id, nak, tx)
                .await?;
            tracing::warn!(
                iface = %config.iface_name,
                auth_type = format!("0x{at:04x}"),
                algorithm = ?alg,
                "peer requested an unsupported authentication, suggesting CHAP/MD5"
            );
            return Ok(None);
        }
        *auth_nak_loops = 0;

        *peer_config_received = true;
        *auth_type = at;
        *auth_algorithm = alg;
        *peer_mru = mru;
        *peer_magic = magic;

        frame.payload = lcp.gen_ack();
        super::send_pppoe_session_frame(
            server_mac,
            config.iface_mac,
            *session_id,
            frame.payload.clone(),
            tx,
        )
        .await?;

        tracing::info!(
            iface = %config.iface_name,
            mru, magic,
            auth_type = format!("0x{at:04x}"),
            "acknowledged peer LCP Config-Request"
        );

        if !*our_config_acked {
            *our_magic = generated_magic;
            *cfg_req_id = cfg_req_id.wrapping_add(1);
            send_lcp_config_request(
                config,
                *session_id,
                *cfg_req_id,
                *our_mru,
                *our_magic,
                server_mac,
                tx,
            )
            .await?;
        }
    } else if lcp.is_ack() {
        let (mru, magic) = parse_lcp_mru_magic_options(&lcp.payload);
        if let (Some(mru), Some(magic)) = (mru, magic) {
            *our_config_acked = true;
            tracing::info!(
                iface = %config.iface_name,
                mru, magic,
                "our LCP config acknowledged by peer"
            );
        }
    } else if lcp.is_nak() {
        let (mru, magic) = parse_lcp_mru_magic_options(&lcp.payload);
        if let (Some(mru), Some(magic)) = (mru, magic) {
            *our_config_acked = false;
            *cfg_req_id = cfg_req_id.wrapping_add(1);
            *our_magic = magic;
            *our_mru = mru.min(*our_mru);
            send_lcp_config_request(
                config,
                *session_id,
                *cfg_req_id,
                *our_mru,
                *our_magic,
                server_mac,
                tx,
            )
            .await?;
            tracing::warn!(
                iface = %config.iface_name,
                suggested_mru = mru,
                suggested_magic = magic,
                "peer NAK'd our LCP config, resending with suggested values"
            );
        }
    } else if lcp.is_reject() {
        tracing::error!(iface = %config.iface_name, "peer rejected our LCP configuration");
        return Err(PppoeError::LcpConfigRejected);
    }

    if *our_config_acked && *peer_config_received {
        return Ok(Some(LcpPhaseResult {
            session_id: *session_id,
            server_mac: server_mac.clone(),
            mru: *our_mru,
            magic_number: *our_magic,
            auth_type: *auth_type,
            auth_algorithm: *auth_algorithm,
            peer_mru: *peer_mru,
            peer_magic: *peer_magic,
        }));
    }

    Ok(None)
}

pub(crate) fn parse_lcp_request_options(
    payload: &[u8],
) -> (Option<u16>, Option<u32>, Option<u16>, Option<u8>, usize) {
    let mut mru = None;
    let mut magic_number = None;
    let mut auth_type = None;
    let mut auth_algorithm = None;
    let mut count = 0;
    for op in PPPOption::from_bytes(payload) {
        count += 1;
        if op.is_mru() && op.data.len() >= 2 {
            mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
        } else if op.is_magic_number() && op.data.len() >= 4 {
            magic_number =
                Some(u32::from_be_bytes([op.data[0], op.data[1], op.data[2], op.data[3]]));
        } else if op.is_auth_type() && op.data.len() >= 2 {
            let proto = u16::from_be_bytes([op.data[0], op.data[1]]);
            auth_type = Some(proto);
            // Only CHAP carries an algorithm byte after the protocol
            // (RFC 1994 §4.1); PAP's option ends at the protocol.
            if proto == 0xc223 && op.data.len() >= 3 {
                auth_algorithm = Some(op.data[2]);
            }
        }
    }
    (mru, magic_number, auth_type, auth_algorithm, count)
}

pub(crate) fn parse_lcp_mru_magic_options(payload: &[u8]) -> (Option<u16>, Option<u32>) {
    let mut mru = None;
    let mut magic_number = None;
    for op in PPPOption::from_bytes(payload) {
        if op.is_mru() && op.data.len() >= 2 {
            mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
        } else if op.is_magic_number() && op.data.len() >= 4 {
            magic_number =
                Some(u32::from_be_bytes([op.data[0], op.data[1], op.data[2], op.data[3]]));
        }
    }
    (mru, magic_number)
}

async fn send_padi(
    config: &PPPoEClientConfig,
    host_uniq: u32,
    tx: &mut mpsc::Sender<Vec<u8>>,
) -> Result<(), PppoeError> {
    tracing::info!(iface = %config.iface_name, host_uniq, "sending PADI");
    let l2 = super::build_l2_header(&MacAddr::broadcast().octets(), config.iface_mac, ETH_P_PPOED);
    let frame = PPPoEFrame::get_discover_with_host_uniq(host_uniq);
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(packet).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}

async fn send_padr(
    config: &PPPoEClientConfig,
    host_uniq: u32,
    server_mac: &[u8],
    ac_cookie: Option<Vec<u8>>,
    tx: &mut mpsc::Sender<Vec<u8>>,
) -> Result<(), PppoeError> {
    tracing::info!(iface = %config.iface_name, host_uniq, "sending PADR");
    let l2 = super::build_l2_header(server_mac, config.iface_mac, ETH_P_PPOED);
    let frame = PPPoEFrame::get_request(host_uniq, ac_cookie);
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(packet).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}

async fn send_lcp_config_request(
    config: &PPPoEClientConfig,
    session_id: u16,
    req_id: u8,
    mru: u16,
    magic: u32,
    server_mac: &[u8],
    tx: &mut mpsc::Sender<Vec<u8>>,
) -> Result<(), PppoeError> {
    let l2 = super::build_l2_header(server_mac, config.iface_mac, ETH_P_PPOES);
    let frame = PPPoEFrame::get_ppp_mru_config_request(session_id, req_id, mru, magic);
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(packet).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}

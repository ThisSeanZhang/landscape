use std::process;

use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::{PPPOption, PointToPoint};
use landscape_common::net_proto::pppoe::{PPPoEFrame, PPPoETag};
use landscape_common::service::WatchService;

use crate::pppoe_client::PPPoEClientConfig;

use super::error::PppoeError;
use super::{PppoeResult, DEFAULT_TIMEOUT, ETH_P_PPOED, ETH_P_PPOES, MAX_DISCOVERY_RETRIES, MAX_LCP_RETRIES};

pub(crate) struct LcpPhaseResult {
    pub session_id: u16,
    pub server_mac: Vec<u8>,
    pub mru: u16,
    pub magic_number: u32,
    pub auth_type: u16,
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
        peer_config_received: bool,
    },
}

pub(crate) async fn run(
    config: &PPPoEClientConfig,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
    rx: &mut mpsc::Receiver<Box<Vec<u8>>>,
    status_rx: &WatchService,
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

    let timeout_sleep = sleep(Duration::from_secs(0));
    tokio::pin!(timeout_sleep);
    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));

    loop {
        tokio::select! {
            _ = status_rx.wait_to_stopping() => {
                return Err(PppoeError::ServiceStopped);
            }
            received = rx.recv() => {
                let Some(raw) = received else {
                    return Err(PppoeError::ChannelClosed);
                };

                match &mut state {
                    Phase1State::Discovering => {
                        if let Some(next) = handle_discovery(&raw, config, host_uniq)? {
                            state = next;
                            discovery_retries = 0;
                            // Send PADR immediately on transition
                            if let Phase1State::ReuqestSession { ref server_mac, ref ac_cookie } = &state {
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
    if data.len() < 14 { return None; }
    Some((&data[6..12], &data[12..]))
}

fn handle_discovery(
    raw: &[u8],
    config: &PPPoEClientConfig,
    host_uniq: u32,
) -> Result<Option<Phase1State>, PppoeError> {
    let Some((src_mac, eth_payload)) = extract_l2(raw) else {
        return Ok(None);
    };
    if eth_payload.len() < 4 || u16::from_be_bytes([eth_payload[0], eth_payload[1]]) != ETH_P_PPOED {
        return Ok(None);
    }
    let Some(frame) = PPPoEFrame::new(&eth_payload[2..]) else {
        return Ok(None);
    };
    if !frame.is_offer() {
        return Ok(None);
    }

    let mut ac_cookie = None;
    let mut matched = host_uniq == 0;
    for tag in PPPoETag::from_bytes(&frame.payload) {
        match tag {
            PPPoETag::HostUniq(id) => matched = id == host_uniq,
            PPPoETag::AcCookie(cookie) => ac_cookie = Some(cookie),
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

    tracing::info!(
        iface = %config.iface_name,
        "received matching PADO"
    );

    Ok(Some(Phase1State::ReuqestSession {
        server_mac: src_mac.to_vec(),
        ac_cookie,
    }))
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
    if eth_payload.len() < 4 || u16::from_be_bytes([eth_payload[0], eth_payload[1]]) != ETH_P_PPOED {
        return Ok(None);
    }
    let Some(frame) = PPPoEFrame::new(&eth_payload[2..]) else {
        return Ok(None);
    };
    if !frame.is_confirm() {
        return Ok(None);
    }

    let mut matched = host_uniq == 0;
    for tag in PPPoETag::from_bytes(&frame.payload) {
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
        peer_config_received: false,
    }))
}

async fn handle_lcp_packet(
    raw: &[u8],
    state: &mut Phase1State,
    config: &PPPoEClientConfig,
    generated_magic: u32,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<Option<LcpPhaseResult>, PppoeError> {
    let Phase1State::LcpNegotiating {
        ref server_mac, session_id, our_mru, ref mut our_magic,
        ref mut cfg_req_id, ref mut our_config_acked,
        peer_mru: _, peer_magic: _, ref mut auth_type,
        ref mut peer_config_received,
    } = state else {
        return Ok(None);
    };

    let Some((_src_mac, eth_payload)) = extract_l2(raw) else {
        return Ok(None);
    };
    if eth_payload.len() < 4 || u16::from_be_bytes([eth_payload[0], eth_payload[1]]) != ETH_P_PPOES {
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
        let (mru, magic, at, _count) = parse_lcp_request_options(&lcp.payload);
        let (Some(mru), Some(magic), Some(at)) = (mru, magic, at) else {
            tracing::warn!(iface = %config.iface_name, "peer LCP Config-Request missing required options");
            return Ok(None);
        };

        *peer_config_received = true;
        *auth_type = at;

        frame.payload = lcp.gen_ack();
        super::send_pppoe_session_frame(server_mac, config.iface_mac, *session_id, frame.payload.clone(), tx).await?;

        tracing::info!(
            iface = %config.iface_name,
            mru, magic,
            auth_type = format!("0x{at:04x}"),
            "acknowledged peer LCP Config-Request"
        );

        if !*our_config_acked {
            *our_magic = generated_magic;
            *cfg_req_id = cfg_req_id.wrapping_add(1);
            send_lcp_config_request(config, *session_id, *cfg_req_id, *our_mru, *our_magic, server_mac, tx).await?;
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
            send_lcp_config_request(config, *session_id, *cfg_req_id, *our_mru, *our_magic, server_mac, tx).await?;
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
        }));
    }

    Ok(None)
}

pub(crate) fn parse_lcp_request_options(payload: &[u8]) -> (Option<u16>, Option<u32>, Option<u16>, usize) {
    let mut mru = None;
    let mut magic_number = None;
    let mut auth_type = None;
    let mut count = 0;
    for op in PPPOption::from_bytes(payload) {
        count += 1;
        if op.is_mru() && op.data.len() >= 2 {
            mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
        } else if op.is_magic_number() && op.data.len() >= 4 {
            magic_number = Some(u32::from_be_bytes([op.data[0], op.data[1], op.data[2], op.data[3]]));
        } else if op.is_auth_type() && op.data.len() >= 2 {
            auth_type = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
        }
    }
    (mru, magic_number, auth_type, count)
}

pub(crate) fn parse_lcp_mru_magic_options(payload: &[u8]) -> (Option<u16>, Option<u32>) {
    let mut mru = None;
    let mut magic_number = None;
    for op in PPPOption::from_bytes(payload) {
        if op.is_mru() && op.data.len() >= 2 {
            mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
        } else if op.is_magic_number() && op.data.len() >= 4 {
            magic_number = Some(u32::from_be_bytes([op.data[0], op.data[1], op.data[2], op.data[3]]));
        }
    }
    (mru, magic_number)
}

async fn send_padi(
    config: &PPPoEClientConfig,
    host_uniq: u32,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    tracing::info!(iface = %config.iface_name, host_uniq, "sending PADI");
    let l2 = super::build_l2_header(&MacAddr::broadcast().octets(), config.iface_mac, ETH_P_PPOED);
    let frame = PPPoEFrame::get_discover_with_host_uniq(host_uniq);
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(Box::new(packet)).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}

async fn send_padr(
    config: &PPPoEClientConfig,
    host_uniq: u32,
    server_mac: &[u8],
    ac_cookie: Option<Vec<u8>>,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    tracing::info!(iface = %config.iface_name, host_uniq, "sending PADR");
    let l2 = super::build_l2_header(server_mac, config.iface_mac, ETH_P_PPOED);
    let frame = PPPoEFrame::get_request(host_uniq, ac_cookie);
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(Box::new(packet)).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}

async fn send_lcp_config_request(
    config: &PPPoEClientConfig,
    session_id: u16,
    req_id: u8,
    mru: u16,
    magic: u32,
    server_mac: &[u8],
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    let l2 = super::build_l2_header(server_mac, config.iface_mac, ETH_P_PPOES);
    let frame = PPPoEFrame::get_ppp_mru_config_request(session_id, req_id, mru, magic);
    let packet: Vec<u8> = [l2.to_vec(), frame.convert_to_payload()].concat();
    tx.send(Box::new(packet)).await.map_err(|_| PppoeError::ChannelClosed)?;
    Ok(())
}

use std::net::Ipv4Addr;

use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::{PPPOption, PointToPoint};
use landscape_common::net_proto::pppoe::PPPoEFrame;
use landscape_common::service::WatchService;

use crate::pppoe_client::auth::{ChapAuthenticator, PapAuthenticator};
use crate::pppoe_client::PPPoEClientConfig;

use super::error::PppoeError;
use super::lcp::LcpPhaseResult;
use super::{PppoeResult, DEFAULT_TIMEOUT, ETH_P_PPOES, LCP_ECHO_INTERVAL};

pub(crate) struct NegotiationResult {
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub ipv6cp_client_id: Option<Vec<u8>>,
    pub ipv6cp_server_id: Option<Vec<u8>>,
    pub echo_req_id: u8,
}

const MAX_AUTH_RETRIES: u8 = 3;
const MAX_NCP_RETRIES: u8 = 5;
const MAX_ECHO_FAILURES: u8 = 5;

struct IpcpState {
    req_id: u8,
    requesting_ip: Ipv4Addr,
    our_ip: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
    retries: u8,
}

impl IpcpState {
    fn new() -> Self {
        Self {
            req_id: 0,
            requesting_ip: Ipv4Addr::UNSPECIFIED,
            our_ip: None,
            peer_ip: None,
            retries: 0,
        }
    }

    fn done(&self) -> bool {
        self.our_ip.is_some() && self.peer_ip.is_some()
    }
}

struct Ipv6cpState {
    req_id: u8,
    our_id: Vec<u8>,
    our_confirmed_id: Option<Vec<u8>>,
    peer_id: Option<Vec<u8>>,
    rejected: bool,
    retries: u8,
}

impl Ipv6cpState {
    fn new(mac: MacAddr) -> Self {
        let octets = mac.octets();
        let id = vec![
            octets[0],
            octets[1],
            octets[2],
            0xff,
            0xfe,
            octets[3],
            octets[4],
            octets[5],
        ];
        Self {
            req_id: 0,
            our_id: id,
            our_confirmed_id: None,
            peer_id: None,
            rejected: false,
            retries: 0,
        }
    }

    fn done(&self) -> bool {
        self.rejected || (self.our_confirmed_id.is_some() && self.peer_id.is_some())
    }
}

pub(crate) async fn run(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
    rx: &mut mpsc::Receiver<Box<Vec<u8>>>,
    status_rx: &WatchService,
) -> PppoeResult<NegotiationResult> {
    let mut auth: Option<Box<dyn crate::pppoe_client::auth::Authenticator>> = match lcp.auth_type {
        0xc023 => Some(Box::new(PapAuthenticator::new(&config.peer_id, &config.password))),
        0xc223 => Some(Box::new(ChapAuthenticator::new(&config.peer_id, &config.password))),
        _ => return Err(PppoeError::UnsupportedAuthType(lcp.auth_type)),
    };
    let auth_is_pap = lcp.auth_type == 0xc023;

    let mut auth_done = false;
    let mut auth_retries: u8 = 0;

    let mut ipcp = IpcpState::new();
    let mut ipv6cp = Ipv6cpState::new(config.iface_mac);

    let mut echo_req_id: u8 = 0;
    let mut echo_failures: u8 = 0;

    if auth_is_pap {
        if let Some(payload) = auth.as_ref().unwrap().outgoing_packet() {
            super::send_pppoe_session_frame(
                &lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx,
            ).await?;
        }
    }

    let timeout_sleep = sleep(Duration::from_secs(0));
    tokio::pin!(timeout_sleep);
    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));

    let echo_sleep = sleep(Duration::from_secs(0));
    tokio::pin!(echo_sleep);
    echo_sleep.as_mut().reset(Instant::now() + Duration::from_secs(LCP_ECHO_INTERVAL));

    loop {
        tokio::select! {
            _ = status_rx.wait_to_stopping() => {
                return Err(PppoeError::ServiceStopped);
            }
            received = rx.recv() => {
                let Some(raw) = received else {
                    return Err(PppoeError::ChannelClosed);
                };

                let Some(ppp) = parse_ppp_packet(&raw, lcp) else { continue; };

                if ppp.is_pap_auth() || ppp.is_chap() {
                    if let Some(mut authenticator) = auth.take() {
                        let result = authenticator.handle_incoming(&ppp);
                        if let Some(response) = result.response {
                            super::send_pppoe_session_frame(
                                &lcp.server_mac, config.iface_mac, lcp.session_id, response, tx,
                            ).await?;
                        }
                        if result.failed {
                            return Err(PppoeError::AuthFailed(
                                format!("{:?}", authenticator)
                            ));
                        }
                        if result.done {
                            tracing::info!(iface = %config.iface_name, "authentication succeeded");
                            auth_done = true;
                            auth = None;

                            send_ipcp_request(config, lcp, &mut ipcp, tx).await?;
                            send_ipv6cp_request(config, lcp, &mut ipv6cp, tx).await?;
                        } else {
                            auth = Some(authenticator);
                        }
                    }
                    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                } else if ppp.is_ipcp() {
                    handle_ipcp_packet(config, lcp, &mut ipcp, &ppp, tx).await?;
                    if ipcp.done() && ipv6cp.done() {
                        return Ok(build_result(&ipcp, &ipv6cp, echo_req_id));
                    }
                    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                } else if ppp.is_ipv6cp() {
                    handle_ipv6cp_packet(config, lcp, &mut ipv6cp, &ppp, tx).await?;
                    if ipcp.done() && ipv6cp.done() {
                        return Ok(build_result(&ipcp, &ipv6cp, echo_req_id));
                    }
                    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                } else if ppp.is_lcp_config() {
                    if ppp.is_echo_request() {
                        echo_failures = 0;
                        send_echo_reply(config, lcp, &ppp, tx).await?;
                    } else if ppp.is_echo_reply() {
                        echo_failures = 0;
                        echo_req_id = echo_req_id.wrapping_add(1);
                    } else if ppp.is_termination() {
                        let ack = ppp.get_termination_ack();
                        super::send_pppoe_session_frame(
                            &lcp.server_mac, config.iface_mac, lcp.session_id, ack, tx,
                        ).await?;
                        return Err(PppoeError::PeerTerminated);
                    } else if ppp.is_termination_ack() {
                        return Err(PppoeError::PeerTerminated);
                    } else if ppp.is_proto_reject() {
                        if ppp.payload.len() >= 2 {
                            let proto = u16::from_be_bytes([ppp.payload[0], ppp.payload[1]]);
                            if proto == 0x8021 {
                                return Err(PppoeError::IpRequiredButRejected);
                            } else if proto == 0x8057 {
                                ipv6cp.rejected = true;
                                tracing::warn!(iface = %config.iface_name, "peer rejected IPv6CP");
                                if ipcp.done() && ipv6cp.done() {
                                    return Ok(build_result(&ipcp, &ipv6cp, echo_req_id));
                                }
                            }
                        }
                    }
                    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                }
            }
            _ = &mut timeout_sleep => {
                if !auth_done {
                    auth_retries += 1;
                    if auth_retries > MAX_AUTH_RETRIES {
                        return Err(PppoeError::AuthFailed("auth timeout".into()));
                    }
                    if auth_is_pap {
                        if let Some(authenticator) = auth.as_ref() {
                            if let Some(payload) = authenticator.outgoing_packet() {
                                super::send_pppoe_session_frame(
                                    &lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx,
                                ).await?;
                            }
                        }
                    }
                    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                } else {
                    if !ipcp.done() {
                        ipcp.retries += 1;
                        if ipcp.retries > MAX_NCP_RETRIES {
                            return Err(PppoeError::LcpTimeout);
                        }
                        send_ipcp_request(config, lcp, &mut ipcp, tx).await?;
                    }
                    if !ipv6cp.done() {
                        ipv6cp.retries += 1;
                        if ipv6cp.retries > MAX_NCP_RETRIES {
                            ipv6cp.rejected = true;
                            tracing::warn!(iface = %config.iface_name, "IPv6CP timeout, marking as unavailable");
                            if ipcp.done() && ipv6cp.done() {
                                return Ok(build_result(&ipcp, &ipv6cp, echo_req_id));
                            }
                        } else {
                            send_ipv6cp_request(config, lcp, &mut ipv6cp, tx).await?;
                        }
                    }
                    timeout_sleep.as_mut().reset(Instant::now() + Duration::from_secs(DEFAULT_TIMEOUT));
                }
            }
            _ = &mut echo_sleep => {
                send_echo_request(config, lcp, echo_req_id, lcp.magic_number, tx).await?;
                echo_failures += 1;
                if echo_failures > MAX_ECHO_FAILURES {
                    return Err(PppoeError::EchoFailed(echo_failures));
                }
                echo_sleep.as_mut().reset(Instant::now() + Duration::from_secs(LCP_ECHO_INTERVAL));
            }
        }
    }
}

fn parse_ppp_packet<'a>(raw: &'a [u8], lcp: &LcpPhaseResult) -> Option<PointToPoint> {
    if raw.len() < 16 { return None; }
    if u16::from_be_bytes([raw[12], raw[13]]) != ETH_P_PPOES { return None; }
    let frame = PPPoEFrame::new(&raw[14..])?;
    if frame.sid != lcp.session_id { return None; }
    if frame.is_terminate() { return None; }
    PointToPoint::new(&frame.payload)
}

fn build_result(ipcp: &IpcpState, ipv6cp: &Ipv6cpState, echo_req_id: u8) -> NegotiationResult {
    NegotiationResult {
        client_ip: ipcp.our_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        server_ip: ipcp.peer_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        ipv6cp_client_id: ipv6cp.our_confirmed_id.clone(),
        ipv6cp_server_id: ipv6cp.peer_id.clone(),
        echo_req_id,
    }
}

async fn handle_ipcp_packet(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    ipcp: &mut IpcpState,
    ppp: &PointToPoint,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    if ppp.is_ack() {
        for op in PPPOption::from_bytes(&ppp.payload) {
            if op.t == 3 && op.data.len() >= 4 {
                let addr = Ipv4Addr::new(op.data[0], op.data[1], op.data[2], op.data[3]);
                tracing::info!(iface = %config.iface_name, ip = %addr, "IPCP: our IPv4 address acknowledged");
                ipcp.our_ip = Some(addr);
            }
        }
    } else if ppp.is_nak() {
        ipcp.req_id = ipcp.req_id.wrapping_add(1);
        for op in PPPOption::from_bytes(&ppp.payload) {
            if op.t == 3 && op.data.len() >= 4 {
                let suggested = Ipv4Addr::new(op.data[0], op.data[1], op.data[2], op.data[3]);
                tracing::warn!(iface = %config.iface_name, ip = %suggested, "IPCP: peer suggested a different IPv4 address");
                ipcp.requesting_ip = suggested;
            }
        }
        send_ipcp_request_raw(config, lcp, ipcp.req_id, ipcp.requesting_ip, tx).await?;
    } else if ppp.is_request() {
        let mut reject_options = vec![];
        for op in PPPOption::from_bytes(&ppp.payload) {
            if op.t == 3 && op.data.len() >= 4 {
                let peer_ip = Ipv4Addr::new(op.data[0], op.data[1], op.data[2], op.data[3]);
                tracing::info!(iface = %config.iface_name, ip = %peer_ip, "IPCP: peer announced remote IPv4 address");
                ipcp.peer_ip = Some(peer_ip);
            } else {
                reject_options.extend(op.convert_to_payload());
            }
        }
        if !reject_options.is_empty() {
            let reject = ppp.gen_reject(reject_options);
            super::send_pppoe_session_frame(
                &lcp.server_mac, config.iface_mac, lcp.session_id, reject, tx,
            ).await?;
        } else if ipcp.peer_ip.is_some() {
            let ack = ppp.gen_ack();
            super::send_pppoe_session_frame(
                &lcp.server_mac, config.iface_mac, lcp.session_id, ack, tx,
            ).await?;
        }
    } else if ppp.is_reject() {
        tracing::error!(iface = %config.iface_name, "IPCP: our request was rejected");
        return Err(PppoeError::IpRequiredButRejected);
    }
    Ok(())
}

async fn handle_ipv6cp_packet(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    ipv6cp: &mut Ipv6cpState,
    ppp: &PointToPoint,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    if ppp.is_ack() {
        for op in PPPOption::from_bytes(&ppp.payload) {
            if op.t == 1 {
                ipv6cp.our_confirmed_id = Some(op.data.clone());
                tracing::info!(iface = %config.iface_name, "IPv6CP: our interface identifier acknowledged");
            }
        }
    } else if ppp.is_nak() {
        ipv6cp.req_id = ipv6cp.req_id.wrapping_add(1);
        for op in PPPOption::from_bytes(&ppp.payload) {
            if op.t == 1 {
                tracing::warn!(iface = %config.iface_name, "IPv6CP: peer suggested a different interface identifier");
                ipv6cp.our_id = op.data.clone();
            }
        }
        send_ipv6cp_request_raw(config, lcp, ipv6cp.req_id, &ipv6cp.our_id, tx).await?;
    } else if ppp.is_request() {
        let mut reject_options = vec![];
        for op in PPPOption::from_bytes(&ppp.payload) {
            if op.t == 1 {
                ipv6cp.peer_id = Some(op.data.clone());
                tracing::info!(iface = %config.iface_name, "IPv6CP: peer announced remote interface identifier");
            } else {
                reject_options.extend(op.convert_to_payload());
            }
        }
        if !reject_options.is_empty() {
            let reject = ppp.gen_reject(reject_options);
            super::send_pppoe_session_frame(
                &lcp.server_mac, config.iface_mac, lcp.session_id, reject, tx,
            ).await?;
        } else if ipv6cp.peer_id.is_some() {
            let ack = ppp.gen_ack();
            super::send_pppoe_session_frame(
                &lcp.server_mac, config.iface_mac, lcp.session_id, ack, tx,
            ).await?;
        }
    } else if ppp.is_reject() {
        ipv6cp.rejected = true;
        tracing::warn!(iface = %config.iface_name, "IPv6CP: our request was rejected");
    }
    Ok(())
}

async fn send_ipcp_request(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    ipcp: &mut IpcpState,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    ipcp.req_id = ipcp.req_id.wrapping_add(1);
    send_ipcp_request_raw(config, lcp, ipcp.req_id, ipcp.requesting_ip, tx).await
}

async fn send_ipcp_request_raw(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    req_id: u8,
    ip: Ipv4Addr,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    let payload = PointToPoint::get_ipcp_request_only_client_ip(req_id, ip)
        .convert_to_payload();
    super::send_pppoe_session_frame(
        &lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx,
    ).await?;
    Ok(())
}

async fn send_ipv6cp_request(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    ipv6cp: &mut Ipv6cpState,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    ipv6cp.req_id = ipv6cp.req_id.wrapping_add(1);
    send_ipv6cp_request_raw(config, lcp, ipv6cp.req_id, &ipv6cp.our_id, tx).await
}

async fn send_ipv6cp_request_raw(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    req_id: u8,
    iface_id: &[u8],
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    let payload = PointToPoint::get_ipv6cp_request(iface_id.to_vec(), req_id)
        .convert_to_payload();
    super::send_pppoe_session_frame(
        &lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx,
    ).await?;
    Ok(())
}

async fn send_echo_request(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    echo_id: u8,
    magic: u32,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    let payload = PointToPoint::gen_echo_request_with_magic(echo_id, magic);
    super::send_pppoe_session_frame(
        &lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx,
    ).await
}

async fn send_echo_reply(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    ppp: &PointToPoint,
    tx: &mut mpsc::Sender<Box<Vec<u8>>>,
) -> Result<(), PppoeError> {
    let reply = ppp.gen_reply_with_magic(lcp.magic_number);
    super::send_pppoe_session_frame(
        &lcp.server_mac, config.iface_mac, lcp.session_id, reply, tx,
    ).await
}

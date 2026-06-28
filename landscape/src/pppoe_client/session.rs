use std::{net::Ipv4Addr, process};

use landscape_common::net::MacAddr;
use landscape_common::net_proto::ppp::{PPPOption, PointToPoint};
use landscape_common::net_proto::pppoe::{PPPoEFrame, PPPoETag};
use tokio::sync::mpsc;

use super::auth::{ChapAuthenticator, PapAuthenticator};
use super::state::{LCPStatus, LcpBaseConfig, PPPoEConnectState, TagValue};
use super::{ETH_P_PPOED, ETH_P_PPOES, LCP_ECHO_INTERVAL};

pub(crate) struct PPPoEClientManager {
    pub(crate) error_count: u16,
    pub(crate) client_mac: MacAddr,
    pub(crate) my_host_id: u32,
    pub(crate) pppoe_status: PPPoEConnectState,
    pub(crate) lcp_status: LCPStatus,
    pub(crate) peer_id: String,
    pub(crate) password: String,
}

impl PPPoEClientManager {
    fn log_protocol_error(&self, reason: &str) {
        tracing::warn!(
            "native PPPoE negotiation issue: {} state={:?} error_count={}",
            reason,
            self.pppoe_status,
            self.error_count
        );
    }

    pub(crate) fn new(
        client_mac: MacAddr,
        requested_mru: u16,
        peer_id: String,
        password: String,
    ) -> Self {
        let my_host_id = process::id().swap_bytes();
        PPPoEClientManager {
            error_count: 0,
            client_mac,
            my_host_id,
            pppoe_status: PPPoEConnectState::Discovering,
            lcp_status: LCPStatus::new(client_mac, requested_mru),
            peer_id,
            password,
        }
    }

    pub(crate) async fn handle_packet(
        &mut self,
        packet: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) -> Option<Vec<Vec<u8>>> {
        let Some(pppoe_data) = PPPoEFrame::new(&packet[14..]) else {
            tracing::error!("conversion to pppoe error, data is: {packet:?}");
            self.error_count += 1;
            return None;
        };

        if !pppoe_data.is_session_data() {
            self.handle_discovery_packet(packet, pppoe_data, data_sender).await;
        } else {
            self.handle_session_packet(pppoe_data, data_sender).await;
        }

        None
    }

    async fn handle_discovery_packet(
        &mut self,
        packet: Vec<u8>,
        pppoe_data: PPPoEFrame,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        match &self.pppoe_status {
            PPPoEConnectState::Discovering => {
                self.handle_offer_packet(packet, pppoe_data, data_sender).await;
            }
            PPPoEConnectState::ReuqestSession { server_mac_addr, .. } => {
                self.handle_session_confirm(pppoe_data, server_mac_addr.clone());
            }
            PPPoEConnectState::SessionConfirm { .. } => {
                self.error_count += 10;
            }
        }
    }

    async fn handle_offer_packet(
        &mut self,
        packet: Vec<u8>,
        pppoe_data: PPPoEFrame,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        if !pppoe_data.is_offer() {
            self.log_protocol_error(
                "expected PADO during discovery but received different discovery code",
            );
            self.error_count += 1;
            return;
        }

        let mut ac_cookie = None;
        let mut is_my_host = self.my_host_id == 0;
        for tag in PPPoETag::from_bytes(&pppoe_data.payload).into_iter() {
            match tag {
                PPPoETag::HostUniq(id) => is_my_host = id == self.my_host_id,
                PPPoETag::AcCookie(cookie) => ac_cookie = Some(cookie),
                _ => {}
            }
        }

        if !is_my_host {
            self.log_protocol_error("received PADO with mismatched Host-Uniq");
            self.error_count += 1;
            return;
        }

        tracing::info!("received matching PADO, sending PADR");

        self.pppoe_status = PPPoEConnectState::ReuqestSession {
            server_mac_addr: packet[6..12].to_vec(),
            ac_cookie: ac_cookie.clone(),
        };

        let eth_head_data =
            [&packet[6..12], self.client_mac.octets().as_ref(), &ETH_P_PPOED.to_be_bytes()]
                .concat();
        let request = PPPoEFrame::get_request(self.my_host_id, ac_cookie);
        data_sender
            .send(Box::new([eth_head_data, request.convert_to_payload()].concat()))
            .await
            .unwrap();
    }

    fn handle_session_confirm(&mut self, pppoe_data: PPPoEFrame, server_mac_addr: Vec<u8>) {
        if !pppoe_data.is_confirm() {
            self.log_protocol_error(
                "expected PADS during session request stage but received different discovery code",
            );
            self.error_count += 1;
            return;
        }
        tracing::info!("got a confirm message");

        let mut confirm = false;
        for tag in PPPoETag::from_bytes(&pppoe_data.payload).into_iter() {
            if let PPPoETag::HostUniq(id) = tag {
                if self.my_host_id != 0 && id == self.my_host_id {
                    confirm = true;
                }
            }
        }

        if confirm {
            tracing::info!("received matching PADS, session established sid={}", pppoe_data.sid);
            self.pppoe_status =
                PPPoEConnectState::SessionConfirm { server_mac_addr, session_id: pppoe_data.sid };
        } else {
            self.log_protocol_error("received PADS with mismatched Host-Uniq");
            self.error_count += 1;
        }
    }

    async fn handle_session_packet(
        &mut self,
        mut pppoe_data: PPPoEFrame,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let Some((l2_header, session_id)) = self.session_l2_header(pppoe_data.sid) else {
            self.log_protocol_error(
                "received session data with unexpected session id or without active session",
            );
            return;
        };

        let Some(lcp) = PointToPoint::new(&pppoe_data.payload) else {
            self.log_protocol_error("failed to parse PPP payload inside PPPoE session data");
            self.error_count += 1;
            return;
        };

        if lcp.is_lcp_config() {
            self.handle_lcp_packet(&mut pppoe_data, lcp, session_id, l2_header, data_sender).await;
        } else if lcp.is_pap_auth() || lcp.is_chap() {
            self.handle_auth_packet(lcp, l2_header, session_id, data_sender).await;
        } else if lcp.is_ipcp() {
            self.handle_ipcp_packet(&mut pppoe_data, lcp, session_id, l2_header, data_sender).await;
        } else if lcp.is_ipv6cp() {
            self.handle_ipv6cp_packet(&mut pppoe_data, lcp, session_id, l2_header, data_sender)
                .await;
        }
    }

    fn session_l2_header(&self, sid: u16) -> Option<(Vec<u8>, u16)> {
        let PPPoEConnectState::SessionConfirm { server_mac_addr, session_id, .. } =
            &self.pppoe_status
        else {
            return None;
        };
        if sid != *session_id {
            return None;
        }
        Some((
            [server_mac_addr, self.client_mac.octets().as_ref(), &ETH_P_PPOES.to_be_bytes()]
                .concat(),
            *session_id,
        ))
    }

    async fn handle_lcp_packet(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        lcp: PointToPoint,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        if lcp.is_ack() {
            self.handle_lcp_ack(session_id, l2_header, &lcp, data_sender).await;
        } else if lcp.is_nak() {
            self.handle_lcp_nak(session_id, l2_header, &lcp, data_sender).await;
        } else if lcp.is_request() {
            self.handle_lcp_request(pppoe_data, session_id, l2_header, &lcp, data_sender).await;
        } else if lcp.is_reject() {
            self.error_count += 10;
        } else if lcp.is_proto_reject() {
            self.handle_lcp_proto_reject(&lcp);
        } else if lcp.is_echo_request() {
            self.handle_lcp_echo_request(pppoe_data, l2_header, &lcp, data_sender).await;
        } else if lcp.is_echo_reply() {
            self.lcp_status.lcp_echo_times = 0;
            self.lcp_status.echo_req_id = self.lcp_status.echo_req_id.wrapping_add(1);
        } else if lcp.is_termination() {
            self.handle_lcp_termination(pppoe_data, l2_header, &lcp, data_sender).await;
        } else if lcp.is_termination_ack() {
            self.error_count += 10;
            self.lcp_status.termination = (true, TagValue::Ack(()));
        }
    }

    async fn handle_lcp_ack(
        &mut self,
        session_id: u16,
        l2_header: Vec<u8>,
        lcp: &PointToPoint,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let (client_mru, magic_number) = Self::parse_lcp_base_options(&lcp.payload);
        if let (Some(mru), Some(magic_number)) = (client_mru, magic_number) {
            self.lcp_status.client_config = TagValue::Ack(LcpBaseConfig { mru, magic_number });
            tracing::info!(
                "LCP local config acknowledged: mru={} magic_number={:#x}",
                mru,
                magic_number
            );
            self.send_auth_if_ready(session_id, l2_header, data_sender).await;
        } else {
            self.log_protocol_error("LCP Configure-Ack missing MRU or magic-number");
            self.error_count += 10;
        }
    }

    async fn handle_lcp_nak(
        &mut self,
        session_id: u16,
        l2_header: Vec<u8>,
        lcp: &PointToPoint,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let (client_mru, magic_number) = Self::parse_lcp_base_options(&lcp.payload);
        if let (Some(mru), Some(magic_number)) = (client_mru, magic_number) {
            tracing::warn!(
                "LCP local config NAK received: suggested_mru={} suggested_magic={:#x}",
                mru,
                magic_number
            );
            self.lcp_status.cfg_req_id += 1;
            self.lcp_status.client_config = TagValue::Nak(LcpBaseConfig { mru, magic_number });

            if let TagValue::Nak(cfg) = &self.lcp_status.client_config {
                let request = PPPoEFrame::get_ppp_mru_config_request(
                    session_id,
                    self.lcp_status.cfg_req_id,
                    cfg.mru,
                    cfg.magic_number,
                );
                data_sender
                    .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                    .await
                    .unwrap();
            }
        } else {
            self.log_protocol_error("LCP Configure-Nak missing MRU or magic-number");
            self.error_count += 10;
        }
        self.error_count += 1;
    }

    async fn handle_lcp_request(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        session_id: u16,
        l2_header: Vec<u8>,
        lcp: &PointToPoint,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let (mru, magic_number, auth_type, size) = Self::parse_lcp_request_options(&lcp.payload);
        if let (Some(mru), Some(magic_number), Some(auth_type)) = (mru, magic_number, auth_type) {
            if size != 3 {
                self.log_protocol_error("LCP Configure-Request contained unexpected option count");
                self.error_count += 10;
                return;
            }
            self.lcp_status.server_config = TagValue::Ack(LcpBaseConfig { mru, magic_number });
            self.lcp_status.auth_type = TagValue::Ack(auth_type);
            self.lcp_status.authenticator = match auth_type {
                0xc023 => Some(Box::new(PapAuthenticator::new(&self.peer_id, &self.password))),
                0xc223 => Some(Box::new(ChapAuthenticator::new(&self.peer_id, &self.password))),
                _ => {
                    tracing::error!("peer requested unsupported auth type {:#x}", auth_type);
                    None
                }
            };
            tracing::info!(
                "accepted peer LCP config: peer_mru={} peer_magic={:#x} auth_type={:#x}",
                mru,
                magic_number,
                auth_type
            );

            pppoe_data.payload = lcp.gen_ack();
            let ack = pppoe_data.clone().convert_to_payload();
            data_sender.send(Box::new([l2_header.clone(), ack].concat())).await.unwrap();

            if let TagValue::Nak(cfg) = &self.lcp_status.client_config {
                let request = PPPoEFrame::get_ppp_mru_config_request(
                    session_id,
                    self.lcp_status.cfg_req_id,
                    cfg.mru,
                    cfg.magic_number,
                );
                data_sender
                    .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                    .await
                    .unwrap();
            }
        } else {
            self.log_protocol_error(
                "LCP Configure-Request missing required MRU, magic-number or auth-type",
            );
            self.error_count += 10;
        }
    }

    fn handle_lcp_proto_reject(&mut self, lcp: &PointToPoint) {
        let proto = u16::from_be_bytes([lcp.payload[0], lcp.payload[1]]);
        if proto == 0x8057 {
            tracing::warn!("peer rejected IPv6CP protocol negotiation");
            self.lcp_status.ip6cp_server_id = TagValue::Reject;
            self.lcp_status.ip6cp_client_id = TagValue::Reject;
            return;
        } else if proto == 0x8021 {
            tracing::error!("peer rejected IPCP protocol negotiation");
            self.lcp_status.client_config = TagValue::Reject;
            self.lcp_status.server_config = TagValue::Reject;
            self.error_count += 10;
        } else if proto == 0xc023 {
            tracing::error!("peer rejected PAP authentication protocol");
            self.lcp_status.auth_type = TagValue::Reject;
            self.lcp_status.authenticator = None;
            self.error_count += 10;
        }
        self.error_count += 1;
    }

    async fn handle_lcp_echo_request(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        l2_header: Vec<u8>,
        lcp: &PointToPoint,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        if let TagValue::Ack(client_config) = &self.lcp_status.client_config {
            pppoe_data.payload = lcp.gen_reply_with_magic(client_config.magic_number);
            let echo_reply = pppoe_data.clone().convert_to_payload();
            data_sender.send(Box::new([l2_header, echo_reply].concat())).await.unwrap();
        }
    }

    async fn handle_lcp_termination(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        l2_header: Vec<u8>,
        lcp: &PointToPoint,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        self.error_count += 10;
        pppoe_data.payload = lcp.get_termination_ack();
        let reply = pppoe_data.clone().convert_to_payload();
        data_sender.send(Box::new([l2_header, reply].concat())).await.unwrap();
        self.lcp_status.termination = (true, TagValue::Ack(()));
    }

    async fn handle_auth_packet(
        &mut self,
        lcp: PointToPoint,
        l2_header: Vec<u8>,
        session_id: u16,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let Some(auth) = self.lcp_status.authenticator.as_mut() else {
            self.log_protocol_error("received auth packet but no authenticator configured");
            self.error_count += 1;
            return;
        };
        let result = auth.handle_incoming(&lcp);
        if let Some(payload) = result.response {
            let frame = PPPoEFrame::get_ppp_auth_response(session_id, payload);
            data_sender
                .send(Box::new([l2_header, frame.convert_to_payload()].concat()))
                .await
                .unwrap();
        }
        if result.failed {
            tracing::error!("authentication failed via {:?}", auth);
            self.error_count += 10;
        }
        if result.done && !result.failed {
            tracing::info!("authentication succeeded via {:?}", auth);
        }
    }

    async fn handle_ipcp_packet(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        lcp: PointToPoint,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        if lcp.is_ack() {
            for each in PPPOption::from_bytes(&lcp.payload) {
                if each.t == 3 {
                    let addr =
                        Ipv4Addr::new(each.data[0], each.data[1], each.data[2], each.data[3]);
                    tracing::info!("IPCP local IPv4 address acknowledged: {}", addr);
                    self.lcp_status.ipcp_client_ipaddr = TagValue::Ack(addr);
                }
            }
        } else if lcp.is_nak() {
            self.lcp_status.ipcp_req_id += 1;
            for each in PPPOption::from_bytes(&lcp.payload) {
                if each.t == 3 {
                    let suggested =
                        Ipv4Addr::new(each.data[0], each.data[1], each.data[2], each.data[3]);
                    tracing::warn!("IPCP suggested a different local IPv4 address: {}", suggested);
                    self.lcp_status.ipcp_client_ipaddr = TagValue::Nak(suggested);
                }
            }
            self.send_ipcp_request_if_needed(session_id, l2_header, data_sender).await;
            self.lcp_status.ipcp_req_id += 1;
        } else if lcp.is_request() {
            self.handle_ipcp_request(pppoe_data, lcp, session_id, l2_header, data_sender).await;
        } else if lcp.is_reject() {
            tracing::error!("IPCP local request was rejected by peer");
            self.error_count += 10;
        }
    }

    async fn handle_ipcp_request(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        lcp: PointToPoint,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let mut reject_options = vec![];
        for each in PPPOption::from_bytes(&lcp.payload) {
            if each.t == 3 {
                let peer_ip = Ipv4Addr::new(each.data[0], each.data[1], each.data[2], each.data[3]);
                tracing::info!("peer IPCP request announced remote IPv4 address: {}", peer_ip);
                self.lcp_status.ipcp_server_ipaddr = TagValue::Ack(peer_ip);
            } else {
                reject_options.extend(each.convert_to_payload());
            }
        }

        if !reject_options.is_empty() {
            tracing::warn!(
                "rejecting unsupported IPCP options from peer, bytes={:?}",
                reject_options
            );
            pppoe_data.payload = lcp.gen_reject(reject_options);
            let reject = pppoe_data.clone().convert_to_payload();
            data_sender.send(Box::new([l2_header, reject].concat())).await.unwrap();
            return;
        }

        if self.lcp_status.ipcp_server_ipaddr.is_confirm() {
            pppoe_data.payload = lcp.gen_ack();
            let ack = pppoe_data.clone().convert_to_payload();
            data_sender.send(Box::new([l2_header.clone(), ack].concat())).await.unwrap();
            self.send_ipcp_request_if_needed(session_id, l2_header, data_sender).await;
        }
    }

    async fn handle_ipv6cp_packet(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        lcp: PointToPoint,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        if lcp.is_ack() {
            for each in PPPOption::from_bytes(&lcp.payload) {
                if each.t == 1 {
                    self.lcp_status.ip6cp_client_id = TagValue::Ack(each.data);
                    tracing::info!("IPv6CP local interface identifier acknowledged");
                }
            }
        } else if lcp.is_nak() {
            self.lcp_status.ip6cp_req_id += 1;
            for each in PPPOption::from_bytes(&lcp.payload) {
                if each.t == 1 {
                    tracing::warn!("IPv6CP suggested a different local interface identifier");
                    self.lcp_status.ip6cp_client_id = TagValue::Nak(each.data);
                }
            }
            self.send_ipv6cp_request_if_needed(session_id, l2_header, data_sender).await;
        } else if lcp.is_request() {
            self.handle_ipv6cp_request(pppoe_data, lcp, session_id, l2_header, data_sender).await;
        } else if lcp.is_reject() {
            tracing::error!("IPv6CP local request was rejected by peer");
            self.error_count += 10;
        }
    }

    async fn handle_ipv6cp_request(
        &mut self,
        pppoe_data: &mut PPPoEFrame,
        lcp: PointToPoint,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let mut reject_options = vec![];
        for each in PPPOption::from_bytes(&lcp.payload) {
            if each.t == 1 {
                self.lcp_status.ip6cp_server_id = TagValue::Ack(each.data);
                tracing::info!("peer IPv6CP request announced remote interface identifier");
            } else {
                reject_options.extend(each.convert_to_payload());
            }
        }

        if !reject_options.is_empty() {
            tracing::warn!(
                "rejecting unsupported IPv6CP options from peer, bytes={:?}",
                reject_options
            );
            pppoe_data.payload = lcp.gen_reject(reject_options);
            let reject = pppoe_data.clone().convert_to_payload();
            data_sender.send(Box::new([l2_header, reject].concat())).await.unwrap();
            return;
        }

        if self.lcp_status.ip6cp_server_id.is_confirm() {
            pppoe_data.payload = lcp.gen_ack();
            let ack = pppoe_data.clone().convert_to_payload();
            data_sender.send(Box::new([l2_header.clone(), ack].concat())).await.unwrap();
            self.send_ipv6cp_request_if_needed(session_id, l2_header, data_sender).await;
        }
    }

    async fn send_auth_if_ready(
        &self,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        let Some(auth) = self.lcp_status.authenticator.as_ref() else {
            return;
        };
        if auth.is_done() {
            return;
        }
        if let Some(payload) = auth.outgoing_packet() {
            let frame = PPPoEFrame::get_ppp_auth_response(session_id, payload);
            data_sender
                .send(Box::new([l2_header, frame.convert_to_payload()].concat()))
                .await
                .unwrap();
        }
    }

    async fn send_ipcp_request_if_needed(
        &self,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        if let TagValue::Nak(ipcp_addr) = &self.lcp_status.ipcp_client_ipaddr {
            tracing::info!("sending IPCP request for local IPv4 address {}", ipcp_addr);
            let request = PPPoEFrame::get_ipcp_request_only_client_ip(
                session_id,
                self.lcp_status.ipcp_req_id,
                *ipcp_addr,
            );
            data_sender
                .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                .await
                .unwrap();
        }
    }

    async fn send_ipv6cp_request_if_needed(
        &self,
        session_id: u16,
        l2_header: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) {
        if let TagValue::Nak(ip6cp_id) = &self.lcp_status.ip6cp_client_id {
            tracing::info!(
                "sending IPv6CP request for local interface identifier len={}",
                ip6cp_id.len()
            );
            let request = PPPoEFrame::get_ipv6cp_request(
                session_id,
                ip6cp_id.clone(),
                self.lcp_status.ip6cp_req_id,
            );
            data_sender
                .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                .await
                .unwrap();
        }
    }

    fn parse_lcp_base_options(payload: &[u8]) -> (Option<u16>, Option<u32>) {
        let mut client_mru = None;
        let mut magic_number = None;
        for op in PPPOption::from_bytes(payload) {
            if op.is_mru() {
                client_mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
            } else if op.is_magic_number() {
                magic_number =
                    Some(u32::from_be_bytes([op.data[0], op.data[1], op.data[2], op.data[3]]));
            }
        }
        (client_mru, magic_number)
    }

    fn parse_lcp_request_options(payload: &[u8]) -> (Option<u16>, Option<u32>, Option<u16>, usize) {
        let mut mru = None;
        let mut magic_number = None;
        let mut auth_type = None;
        let mut size = 0;
        for op in PPPOption::from_bytes(payload) {
            size += 1;
            if op.is_mru() {
                mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
            } else if op.is_magic_number() {
                magic_number =
                    Some(u32::from_be_bytes([op.data[0], op.data[1], op.data[2], op.data[3]]));
            } else if op.is_auth_type() {
                auth_type = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
            }
        }
        (mru, magic_number, auth_type, size)
    }

    pub(crate) async fn get_keep_alive_pkt(
        &mut self,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) -> Option<(u16, u64)> {
        let PPPoEConnectState::SessionConfirm { server_mac_addr, session_id, .. } =
            &self.pppoe_status
        else {
            return None;
        };

        if let TagValue::Ack(config) = &self.lcp_status.client_config {
            let l2_header =
                [server_mac_addr, self.client_mac.octets().as_ref(), &ETH_P_PPOES.to_be_bytes()]
                    .concat();
            let request = PPPoEFrame::gen_echo_request_with_magic(
                *session_id,
                self.lcp_status.echo_req_id,
                config.magic_number,
            );
            if let Err(e) =
                data_sender.send(Box::new([l2_header, request.convert_to_payload()].concat())).await
            {
                tracing::error!("failed to send LCP echo request: {e:?}");
                return Some((self.lcp_status.lcp_echo_times, LCP_ECHO_INTERVAL));
            }
            tracing::debug!("sending LCP echo request id={}", self.lcp_status.echo_req_id);
            Some((self.lcp_status.lcp_echo_times, LCP_ECHO_INTERVAL))
        } else {
            None
        }
    }

    pub(crate) async fn send_packet(&self, data_sender: &mpsc::Sender<Box<Vec<u8>>>) -> bool {
        // tracing::info!("send_packet, cueernt_status: {:?}", self.pppoe_status);
        let (eth_head_data, sid) = match &self.pppoe_status {
            PPPoEConnectState::Discovering => {
                tracing::info!("sending PADI host_uniq={}", self.my_host_id);
                let eth_head_data = [
                    MacAddr::broadcast().octets().as_ref(),
                    self.client_mac.octets().as_ref(),
                    &ETH_P_PPOED.to_be_bytes(),
                ]
                .concat();
                let discovery = PPPoEFrame::get_discover_with_host_uniq(self.my_host_id);
                data_sender
                    .send(Box::new([eth_head_data, discovery.convert_to_payload()].concat()))
                    .await
                    .unwrap();
                return true;
            }
            PPPoEConnectState::ReuqestSession { server_mac_addr, ac_cookie } => {
                let eth_head_data = [
                    server_mac_addr.as_ref(),
                    self.client_mac.octets().as_ref(),
                    &ETH_P_PPOED.to_be_bytes(),
                ]
                .concat();

                let request = PPPoEFrame::get_request(self.my_host_id, ac_cookie.clone());
                tracing::info!(
                    "sending PADR with host_uniq={} ac_cookie_present={}",
                    self.my_host_id,
                    ac_cookie.is_some()
                );
                data_sender
                    .send(Box::new([eth_head_data, request.convert_to_payload()].concat()))
                    .await
                    .unwrap();
                return true;
            }
            PPPoEConnectState::SessionConfirm { server_mac_addr, session_id } => (
                [server_mac_addr, self.client_mac.octets().as_ref(), &ETH_P_PPOES.to_be_bytes()]
                    .concat(),
                session_id,
            ),
        };

        if self.lcp_status.termination.0 {
            if let TagValue::Nak(()) = &self.lcp_status.termination.1 {
                tracing::info!("sending LCP termination request");
                let termination_request = PPPoEFrame::get_termination_request(*sid, 1);

                if let Err(e) = data_sender
                    .send(Box::new(
                        [eth_head_data, termination_request.convert_to_payload()].concat(),
                    ))
                    .await
                {
                    tracing::error!("failed to send LCP termination request: {e:?}");
                    return false;
                }
                return true;
            }
            return true;
        }

        if !matches!(self.lcp_status.server_config, TagValue::Ack(_)) {
            tracing::debug!("waiting for peer LCP config before sending local LCP config");
            return false;
        }

        if let TagValue::Nak(cfg) = &self.lcp_status.client_config {
            let request = PPPoEFrame::get_ppp_mru_config_request(
                *sid,
                self.lcp_status.cfg_req_id,
                cfg.mru,
                cfg.magic_number,
            );

            data_sender
                .send(Box::new([eth_head_data, request.convert_to_payload()].concat()))
                .await
                .unwrap();
            return true;
        }

        if !self.lcp_status.connect_base_cfg_redy() {
            tracing::debug!("waiting for base LCP config to complete");
            return false;
        }

        if let Some(auth) = self.lcp_status.authenticator.as_ref() {
            if !auth.is_done() {
                if let Some(payload) = auth.outgoing_packet() {
                    let frame = PPPoEFrame::get_ppp_auth_response(*sid, payload);
                    data_sender
                        .send(Box::new(
                            [eth_head_data.clone(), frame.convert_to_payload()].concat(),
                        ))
                        .await
                        .unwrap();
                } else {
                    return false;
                }
            }
        } else if !self.lcp_status.auth_type.is_confirm() {
            tracing::debug!("waiting for peer auth-type");
            return false;
        }

        if let TagValue::Nak(ipcp_addr) = &self.lcp_status.ipcp_client_ipaddr {
            let request = PPPoEFrame::get_ipcp_request_only_client_ip(
                *sid,
                self.lcp_status.ipcp_req_id,
                *ipcp_addr,
            );

            data_sender
                .send(Box::new([eth_head_data, request.convert_to_payload()].concat()))
                .await
                .unwrap();
            return true;
        }

        if let TagValue::Nak(ip6cp_id) = &self.lcp_status.ip6cp_client_id {
            let request = PPPoEFrame::get_ipv6cp_request(
                *sid,
                ip6cp_id.clone(),
                self.lcp_status.ip6cp_req_id,
            );

            data_sender
                .send(Box::new([eth_head_data, request.convert_to_payload()].concat()))
                .await
                .unwrap();
            return true;
        }

        false
    }

    pub(crate) fn can_enable_ebpf_prog(&self) -> bool {
        self.lcp_status.client_config.is_confirm()
            && self.lcp_status.server_config.is_confirm()
            && self.lcp_status.authenticator.as_ref().map_or(false, |a| a.is_done())
            && self.lcp_status.ipcp_client_ipaddr.is_confirm()
            && self.lcp_status.ipcp_server_ipaddr.is_confirm()
    }
}

#[cfg(test)]
mod tests {
    use super::super::auth::ChapAuthenticator;
    use super::super::auth::PapAuthenticator;
    use super::PPPoEClientManager;
    use landscape_common::net::MacAddr;

    #[test]
    fn parse_lcp_base_options_extracts_mru_and_magic() {
        let payload = [1, 4, 0x05, 0xd4, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let (mru, magic) = PPPoEClientManager::parse_lcp_base_options(&payload);

        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
    }

    #[test]
    fn parse_lcp_request_options_extracts_auth_type_and_count() {
        let payload = [1, 4, 0x05, 0xd4, 3, 4, 0xc0, 0x23, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let (mru, magic, auth_type, size) = PPPoEClientManager::parse_lcp_request_options(&payload);

        assert_eq!(mru, Some(1492));
        assert_eq!(magic, Some(0x1234_5678));
        assert_eq!(auth_type, Some(0xc023));
        assert_eq!(size, 3);
    }

    #[test]
    fn can_enable_ebpf_prog_after_lcp_pap_ipcp() {
        let mut manager = PPPoEClientManager::new(
            MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55),
            1492,
            "user".to_string(),
            "pass".to_string(),
        );
        assert!(!manager.can_enable_ebpf_prog());

        manager.lcp_status.client_config = super::TagValue::Reject;
        manager.lcp_status.server_config = super::TagValue::Reject;
        manager.lcp_status.authenticator = Some(Box::new(PapAuthenticator::new("user", "pass")));
        manager.lcp_status.authenticator.as_mut().unwrap().handle_incoming(
            &landscape_common::net_proto::ppp::PointToPoint {
                protocol: 0xc023,
                code: 2,
                id: 1,
                length: 4,
                payload: vec![],
            },
        );
        manager.lcp_status.ipcp_client_ipaddr =
            super::TagValue::Ack(std::net::Ipv4Addr::new(10, 0, 0, 100));
        manager.lcp_status.ipcp_server_ipaddr =
            super::TagValue::Ack(std::net::Ipv4Addr::new(10, 0, 0, 1));

        assert!(manager.can_enable_ebpf_prog());
    }

    #[test]
    fn ipv6cp_protocol_reject_does_not_increment_error_count() {
        let mut manager = PPPoEClientManager::new(
            MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55),
            1492,
            "user".to_string(),
            "pass".to_string(),
        );
        let lcp = landscape_common::net_proto::ppp::PointToPoint {
            protocol: 0xc021,
            code: 8,
            id: 1,
            length: 6,
            payload: vec![0x80, 0x57],
        };

        manager.handle_lcp_proto_reject(&lcp);

        assert_eq!(manager.error_count, 0);
        assert!(matches!(manager.lcp_status.ip6cp_client_id, super::TagValue::Reject));
        assert!(matches!(manager.lcp_status.ip6cp_server_id, super::TagValue::Reject));
    }

    #[test]
    fn can_enable_ebpf_prog_with_chap() {
        let mut manager = PPPoEClientManager::new(
            MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55),
            1492,
            "user".to_string(),
            "pass".to_string(),
        );
        assert!(!manager.can_enable_ebpf_prog());

        manager.lcp_status.client_config = super::TagValue::Reject;
        manager.lcp_status.server_config = super::TagValue::Reject;
        manager.lcp_status.authenticator = Some(Box::new(ChapAuthenticator::new("user", "pass")));
        manager.lcp_status.authenticator.as_mut().unwrap().handle_incoming(
            &landscape_common::net_proto::ppp::PointToPoint {
                protocol: 0xc223,
                code: 3,
                id: 1,
                length: 4,
                payload: vec![],
            },
        );
        manager.lcp_status.ipcp_client_ipaddr =
            super::TagValue::Ack(std::net::Ipv4Addr::new(10, 0, 0, 100));
        manager.lcp_status.ipcp_server_ipaddr =
            super::TagValue::Ack(std::net::Ipv4Addr::new(10, 0, 0, 1));

        assert!(manager.can_enable_ebpf_prog());
    }

    #[test]
    fn can_enable_ebpf_prog_false_when_chap_not_done() {
        let mut manager = PPPoEClientManager::new(
            MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55),
            1492,
            "user".to_string(),
            "pass".to_string(),
        );

        manager.lcp_status.client_config = super::TagValue::Reject;
        manager.lcp_status.server_config = super::TagValue::Reject;
        manager.lcp_status.authenticator = Some(Box::new(ChapAuthenticator::new("user", "pass")));
        manager.lcp_status.ipcp_client_ipaddr =
            super::TagValue::Ack(std::net::Ipv4Addr::new(10, 0, 0, 100));
        manager.lcp_status.ipcp_server_ipaddr =
            super::TagValue::Ack(std::net::Ipv4Addr::new(10, 0, 0, 1));

        assert!(!manager.can_enable_ebpf_prog(), "CHAP not done yet");
    }
}

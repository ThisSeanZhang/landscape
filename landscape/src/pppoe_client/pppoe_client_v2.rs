use std::net::Ipv4Addr;
use std::process;

use tokio::sync::{mpsc, oneshot, watch};

use super::{DEFAULT_CLIENT_MRU, ETH_P_PPOED, ETH_P_PPOES, LCP_ECHO_INTERVAL};
use crate::dump::pppoe::tags::PPPoETag;
use crate::dump::pppoe::{PPPOption, PPPoEFrame, PointToPoint};
use crate::pppoe_client::DEFAULT_TIME_OUT;
use crate::{macaddr::MacAddr, service::ServiceStatus};
use landscape_ebpf::pppoe;

pub async fn create_pppoe_client(
    index: u32,
    iface_name: String,
    iface_mac: MacAddr,
    peer_id: String,
    password: String,
    service_status: watch::Sender<ServiceStatus>,
) {
    service_status.send_replace(ServiceStatus::Staring);

    let (tx, mut rx) = pppoe::start(index).await.unwrap();

    let mut pkt_manager = PPPoEClientManager::new(iface_mac, peer_id, password);

    let mut bpf_thread_notice = None;

    let mut timeout_times = 0_u64;
    let resend_timeout_timer = tokio::time::sleep(tokio::time::Duration::from_secs(0));
    tokio::pin!(resend_timeout_timer);

    let echo_timeout_timer = tokio::time::sleep(tokio::time::Duration::from_secs(3));
    tokio::pin!(echo_timeout_timer);
    resend_timeout_timer
        .as_mut()
        .reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(DEFAULT_TIME_OUT));

    let mut service_status_rx = service_status.subscribe();
    loop {
        tokio::select! {
            receive_data = rx.recv() => {
                if let Some(receive_data) = receive_data {
                    // 接收到数据包
                    pkt_manager.handle_packet(*receive_data, &tx).await;
                    if pkt_manager.error_count > 10 {
                        tracing::error!("出现致命错误, 退出");
                        break;
                    }

                    if bpf_thread_notice.is_none() {
                        if pkt_manager.can_enable_ebpf_prog() {
                            bpf_thread_notice = pkt_manager.enable_ebpf(index, &iface_name).await;
                        }
                    }
                    timeout_times = 0;
                    resend_timeout_timer.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(DEFAULT_TIME_OUT));
                } else {
                    break
                }
            },
            // 发送超时发送
            _ = &mut resend_timeout_timer => {
                if timeout_times > 3 {
                    tracing::error!("超时次数过多");
                    break;
                }
                pkt_manager.send_packet(&tx).await;
                // 需要检测重发
                timeout_times += 1;
                resend_timeout_timer.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_times * 2 * DEFAULT_TIME_OUT));
            }
            // lcp 连接维护心跳
            _ = &mut echo_timeout_timer => {
                if let Some((cueernt_timeout_times, wait_time)) = pkt_manager.get_keep_alive_pkt(&tx).await {
                    if cueernt_timeout_times > 5 {
                        break;
                    }
                    echo_timeout_timer.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(wait_time));
                } else {
                    echo_timeout_timer.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(3));
                }
            }
            // 外部状态变化回调
            change_result = service_status_rx.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }

                if pkt_manager.lcp_status.termination.0 == false {
                    pkt_manager.lcp_status.termination = (true, TagValue::Nak(()));
                    pkt_manager.send_packet(&tx).await;
                }

                let current_status = &*service_status.borrow();
                match current_status {
                    ServiceStatus::Stopping => {
                        tracing::error!("pppoe reciver thread exit");
                        break;
                    },
                    _ => {}
                }
            }
        }
    }

    if let Some(bpf_thread_notice) = bpf_thread_notice {
        let (tx, rx) = oneshot::channel::<()>();
        if let Ok(_) = bpf_thread_notice.send(tx) {
            let _ = rx.await;
        }
    }

    service_status.send_replace(ServiceStatus::Stop { message: None });
    tracing::info!("pppoe client down");
}

/// PPPoE 的连接状态
#[derive(Debug)]
enum PPPoEConnectState {
    /// 发送 Discover 报文
    Discovering,
    /// 发送 Session 请求报文
    ReuqestSession { server_mac_addr: Vec<u8>, ac_cookie: Option<Vec<u8>> },
    /// 确定 Session
    SessionConfirm { server_mac_addr: Vec<u8>, session_id: u16 },
}

///
struct PPPoEClientManager {
    // 协商过程中出现的不匹配次数, NAK REJECT 之类的
    error_count: u16,
    client_mac: MacAddr,
    // TODO: 校验传来的 host unique 对不对
    my_host_id: u32,

    pppoe_status: PPPoEConnectState,

    lcp_status: LCPStatus,

    peer_id: String,
    password: String,
}

impl PPPoEClientManager {
    pub fn new(client_mac: MacAddr, peer_id: String, password: String) -> Self {
        let my_host_id = process::id().swap_bytes();
        // let my_host_id =
        //     SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32;
        PPPoEClientManager {
            error_count: 0,
            client_mac,
            my_host_id,
            pppoe_status: PPPoEConnectState::Discovering,
            lcp_status: LCPStatus::new(client_mac.clone()),
            peer_id,
            password,
        }
    }

    /// 处理数据包, 可能返回需要发送的数据包
    pub async fn handle_packet(
        &mut self,
        packet: Vec<u8>,
        data_sender: &mpsc::Sender<Box<Vec<u8>>>,
    ) -> Option<Vec<Vec<u8>>> {
        // TODO: 比较 mac 地址
        let Some(mut pppoe_data) = PPPoEFrame::new(&packet[14..]) else {
            tracing::error!("conversion to pppoe error, data is: {packet:?}");
            self.error_count += 1;
            return None;
        };

        if !pppoe_data.is_session_data() {
            // PPPoE 非 session 部分

            match &self.pppoe_status {
                PPPoEConnectState::Discovering => {
                    if !pppoe_data.is_offer() {
                        self.error_count += 1;
                        return None;
                    }
                    // let mut ac_name = None;
                    let mut ac_cookie = None;
                    let mut is_my_host = self.my_host_id == 0;
                    for tag in PPPoETag::from_bytes(&pppoe_data.payload).into_iter() {
                        match tag {
                            // PPPoETag::AcName(name) => {
                            //     ac_name = Some(String::from_utf8(name).unwrap());
                            // }
                            PPPoETag::HostUniq(id) => {
                                is_my_host = id == self.my_host_id;
                            }
                            PPPoETag::AcCookie(cookie) => {
                                ac_cookie = Some(cookie);
                            }
                            _ => {}
                        }
                    }
                    if is_my_host {
                        self.pppoe_status = PPPoEConnectState::ReuqestSession {
                            server_mac_addr: packet[6..12].to_vec(),
                            ac_cookie: ac_cookie.clone(),
                        };

                        let eth_head_data = [
                            &packet[6..12],
                            self.client_mac.octets().as_ref(),
                            &ETH_P_PPOED.to_be_bytes(),
                        ]
                        .concat();

                        let request = PPPoEFrame::get_request(self.my_host_id, ac_cookie);
                        data_sender
                            .send(Box::new([eth_head_data, request.convert_to_payload()].concat()))
                            .await
                            .unwrap();
                    } else {
                        self.error_count += 1;
                    }
                }
                PPPoEConnectState::ReuqestSession { server_mac_addr, ac_cookie: _ } => {
                    if !pppoe_data.is_confirm() {
                        self.error_count += 1;
                        return None;
                    }
                    tracing::info!("got a confirm message");
                    let mut confirm = false;
                    for tag in PPPoETag::from_bytes(&pppoe_data.payload).into_iter() {
                        match tag {
                            PPPoETag::HostUniq(id) => {
                                if self.my_host_id != 0 && id == self.my_host_id {
                                    confirm = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    if confirm {
                        self.pppoe_status = PPPoEConnectState::SessionConfirm {
                            server_mac_addr: server_mac_addr.clone(),
                            session_id: pppoe_data.sid,
                        }
                    } else {
                        self.error_count += 1;
                    }
                }
                PPPoEConnectState::SessionConfirm { server_mac_addr: _, session_id: _ } => {
                    // PPPOE 结束的 packet 会到这
                    self.error_count += 10;
                    return None;
                }
            }
        } else {
            // PPPoE LCP 部分

            let PPPoEConnectState::SessionConfirm { server_mac_addr, session_id, .. } =
                &self.pppoe_status
            else {
                return None;
            };

            if pppoe_data.sid != *session_id {
                return None;
            }

            let l2_header =
                [server_mac_addr, self.client_mac.octets().as_ref(), &ETH_P_PPOES.to_be_bytes()]
                    .concat();

            let lcp = PointToPoint::new(&pppoe_data.payload).unwrap();

            if lcp.is_lcp_config() {
                if lcp.is_ack() {
                    // 确认我们发送的配置
                    let mut client_mru = None;
                    let mut magic_number = None;
                    for op in PPPOption::from_bytes(&lcp.payload) {
                        if op.is_mru() {
                            client_mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
                        } else if op.is_magic_number() {
                            magic_number = Some(u32::from_be_bytes([
                                op.data[0], op.data[1], op.data[2], op.data[3],
                            ]));
                        }
                    }
                    if client_mru.is_some() && magic_number.is_some() {
                        self.lcp_status.client_config = TagValue::Ack(LcpBaseConfig {
                            mru: client_mru.unwrap(),
                            magic_number: magic_number.unwrap(),
                        });

                        if !self.lcp_status.pap.0 {
                            if let TagValue::Ack(auth_type) = &self.lcp_status.auth_type {
                                if *auth_type == 0xc023 {
                                    let pppoe_pap = PPPoEFrame::get_ppp_lcp_pap(
                                        *session_id,
                                        &self.peer_id,
                                        &self.password,
                                    );
                                    data_sender
                                        .send(Box::new(
                                            [l2_header, pppoe_pap.convert_to_payload()].concat(),
                                        ))
                                        .await
                                        .unwrap();
                                }
                            }
                        }
                    } else {
                        // 如果确认应当都有的
                        self.error_count += 10;
                    }
                } else if lcp.is_nak() {
                    // 需要修改我们发送的配置
                    let mut client_mru = None;
                    let mut magic_number = None;
                    for op in PPPOption::from_bytes(&lcp.payload) {
                        if op.is_mru() {
                            client_mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
                        } else if op.is_magic_number() {
                            magic_number = Some(u32::from_be_bytes([
                                op.data[0], op.data[1], op.data[2], op.data[3],
                            ]));
                        }
                    }
                    if client_mru.is_some() && magic_number.is_some() {
                        self.lcp_status.cfg_req_id += 1;
                        self.lcp_status.client_config = TagValue::Nak(LcpBaseConfig {
                            mru: client_mru.unwrap(),
                            magic_number: magic_number.unwrap(),
                        });

                        // 使用建议的值 重新进行发送请求
                        if let TagValue::Nak(cfg) = &self.lcp_status.client_config {
                            let request = PPPoEFrame::get_ppp_mru_config_request(
                                *session_id,
                                self.lcp_status.cfg_req_id,
                                cfg.magic_number,
                            );

                            data_sender
                                .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                                .await
                                .unwrap();
                        }
                    } else {
                        // 如果确认应当都有的
                        self.error_count += 10;
                    }
                    self.error_count += 1;
                } else if lcp.is_request() {
                    // 确认服务端发送的配置
                    let mut mru = None;
                    let mut magic_number = None;
                    let mut auth_type = None;
                    let mut size = 0;
                    for op in PPPOption::from_bytes(&lcp.payload) {
                        size += 1;
                        if op.is_mru() {
                            mru = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
                        } else if op.is_magic_number() {
                            magic_number = Some(u32::from_be_bytes([
                                op.data[0], op.data[1], op.data[2], op.data[3],
                            ]));
                        } else if op.is_auth_type() {
                            auth_type = Some(u16::from_be_bytes([op.data[0], op.data[1]]));
                        }
                    }
                    if mru.is_some() && magic_number.is_some() && auth_type.is_some() && size == 3 {
                        self.lcp_status.server_config = TagValue::Ack(LcpBaseConfig {
                            mru: mru.unwrap(),
                            magic_number: magic_number.unwrap(),
                        });

                        self.lcp_status.auth_type = TagValue::Ack(auth_type.unwrap());

                        pppoe_data.payload = lcp.gen_ack();
                        let ppp_lcp_config_ack = pppoe_data.convert_to_payload();
                        data_sender
                            .send(Box::new([l2_header.clone(), ppp_lcp_config_ack].concat()))
                            .await
                            .unwrap();

                        // 检查当前是否设置了, 没有就发送
                        if let TagValue::Nak(cfg) = &self.lcp_status.client_config {
                            let request = PPPoEFrame::get_ppp_mru_config_request(
                                *session_id,
                                self.lcp_status.cfg_req_id,
                                cfg.magic_number,
                            );

                            data_sender
                                .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                                .await
                                .unwrap();
                        }
                    } else {
                        // 如果确认应当都有的
                        self.error_count += 10;
                    }
                } else if lcp.is_reject() {
                    // 拒绝我们请求的配置 需要删除 我们的 tag 但是此处 因为是基础配置, 我们就直接退出
                    self.error_count += 10;
                } else if lcp.is_proto_reject() {
                    let proto = u16::from_be_bytes([lcp.payload[0], lcp.payload[1]]);
                    if proto == 0x8057 {
                        self.lcp_status.ip6cp_server_id = TagValue::Reject;
                        self.lcp_status.ip6cp_client_id = TagValue::Reject;
                    } else if proto == 0x8021 {
                        self.lcp_status.client_config = TagValue::Reject;
                        self.lcp_status.server_config = TagValue::Reject;
                        self.error_count += 10;
                    } else if proto == 0xc023 {
                        self.lcp_status.auth_type = TagValue::Reject;
                        self.lcp_status.pap = (false, None);
                        self.error_count += 10;
                    }
                    self.error_count += 1;
                } else if lcp.is_echo_request() {
                    // 心跳请求, 响应心跳
                    if let TagValue::Ack(client_config) = &self.lcp_status.client_config {
                        pppoe_data.payload = lcp.gen_reply_with_magic(client_config.magic_number);
                        let echo_reply = pppoe_data.convert_to_payload();
                        data_sender.send(Box::new([l2_header, echo_reply].concat())).await.unwrap();
                    }
                } else if lcp.is_echo_reply() {
                    // 重置 echo 超时计时
                    self.lcp_status.lcp_echo_times = 0;
                    self.lcp_status.echo_req_id = self.lcp_status.echo_req_id.wrapping_add(1);
                } else if lcp.is_termination() {
                    // 响应 ACK 后终止 LCP 连接
                    self.error_count += 10;
                    pppoe_data.payload = lcp.get_termination_ack();
                    let echo_reply = pppoe_data.convert_to_payload();
                    data_sender.send(Box::new([l2_header, echo_reply].concat())).await.unwrap();
                    self.lcp_status.termination = (true, TagValue::Ack(()));
                } else if lcp.is_termination_ack() {
                    // 响应 ACK 后终止 LCP 连接
                    self.error_count += 10;
                    self.lcp_status.termination = (true, TagValue::Ack(()));
                }
            } else if lcp.is_pap_auth() {
                if lcp.is_ack() {
                    // 确认我们发送的配置
                    self.lcp_status.pap = (true, Some(lcp.payload));
                } else if lcp.is_nak() {
                    // 认证失败 直接退出
                    self.error_count += 10;
                } else if lcp.is_reject() {
                    // 拒绝我们请求的配置 目前直接退出
                    self.error_count += 10;
                }
            } else if lcp.is_ipcp() {
                if lcp.is_ack() {
                    // 确认我们发送的配置
                    for each in PPPOption::from_bytes(&lcp.payload).into_iter() {
                        if each.t == 3 {
                            self.lcp_status.ipcp_client_ipaddr = TagValue::Ack(Ipv4Addr::new(
                                each.data[0],
                                each.data[1],
                                each.data[2],
                                each.data[3],
                            ));
                        }
                    }
                } else if lcp.is_nak() {
                    // 需要修改我们发送的配置
                    self.lcp_status.ipcp_req_id += 1;
                    for each in PPPOption::from_bytes(&lcp.payload).into_iter() {
                        if each.t == 3 {
                            self.lcp_status.ipcp_client_ipaddr = TagValue::Nak(Ipv4Addr::new(
                                each.data[0],
                                each.data[1],
                                each.data[2],
                                each.data[3],
                            ));
                        }
                    }
                    if let TagValue::Nak(ipcp_addr) = &self.lcp_status.ipcp_client_ipaddr {
                        let request = PPPoEFrame::get_ipcp_request_only_client_ip(
                            *session_id,
                            self.lcp_status.ipcp_req_id,
                            *ipcp_addr,
                        );

                        data_sender
                            .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                            .await
                            .unwrap();
                    }
                    self.lcp_status.ipcp_req_id += 1;
                } else if lcp.is_request() {
                    let mut reject_options = vec![];
                    for each in PPPOption::from_bytes(&lcp.payload).into_iter() {
                        if each.t == 3 {
                            self.lcp_status.ipcp_server_ipaddr = TagValue::Ack(Ipv4Addr::new(
                                each.data[0],
                                each.data[1],
                                each.data[2],
                                each.data[3],
                            ));
                        } else {
                            reject_options.extend(each.convert_to_payload());
                        }
                    }

                    if reject_options.len() > 0 {
                        pppoe_data.payload = lcp.gen_reject(reject_options);
                        let ppp_lcp_config_reject = pppoe_data.convert_to_payload();
                        data_sender
                            .send(Box::new([l2_header.clone(), ppp_lcp_config_reject].concat()))
                            .await
                            .unwrap();
                    } else if self.lcp_status.ipcp_server_ipaddr.is_confirm() {
                        pppoe_data.payload = lcp.gen_ack();
                        let ppp_lcp_config_ack = pppoe_data.convert_to_payload();

                        data_sender
                            .send(Box::new([l2_header.clone(), ppp_lcp_config_ack].concat()))
                            .await
                            .unwrap();

                        if let TagValue::Nak(ipcp_addr) = &self.lcp_status.ipcp_client_ipaddr {
                            let request = PPPoEFrame::get_ipcp_request_only_client_ip(
                                *session_id,
                                self.lcp_status.ipcp_req_id,
                                *ipcp_addr,
                            );

                            data_sender
                                .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                                .await
                                .unwrap();
                        }
                    }
                    // 确认服务端发送的配置
                } else if lcp.is_reject() {
                    // 拒绝我们请求的配置 目前直接退出
                    self.error_count += 10;
                }
            } else if lcp.is_ipv6cp() {
                if lcp.is_ack() {
                    // 确认我们发送的配置
                    for each in PPPOption::from_bytes(&lcp.payload).into_iter() {
                        if each.t == 1 {
                            self.lcp_status.ip6cp_client_id = TagValue::Ack(each.data);
                        }
                    }
                } else if lcp.is_nak() {
                    self.lcp_status.ip6cp_req_id += 1;
                    // 需要修改我们发送的配置
                    for each in PPPOption::from_bytes(&lcp.payload).into_iter() {
                        if each.t == 1 {
                            self.lcp_status.ip6cp_client_id = TagValue::Nak(each.data);
                        }
                    }
                    if let TagValue::Nak(ip6cp_id) = &self.lcp_status.ip6cp_client_id {
                        let request = PPPoEFrame::get_ipv6cp_request(
                            *session_id,
                            ip6cp_id.clone(),
                            self.lcp_status.ip6cp_req_id,
                        );

                        data_sender
                            .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                            .await
                            .unwrap();
                    }
                } else if lcp.is_request() {
                    // 确认服务端发送的配置
                    let mut reject_options = vec![];
                    for each in PPPOption::from_bytes(&lcp.payload).into_iter() {
                        if each.t == 1 {
                            self.lcp_status.ip6cp_server_id = TagValue::Ack(each.data);
                        } else {
                            reject_options.extend(each.convert_to_payload());
                        }
                    }

                    if reject_options.len() > 0 {
                        pppoe_data.payload = lcp.gen_reject(reject_options);
                        let ppp_lcp_config_reject = pppoe_data.convert_to_payload();
                        data_sender
                            .send(Box::new([l2_header.clone(), ppp_lcp_config_reject].concat()))
                            .await
                            .unwrap();
                    } else if self.lcp_status.ip6cp_server_id.is_confirm() {
                        pppoe_data.payload = lcp.gen_ack();
                        let ppp_lcp_config_ack = pppoe_data.convert_to_payload();

                        data_sender
                            .send(Box::new([l2_header.clone(), ppp_lcp_config_ack].concat()))
                            .await
                            .unwrap();

                        if let TagValue::Nak(ip6cp_id) = &self.lcp_status.ip6cp_client_id {
                            let request = PPPoEFrame::get_ipv6cp_request(
                                *session_id,
                                ip6cp_id.clone(),
                                self.lcp_status.ip6cp_req_id,
                            );

                            data_sender
                                .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                                .await
                                .unwrap();
                        }
                    }
                } else if lcp.is_reject() {
                    // 拒绝我们请求的配置 目前直接退出
                    self.error_count += 10;
                }
            }
        }

        return None;
    }

    /// 获得 ( 以超时次数, 和保持心跳发送的数据包 )
    pub async fn get_keep_alive_pkt(
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
            data_sender
                .send(Box::new([l2_header, request.convert_to_payload()].concat()))
                .await
                .unwrap();
            Some((self.lcp_status.lcp_echo_times, LCP_ECHO_INTERVAL))
        } else {
            None
        }
    }

    /// 处理发送数据包
    /// 会在 handle 之后调用
    /// 也会在发送超时之后调用
    /// 函数需要返回一个值 提示是否进行超时调用
    /// 比如如果需要 那么就开始超时计时
    pub async fn send_packet(&self, data_sender: &mpsc::Sender<Box<Vec<u8>>>) -> bool {
        tracing::info!("send_packet, cueernt_status: {:?}", self.pppoe_status);
        let (eth_head_data, sid) = match &self.pppoe_status {
            PPPoEConnectState::Discovering => {
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
                tracing::info!("pppoe request: {:?}, ac_cookie: {ac_cookie:?}", request);
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
                let termination_request = PPPoEFrame::get_termination_request(*sid, 1);

                data_sender
                    .send(Box::new(
                        [eth_head_data, termination_request.convert_to_payload()].concat(),
                    ))
                    .await
                    .unwrap();
                return true;
            } else {
                return true;
            }
        }

        // 先检查 服务端的  mru 是否设置了
        if !matches!(self.lcp_status.server_config, TagValue::Ack(_)) {
            return false;
        }

        if let TagValue::Nak(cfg) = &self.lcp_status.client_config {
            let request = PPPoEFrame::get_ppp_mru_config_request(
                *sid,
                self.lcp_status.cfg_req_id,
                cfg.magic_number,
            );

            data_sender
                .send(Box::new([eth_head_data, request.convert_to_payload()].concat()))
                .await
                .unwrap();
            return true;
        }

        if !self.lcp_status.connect_base_cfg_redy() {
            return false;
        }

        if !self.lcp_status.pap.0 {
            if let TagValue::Ack(auth_type) = &self.lcp_status.auth_type {
                if *auth_type == 0xc023 {
                    let pppoe_pap =
                        PPPoEFrame::get_ppp_lcp_pap(*sid, &self.peer_id, &self.password);
                    data_sender
                        .send(Box::new(
                            [eth_head_data.clone(), pppoe_pap.convert_to_payload()].concat(),
                        ))
                        .await
                        .unwrap();
                } else {
                    return false;
                }
            } else {
                return false;
            }
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

        return false;
    }

    pub fn can_enable_ebpf_prog(&self) -> bool {
        self.lcp_status.client_config.is_confirm()
            && self.lcp_status.server_config.is_confirm()
            && self.lcp_status.pap.0
            && self.lcp_status.ipcp_client_ipaddr.is_confirm()
            && self.lcp_status.ipcp_server_ipaddr.is_confirm()
            && self.lcp_status.ip6cp_client_id.is_confirm()
            && self.lcp_status.ip6cp_server_id.is_confirm()
    }

    pub async fn enable_ebpf(
        &self,
        index: u32,
        iface_name: &str,
    ) -> Option<oneshot::Sender<oneshot::Sender<()>>> {
        let mru = if let TagValue::Ack(client_cfg) = &self.lcp_status.client_config {
            client_cfg.mru
        } else {
            return None;
        };

        let client_ifece_id = self.lcp_status.ip6cp_client_id.get_value();
        let server_ifece_id = self.lcp_status.ip6cp_server_id.get_value();

        let Some(client_ip) = self.lcp_status.ipcp_client_ipaddr.get_value() else { return None };
        let Some(server_ip) = self.lcp_status.ipcp_server_ipaddr.get_value() else { return None };

        let PPPoEConnectState::SessionConfirm { server_mac_addr, session_id } = &self.pppoe_status
        else {
            return None;
        };
        tracing::info!(
            "server_ip: {:?}, client_ip: {:?}, server_ifece_id: {:?}, client_ipv6_id: {:?}",
            server_ip,
            client_ip,
            server_ifece_id,
            client_ifece_id
        );

        let (outside_notice_tx, outside_notice_rx) = oneshot::channel::<oneshot::Sender<()>>();
        let iface_name = iface_name.to_string();
        let session_id = session_id.clone();
        let server_mac_addr = server_mac_addr.clone();
        tokio::spawn(async move {
            landscape_ebpf::map_setting::add_wan_ip(index, client_ip);
            let _ = std::process::Command::new("ip")
                .args(&["link", "set", "dev", &iface_name, "mtu", &format!("{}", mru)])
                .output();

            let _ = std::process::Command::new("ip")
                .args(&[
                    "addr",
                    "add",
                    &format!("{}", client_ip),
                    "peer",
                    &format!("{}/32", server_ip),
                    "dev",
                    &iface_name,
                ])
                .output();
            let _ = std::process::Command::new("ip")
                .args(&["route", "replace", "default", "via", &format!("{}", server_ip)])
                .output();
            let neight_run_result = std::process::Command::new("ip")
                .args(&[
                    "neigh",
                    "add",
                    &format!("{}", server_ip),
                    "lladdr",
                    &format!(
                        "{}",
                        MacAddr::new(
                            server_mac_addr[0],
                            server_mac_addr[1],
                            server_mac_addr[2],
                            server_mac_addr[3],
                            server_mac_addr[4],
                            server_mac_addr[5],
                        )
                    ),
                    "dev",
                    &iface_name,
                ])
                .output();
            if let Err(e) = neight_run_result {
                tracing::error!("add neigh error: {e:?}");
            }
            let notise = pppoe::pppoe_tc::create_pppoe_tc_ebpf_3(index, session_id, mru).await;
            let outside_callback = outside_notice_rx.await;

            // clean resourse
            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Ok(_) = notise.send(tx) {
                if let Err(e) = rx.await {
                    tracing::error!("wait ebpf tc detach fail: {e:?}");
                }
            }

            let _ = std::process::Command::new("ip")
                .args(&[
                    "addr",
                    "del",
                    &format!("{}", client_ip),
                    "peer",
                    &format!("{}/32", server_ip),
                    "dev",
                    &iface_name,
                ])
                .output();

            landscape_ebpf::map_setting::del_wan_ip(index);
            let _ = std::process::Command::new("ip")
                .args(&["link", "set", "dev", &iface_name, "mtu", "1500"])
                .output();

            if let Ok(callback) = outside_callback {
                let _ = callback.send(());
            }
        });

        Some(outside_notice_tx)
    }
}

struct LcpBaseConfig {
    mru: u16,
    magic_number: u32,
}

impl LcpBaseConfig {
    pub fn new_client() -> Self {
        let now =
            std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap();
        let magic_number = now.as_secs() as u32;
        LcpBaseConfig { mru: DEFAULT_CLIENT_MRU, magic_number }
    }
}

struct LCPStatus {
    /// 当前已发送, 且没有响应的 ECHO 次数
    /// 当收到 Reply 之后将会重置
    lcp_echo_times: u16,
    echo_req_id: u8,

    client_config: TagValue<LcpBaseConfig>,
    server_config: TagValue<LcpBaseConfig>,
    cfg_req_id: u8,

    /// 认证方式
    auth_type: TagValue<u16>,
    /// 存储 PAP 认证消息
    pap: (bool, Option<Vec<u8>>),
    // auth_req_id: u8,
    ipcp_server_ipaddr: TagValue<Ipv4Addr>,
    ipcp_client_ipaddr: TagValue<Ipv4Addr>,
    ipcp_req_id: u8,

    ip6cp_server_id: TagValue<Vec<u8>>,
    ip6cp_client_id: TagValue<Vec<u8>>,
    ip6cp_req_id: u8,

    termination: (bool, TagValue<()>),
}

impl LCPStatus {
    pub fn new(client_mac: MacAddr) -> Self {
        let mut ipv6_interface_id = [0_u8; 8];
        let mac_addr = client_mac.octets();
        // let process_id = process::id().to_le_bytes();
        // let mut ipv6_interface_id = client_mac.octets().to_vec();
        // ipv6_interface_id.push(process_id[0]);
        // ipv6_interface_id.push(process_id[1]);
        ipv6_interface_id[0] = mac_addr[0];
        ipv6_interface_id[1] = mac_addr[1];
        ipv6_interface_id[2] = mac_addr[2];

        ipv6_interface_id[3] = 0xff;
        ipv6_interface_id[4] = 0xfe;

        ipv6_interface_id[5] = mac_addr[3];
        ipv6_interface_id[6] = mac_addr[4];
        ipv6_interface_id[7] = mac_addr[5];
        LCPStatus {
            lcp_echo_times: 0,
            echo_req_id: 0,
            client_config: TagValue::Nak(LcpBaseConfig::new_client()),
            server_config: TagValue::Nak(LcpBaseConfig::new_client()),
            cfg_req_id: 1,
            auth_type: TagValue::Nak(0),
            pap: (false, None),
            // auth_req_id: 1,
            ipcp_server_ipaddr: TagValue::Nak(Ipv4Addr::UNSPECIFIED),
            ipcp_client_ipaddr: TagValue::Nak(Ipv4Addr::UNSPECIFIED),
            ipcp_req_id: 1,
            ip6cp_server_id: TagValue::Nak(vec![]),
            ip6cp_client_id: TagValue::Nak(ipv6_interface_id.to_vec()),
            ip6cp_req_id: 1,
            termination: (false, TagValue::Nak(())),
        }
    }

    pub fn connect_base_cfg_redy(&self) -> bool {
        self.client_config.is_confirm() && self.server_config.is_confirm()
    }
}

enum TagValue<T> {
    /// 还未协商
    Nak(T),
    /// 协商完成
    Ack(T),
    /// 拒绝协商
    Reject,
}

impl<T> TagValue<T> {
    pub fn is_confirm(&self) -> bool {
        match self {
            TagValue::Nak(_) => false,
            TagValue::Ack(_) | TagValue::Reject => true,
        }
    }
}

impl<T: Clone> TagValue<T> {
    pub fn get_value(&self) -> Option<T> {
        match self {
            TagValue::Ack(v) => Some(v.clone()),
            TagValue::Nak(_) | TagValue::Reject => None,
        }
    }
}

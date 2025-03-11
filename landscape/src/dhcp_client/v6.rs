use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use dhcproto::{
    v6::{self, DhcpOption, DhcpOptions, Message, OptionCode},
    Decodable, Decoder, Encodable, Encoder,
};

use socket2::{Domain, Protocol, Type};
use tokio::{net::UdpSocket, time::Instant};

use crate::{dump::udp_packet::dhcp_v6::get_solicit_options, macaddr::MacAddr};
use landscape_common::{
    global_const::LD_PD_WATCHES,
    service::{DefaultWatchServiceStatus, ServiceStatus},
    LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT,
};

pub const IPV6_TIMEOUT_DEFAULT_DURACTION: u64 = 10;
pub const IPV6_TIMEOUT_RENEW_DURACTION: u64 = 10;
pub const IPV6_TIMEOUT_REBIND_DURACTION: u64 = 20;

pub const IPV6_T1_DEFAULT: u64 = 60 * 60 * 12;
pub const IPV6_T2_DEFAULT: u64 = (IPV6_T1_DEFAULT * 8) / 5; // IPV6_T1_DEFAULT * 1.6

static DHCPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2);

type V6MessageType = dhcproto::v6::MessageType;
#[derive(Clone, Debug)]
pub enum IpV6PdState {
    /// 初始状态
    Solicit { xid: u32 },
    /// 发起地址请求
    Request { xid: u32, service_id: Vec<u8>, iapd: v6::IAPD, service_sock: SocketAddr },

    /// 地址激活使用
    Bound { xid: u32, service_id: Vec<u8>, iapd: v6::IAPD, bound_time: Instant },
    /// 确认当前地址状态
    Confirm,
    /// Renew 续订 T1 事件触发
    Renew {
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        renew_time: Instant,
        bound_time: Instant,
    },
    WaitToRebind {
        // 用于在 WaitToRebind 是也可确认 Renew 最后一次发送的数据包
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        bound_time: Instant,
    },
    /// 续订超时
    Rebind {
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        rebind_time: Instant,
        bound_time: Instant,
    },

    ///
    Release { xid: u32, service_id: Vec<u8> },
    ///
    Decline,
    /// 结束
    Stop,
}

fn get_new_ipv6_xid() -> u32 {
    let mut xid = rand::random();
    xid = xid & 0x00FFFFFF;
    xid
}
impl IpV6PdState {
    pub fn init_status() -> IpV6PdState {
        IpV6PdState::Solicit { xid: get_new_ipv6_xid() }
    }

    pub fn get_xid(&self) -> u32 {
        match self {
            IpV6PdState::Solicit { xid, .. } => xid.clone(),
            // IpV6PdState::Advertise { xid, .. } => xid.clone(),
            IpV6PdState::Request { xid, .. } => xid.clone(),
            IpV6PdState::Bound { xid, .. } => xid.clone(),
            IpV6PdState::Confirm => todo!(),
            IpV6PdState::Renew { xid, .. } => xid.clone(),
            IpV6PdState::WaitToRebind { xid, .. } => xid.clone(),
            IpV6PdState::Rebind { xid, .. } => xid.clone(),
            IpV6PdState::Release { xid, .. } => xid.clone(),
            IpV6PdState::Decline => todo!(),
            IpV6PdState::Stop => 0,
        }
    }

    pub fn into_release(self) -> Option<Vec<u8>> {
        match self {
            IpV6PdState::Solicit { .. } => None,
            IpV6PdState::Request { service_id, .. }
            | IpV6PdState::Bound { service_id, .. }
            | IpV6PdState::Renew { service_id, .. }
            | IpV6PdState::WaitToRebind { service_id, .. }
            // TODO: simple exit
            | IpV6PdState::Rebind { service_id, .. } => Some(service_id),
            IpV6PdState::Confirm => todo!(),
            IpV6PdState::Release { .. } => None,
            IpV6PdState::Decline => None,
            IpV6PdState::Stop => None,
        }
    }
}

impl IpV6PdState {
    pub fn can_handle_message(&self, message_type: &V6MessageType) -> bool {
        match self {
            IpV6PdState::Solicit { .. } => matches!(message_type, V6MessageType::Advertise),
            IpV6PdState::Request { .. } => {
                matches!(message_type, V6MessageType::Reply)
            }
            IpV6PdState::Renew { .. } => {
                matches!(message_type, V6MessageType::Reply)
            }
            IpV6PdState::WaitToRebind { .. } => {
                matches!(message_type, V6MessageType::Reply)
            }
            IpV6PdState::Rebind { .. } => {
                matches!(message_type, V6MessageType::Reply)
            }
            _ => false,
        }
    }

    pub fn check_service_id(&self, new_v6_msg: &Message) -> bool {
        match self {
            IpV6PdState::Solicit { .. } | IpV6PdState::Rebind { .. } => true,
            IpV6PdState::Request { service_id, .. }
            | IpV6PdState::Renew { service_id, .. }
            | IpV6PdState::WaitToRebind { service_id, .. } => {
                if let Some(v6::DhcpOption::ServerId(new_service_id)) =
                    new_v6_msg.opts().get(OptionCode::ServerId)
                {
                    if service_id == new_service_id {
                        return true;
                    }
                }
                false
            }
            _ => true,
        }
    }
}

fn gen_client_id(mac_addr: MacAddr) -> Vec<u8> {
    let mut result = Vec::with_capacity(10);
    result.extend_from_slice(&[00, 03, 00, 01]);
    result.extend_from_slice(&mac_addr.octets());
    result
}
pub async fn dhcp_v6_pd_client(
    iface_name: String,
    mac_addr: MacAddr,
    client_port: u16,
    service_status: DefaultWatchServiceStatus,
) {
    LD_PD_WATCHES.init(&iface_name).await;
    let client_id = gen_client_id(mac_addr);
    service_status.just_change_status(ServiceStatus::Staring);

    tracing::info!("DHCP V6 Client Staring");
    landscape_ebpf::map_setting::add_expose_port(client_port);
    let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), client_port);

    let socket2 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    socket2.set_only_v6(true).unwrap();
    socket2.set_reuse_address(true).unwrap();
    socket2.set_reuse_port(true).unwrap();
    socket2.bind(&socket_addr.into()).unwrap();
    socket2.set_nonblocking(true).unwrap();
    socket2.bind_device(Some(iface_name.as_bytes())).unwrap();
    // socket2.set_broadcast(true).unwrap();

    let socket = UdpSocket::from_std(socket2.into()).unwrap();

    let send_socket = Arc::new(socket);

    let recive_socket_raw = send_socket.clone();

    let (message_tx, mut message_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    // 接收数据
    tokio::spawn(async move {
        // 超时重发定时器

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = recive_socket_raw.recv_from(&mut buf) => {
                    // 接收数据包
                    match result {
                        Ok((len, addr)) => {
                            let message = buf[..len].to_vec();
                            if let Err(e) = message_tx.try_send((message, addr)) {
                                tracing::error!("Error sending message to channel: {:?}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error receiving data: {:?}", e);
                        }
                    }
                },
                _ = message_tx.closed() => {
                    tracing::error!("message_tx closed");
                    break;
                }
            }
        }

        tracing::info!("DHCP recv client loop down");
    });

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("DHCP V6 Client Running");

    // 超时次数
    let mut timeout_times: u64 = 1;
    // 下一次超时事件
    // let mut current_timeout_time = IPV6_TIMEOUT_DEFAULT_DURACTION;

    let mut active_send = Box::pin(tokio::time::sleep(Duration::from_secs(0)));

    let mut status = IpV6PdState::init_status();
    #[cfg(debug_assertions)]
    let time = tokio::time::Instant::now();

    loop {
        let mut service_status_subscribe = service_status.subscribe();
        tokio::select! {
            // 超时激发重发
            _ = active_send.as_mut() => {
                #[cfg(debug_assertions)]
                {
                    tracing::error!("Timeout active at: {:?}",  time.elapsed());
                }
                if timeout_times > 4 {
                    // 如果当前状态是 Solicit 并且 超时 4 次 就退出
                    if matches!(status, IpV6PdState::Solicit { .. }) {
                        tracing::error!("Timeout exceeded limit");
                        break;
                    // } else {
                    //     timeout_times = 0;
                    //     // current_timeout_time = IPV6_TIMEOUT_DEFAULT_DURACTION;
                    //     status = IpV6PdState::init_status();
                    //     tracing::error!("Start from Solicit: {:#?}", status);
                    }
                }

                let need_reset_timeout = send_current_status_packet(&client_id, &send_socket, &mut status).await;
                if need_reset_timeout {
                    timeout_times = 0;
                }
                timeout_times = get_status_timeout_config(&status, timeout_times, active_send.as_mut());
                // active_send.as_mut().set(tokio::time::sleep(Duration::from_secs(current_timeout_time * timeout_times)));
                // timeout_times += 1;
            },
            message_result = message_rx.recv() => {
                // 处理接收到的数据包
                match message_result {
                    Some(data) => {
                        let need_reset_time = handle_packet(&iface_name, &client_id, &mut status, data, ).await;
                        if need_reset_time {
                            timeout_times = get_status_timeout_config(&status, 0, active_send.as_mut());
                            // current_timeout_time = t2;

                        }
                    }
                    // message_rx close
                    None => break
                }
            },
            change_result = service_status_subscribe.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }
                // let exit =  {
                //     let current_status = &*service_status_subscribe.borrow();
                //     match current_status {
                //         ServiceStatus::Stopping |ServiceStatus::Stop => true,
                //         _ => false
                //     }
                // };
                if service_status.is_exit() {
                    if let Some(service_id) = status.into_release() {
                        let mut send_msg = v6::Message::new(V6MessageType::Release);
                        send_msg.opts_mut().insert(DhcpOption::ServerId(service_id));
                        send_msg.opts_mut().insert(DhcpOption::ClientId(client_id));
                        send_msg.opts_mut().insert(v6::DhcpOption::ElapsedTime(0));
                        send_data(&send_msg, &send_socket, None).await;
                    }
                    service_status.just_change_status(ServiceStatus::Stop);
                    tracing::info!("release send and stop");
                    break;
                }
            }
        }
    }
    tracing::info!("DHCP V6 Client Stop: {:#?}", service_status);

    if !service_status.is_stop() {
        service_status.just_change_status(ServiceStatus::Stop);
    }
}

/// 处理当前状态应该发送什么数据包
/// 当需要重置 timeout 就返回 true
async fn send_current_status_packet(
    my_client_id: &[u8],
    send_socket: &UdpSocket,
    current_status: &mut IpV6PdState,
) -> bool {
    match current_status {
        IpV6PdState::Solicit { xid } => {
            let mut msg = v6::Message::new(v6::MessageType::Solicit);
            msg.set_opts(get_solicit_options());
            msg.set_xid_num(xid.clone());
            msg.opts_mut().insert(v6::DhcpOption::ClientId(my_client_id.to_vec()));

            send_data(&msg, send_socket, None).await;
        }
        // IpV6PdState::Advertise { xid } => todo!(),
        IpV6PdState::Request { xid, service_id, iapd, service_sock: _ } => {
            let mut send_msg = v6::Message::new(V6MessageType::Request);
            send_msg.set_xid_num(*xid);
            let mut options = DhcpOptions::new();
            if let Some(ia_prefix) = iapd.opts.get(OptionCode::IAPrefix) {
                options.insert(ia_prefix.clone());
            }
            let iapd = DhcpOption::IAPD(v6::IAPD {
                id: iapd.id,
                t1: iapd.t1,
                t2: iapd.t2,
                opts: options,
            });
            send_msg.opts_mut().insert(iapd);
            send_msg.opts_mut().insert(v6::DhcpOption::ClientId(my_client_id.to_vec()));
            send_msg.opts_mut().insert(DhcpOption::ServerId(service_id.clone()));

            send_data(&send_msg, send_socket, None).await;
        }
        IpV6PdState::Bound { xid: _, service_id, iapd, bound_time } => {
            // t1 时间到 转换状态为 Renew
            *current_status = IpV6PdState::Renew {
                xid: get_new_ipv6_xid(),
                service_id: service_id.clone(),
                renew_time: Instant::now(),
                bound_time: bound_time.clone(),
                iapd: iapd.clone(),
            };
            return true;
        }
        IpV6PdState::Confirm => todo!(),
        IpV6PdState::Renew { xid, service_id, iapd, renew_time, bound_time } => {
            //
            let mut send_msg = v6::Message::new(V6MessageType::Renew);
            send_msg.set_xid_num(xid.clone());
            let mut options = DhcpOptions::new();
            if let Some(ia_prefix) = iapd.opts.get(OptionCode::IAPrefix) {
                options.insert(ia_prefix.clone());
            }
            let iapd_options = DhcpOption::IAPD(v6::IAPD {
                id: iapd.id,
                t1: iapd.t1,
                t2: iapd.t2,
                opts: options,
            });
            send_msg.opts_mut().insert(iapd_options);
            //
            let now = (renew_time.elapsed().as_millis() as u16) / 10;
            send_msg.opts_mut().insert(v6::DhcpOption::ElapsedTime(now));
            send_msg.opts_mut().insert(v6::DhcpOption::ClientId(my_client_id.to_vec()));
            send_msg.opts_mut().insert(DhcpOption::ServerId(service_id.clone()));

            send_data(&send_msg, send_socket, None).await;

            let t2 = if iapd.t2 == 0 { IPV6_T2_DEFAULT } else { iapd.t2 as u64 };
            let t2 = t2 / 10 * 8;
            // Reach 80% wait to rebind
            if bound_time.elapsed().as_secs() >= t2 {
                tracing::warn!("Renew turn to WaitToRebind");
                // 切换状态为 Rebind
                *current_status = IpV6PdState::WaitToRebind {
                    xid: xid.clone(),
                    service_id: service_id.clone(),
                    bound_time: bound_time.clone(),
                    iapd: iapd.clone(),
                };
                return true;
            }
        }
        IpV6PdState::WaitToRebind { xid: _, service_id, iapd, bound_time } => {
            tracing::warn!("WaitToRebind turn to Rebind");
            // 切换状态为 Rebind
            *current_status = IpV6PdState::Rebind {
                xid: get_new_ipv6_xid(),
                service_id: service_id.clone(),
                rebind_time: Instant::now(),
                bound_time: bound_time.clone(),
                iapd: iapd.clone(),
            };
            return true;
        }
        IpV6PdState::Rebind { xid, service_id: _, iapd, rebind_time, bound_time } => {
            let bind_end = if iapd.t2 == 0 { IPV6_T2_DEFAULT } else { iapd.t2 as u64 };
            let bind_end = bind_end / 8 * 10;
            // Reach 125% to Solicit
            if bound_time.elapsed().as_secs() >= bind_end {
                tracing::warn!("Rebind turn to Solicit");
                // 切换状态为 Solicit 重新开始
                *current_status = IpV6PdState::Solicit { xid: get_new_ipv6_xid() };
                return true;
            }

            let mut send_msg = v6::Message::new(V6MessageType::Rebind);
            send_msg.set_xid_num(xid.clone());
            let mut options = DhcpOptions::new();
            if let Some(ia_prefix) = iapd.opts.get(OptionCode::IAPrefix) {
                options.insert(ia_prefix.clone());
            }
            let iapd = DhcpOption::IAPD(v6::IAPD {
                id: iapd.id,
                t1: iapd.t1,
                t2: iapd.t2,
                opts: options,
            });
            send_msg.opts_mut().insert(iapd);
            //
            let now = (rebind_time.elapsed().as_millis() as u16) / 10;
            send_msg.opts_mut().insert(v6::DhcpOption::ElapsedTime(now));
            send_msg.opts_mut().insert(v6::DhcpOption::ClientId(my_client_id.to_vec()));
            // send_msg.opts_mut().insert(DhcpOption::ServerId(service_id.clone()));

            send_data(&send_msg, send_socket, None).await;
        }
        IpV6PdState::Release { .. } => todo!(),
        IpV6PdState::Decline => todo!(),
        IpV6PdState::Stop => todo!(),
    }
    false
}

async fn send_data(msg: &v6::Message, send_socket: &UdpSocket, target_sock: Option<SocketAddr>) {
    let target_sock = if let Some(target_sock) = target_sock {
        target_sock
    } else {
        SocketAddr::new(IpAddr::V6(DHCPV6_MULTICAST), LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT)
    };
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    if let Err(e) = msg.encode(&mut e) {
        tracing::error!("msg encode error: {e:?}");
        return;
    }
    match send_socket.send_to(&buf, &target_sock).await {
        Ok(len) => {
            tracing::debug!("send dhcpv6 fram: {msg:?},  len: {len:?}");
        }
        Err(e) => {
            tracing::error!("error: {:?}", e);
        }
    }
}
fn get_status_timeout_config(
    current_status: &IpV6PdState,
    prev_timeout_times: u64,
    mut timeout: Pin<&mut tokio::time::Sleep>,
) -> u64 {
    let current_timeout_time = match current_status {
        // 绑定后的超时时间是 由 iapd 的 t1 决定
        IpV6PdState::Bound { iapd, .. } => iapd.t1 as u64,
        // 等待的时间是 t2 - bound_time
        IpV6PdState::WaitToRebind { iapd, bound_time, .. } => {
            let t2 = if iapd.t2 == 0 { IPV6_T2_DEFAULT } else { iapd.t2 as u64 };
            t2 - bound_time.elapsed().as_secs()
        }
        _ => IPV6_TIMEOUT_DEFAULT_DURACTION * prev_timeout_times,
    };

    timeout.set(tokio::time::sleep(Duration::from_secs(current_timeout_time)));
    prev_timeout_times + 1
}
/// 处理接收到的报文，根据当前状态决定如何处理
/// 返回值为是否要进行检查刷新超时时间
async fn handle_packet(
    iface_name: &str,
    my_client_id: &[u8],
    current_status: &mut IpV6PdState,
    (msg, msg_addr): (Vec<u8>, SocketAddr),
) -> bool {
    let new_v6_msg = Message::decode(&mut Decoder::new(&msg));
    let new_v6_msg = match new_v6_msg {
        Ok(msg) => msg,
        Err(e) => {
            tracing::error!("decode msg error: {e:?}");
            return true;
        }
    };

    if new_v6_msg.xid_num() != current_status.get_xid() {
        return false;
    }

    // tracing::debug!("recv msg: {new_v6_msg:?}");

    if let Some(v6::DhcpOption::ClientId(client_id)) = new_v6_msg.opts().get(OptionCode::ClientId) {
        // 比较 client id
        if my_client_id != client_id {
            tracing::debug!(
                "client_id not same. our ID: {:?}, recv ID: {:?}",
                my_client_id,
                client_id
            );
            return false;
        }
    }
    if !current_status.can_handle_message(&new_v6_msg.msg_type()) {
        tracing::error!("self: {current_status:?}");
        tracing::error!("recv msg: {msg:?}");
        tracing::error!("current status can not handle this status");
        return false;
    }
    tracing::debug!("recv msg: {new_v6_msg:?}");
    match current_status.clone() {
        IpV6PdState::Solicit { .. } => {
            // REMOVE
            // *current_status = IpV6PdState::Advertise { xid };

            let mut my_service_id = vec![];
            let mut iapd = None;

            if let Some(v6::DhcpOption::ServerId(service_id)) =
                new_v6_msg.opts().get(OptionCode::ServerId)
            {
                my_service_id = service_id.clone();
                tracing::info!("service_id: {:?}", service_id);
            }

            if let Some(v6::DhcpOption::IAPD(new_iapd)) = new_v6_msg.opts().get(OptionCode::IAPD) {
                iapd = Some(new_iapd.clone());
            }

            if !my_service_id.is_empty() {
                if let Some(iapd) = iapd {
                    *current_status = IpV6PdState::Request {
                        xid: get_new_ipv6_xid(),
                        service_id: my_service_id,
                        iapd,
                        service_sock: msg_addr,
                    };

                    tracing::debug!("current status move to: {:#?}", current_status);
                    return true;
                } else {
                    tracing::debug!("iapd not exist");
                }
            } else {
                tracing::error!("service_id is empty, ignore this msg");
            }
        }
        IpV6PdState::Request { service_id, .. }
        | IpV6PdState::Renew { service_id, .. }
        | IpV6PdState::WaitToRebind { service_id, .. }
        | IpV6PdState::Rebind { service_id, .. } => match new_v6_msg.msg_type() {
            V6MessageType::Reply => {
                if let Some(v6::DhcpOption::ServerId(new_service_id)) =
                    new_v6_msg.opts().get(OptionCode::ServerId)
                {
                    if &service_id != new_service_id {
                        return false;
                    }
                }

                if let Some(v6::DhcpOption::IAPD(iapd)) = new_v6_msg.opts().get(OptionCode::IAPD) {
                    let mut success = true;
                    let mut ia_prefix = None;
                    for opt in iapd.opts.iter() {
                        match opt {
                            DhcpOption::StatusCode(code) => {
                                if matches!(code.status, v6::Status::Success) {
                                    success = true;
                                } else {
                                    success = false;
                                    tracing::error!(
                                        "current_status {:#?}, replay error: {:?}",
                                        current_status,
                                        new_v6_msg
                                    );
                                }
                            }
                            DhcpOption::IAPrefix(data) => {
                                ia_prefix = Some(data);
                            }
                            _ => {}
                        }
                    }
                    if let Some(ia_prefix) = ia_prefix {
                        if success {
                            *current_status = IpV6PdState::Bound {
                                xid: get_new_ipv6_xid(),
                                service_id,
                                iapd: iapd.clone(),
                                bound_time: Instant::now(),
                            };
                            // setting IA prefix to IAPrefixMap
                            LD_PD_WATCHES
                                .insert_or_replace(
                                    iface_name,
                                    landscape_common::global_const::LDIAPrefix {
                                        preferred_lifetime: ia_prefix.preferred_lifetime,
                                        valid_lifetime: ia_prefix.valid_lifetime,
                                        prefix_len: ia_prefix.prefix_len,
                                        prefix_ip: ia_prefix.prefix_ip,
                                    },
                                )
                                .await;
                            tracing::debug!("current status move to: {:#?}", current_status);
                            return true;
                        } else {
                            tracing::error!("current status error: {:#?}", new_v6_msg);
                        }
                    } else {
                        tracing::error!("current msg without ia_prefix: {:#?}", new_v6_msg);
                    }
                }
            }
            _ => {}
        },
        IpV6PdState::Release { .. } => {}
        IpV6PdState::Stop => {}
        _ => {}
    }

    false
}

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use dhcproto::{
    v6::{self, DhcpOption, Message, OptionCode},
    Decodable, Decoder, Encodable, Encoder,
};

use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;

use crate::{
    dhcp_client::DEFAULT_TIME_OUT, dump::udp_packet::dhcp_v6::get_solicit_options, macaddr::MacAddr,
};
use landscape_common::{
    service::{DefaultServiceStatus, DefaultWatchServiceStatus},
    LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT,
};

static DHCPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2);

type V6MessageType = dhcproto::v6::MessageType;
#[derive(Clone, Debug)]
pub enum IpV6PdState {
    /// 初始状态
    Solicit {
        xid: u32,
    },
    /// 获得服务端响应
    // Advertise {
    //     xid: u32,
    // },
    /// 发起地址请求
    Request {
        xid: u32,
        msg: Message,
        service_id: Vec<u8>,
    },

    /// 地址激活使用
    Bound {
        xid: u32,
        msg: Message,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
    },

    /// 确认当前地址状态
    Confirm,
    /// Renew 续订 T1 事件触发
    Renew {
        xid: u32,
        msg: Message,
        service_id: Vec<u8>,
    },
    /// 续订超时
    Rebind {
        xid: u32,
        msg: Message,
        service_id: Vec<u8>,
    },

    ///
    Release,
    ///
    Decline,

    Stopping,
    Stop,
}

impl IpV6PdState {
    pub fn init_status() -> IpV6PdState {
        IpV6PdState::Solicit { xid: rand::random() }
    }

    pub fn get_xid(&self) -> u32 {
        match self {
            IpV6PdState::Solicit { xid, .. } => xid.clone(),
            // IpV6PdState::Advertise { xid, .. } => xid.clone(),
            IpV6PdState::Request { xid, .. } => xid.clone(),
            IpV6PdState::Bound { xid, .. } => xid.clone(),
            IpV6PdState::Confirm => todo!(),
            IpV6PdState::Renew { xid, .. } => xid.clone(),
            IpV6PdState::Rebind { xid, .. } => xid.clone(),
            IpV6PdState::Release => todo!(),
            IpV6PdState::Decline => todo!(),
            IpV6PdState::Stopping => 0,
            IpV6PdState::Stop => 0,
        }
    }
}

impl IpV6PdState {
    pub fn can_handle_message(&self, message_type: &V6MessageType) -> bool {
        match self {
            IpV6PdState::Solicit { .. } => matches!(message_type, V6MessageType::Advertise),
            // IpV6PdState::Advertise { .. } => matches!(message_type, V6MessageType::Request),
            IpV6PdState::Request { .. } => {
                matches!(message_type, V6MessageType::Reply)
            }
            IpV6PdState::Renew { .. } => {
                matches!(message_type, V6MessageType::Reply)
            }
            IpV6PdState::Rebind { .. } => {
                matches!(message_type, V6MessageType::Reply)
            }
            _ => false,
        }
    }
    pub fn is_stopping(&self) -> bool {
        match self {
            IpV6PdState::Stopping => true,
            _ => false,
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
    let client_id = gen_client_id(mac_addr);
    service_status.send_replace(DefaultServiceStatus::Staring);

    landscape_ebpf::map_setting::add_expose_port(client_port);
    let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), client_port);

    let socket2 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    socket2.set_reuse_address(true).unwrap();
    socket2.set_reuse_port(true).unwrap();
    socket2.bind(&socket_addr.into()).unwrap();
    socket2.set_nonblocking(true).unwrap();
    socket2.bind_device(Some(iface_name.as_bytes())).unwrap();
    socket2.set_broadcast(true).unwrap();

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
                            // println!("Received {} bytes from {}", len, addr);
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

        tracing::info!("DHCP recv client loop");
    });

    service_status.send_replace(DefaultServiceStatus::Running);

    // 超时次数
    let mut timeout_times: u32 = 1;
    // 下一次超时事件
    let mut current_timeout_time = DEFAULT_TIME_OUT;

    let mut active_send = Box::pin(tokio::time::sleep(Duration::from_secs(0)));

    let mut status = IpV6PdState::init_status();
    loop {
        let mut service_status_subscribe = service_status.subscribe();
        tokio::select! {
            // 超时激发重发
            _ = active_send.as_mut() => {
                if timeout_times > 4 {
                    if matches!(status, IpV6PdState::Solicit { .. }) {
                        break;
                    } else {
                        timeout_times = 1;
                        current_timeout_time = DEFAULT_TIME_OUT;
                        status = IpV6PdState::init_status();
                    }
                }
                send_current_status_packet(&client_id, &send_socket, &mut status).await;
                active_send.as_mut().set(tokio::time::sleep(Duration::from_secs(current_timeout_time.pow(timeout_times))));
                timeout_times += 1;
            },
            message_result = message_rx.recv() => {
                // 处理接收到的数据包
                match message_result {
                    Some(data) => {
                        let need_reset_time = handle_packet(&client_id, &mut status, data, ).await;
                        if need_reset_time {
                            let (t1, t2) = get_status_timeout_config(&status);
                            timeout_times = t1;
                            current_timeout_time = t2;
                            active_send.as_mut().set(tokio::time::sleep(Duration::from_secs(current_timeout_time.pow(timeout_times))));
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
                let current_status = &*service_status_subscribe.borrow();
                match current_status {
                    DefaultServiceStatus::Stopping| DefaultServiceStatus::Stop {..} => {
                        tracing::error!("stop exit");
                        break;
                    },
                    _ => {}
                }
            }
        }
    }
    tracing::info!("exit dhcpv6 loop");
    // TODO: 检查是不是 Stop
    service_status.send_replace(DefaultServiceStatus::Stop { message: None });
}

async fn send_current_status_packet(
    my_client_id: &[u8],
    send_socket: &UdpSocket,
    current_status: &mut IpV6PdState,
) {
    match current_status {
        IpV6PdState::Solicit { xid } => {
            let mut msg = v6::Message::new(v6::MessageType::Solicit);
            msg.set_opts(get_solicit_options());
            msg.set_xid_num(xid.clone());
            msg.opts_mut().insert(v6::DhcpOption::ClientId(my_client_id.to_vec()));

            let mut buf = Vec::new();
            let mut e = Encoder::new(&mut buf);
            if let Err(e) = msg.encode(&mut e) {
                tracing::error!("msg encode error: {e:?}");
                return;
            }
            match send_socket
                .send_to(
                    &buf,
                    &SocketAddr::new(
                        IpAddr::V6(DHCPV6_MULTICAST),
                        LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT,
                    ),
                )
                .await
            {
                Ok(len) => {
                    tracing::debug!("send len: {:?}", len);
                    tracing::debug!("dhcp fram: {:#?}", msg);
                }
                Err(e) => {
                    tracing::error!("error: {:?}", e);
                }
            }
        }
        // IpV6PdState::Advertise { xid } => todo!(),
        IpV6PdState::Request { xid, msg, service_id } => todo!(),
        IpV6PdState::Bound { xid, msg, service_id, iapd } => todo!(),
        IpV6PdState::Confirm => todo!(),
        IpV6PdState::Renew { xid, msg, service_id } => todo!(),
        IpV6PdState::Rebind { xid, msg, service_id } => todo!(),
        IpV6PdState::Release => todo!(),
        IpV6PdState::Decline => todo!(),
        IpV6PdState::Stopping => todo!(),
        IpV6PdState::Stop => todo!(),
    }
}

fn get_status_timeout_config(current_status: &IpV6PdState) -> (u32, u64) {
    match current_status {
        IpV6PdState::Bound { xid, msg, service_id, iapd } => todo!(),
        _ => (1, DEFAULT_TIME_OUT),
    }
}
// 处理接收到的报文，根据当前状态决定如何处理
async fn handle_packet(
    my_client_id: &[u8],
    current_status: &mut IpV6PdState,
    (msg, _msg_addr): (Vec<u8>, SocketAddr),
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

    if let Some(v6::DhcpOption::ClientId(client_id)) = new_v6_msg.opts().get(OptionCode::ClientId) {
        // 比较 client id
        if my_client_id != client_id {
            return false;
        }
    }
    if !current_status.can_handle_message(&new_v6_msg.msg_type()) {
        tracing::error!("self: {current_status:?}");
        tracing::error!("dhcp: {msg:?}");
        tracing::error!("current status can not handle this status");
        return false;
    }
    match current_status.clone() {
        IpV6PdState::Solicit { xid, .. } => {
            // REMOVE
            // *current_status = IpV6PdState::Advertise { xid };

            let mut my_service_id = vec![];
            let mut has_iapd = false;

            if let Some(v6::DhcpOption::ClientId(service_id)) =
                new_v6_msg.opts().get(OptionCode::ServerId)
            {
                my_service_id = service_id.clone();
            }

            if let Some(v6::DhcpOption::IAPD(_)) = new_v6_msg.opts().get(OptionCode::IAPD) {
                has_iapd = true;
            }

            if !my_service_id.is_empty() && has_iapd {
                let xid = rand::random();
                *current_status =
                    IpV6PdState::Request { xid, msg: new_v6_msg, service_id: my_service_id };
            } else {
                *current_status = IpV6PdState::Solicit { xid };
            }
        }
        IpV6PdState::Request { msg, service_id, .. }
        | IpV6PdState::Renew { msg, service_id, .. }
        | IpV6PdState::Rebind { msg, service_id, .. } => {
            match new_v6_msg.msg_type() {
                V6MessageType::Reply => {
                    if let Some(v6::DhcpOption::ClientId(new_service_id)) =
                        new_v6_msg.opts().get(OptionCode::ServerId)
                    {
                        if &service_id != new_service_id {
                            return false;
                        }
                    }

                    if let Some(v6::DhcpOption::IAPD(iapd)) =
                        new_v6_msg.opts().get(OptionCode::IAPD)
                    {
                        let mut success = true;
                        for opt in iapd.opts.iter() {
                            match opt {
                                DhcpOption::StatusCode(code) => {
                                    if matches!(code.status, v6::Status::Success) {
                                        success = true;
                                    } else {
                                        success = false;
                                        tracing::error!(
                                            "cueernt_status {:#?}, replay error: {:?}",
                                            current_status,
                                            new_v6_msg
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                        if success {
                            // 这个 ID 是下次 Renewing 的时候使用
                            let xid = rand::random();
                            *current_status =
                                IpV6PdState::Bound { xid, msg, service_id, iapd: iapd.clone() };
                        } else {
                        }
                    }
                }
                _ => {}
            }
        }
        IpV6PdState::Stopping => {}
        IpV6PdState::Stop => {}
        _ => {}
    }

    false
}

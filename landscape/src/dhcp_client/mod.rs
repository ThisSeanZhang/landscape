use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    dump::udp_packet::dhcp::{options::DhcpOptionMessageType, DhcpOptionFrame},
    service::ServiceStatus,
};
use socket2::{Domain, Protocol, Type};
use tokio::{net::UdpSocket, sync::watch};

use crate::{
    dump::udp_packet::dhcp::{options::DhcpOptions, DhcpEthFrame},
    macaddr::MacAddr,
};

const DEFAULT_TIME_OUT: u64 = 4;

#[derive(Clone, Debug)]
pub enum DhcpState {
    /// 控制发送线程发送 discover
    Discovering {
        /// 为会话 ID
        xid: u32,
        /// 初始的 IPV4 地址
        ciaddr: Option<Ipv4Addr>,
    },
    /// 发送线程停止发送 进入等待 changed 的状态
    Offer {
        xid: u32,
    },
    /// 控制发送线程发送 request
    /// TODO 端口号可能也要保存
    Requesting {
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpOptionFrame,
    },
    /// 获得了 服务端的响应, 但是可能是 AKC 或者 ANK, 但是停止发送 Request 或者 Renew 请求
    Bound {
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpOptionFrame,
    },
    /// 客户端发起
    Renewing {
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpOptionFrame,
        rebinding_time: Instant,
    },
    Stopping,
    Stop,
}

impl DhcpState {
    pub fn init_status(renew_ip: Option<Ipv4Addr>) -> DhcpState {
        DhcpState::Discovering { ciaddr: renew_ip, xid: rand::random() }
    }

    pub fn get_xid(&self) -> u32 {
        match self {
            DhcpState::Discovering { xid, .. } => xid.clone(),
            DhcpState::Offer { xid, .. } => xid.clone(),
            DhcpState::Requesting { xid, .. } => xid.clone(),
            DhcpState::Bound { xid, .. } => xid.clone(),
            DhcpState::Renewing { xid, .. } => xid.clone(),
            DhcpState::Stopping => 0,
            DhcpState::Stop => 0,
        }
    }
}

impl DhcpState {
    pub fn can_handle_message(&self, message_type: &DhcpOptionMessageType) -> bool {
        match self {
            DhcpState::Discovering { .. } => matches!(message_type, DhcpOptionMessageType::Offer),
            DhcpState::Offer { .. } => matches!(message_type, DhcpOptionMessageType::Request),
            DhcpState::Requesting { .. } => {
                matches!(message_type, DhcpOptionMessageType::Ack | DhcpOptionMessageType::Nak)
            }
            DhcpState::Renewing { .. } => {
                matches!(message_type, DhcpOptionMessageType::Ack | DhcpOptionMessageType::Nak)
            }
            _ => false,
        }
    }
    pub fn is_stopping(&self) -> bool {
        match self {
            DhcpState::Stopping => true,
            _ => false,
        }
    }
}

pub async fn dhcp_client(
    index: u32,
    iface_name: String,
    mac_addr: MacAddr,
    client_port: u16,
    service_status: watch::Sender<ServiceStatus>,
    hostname: String,
    default_router: bool,
) {
    service_status.send_replace(ServiceStatus::Staring);
    landscape_ebpf::map_setting::add_expose_port(client_port);
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), client_port);

    let socket2 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    // TODO: Error handle
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

    let (status_tx, mut status_rx) = watch::channel::<DhcpState>(DhcpState::init_status(None));
    // 处理接收循环
    let status_tx_status = status_tx.clone();
    let mut hdcp_rx_status = status_rx.clone();
    tokio::task::spawn(async move {
        //
        loop {
            // let state_end_loop = hdcp_rx_status.wait_for(|status| status.is_stopping());
            tokio::select! {
                change_result = hdcp_rx_status.changed() => {
                    if let Err(_) = change_result {
                        tracing::error!("get change result error. exit loop");
                        break;
                    }
                    let current_status = &*hdcp_rx_status.borrow();
                    match current_status {
                        DhcpState::Stopping| DhcpState::Stop => {
                            tracing::error!("stop exit");
                            break;
                        },
                        _ => {}
                    }
                },
                message = message_rx.recv() => {
                    if let Some(msg) = message {
                        handle_packet(&status_tx_status, msg).await;
                    } else {
                        break;
                    }
                }
            }
        }
    });

    // 处理发送循环
    let status_tx_status = status_tx.clone();
    let service_status_clone = service_status.clone();
    tokio::task::spawn(async move {
        let service_status = service_status_clone;
        let mut timeout_times: u32 = 0;
        let mut current_timeout_time = DEFAULT_TIME_OUT;

        let times_limit_send = TimeoutModel::new(|times: u32| times >= 3);
        let times_ulimit_send = TimeoutModel::new(|_: u32| false);

        let mut current_model = &times_limit_send;

        let mut ip_arg: Option<Vec<String>> = None;
        //
        loop {
            let wait_change = tokio::time::timeout(
                Duration::from_secs(current_timeout_time),
                status_rx.changed(),
            );
            match wait_change.await {
                Ok(Err(_)) => {
                    tracing::error!("watch 的另外一端丢弃了");
                    // 退出
                    break;
                }
                Ok(Ok(_)) => {
                    current_timeout_time = DEFAULT_TIME_OUT;
                    timeout_times = 0;
                }
                Err(_) => {
                    // 超时了
                    current_timeout_time *= 2;
                    timeout_times += 1;
                    if current_model.check(timeout_times) {
                        break;
                    }
                }
            }

            let current_dhcp_client_status = (*status_rx.borrow()).clone();
            match current_dhcp_client_status {
                DhcpState::Discovering { ciaddr, xid } => {
                    // send
                    current_model = &times_limit_send;

                    let dhcp_discover = crate::dump::udp_packet::dhcp::gen_discover(
                        xid,
                        mac_addr,
                        ciaddr,
                        hostname.clone(),
                    );

                    match send_socket
                        .send_to(
                            &dhcp_discover.convert_to_payload(),
                            &SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 67),
                        )
                        .await
                    {
                        Ok(len) => {
                            tracing::debug!("send len: {:?}", len);
                            tracing::debug!("dhcp fram: {:#?}", dhcp_discover);
                        }
                        Err(e) => {
                            tracing::error!("error: {:?}", e);
                        }
                    }
                }
                DhcpState::Offer { .. } => {
                    // 进行轮空
                    current_timeout_time = Duration::MAX.as_secs();
                }
                DhcpState::Requesting { xid, ciaddr, yiaddr, mut options, .. } => {
                    current_model = &times_ulimit_send;
                    if let Some(DhcpOptions::AddressLeaseTime(time)) = options.has_option(51) {
                        options.modify_option(DhcpOptions::AddressLeaseTime(time));
                    }

                    // if let Some(DhcpOptions::AddressLeaseTime(time)) = options.has_option(51); {
                    //     options.modify_option(DhcpOptions::AddressLeaseTime(20));
                    // }
                    // send request
                    let dhcp_discover = crate::dump::udp_packet::dhcp::gen_request(
                        xid, mac_addr, ciaddr, yiaddr, options,
                    );

                    match send_socket
                        .send_to(
                            &dhcp_discover.convert_to_payload(),
                            &SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 67),
                        )
                        .await
                    {
                        Ok(len) => {
                            tracing::debug!("send len: {:?}", len);
                            tracing::debug!("dhcp fram: {:#?}", dhcp_discover);
                        }
                        Err(e) => {
                            tracing::error!("error: {:?}", e);
                        }
                    }

                    if timeout_times > 4 {
                        status_tx_status.send(DhcpState::init_status(None)).unwrap();
                    }
                }
                DhcpState::Bound { xid, ciaddr, yiaddr, siaddr, options } => {
                    // 进行一个等待, 等待到租期时间到 70% 后 将当前的状态设置为 Renewing 以便进行续期

                    tracing::info!(
                        "start Bound ip: {} {} {} {:?}",
                        ciaddr,
                        yiaddr,
                        siaddr,
                        options
                    );
                    let Some((renew_time, rebinding_time)) = options.get_renew_time() else {
                        continue;
                    };
                    let sleep_time = tokio::time::Instant::now() + Duration::from_secs(renew_time);

                    let mask = if let Some(DhcpOptions::SubnetMask(mask)) = options.has_option(1) {
                        mask.to_bits().count_ones()
                    } else {
                        24
                    };
                    tracing::info!("setting ip: {} {} {} {:?}", ciaddr, yiaddr, siaddr, options);
                    landscape_ebpf::map_setting::add_wan_ip(index, yiaddr.clone());
                    if let Some(args) = ip_arg.take() {
                        if let Err(result) = std::process::Command::new("ip").args(&args).output() {
                            tracing::error!("{:?}", result);
                        }
                    }
                    let mut args =
                        vec!["addr".to_string(), "add".to_string(), format!("{}/{}", yiaddr, mask)];

                    if let Some(DhcpOptions::BroadcastAddr(broadcast)) = options.has_option(28) {
                        args.extend(["brd".to_string(), format!("{}", broadcast)]);
                    }
                    args.extend(["dev".to_string(), iface_name.clone()]);

                    tracing::info!("{:?}", args);
                    let result = std::process::Command::new("ip").args(&args).output();
                    if let Err(e) = result {
                        tracing::error!("{:?}", e);
                    } else {
                        if let Some(value) = args.get_mut(1) {
                            *value = "del".to_string();
                        }
                        ip_arg = Some(args);
                    }

                    if default_router {
                        if let Some(DhcpOptions::Router(router_ip)) = options.has_option(3) {
                            let _ = std::process::Command::new("ip")
                                .args(&[
                                    "route",
                                    "replace",
                                    "default",
                                    "via",
                                    &format!("{}", router_ip),
                                    "dev",
                                    &iface_name,
                                ])
                                .output();
                        }
                    }

                    let rebinding_time = Instant::now() + Duration::from_secs(rebinding_time);
                    // 进行等待超时
                    tokio::select! {
                        _ = tokio::time::sleep_until(sleep_time) => {
                            tracing::error!("Time to renew lease, switching to Renewing...");
                            status_tx_status.send(DhcpState::Renewing {xid, ciaddr: yiaddr.clone(), yiaddr, siaddr, options, rebinding_time }).unwrap();
                        },
                        _ = status_rx.changed() => {
                        }
                    }
                }
                DhcpState::Renewing {
                    xid,
                    ciaddr,
                    yiaddr,
                    siaddr,
                    options,
                    rebinding_time,
                } => {
                    current_model = &times_ulimit_send;

                    let addr = if siaddr.is_unspecified() {
                        if let Some(DhcpOptions::ServerIdentifier(addr)) = options.has_option(54) {
                            addr
                        } else {
                            Ipv4Addr::BROADCAST
                        }
                    } else {
                        siaddr
                    };

                    let dhcp_discover = crate::dump::udp_packet::dhcp::gen_request(
                        xid, mac_addr, ciaddr, yiaddr, options,
                    );

                    match send_socket
                        .send_to(
                            &dhcp_discover.convert_to_payload(),
                            &SocketAddr::new(IpAddr::V4(addr), 67),
                        )
                        .await
                    {
                        Ok(len) => {
                            tracing::debug!("send len: {:?}", len);
                            // println!("Renewing dhcp: {:?}", dhcp_discover);
                        }
                        Err(e) => {
                            tracing::error!("error: {:?}", e);
                        }
                    }

                    if Instant::now() >= rebinding_time {
                        // 超过租期的最后期限 尝试获得新的 DHCP 响应
                        status_tx_status.send(DhcpState::init_status(None)).unwrap();
                    }
                }
                DhcpState::Stopping | DhcpState::Stop => {
                    if let Some(args) = ip_arg.take() {
                        let result = std::process::Command::new("ip").args(&args).output();
                        tracing::info!("{:?}", result);
                    }
                    status_tx_status.send(DhcpState::Stop).unwrap();
                    tracing::info!("stop dhcp client");
                    break;
                }
            }
        }

        service_status.send_replace(ServiceStatus::Stop { message: None });
        tracing::info!("dhcp message send loop exit");
    });

    service_status.send_replace(ServiceStatus::Running);

    let mut status_rx = status_tx.subscribe();
    let mut service_status_rx = service_status.subscribe();
    loop {
        tokio::select! {
            change_result = status_rx.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }
                let current_status = status_rx.borrow().clone();
                if matches!(current_status, DhcpState::Stopping) {
                    break;
                }
            },
            change_result = service_status_rx.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }
                let current_status = service_status_rx.borrow().clone();
                if matches!(current_status, ServiceStatus::Stopping) {
                    status_tx.send_replace(DhcpState::Stopping);
                    break;
                }
            }
        }
    }
}

// 处理接收到的报文，根据当前状态决定如何处理
async fn handle_packet(status: &watch::Sender<DhcpState>, (msg, _msg_addr): (Vec<u8>, SocketAddr)) {
    let dhcp = DhcpEthFrame::new(&msg);
    let Some(dhcp) = dhcp else {
        tracing::error!("handle message error");
        return;
    };
    // println!("dhcp: {dhcp:?}");
    if dhcp.op != 2 {
        tracing::error!("is not server op");
        return;
    }

    // let current_client_status_rx = ;
    let current_client_status = status.subscribe().borrow().clone();
    if dhcp.xid != current_client_status.get_xid() {
        return;
    }
    if !current_client_status.can_handle_message(&dhcp.options.message_type) {
        tracing::error!("self: {current_client_status:?}");
        tracing::error!("dhcp: {dhcp:?}");
        tracing::error!("current status can not handle this status");
        return;
    }
    match current_client_status {
        DhcpState::Discovering { xid, .. } => {
            // drop(current_client_status);
            status.send_replace(DhcpState::Offer { xid });
            let ciaddr = dhcp.ciaddr;
            let yiaddr = dhcp.yiaddr;
            let siaddr = dhcp.siaddr;

            let options = dhcp.options;
            // TODO: 判断是否符合, 不符合退回 Discovering 状态
            status.send_replace(DhcpState::Requesting { xid, ciaddr, yiaddr, siaddr, options });
        }
        DhcpState::Requesting { yiaddr, .. } | DhcpState::Renewing { yiaddr, .. } => {
            match dhcp.options.message_type {
                DhcpOptionMessageType::Ack => {
                    if dhcp.yiaddr == yiaddr {
                        // 成功获得 IP
                        let new_ciaddr = dhcp.ciaddr;
                        let new_yiaddr = dhcp.yiaddr;
                        let new_siaddr = dhcp.siaddr;

                        let options = dhcp.options;
                        tracing::debug!("get bound ip, {:?}", yiaddr);

                        // 这个 ID 是下次 Renewing 的时候使用
                        let xid = rand::random();
                        status.send_replace(DhcpState::Bound {
                            xid,
                            ciaddr: new_ciaddr,
                            yiaddr: new_yiaddr,
                            siaddr: new_siaddr,
                            options,
                        });
                    } else {
                        tracing::error!("IP 地址不符合")
                    }
                }
                DhcpOptionMessageType::Nak => {
                    // 获取 ip 失败 重新进入 discover
                    let _ = status.send(DhcpState::init_status(None));
                }
                _ => {}
            }
        }
        DhcpState::Stopping => {}
        DhcpState::Stop => {}
        _ => {}
    }
}

struct TimeoutModel {
    limit_check: Box<dyn Fn(u32) -> bool + Send + Sync>,
}

impl TimeoutModel {
    fn new<F>(check: F) -> Self
    where
        F: Fn(u32) -> bool + Send + Sync + 'static,
    {
        TimeoutModel { limit_check: Box::new(check) }
    }

    fn check(&self, times: u32) -> bool {
        (self.limit_check)(times)
    }
}

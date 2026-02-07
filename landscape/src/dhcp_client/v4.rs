use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use socket2::{Domain, Protocol, Type};
use tokio::{net::UdpSocket, time::Instant};

use crate::route::IpRouteService;
use bytes::BytesMut;
use landscape_common::{
    global_const::default_router::{RouteInfo, RouteType, LD_ALL_ROUTERS},
    net::MacAddr,
    net_proto::{
        dhcp::{
            DhcpV4Flags, DhcpV4Message, DhcpV4MessageType as MessageType, DhcpV4OpCode,
            DhcpV4Option as DhcpOption, DhcpV4OptionCode as OptionCode, DhcpV4Options,
        },
        NetProtoCodec,
    },
    route::RouteTargetInfo,
    route::{LanRouteInfo, LanRouteMode},
    service::{DefaultWatchServiceStatus, ServiceStatus},
    SYSCTL_IPV4_RP_FILTER_PATTERN,
};

pub const DEFAULT_TIME_OUT: u64 = 4;

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
    // Offer {
    //     xid: u32,
    // },
    /// 控制发送线程发送 request
    /// TODO 端口号可能也要保存
    Requesting {
        xid: u32,
        send_times: u8,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpV4Options,
    },
    /// 获得了 服务端的响应, 但是可能是 AKC 或者 ANK, 但是停止发送 Request 或者 Renew 请求
    Bound {
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpV4Options,
        // 对 IP 进行续期的时间
        renew_time: Instant,
        // 对 IP 进行重新绑定
        rebinding_time: Instant,
        // 租期到期，重新获取
        lease_time: Instant,
    },
    /// 客户端发起
    Renewing {
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpV4Options,
        // 对 IP 进行续期的时间
        renew_time: Instant,
        // 对 IP 进行重新绑定
        rebinding_time: Instant,
        // 租期到期，重新获取
        lease_time: Instant,
    },
    WaitToRebind {
        // 用于在 WaitToRebind 是也可确认 Renew 最后一次发送的数据包
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpV4Options,
        // 对 IP 进行重新绑定
        rebinding_time: Instant,
        // 租期到期，重新获取
        lease_time: Instant,
    },
    Rebind {
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: DhcpV4Options,
        // 租期到期，重新获取
        lease_time: Instant,
    },
    Stopping,
    Stop,
}

fn get_new_ipv4_xid() -> u32 {
    rand::random()
}

impl DhcpState {
    pub fn init_status(renew_ip: Option<Ipv4Addr>) -> DhcpState {
        DhcpState::Discovering { ciaddr: renew_ip, xid: get_new_ipv4_xid() }
    }

    pub fn get_xid(&self) -> u32 {
        match self {
            DhcpState::Discovering { xid, .. } => xid.clone(),
            // DhcpState::Offer { xid, .. } => xid.clone(),
            DhcpState::Requesting { xid, .. } => xid.clone(),
            DhcpState::Bound { xid, .. } => xid.clone(),
            DhcpState::Renewing { xid, .. } => xid.clone(),
            DhcpState::WaitToRebind { xid, .. } => xid.clone(),
            DhcpState::Rebind { xid, .. } => xid.clone(),
            DhcpState::Stopping => 0,
            DhcpState::Stop => 0,
        }
    }

    pub fn can_handle_message(&self, message_type: &MessageType) -> bool {
        match self {
            DhcpState::Discovering { .. } => matches!(message_type, MessageType::Offer),
            // DhcpState::Offer { .. } => matches!(message_type, DhcpOptionMessageType::Request),
            DhcpState::Requesting { .. } => {
                matches!(message_type, MessageType::Ack | MessageType::Nak)
            }
            DhcpState::Renewing { .. } => {
                matches!(message_type, MessageType::Ack | MessageType::Nak)
            }
            DhcpState::Rebind { .. } => {
                matches!(message_type, MessageType::Ack | MessageType::Nak)
            }
            DhcpState::WaitToRebind { .. } => {
                matches!(message_type, MessageType::Ack | MessageType::Nak)
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

#[tracing::instrument(skip(
    ifindex,
    mac_addr,
    client_port,
    service_status,
    hostname,
    route_service
))]
pub async fn dhcp_v4_client(
    ifindex: u32,
    iface_name: String,
    mac_addr: MacAddr,
    client_port: u16,
    service_status: DefaultWatchServiceStatus,
    hostname: String,
    default_router: bool,
    route_service: IpRouteService,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    // landscape_ebpf::map_setting::add_expose_port(client_port);

    tracing::info!("DHCP V4 Client Staring");

    set_iface_ipv4_rp_filter_to_0(&iface_name);

    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), client_port);

    let socket2 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    // TODO: Error handle
    socket2.set_reuse_address(true).unwrap();
    socket2.set_reuse_port(true).unwrap();
    socket2.bind(&socket_addr.into()).unwrap();
    socket2.set_nonblocking(true).unwrap();
    socket2.bind_device(Some(iface_name.as_bytes())).unwrap();
    socket2.set_broadcast(true).unwrap();

    // let router_iface_name = iface_name.clone();

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

        tracing::info!("DHCP V4 recv client loop");
    });

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("DHCP V4 Client Running");

    // 超时次数
    let mut timeout_times: u64 = 1;
    // 下一次超时事件
    // let mut current_timeout_time = IPV6_TIMEOUT_DEFAULT_DURACTION;

    let mut active_send = Box::pin(tokio::time::sleep(Duration::from_secs(0)));

    let mut status = DhcpState::init_status(None);
    #[cfg(debug_assertions)]
    let time = tokio::time::Instant::now();

    let mut ip_arg: Option<Vec<String>> = None;

    let mut service_status_subscribe = service_status.subscribe();
    loop {
        tokio::select! {
            // 超时激发重发
            _ = active_send.as_mut() => {
                #[cfg(debug_assertions)]
                {
                    tracing::error!("Timeout active at: {:?}",  time.elapsed());
                }
                if timeout_times > 4 {
                    // 如果当前状态是 Discovering 并且 超时 4 次 就退出
                    if matches!(status, DhcpState::Discovering { .. }) {
                        tracing::error!("Timeout exceeded limit");
                        break;
                    }
                }

                let need_reset_timeout = send_current_status_packet(
                    mac_addr, &send_socket, &mut status, &hostname
                ).await;
                if need_reset_timeout {
                    timeout_times = 0;
                }
                timeout_times = get_status_timeout_config(&status, timeout_times, active_send.as_mut());
            },
            message_result = message_rx.recv() => {
                // 处理接收到的数据包
                match message_result {
                    Some(data) => {
                        let need_reset_time =
                            handle_packet(&mut status, data,
                            &mut ip_arg, default_router, &iface_name, ifindex, &route_service, &mac_addr).await;
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
                if service_status.is_exit() {
                    // 1. send release

                    // 2. clean route
                    if let Some(args) = ip_arg.take() {
                        let result = std::process::Command::new("ip").args(&args).output();
                        tracing::info!("{:?}", result);
                    }
                    tracing::info!("dhcp release send and stop");
                    break;
                }
            }
        }
    }
    tracing::info!("DHCPv4 Client Stop: {:#?}", service_status);

    if default_router {
        LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
    }
    route_service.remove_ipv4_wan_route(&iface_name).await;
    route_service.remove_ipv4_lan_route(&iface_name).await;

    if !service_status.is_stop() {
        service_status.just_change_status(ServiceStatus::Stop);
    }
}

/// 处理当前状态应该发送什么数据包
/// 当需要重置 timeout 就返回 true
async fn send_current_status_packet(
    mac_addr: MacAddr,
    send_socket: &UdpSocket,
    current_status: &mut DhcpState,
    hostname: &str,
) -> bool {
    let mut buf = BytesMut::new();
    match current_status {
        DhcpState::Discovering { ciaddr, xid } => {
            let dhcp_discover = gen_discover(*xid, mac_addr, *ciaddr, hostname.to_string());

            if let Ok(_) = dhcp_discover.encode(&mut buf) {
                match send_socket
                    .send_to(&buf, &SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 67))
                    .await
                {
                    Ok(len) => {
                        tracing::debug!("send len: {:?}", len);
                        tracing::debug!("dhcp fram: {:?}", dhcp_discover);
                    }
                    Err(e) => {
                        tracing::error!("error: {:?}", e);
                    }
                }
            }
        }
        // DhcpState::Offer { .. } => {}
        DhcpState::Requesting { xid, send_times, ciaddr, yiaddr, options, .. } => {
            *send_times += 1;
            if *send_times > 3 {
                *current_status = DhcpState::init_status(None);
                return true;
            }

            // send request
            let dhcp_request =
                gen_request(*xid, mac_addr, *ciaddr, *yiaddr, options.clone(), hostname);

            if let Ok(_) = dhcp_request.encode(&mut buf) {
                match send_socket
                    .send_to(&buf, &SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 67))
                    .await
                {
                    Ok(len) => {
                        tracing::debug!("send len: {:?}", len);
                        tracing::debug!("dhcp fram: {:?}", dhcp_request);
                    }
                    Err(e) => {
                        tracing::error!("error: {:?}", e);
                    }
                }
            }
        }
        DhcpState::Bound {
            yiaddr,
            siaddr,
            options,
            renew_time,
            rebinding_time,
            lease_time,
            ..
        } => {
            *current_status = DhcpState::Renewing {
                xid: get_new_ipv4_xid(),
                ciaddr: yiaddr.clone(),
                yiaddr: Ipv4Addr::UNSPECIFIED,
                siaddr: *siaddr,
                options: options.clone(),
                renew_time: *renew_time,
                rebinding_time: *rebinding_time,
                lease_time: *lease_time,
            };
            return true;
        }
        DhcpState::Renewing {
            xid,
            ciaddr,
            yiaddr,
            siaddr,
            options,
            renew_time,
            rebinding_time,
            lease_time,
            ..
        } => {
            tracing::error!("Time to renew lease, Renewing Strat...");
            let addr = if siaddr.is_unspecified() {
                if let Some(DhcpOption::ServerIdentifier(addr)) =
                    options.get(OptionCode::ServerIdentifier)
                {
                    *addr
                } else {
                    Ipv4Addr::BROADCAST
                }
            } else {
                *siaddr
            };

            let mut request_options = DhcpV4Options::default();
            request_options.insert(DhcpOption::MessageType(MessageType::Request));
            request_options.insert(DhcpOption::Hostname(hostname.to_string()));

            let dhcp_renew =
                gen_request(*xid, mac_addr, *ciaddr, *yiaddr, request_options, hostname);

            if let Ok(_) = dhcp_renew.encode(&mut buf) {
                match send_socket.send_to(&buf, &SocketAddr::new(IpAddr::V4(addr), 67)).await {
                    Ok(len) => {
                        tracing::debug!("send len: {:?}", len);
                        // println!("Renewing dhcp: {:?}", dhcp_discover);
                    }
                    Err(e) => {
                        tracing::error!("error: {:?}", e);
                    }
                }
            }

            let lease_renew_time = (*rebinding_time - *renew_time).as_secs() / 6;

            if Instant::now() >= *rebinding_time - Duration::from_secs(lease_renew_time) {
                // 超过租期的最后期限 尝试获得新的 DHCP 响应
                *current_status = DhcpState::WaitToRebind {
                    xid: get_new_ipv4_xid(),
                    ciaddr: *ciaddr,
                    yiaddr: *yiaddr,
                    siaddr: *siaddr,
                    options: options.clone(),
                    rebinding_time: *rebinding_time,
                    lease_time: *lease_time,
                };
                return true;
            }
        }
        DhcpState::WaitToRebind { yiaddr, siaddr, options, lease_time, .. } => {
            *current_status = DhcpState::Rebind {
                xid: get_new_ipv4_xid(),
                ciaddr: yiaddr.clone(),
                yiaddr: Ipv4Addr::UNSPECIFIED,
                siaddr: *siaddr,
                options: options.clone(),
                lease_time: *lease_time,
            };
            return true;
        }
        DhcpState::Rebind { lease_time, .. } => {
            if Instant::now() > *lease_time {
                tracing::warn!("Rebind turn to Discover");
                // 切换状态为 Solicit 重新开始
                *current_status = DhcpState::init_status(None);
                return true;
            }
        }
        DhcpState::Stopping | DhcpState::Stop => {}
    }
    false
}

fn get_status_timeout_config(
    current_status: &DhcpState,
    prev_timeout_times: u64,
    mut timeout: Pin<&mut tokio::time::Sleep>,
) -> u64 {
    let current_timeout_time = match current_status {
        // 绑定后的超时时间是
        DhcpState::Bound { renew_time, .. } => {
            let wait_time = *renew_time - Instant::now();
            let wait_time = wait_time.as_secs();
            tracing::info!("wait {wait_time}s to start renew...");
            wait_time
        }
        // 等待的时间是 t2 - bound_time
        DhcpState::WaitToRebind { rebinding_time, .. } => {
            let wait_time = *rebinding_time - Instant::now();
            let wait_time = wait_time.as_secs();
            tracing::info!("wait {wait_time}s to start rebind...");
            wait_time
        }
        _ => DEFAULT_TIME_OUT * prev_timeout_times,
    };

    timeout.set(tokio::time::sleep(Duration::from_secs(current_timeout_time)));
    prev_timeout_times + 1
}
/// 处理接收到的报文，根据当前状态决定如何处理
/// 返回值为是否要进行检查刷新超时时间
async fn handle_packet(
    current_status: &mut DhcpState,
    (msg, _msg_addr): (Vec<u8>, SocketAddr),

    ip_arg: &mut Option<Vec<String>>,
    default_router: bool,
    iface_name: &str,
    ifindex: u32,
    route_service: &IpRouteService,
    mac_addr: &MacAddr,
) -> bool {
    let mut buf = BytesMut::from(&msg[..]);
    let Ok(Some(dhcp)) = DhcpV4Message::decode(&mut buf) else {
        tracing::error!("handle message error");
        return true;
    };

    if dhcp.opcode() != DhcpV4OpCode::BootReply {
        tracing::error!("is not server op");
        return true;
    }

    if dhcp.xid() != current_status.get_xid() {
        return false;
    }

    let Some(DhcpOption::MessageType(msg_type)) = dhcp.opts().get(OptionCode::MessageType) else {
        return false;
    };

    if !current_status.can_handle_message(&msg_type) {
        tracing::error!("self: {current_status:?}");
        tracing::error!("recv msg: {msg:?}");
        tracing::error!("current status can not handle this status");
        return false;
    }

    tracing::debug!("recv msg: {dhcp:?}");

    match current_status {
        DhcpState::Discovering { xid, .. } => {
            let ciaddr = dhcp.ciaddr();
            let yiaddr = dhcp.yiaddr();
            let siaddr = dhcp.siaddr();

            let options = dhcp.opts().clone();
            // TODO: 判断是否符合, 不符合退回 Discovering 状态
            *current_status = DhcpState::Requesting {
                send_times: 0,
                xid: *xid,
                ciaddr,
                yiaddr,
                siaddr,
                options,
            };

            tracing::debug!("current status move to: {:#?}", current_status);
            return true;
        }
        DhcpState::Requesting { yiaddr, .. } | DhcpState::Renewing { yiaddr, .. } => {
            match msg_type {
                MessageType::Ack => {
                    if *yiaddr == Ipv4Addr::UNSPECIFIED || dhcp.yiaddr() == *yiaddr {
                        // 成功获得 IP
                        let new_ciaddr = dhcp.ciaddr();
                        let new_yiaddr = dhcp.yiaddr();
                        let new_siaddr = dhcp.siaddr();

                        let options = dhcp.opts().clone();
                        tracing::debug!("get bound ip, {:?}", yiaddr);

                        tracing::info!(
                            "start Bound ip: {} {} {} {:?}",
                            new_ciaddr,
                            new_yiaddr,
                            new_siaddr,
                            options
                        );
                        let Some((renew_time, rebinding_time, lease_time)) =
                            get_renew_times(&options)
                        else {
                            tracing::error!("can not read renew time options");
                            return false;
                        };

                        let Some(DhcpOption::SubnetMask(mask)) =
                            options.get(OptionCode::SubnetMask)
                        else {
                            tracing::error!("can not read mask in options");
                            return false;
                        };

                        let mask = u32::from_be_bytes(mask.octets()).count_ones();

                        *current_status = bind_ipv4(
                            renew_time,
                            rebinding_time,
                            lease_time,
                            mask,
                            new_ciaddr,
                            new_yiaddr,
                            new_siaddr,
                            options,
                            ip_arg,
                            default_router,
                            iface_name,
                            ifindex,
                            route_service,
                            mac_addr,
                        )
                        .await;

                        tracing::debug!("current status move to: {:#?}", current_status);
                        return true;
                    } else {
                        tracing::error!(
                            "IP 地址不符合: new ip: {:?}, old ip: {:?}",
                            dhcp.yiaddr(),
                            *yiaddr
                        )
                    }
                }
                MessageType::Nak => {
                    // 获取 ip 失败 重新进入 discover
                    *current_status = DhcpState::init_status(None);
                    return true;
                }
                _ => {}
            }
        }
        _ => {}
    }

    false
}

async fn bind_ipv4(
    renew_time: u64,
    rebinding_time: u64,
    lease_time: u64,
    mask: u32,
    new_ciaddr: Ipv4Addr,
    new_yiaddr: Ipv4Addr,
    new_siaddr: Ipv4Addr,
    options: DhcpV4Options,
    // TODO： 应该放在一个结构体中
    ip_arg: &mut Option<Vec<String>>,
    default_router: bool,
    iface_name: &str,
    ifindex: u32,
    route_service: &IpRouteService,
    mac_addr: &MacAddr,
) -> DhcpState {
    if let Some(args) = ip_arg.take() {
        if let Err(result) = std::process::Command::new("ip").args(&args).output() {
            tracing::error!("{:?}", result);
        }
    }
    let mut args =
        vec!["addr".to_string(), "replace".to_string(), format!("{}/{}", new_yiaddr, mask)];

    if let Some(DhcpOption::BroadcastAddr(broadcast)) = options.get(OptionCode::BroadcastAddr) {
        args.extend(["brd".to_string(), format!("{}", broadcast)]);
    }
    args.extend([
        "dev".to_string(),
        iface_name.to_string(),
        "valid_lft".to_string(),
        format!("{}", lease_time),
        "preferred_lft".to_string(),
        format!("{}", renew_time),
    ]);

    tracing::info!("{:?}", args);
    let result = std::process::Command::new("ip").args(&args).output();
    if let Err(e) = result {
        tracing::error!("{:?}", e);
    } else {
        if let Some(value) = args.get_mut(1) {
            *value = "del".to_string();
        }
        *ip_arg = Some(args);
    }

    let lan_info = LanRouteInfo {
        ifindex: ifindex,
        iface_name: iface_name.to_string(),
        iface_ip: IpAddr::V4(new_yiaddr),
        mac: Some(mac_addr.clone()),
        prefix: mask as u8,
        mode: LanRouteMode::Reachable,
    };
    route_service.insert_ipv4_lan_route(&iface_name, lan_info).await;

    let mut gateway_ip = None;
    if let Some(DhcpOption::Router(router_ips)) = options.get(OptionCode::Router) {
        if let Some(router_ip) = router_ips.get(0) {
            gateway_ip = Some(router_ip.clone());
            route_service
                .insert_ipv4_wan_route(
                    &iface_name,
                    RouteTargetInfo {
                        ifindex: ifindex,
                        weight: 1,
                        mac: Some(mac_addr.clone()),
                        is_docker: false,
                        default_route: default_router,
                        iface_name: iface_name.to_string(),
                        iface_ip: IpAddr::V4(new_yiaddr),
                        gateway_ip: IpAddr::V4(router_ip.clone()),
                    },
                )
                .await;
            if default_router {
                LD_ALL_ROUTERS
                    .add_route(RouteInfo {
                        iface_name: iface_name.to_string(),
                        weight: 1,
                        route: RouteType::Ipv4(router_ip.clone()),
                    })
                    .await;
            } else {
                LD_ALL_ROUTERS.del_route_by_iface(iface_name).await;
            }
        }
    }
    landscape_ebpf::map_setting::add_ipv4_wan_ip(
        ifindex,
        new_yiaddr.clone(),
        gateway_ip,
        mask as u8,
        Some(mac_addr.clone()),
    );

    let renew_time = tokio::time::Instant::now() + Duration::from_secs(renew_time);
    let rebinding_time = Instant::now() + Duration::from_secs(rebinding_time);
    let lease_time = Instant::now() + Duration::from_secs(lease_time);
    DhcpState::Bound {
        xid: get_new_ipv4_xid(),
        ciaddr: new_ciaddr,
        yiaddr: new_yiaddr,
        siaddr: new_siaddr,
        options,
        renew_time,
        rebinding_time,
        lease_time,
    }
}

fn set_iface_ipv4_rp_filter_to_0(iface_name: &str) {
    use sysctl::Sysctl;
    if let Ok(ctl) = sysctl::Ctl::new(&SYSCTL_IPV4_RP_FILTER_PATTERN.replace("{}", iface_name)) {
        match ctl.set_value_string("0") {
            Ok(value) => {
                if value != "0" {
                    tracing::error!("modify value error: {:?}", value)
                }
            }
            Err(e) => {
                tracing::error!("err: {e:?}")
            }
        }
    }
}

fn gen_discover(
    xid: u32,
    mac_addr: MacAddr,
    ciaddr: Option<Ipv4Addr>,
    hostname: String,
) -> DhcpV4Message {
    let mut msg = DhcpV4Message::default();
    msg.set_opcode(DhcpV4OpCode::BootRequest);
    msg.set_xid(xid);
    let mut flags = DhcpV4Flags::default();
    if ciaddr.is_none() {
        flags = flags.set_broadcast();
    }
    msg.set_flags(flags);
    msg.set_ciaddr(ciaddr.unwrap_or(Ipv4Addr::UNSPECIFIED));
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac_addr.octets());
    msg.set_chaddr(&chaddr);

    msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Discover));
    if let Some(ip) = ciaddr {
        msg.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
    }
    msg.opts_mut().insert(DhcpOption::Hostname(hostname));
    msg.opts_mut().insert(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::DomainName,
        OptionCode::InterfaceMtu,
        OptionCode::BroadcastAddr,
        OptionCode::Hostname,
        OptionCode::NtpServers,
        OptionCode::AddressLeaseTime,
        OptionCode::DomainSearch,
    ]));
    msg
}

fn gen_request(
    xid: u32,
    mac_addr: MacAddr,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    mut options: DhcpV4Options,
    hostname: &str,
) -> DhcpV4Message {
    let mut msg = DhcpV4Message::default();
    msg.set_opcode(DhcpV4OpCode::BootRequest);
    msg.set_xid(xid);

    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac_addr.octets());
    msg.set_chaddr(&chaddr);

    msg.set_ciaddr(ciaddr);

    options.insert(DhcpOption::ClassIdentifier(b"MSFT 5.0".to_vec()));
    let mut client_id = vec![1u8];
    client_id.extend_from_slice(&mac_addr.octets());
    options.insert(DhcpOption::ClientIdentifier(client_id));

    options.insert(DhcpOption::MessageType(MessageType::Request));
    options.insert(DhcpOption::Hostname(hostname.to_string()));
    options.insert(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::DomainName,
        OptionCode::InterfaceMtu,
        OptionCode::BroadcastAddr,
        OptionCode::Hostname,
        OptionCode::NtpServers,
        OptionCode::AddressLeaseTime,
        OptionCode::DomainSearch,
    ]));

    if ciaddr.is_unspecified() {
        options.insert(DhcpOption::RequestedIpAddress(yiaddr));
        msg.set_flags(DhcpV4Flags::default().set_broadcast());
    } else {
        msg.set_flags(DhcpV4Flags::default());
    }

    *msg.opts_mut() = options;
    msg
}

fn get_renew_times(options: &DhcpV4Options) -> Option<(u64, u64, u64)> {
    let lease_time = match options.get(OptionCode::AddressLeaseTime)? {
        DhcpOption::AddressLeaseTime(t) => *t,
        _ => return None,
    };
    let renew_time = match options.get(OptionCode::Renewal) {
        Some(DhcpOption::Renewal(t)) => *t as u64,
        _ => (lease_time / 2) as u64,
    };
    let rebind_time = match options.get(OptionCode::Rebinding) {
        Some(DhcpOption::Rebinding(t)) => *t as u64,
        _ => (lease_time * 7 / 8) as u64,
    };
    Some((renew_time, rebind_time, lease_time as u64))
}

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use landscape_common::net_proto::udp::dhcp::{
    Decodable, Decoder, Encodable, Encoder, get_solicit_options,
    v6::{self, DhcpOption, DhcpOptions, Message, OptionCode},
};

use socket2::{Domain, Protocol, Type};
use tokio::{net::UdpSocket, time::Instant};
use uuid::Uuid;

use crate::{
    netlink::ipv6::{del_iface_ip, set_iface_ip},
    sys_service::route::IpRouteService,
};

use landscape_common::{
    LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT,
    event::hub::IAPrefixEventSender,
    lan_service::lan_ipv6::checked_allocate_subnet,
    service::{ServiceHandle, ServiceStatus},
    utils::time::get_f64_timestamp,
    wan_service::addr_binding::WanAddrBinding,
    wan_service::ipv6_pd::LDIAPrefix,
};
use landscape_common::{
    concurrency::{spawn_task, task_label},
    event::hub::IAPrefixEvent,
    net::MacAddr,
    sys_service::route_service::RouteTargetInfo,
};
use landscape_core::pd_prefix::IAPrefixMap;

pub const IPV6_TIMEOUT_DEFAULT_DURACTION: u64 = 10;
pub const IPV6_TIMEOUT_RENEW_DURACTION: u64 = 10;
pub const IPV6_TIMEOUT_REBIND_DURACTION: u64 = 20;
const MAX_CONNECT_RETRY_BACKOFF_SECS: u64 = 10 * 60;

pub const IPV6_T1_DEFAULT: u64 = 60 * 60 * 12;
pub const IPV6_T2_DEFAULT: u64 = (IPV6_T1_DEFAULT * 8) / 5; // IPV6_T1_DEFAULT * 1.6

static DHCPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2);

fn calc_connect_retry_backoff_secs(failure_count: u32) -> u64 {
    let exp = failure_count.saturating_sub(1).min(31);
    let secs = IPV6_TIMEOUT_DEFAULT_DURACTION.saturating_mul(1u64 << exp);
    secs.min(MAX_CONNECT_RETRY_BACKOFF_SECS)
}

type V6MessageType = landscape_common::net_proto::udp::dhcp::v6::MessageType;
#[derive(Clone, Debug)]
pub enum IpV6PdState {
    /// 初始状态
    Solicit {
        xid: u32,
    },
    /// 发起地址请求
    Request {
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        service_sock: SocketAddr,
        server_unicast: Option<Ipv6Addr>,
        send_times: u8,
    },

    /// 地址激活使用
    Bound {
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        server_unicast: Option<Ipv6Addr>,
        bound_time: Instant,
    },
    /// 确认当前地址状态
    Confirm,
    /// Renew 续订 T1 事件触发
    Renew {
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        server_unicast: Option<Ipv6Addr>,
        renew_time: Instant,
        bound_time: Instant,
    },
    WaitToRebind {
        // 用于在 WaitToRebind 是也可确认 Renew 最后一次发送的数据包
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        server_unicast: Option<Ipv6Addr>,
        bound_time: Instant,
    },
    /// 续订超时
    Rebind {
        xid: u32,
        service_id: Vec<u8>,
        iapd: v6::IAPD,
        server_unicast: Option<Ipv6Addr>,
        rebind_time: Instant,
        bound_time: Instant,
    },
    Release {
        xid: u32,
        service_id: Vec<u8>,
    },
    Decline,
    /// 结束
    Stop,
}

fn get_new_ipv6_xid() -> u32 {
    let mut xid = rand::random();
    xid &= 0x00FFFFFF;
    xid
}
impl IpV6PdState {
    pub fn init_status() -> IpV6PdState {
        IpV6PdState::Solicit { xid: get_new_ipv6_xid() }
    }

    pub fn get_xid(&self) -> u32 {
        match self {
            IpV6PdState::Solicit { xid, .. } => *xid,
            // IpV6PdState::Advertise { xid, .. } => xid.clone(),
            IpV6PdState::Request { xid, .. } => *xid,
            IpV6PdState::Bound { xid, .. } => *xid,
            IpV6PdState::Confirm => todo!(),
            IpV6PdState::Renew { xid, .. } => *xid,
            IpV6PdState::WaitToRebind { xid, .. } => *xid,
            IpV6PdState::Rebind { xid, .. } => *xid,
            IpV6PdState::Release { xid, .. } => *xid,
            IpV6PdState::Decline => todo!(),
            IpV6PdState::Stop => 0,
        }
    }

    pub fn into_release(self) -> Option<(Vec<u8>, v6::IAPD, Option<Ipv6Addr>)> {
        match self {
            IpV6PdState::Solicit { .. } => None,
            IpV6PdState::Request { service_id, iapd, server_unicast, .. }
            | IpV6PdState::Bound { service_id, iapd, server_unicast, .. }
            | IpV6PdState::Renew { service_id, iapd, server_unicast, .. }
            | IpV6PdState::WaitToRebind { service_id, iapd, server_unicast, .. }
            // TODO: simple exit
            | IpV6PdState::Rebind { service_id, iapd, server_unicast, .. } => {
                Some((service_id, iapd, server_unicast))
            }
            IpV6PdState::Confirm => None,
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
                    && service_id == new_service_id
                {
                    return true;
                }
                false
            }
            _ => true,
        }
    }
}

fn gen_client_id(config_mac: MacAddr) -> Vec<u8> {
    let mut result = Vec::with_capacity(10);
    result.extend_from_slice(&[0x00, 0x03, 0x00, 0x01]);
    result.extend_from_slice(&config_mac.octets());
    result
}

fn create_pd_socket(socket_addr: &SocketAddr, iface_name: &[u8]) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    if let Err(err) = socket.set_reuse_port(true) {
        tracing::warn!("set_reuse_port failed (non-fatal): {err:?}");
    }
    socket.bind(&(*socket_addr).into())?;
    socket.set_nonblocking(true)?;
    socket.bind_device(Some(iface_name))?;
    UdpSocket::from_std(socket.into())
}

/// 从 Advertise/Reply 中解析 Server Unicast option(RFC 8415 §21.12)。
/// 仅当服务器通过该 option 显式授权时,客户端才可以单播 Release 等消息。
fn extract_server_unicast(msg: &v6::Message) -> Option<Ipv6Addr> {
    match msg.opts().get(OptionCode::ServerUnicast) {
        Some(DhcpOption::ServerUnicast(addr)) => Some(*addr),
        _ => None,
    }
}

/// Release 的发送目标(RFC 8415 §18.2/§21.12):
/// 服务器授权了 Server Unicast option 时单播到该地址,否则返回 None(组播)。
fn release_target(server_unicast: Option<Ipv6Addr>) -> Option<SocketAddr> {
    server_unicast
        .map(|addr| SocketAddr::new(IpAddr::V6(addr), LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT))
}

/// 构造 Release 消息:回显 ServerId/ClientId,并携带被释放的 IA_PD
/// (RFC 8415 §18.2.7;IA_PD 的 t1/t2 与前缀生命周期清零为惯例做法,
/// RFC 8415 未明文规定;§16.1 Release 属于新事务,使用新的随机 xid)。
/// 若 IA_PD 不含任何 IA_Prefix,则没有可释放的前缀绑定,返回 None。
fn gen_release(client_id: &[u8], service_id: Vec<u8>, iapd: v6::IAPD) -> Option<v6::Message> {
    let mut release_opts = DhcpOptions::new();
    let prefixes = iapd.opts.get_all(OptionCode::IAPrefix)?;
    for prefix in prefixes {
        if let DhcpOption::IAPrefix(mut prefix) = prefix.clone() {
            prefix.preferred_lifetime = 0;
            prefix.valid_lifetime = 0;
            release_opts.insert(DhcpOption::IAPrefix(prefix));
        }
    }
    let release_iapd = v6::IAPD { id: iapd.id, t1: 0, t2: 0, opts: release_opts };

    let mut send_msg = v6::Message::new(V6MessageType::Release);
    send_msg.set_xid_num(get_new_ipv6_xid());
    send_msg.opts_mut().insert(DhcpOption::ServerId(service_id));
    send_msg.opts_mut().insert(DhcpOption::ClientId(client_id.to_vec()));
    send_msg.opts_mut().insert(v6::DhcpOption::ElapsedTime(0));
    send_msg.opts_mut().insert(DhcpOption::IAPD(release_iapd));
    Some(send_msg)
}

#[allow(clippy::too_many_arguments)]
pub async fn dhcp_v6_pd_client(
    link_id: Uuid,
    iface_name: String,
    ifindex: u32,
    // for ebpf map setting
    mac_addr: Option<MacAddr>,
    // for pd request
    config_mac: MacAddr,
    expected_pd_len: u8,
    client_port: u16,
    service_status: ServiceHandle,
    wan_route_info: RouteTargetInfo,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    prefix_map: IAPrefixMap,
    shared_wan_iid: Arc<u64>,
    prefix_sender: IAPrefixEventSender,
) {
    let client_id = gen_client_id(config_mac);
    service_status.just_change_status(ServiceStatus::Staring);

    // if let Err(e) = std::process::Command::new("sysctl")
    //     .args(["-w", &format!("net.ipv6.conf.{}.accept_ra=2", iface_name)])
    //     .output()
    // {
    //     tracing::error!("sysctl cmd exec err: {e:#?}");
    // }

    tracing::info!("DHCP V6 Client Staring");
    // landscape_ebpf::maps::add_expose_port(client_port);
    let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), client_port);

    let socket = match create_pd_socket(&socket_addr, iface_name.as_bytes()) {
        Ok(socket) => socket,
        Err(e) => {
            tracing::error!("failed to create DHCPv6 PD socket on {}: {e:?}", iface_name);
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    let send_socket = Arc::new(socket);

    let recive_socket_raw = send_socket.clone();

    let (message_tx, mut message_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    // 接收数据
    spawn_task(task_label::task::WAN_IPV6PD_CLIENT_RENEW, async move {
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
    let mut connect_failure_count: u32 = 0;
    // 下一次超时事件
    // let mut current_timeout_time = IPV6_TIMEOUT_DEFAULT_DURACTION;

    let mut active_send = Box::pin(tokio::time::sleep(Duration::from_secs(0)));

    let mut status = IpV6PdState::init_status();
    #[cfg(debug_assertions)]
    let time = tokio::time::Instant::now();
    let mut current_wan_addr: Option<Ipv6Addr> = None;

    let stop_token = service_status.stop_token();
    let mut cleaned_up = false;
    loop {
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
                        connect_failure_count = connect_failure_count.saturating_add(1);
                        let backoff = calc_connect_retry_backoff_secs(connect_failure_count);
                        tracing::warn!(
                            "DHCPv6 solicit timeout exceeded limit, retry in {}s (failure_count={})",
                            backoff,
                            connect_failure_count
                        );
                        status = IpV6PdState::init_status();
                        timeout_times = 1;
                        active_send
                            .as_mut()
                            .set(tokio::time::sleep(Duration::from_secs(backoff)));
                        continue;
                    // } else {
                    //     timeout_times = 0;
                    //     // current_timeout_time = IPV6_TIMEOUT_DEFAULT_DURACTION;
                    //     status = IpV6PdState::init_status();
                    //     tracing::error!("Start from Solicit: {:#?}", status);
                    }
                }

                let send_outcome = send_current_status_packet(&client_id, &send_socket, &mut status).await;
                if send_outcome.prefix_expired {
                    clear_active_pd_prefix(
                        link_id,
                        &iface_name,
                        ifindex,
                        &route_service,
                        addr_binding.as_ref(),
                        &prefix_map,
                        &prefix_sender,
                        &mut current_wan_addr,
                    )
                    .await;
                }
                if send_outcome.reset_timeout {
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
                        let need_reset_time = handle_packet(
                            link_id,
                            &iface_name,
                            ifindex,
                            &client_id,
                            &mut status,
                            data,
                            &wan_route_info,
                            &route_service,
                            addr_binding.as_ref(),
                            &prefix_map,
                            &mac_addr,
                            shared_wan_iid.as_ref(),
                            &mut current_wan_addr,
                            &prefix_sender,
                            expected_pd_len,
                        )
                        .await;
                        if matches!(status, IpV6PdState::Bound { .. }) {
                            connect_failure_count = 0;
                        }
                        if need_reset_time {
                            timeout_times = get_status_timeout_config(&status, 0, active_send.as_mut());
                            // current_timeout_time = t2;

                        }
                    }
                    // message_rx close
                    None => break
                }
            },
            // 停止信号(进入退出态即触发):先停用租约再发送 Release 后收尾
            () = stop_token.cancelled() => {
                // RFC 8415 §18.2.7: 客户端 MUST 在发起 Release 交换前停止使用所有被释放的租约
                clear_active_pd_prefix(
                    link_id,
                    &iface_name,
                    ifindex,
                    &route_service,
                    addr_binding.as_ref(),
                    &prefix_map,
                    &prefix_sender,
                    &mut current_wan_addr,
                )
                .await;
                cleaned_up = true;
                if let Some((service_id, iapd, server_unicast)) = status.into_release()
                    && let Some(send_msg) = gen_release(&client_id, service_id, iapd)
                {
                    // RFC 8415 §18.2/§21.12: 仅当服务器授权 Server Unicast option 时单播,否则组播
                    send_data(&send_msg, &send_socket, release_target(server_unicast)).await;
                }
                service_status.just_change_status(ServiceStatus::Stop);
                tracing::info!("release send and stop");
                break;
            }
        }
    }

    if !cleaned_up {
        clear_active_pd_prefix(
            link_id,
            &iface_name,
            ifindex,
            &route_service,
            addr_binding.as_ref(),
            &prefix_map,
            &prefix_sender,
            &mut current_wan_addr,
        )
        .await;
    }
    tracing::info!("DHCP V6 Client Stop: {:#?}", service_status);

    if !service_status.is_stop() {
        service_status.just_change_status(if service_status.is_exit() {
            ServiceStatus::Stop
        } else {
            ServiceStatus::Failed
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn clear_active_pd_prefix(
    link_id: Uuid,
    iface_name: &str,
    ifindex: u32,
    route_service: &IpRouteService,
    addr_binding: &dyn WanAddrBinding,
    prefix_map: &IAPrefixMap,
    prefix_sender: &IAPrefixEventSender,
    current_wan_addr: &mut Option<Ipv6Addr>,
) {
    let removed = prefix_map.remove(&link_id);
    if let Some(status) = removed.as_ref() {
        remove_ip_route(&status.actual_prefix, iface_name);
    }

    route_service.remove_ipv6_link_route(link_id).await;
    addr_binding.unbind_ipv6(ifindex);
    if let Some(wan_addr) = current_wan_addr.take() {
        del_iface_ip(wan_addr, 128, iface_name);
    }

    if removed.is_some() {
        let _ = prefix_sender.send(IAPrefixEvent::Expired { link_id }).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendStatusOutcome {
    reset_timeout: bool,
    prefix_expired: bool,
}

impl SendStatusOutcome {
    const NO_CHANGE: Self = Self { reset_timeout: false, prefix_expired: false };
    const RESET_TIMEOUT: Self = Self { reset_timeout: true, prefix_expired: false };
    const PREFIX_EXPIRED: Self = Self { reset_timeout: true, prefix_expired: true };
}

fn active_prefix_lease(status: &IpV6PdState) -> Option<(&v6::IAPD, &Instant)> {
    match status {
        IpV6PdState::Bound { iapd, bound_time, .. }
        | IpV6PdState::Renew { iapd, bound_time, .. }
        | IpV6PdState::WaitToRebind { iapd, bound_time, .. }
        | IpV6PdState::Rebind { iapd, bound_time, .. } => Some((iapd, bound_time)),
        _ => None,
    }
}

fn active_prefix_remaining(status: &IpV6PdState) -> Option<Duration> {
    let (iapd, bound_time) = active_prefix_lease(status)?;
    let valid_lifetime = match iapd.opts.get(OptionCode::IAPrefix) {
        Some(DhcpOption::IAPrefix(prefix)) => Duration::from_secs(prefix.valid_lifetime as u64),
        _ => Duration::ZERO,
    };
    Some(valid_lifetime.saturating_sub(bound_time.elapsed()))
}

/// Send the packet for the current state and report state-machine side effects.
async fn send_current_status_packet(
    my_client_id: &[u8],
    send_socket: &UdpSocket,
    current_status: &mut IpV6PdState,
) -> SendStatusOutcome {
    if active_prefix_remaining(current_status).is_some_and(|remaining| remaining.is_zero()) {
        tracing::warn!("DHCPv6 PD prefix valid lifetime expired; restarting solicitation");
        *current_status = IpV6PdState::Solicit { xid: get_new_ipv6_xid() };
        return SendStatusOutcome::PREFIX_EXPIRED;
    }

    match current_status {
        IpV6PdState::Solicit { xid } => {
            let mut msg = v6::Message::new(v6::MessageType::Solicit);
            msg.set_opts(get_solicit_options());
            msg.set_xid_num(*xid);
            msg.opts_mut().insert(v6::DhcpOption::ClientId(my_client_id.to_vec()));

            send_data(&msg, send_socket, None).await;
        }
        // IpV6PdState::Advertise { xid } => todo!(),
        IpV6PdState::Request {
            xid,
            service_id,
            iapd,
            service_sock: _,
            server_unicast: _,
            send_times,
        } => {
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

            // Request 没有收到响应到达一定次数需要进行回退到 Solicit
            if *send_times > 4 {
                tracing::warn!("Request send times: {send_times} timeout turn to Solicit");
                // 切换状态为 Solicit 重新开始
                *current_status = IpV6PdState::Solicit { xid: get_new_ipv6_xid() };
                return SendStatusOutcome::RESET_TIMEOUT;
            }
            *send_times += 1;
        }
        IpV6PdState::Bound {
            xid: _,
            service_id,
            iapd,
            server_unicast,
            bound_time,
        } => {
            // t1 时间到 转换状态为 Renew
            *current_status = IpV6PdState::Renew {
                xid: get_new_ipv6_xid(),
                service_id: service_id.clone(),
                renew_time: Instant::now(),
                bound_time: *bound_time,
                iapd: iapd.clone(),
                server_unicast: *server_unicast,
            };
            return SendStatusOutcome::RESET_TIMEOUT;
        }
        IpV6PdState::Confirm => todo!(),
        IpV6PdState::Renew {
            xid,
            service_id,
            iapd,
            server_unicast,
            renew_time,
            bound_time,
        } => {
            //
            let mut send_msg = v6::Message::new(V6MessageType::Renew);
            send_msg.set_xid_num(*xid);
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
                    xid: *xid,
                    service_id: service_id.clone(),
                    bound_time: *bound_time,
                    iapd: iapd.clone(),
                    server_unicast: *server_unicast,
                };
                return SendStatusOutcome::RESET_TIMEOUT;
            }
        }
        IpV6PdState::WaitToRebind {
            xid: _,
            service_id,
            iapd,
            server_unicast,
            bound_time,
        } => {
            tracing::warn!("WaitToRebind turn to Rebind");
            // 切换状态为 Rebind
            *current_status = IpV6PdState::Rebind {
                xid: get_new_ipv6_xid(),
                service_id: service_id.clone(),
                rebind_time: Instant::now(),
                bound_time: *bound_time,
                iapd: iapd.clone(),
                server_unicast: *server_unicast,
            };
            return SendStatusOutcome::RESET_TIMEOUT;
        }
        IpV6PdState::Rebind { xid, service_id: _, iapd, rebind_time, .. } => {
            let mut send_msg = v6::Message::new(V6MessageType::Rebind);
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
    SendStatusOutcome::NO_CHANGE
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
            tracing::error!("target sock addr: {target_sock:?}, error: {:?}", e);
        }
    }
}
fn get_status_timeout_config(
    current_status: &IpV6PdState,
    prev_timeout_times: u64,
    mut timeout: Pin<&mut tokio::time::Sleep>,
) -> u64 {
    let current_timeout = status_timeout_duration(current_status, prev_timeout_times);

    timeout.set(tokio::time::sleep(current_timeout));
    prev_timeout_times + 1
}

fn status_timeout_duration(current_status: &IpV6PdState, prev_timeout_times: u64) -> Duration {
    let protocol_timeout = match current_status {
        // 绑定后的超时时间是 由 iapd 的 t1 决定
        IpV6PdState::Bound { iapd, .. } => Duration::from_secs(iapd.t1 as u64),
        // 等待的时间是 t2 - bound_time
        IpV6PdState::WaitToRebind { iapd, bound_time, .. } => {
            let t2 = if iapd.t2 == 0 { IPV6_T2_DEFAULT } else { iapd.t2 as u64 };
            Duration::from_secs(t2).saturating_sub(bound_time.elapsed())
        }
        _ => Duration::from_secs(IPV6_TIMEOUT_DEFAULT_DURACTION.saturating_mul(prev_timeout_times)),
    };

    active_prefix_remaining(current_status)
        .map(|remaining| protocol_timeout.min(remaining))
        .unwrap_or(protocol_timeout)
}
/// 处理接收到的报文，根据当前状态决定如何处理
/// 返回值为是否要进行检查刷新超时时间
#[allow(clippy::too_many_arguments)]
async fn handle_packet(
    link_id: Uuid,
    iface_name: &str,
    ifindex: u32,
    my_client_id: &[u8],
    current_status: &mut IpV6PdState,
    (msg, msg_addr): (Vec<u8>, SocketAddr),
    wan_route_info: &RouteTargetInfo,
    route_service: &IpRouteService,
    addr_binding: &dyn WanAddrBinding,
    prefix_map: &IAPrefixMap,
    mac_addr: &Option<MacAddr>,
    shared_wan_iid: &u64,
    current_wan_addr: &mut Option<Ipv6Addr>,
    prefix_sender: &IAPrefixEventSender,
    expected_pd_len: u8,
) -> bool {
    let IpAddr::V6(ipv6addr) = msg_addr.ip() else {
        tracing::error!("unexpected IPV4 packet");
        return true;
    };
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
                        server_unicast: extract_server_unicast(&new_v6_msg),
                        send_times: 0,
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
        | IpV6PdState::Rebind { service_id, .. } => {
            if new_v6_msg.msg_type() == V6MessageType::Reply {
                if let Some(v6::DhcpOption::ServerId(new_service_id)) =
                    new_v6_msg.opts().get(OptionCode::ServerId)
                    && &service_id != new_service_id
                {
                    tracing::warn!(
                        "receiver a replay from another server, id is: {:?}",
                        new_service_id
                    );
                    return false;
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
                                server_unicast: extract_server_unicast(&new_v6_msg),
                                bound_time: Instant::now(),
                            };

                            let ia_prefix = LDIAPrefix {
                                preferred_lifetime: ia_prefix.preferred_lifetime,
                                valid_lifetime: ia_prefix.valid_lifetime,
                                prefix_len: ia_prefix.prefix_len,
                                prefix_ip: ia_prefix.prefix_ip,
                                last_update_time: get_f64_timestamp(),
                            };

                            let mut info = wan_route_info.clone();
                            if let Some(wan_addr) = derive_wan_pd_addr(&ia_prefix, *shared_wan_iid)
                            {
                                if current_wan_addr.as_ref() != Some(&wan_addr)
                                    && let Some(old_addr) = current_wan_addr.replace(wan_addr)
                                {
                                    del_iface_ip(old_addr, 128, iface_name);
                                }

                                set_iface_ip(
                                    wan_addr,
                                    128,
                                    iface_name,
                                    Some(ia_prefix.valid_lifetime),
                                    Some(ia_prefix.preferred_lifetime),
                                );
                                info.iface_ip = IpAddr::V6(wan_addr);
                            }
                            info.gateway_ip = IpAddr::V6(ipv6addr);
                            route_service.insert_ipv6_link_route(link_id, info).await;
                            replace_ip_route(
                                &ia_prefix,
                                ipv6addr,
                                iface_name,
                                ifindex,
                                mac_addr,
                                addr_binding,
                            );
                            prefix_map.store(link_id, ia_prefix, expected_pd_len);
                            let _ = prefix_sender.send(IAPrefixEvent::Updated { link_id }).await;
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
        }
        IpV6PdState::Release { .. } => {}
        IpV6PdState::Stop => {}
        _ => {}
    }

    false
}

fn replace_ip_route(
    iapd: &landscape_common::wan_service::ipv6_pd::LDIAPrefix,
    route_ip: Ipv6Addr,
    iface_name: &str,
    ifindex: u32,
    mac: &Option<MacAddr>,
    addr_binding: &dyn WanAddrBinding,
) {
    let result = std::process::Command::new("ip")
        .args([
            "-6",
            "route",
            "replace",
            "default",
            "from",
            &format!("{}/{}", iapd.prefix_ip, iapd.prefix_len),
            "via",
            &format!("{}", route_ip),
            "dev",
            iface_name,
            "expires",
            &format!("{}", iapd.valid_lifetime),
        ])
        .output();

    addr_binding.bind_ipv6(ifindex, iapd.prefix_ip, Some(route_ip), iapd.prefix_len, *mac);
    if let Err(e) = result {
        tracing::error!("{e:?}");
    }
}

fn remove_ip_route(iapd: &LDIAPrefix, iface_name: &str) {
    let result = std::process::Command::new("ip")
        .args([
            "-6",
            "route",
            "del",
            "default",
            "from",
            &format!("{}/{}", iapd.prefix_ip, iapd.prefix_len),
            "dev",
            iface_name,
        ])
        .output();

    if let Err(err) = result {
        tracing::error!(?err, "failed to remove expired IPv6 PD source route");
    }
}

fn derive_wan_pd_addr(
    ia_prefix: &landscape_common::wan_service::ipv6_pd::LDIAPrefix,
    shared_wan_iid: u64,
) -> Option<Ipv6Addr> {
    let wan_prefix = match ia_prefix.prefix_len {
        0..=63 => checked_allocate_subnet(ia_prefix.prefix_ip, ia_prefix.prefix_len, 64, 0)?.0,
        64 => ia_prefix.prefix_ip,
        _ => return None,
    };

    let prefix_bits = u128::from(wan_prefix) & (!0u128 << 64);
    Some(Ipv6Addr::from(prefix_bits | shared_wan_iid as u128))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(address: &str, prefix_len: u8) -> LDIAPrefix {
        LDIAPrefix {
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            prefix_len,
            prefix_ip: address.parse().unwrap(),
            last_update_time: 0.0,
        }
    }

    fn iapd(t1: u32, t2: u32, valid_lifetime: u32) -> v6::IAPD {
        let mut opts = DhcpOptions::new();
        opts.insert(DhcpOption::IAPrefix(v6::IAPrefix {
            preferred_lifetime: valid_lifetime,
            valid_lifetime,
            prefix_len: 56,
            prefix_ip: "2001:db8:1200::".parse().unwrap(),
            opts: DhcpOptions::new(),
        }));
        v6::IAPD { id: 1, t1, t2, opts }
    }

    #[tokio::test]
    async fn expired_rebind_reports_prefix_expiration() {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut status = IpV6PdState::Rebind {
            xid: get_new_ipv6_xid(),
            service_id: Vec::new(),
            iapd: iapd(4, 8, 10),
            server_unicast: None,
            rebind_time: Instant::now(),
            bound_time: Instant::now() - Duration::from_secs(11),
        };

        let outcome = send_current_status_packet(&[], &socket, &mut status).await;

        assert_eq!(outcome, SendStatusOutcome::PREFIX_EXPIRED);
        assert!(matches!(status, IpV6PdState::Solicit { .. }));
    }

    #[tokio::test]
    async fn rebind_keeps_prefix_until_valid_lifetime_expires() {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut status = IpV6PdState::Rebind {
            xid: get_new_ipv6_xid(),
            service_id: Vec::new(),
            iapd: iapd(4, 8, 30),
            server_unicast: None,
            rebind_time: Instant::now(),
            bound_time: Instant::now() - Duration::from_secs(11),
        };

        let outcome = send_current_status_packet(&[], &socket, &mut status).await;

        assert_eq!(outcome, SendStatusOutcome::NO_CHANGE);
        assert!(matches!(status, IpV6PdState::Rebind { .. }));
    }

    #[test]
    fn active_timeout_is_capped_by_prefix_valid_lifetime() {
        let status = IpV6PdState::Bound {
            xid: get_new_ipv6_xid(),
            service_id: Vec::new(),
            iapd: iapd(120, 180, 20),
            server_unicast: None,
            bound_time: Instant::now() - Duration::from_secs(5),
        };

        let timeout = status_timeout_duration(&status, 1);

        assert!(timeout > Duration::from_secs(14));
        assert!(timeout <= Duration::from_secs(15));
    }

    #[tokio::test]
    async fn active_state_without_prefix_option_expires_immediately() {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut status = IpV6PdState::Bound {
            xid: get_new_ipv6_xid(),
            service_id: Vec::new(),
            iapd: v6::IAPD { id: 1, t1: 4, t2: 8, opts: DhcpOptions::new() },
            server_unicast: None,
            bound_time: Instant::now(),
        };

        let outcome = send_current_status_packet(&[], &socket, &mut status).await;

        assert_eq!(outcome, SendStatusOutcome::PREFIX_EXPIRED);
        assert!(matches!(status, IpV6PdState::Solicit { .. }));
    }

    #[tokio::test]
    async fn zero_valid_lifetime_expires_immediately() {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let mut status = IpV6PdState::Bound {
            xid: get_new_ipv6_xid(),
            service_id: Vec::new(),
            iapd: iapd(4, 8, 0),
            server_unicast: None,
            bound_time: Instant::now(),
        };

        let outcome = send_current_status_packet(&[], &socket, &mut status).await;

        assert_eq!(outcome, SendStatusOutcome::PREFIX_EXPIRED);
        assert!(matches!(status, IpV6PdState::Solicit { .. }));
    }

    #[test]
    fn wan_pd_addresses_share_the_startup_iid() {
        let iid = 0x9234_5678_9abc_def0;
        let first = derive_wan_pd_addr(&prefix("2001:db8:1000::", 56), iid).unwrap();
        let second = derive_wan_pd_addr(&prefix("2001:db8:2000::", 60), iid).unwrap();

        assert_ne!(&first.octets()[..8], &second.octets()[..8]);
        assert_eq!(&first.octets()[8..], &iid.to_be_bytes());
        assert_eq!(&second.octets()[8..], &iid.to_be_bytes());
    }

    #[test]
    fn release_echoes_server_and_client_id_and_zeroes_iapd() {
        let server_unicast_addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let status = IpV6PdState::Bound {
            xid: get_new_ipv6_xid(),
            service_id: vec![0x00, 0x01],
            iapd: iapd(120, 180, 7200),
            server_unicast: Some(server_unicast_addr),
            bound_time: Instant::now(),
        };
        let client_id = [0x00, 0x03, 0x00, 0x01, 0xaa];

        let (service_id, iapd, server_unicast) =
            status.into_release().expect("bound state holds a lease");
        assert_eq!(
            release_target(server_unicast),
            Some(SocketAddr::new(
                IpAddr::V6(server_unicast_addr),
                LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT
            )),
            "Release must unicast to the authorized Server Unicast address"
        );
        let msg = gen_release(&client_id, service_id, iapd).expect("lease holds a prefix");

        assert_eq!(msg.msg_type(), V6MessageType::Release);
        let Some(DhcpOption::ServerId(id)) = msg.opts().get(OptionCode::ServerId) else {
            panic!("Release must echo the server id");
        };
        assert_eq!(id, &[0x00, 0x01]);
        let Some(DhcpOption::ClientId(id)) = msg.opts().get(OptionCode::ClientId) else {
            panic!("Release must carry the client id");
        };
        assert_eq!(id, &client_id);

        let Some(DhcpOption::IAPD(release_iapd)) = msg.opts().get(OptionCode::IAPD) else {
            panic!("Release must carry the IA_PD being released (RFC 8415 §18.2.7)");
        };
        assert_eq!(release_iapd.id, 1);
        assert_eq!(release_iapd.t1, 0);
        assert_eq!(release_iapd.t2, 0);
        let Some(DhcpOption::IAPrefix(prefix)) = release_iapd.opts.get(OptionCode::IAPrefix) else {
            panic!("Release IA_PD must carry the released IAPrefix");
        };
        assert_eq!(prefix.preferred_lifetime, 0);
        assert_eq!(prefix.valid_lifetime, 0);
    }

    #[test]
    fn states_without_a_lease_have_no_release_target() {
        assert!(IpV6PdState::init_status().into_release().is_none());
        assert!(IpV6PdState::Confirm.into_release().is_none());
        assert!(IpV6PdState::Stop.into_release().is_none());
    }

    #[test]
    fn request_state_into_release_returns_lease() {
        let status = IpV6PdState::Request {
            xid: get_new_ipv6_xid(),
            service_id: vec![0x00, 0x01],
            iapd: iapd(120, 180, 7200),
            service_sock: "[::1]:547".parse().unwrap(),
            server_unicast: None,
            send_times: 1,
        };

        let (service_id, iapd, server_unicast) =
            status.into_release().expect("request state holds a pending lease");

        assert_eq!(service_id, vec![0x00, 0x01]);
        assert_eq!(iapd.id, 1);
        assert_eq!(server_unicast, None);
    }

    #[test]
    fn release_zeroes_all_iaprefixes() {
        let mut opts = DhcpOptions::new();
        for i in 0u32..2 {
            opts.insert(DhcpOption::IAPrefix(v6::IAPrefix {
                preferred_lifetime: 3600 + i,
                valid_lifetime: 7200 + i,
                prefix_len: 56,
                prefix_ip: format!("2001:db8:{}00::", i + 1).parse().unwrap(),
                opts: DhcpOptions::new(),
            }));
        }
        let status = IpV6PdState::Bound {
            xid: get_new_ipv6_xid(),
            service_id: vec![0x00, 0x02],
            iapd: v6::IAPD { id: 7, t1: 120, t2: 180, opts },
            server_unicast: None,
            bound_time: Instant::now(),
        };

        let (service_id, iapd, _) = status.into_release().expect("bound state holds a lease");
        let msg = gen_release(&[0x00, 0x03, 0x00, 0x01, 0xbb], service_id, iapd)
            .expect("lease holds prefixes");

        let Some(DhcpOption::IAPD(release_iapd)) = msg.opts().get(OptionCode::IAPD) else {
            panic!("Release must carry the IA_PD being released (RFC 8415 §18.2.7)");
        };
        assert_eq!(release_iapd.id, 7);
        let prefixes = release_iapd
            .opts
            .get_all(OptionCode::IAPrefix)
            .expect("release IA_PD must carry every released prefix");
        assert_eq!(prefixes.len(), 2);
        for prefix in prefixes {
            let DhcpOption::IAPrefix(prefix) = prefix else {
                panic!("expected IAPrefix options");
            };
            assert_eq!(prefix.preferred_lifetime, 0);
            assert_eq!(prefix.valid_lifetime, 0);
        }
    }

    #[test]
    fn gen_release_skips_when_iapd_has_no_prefix() {
        let status = IpV6PdState::Bound {
            xid: get_new_ipv6_xid(),
            service_id: vec![0x00, 0x01],
            iapd: v6::IAPD { id: 1, t1: 4, t2: 8, opts: DhcpOptions::new() },
            server_unicast: None,
            bound_time: Instant::now(),
        };

        let (service_id, iapd, _) = status.into_release().expect("bound state holds a lease");
        assert!(
            gen_release(&[0x00, 0x03, 0x00, 0x01, 0xcc], service_id, iapd).is_none(),
            "a prefix-less IA_PD has no binding to release"
        );
    }

    #[tokio::test]
    async fn bound_forwards_server_unicast_to_renew() {
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        let server_unicast_addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut status = IpV6PdState::Bound {
            xid: get_new_ipv6_xid(),
            service_id: vec![0x00, 0x01],
            iapd: iapd(120, 180, 7200),
            server_unicast: Some(server_unicast_addr),
            bound_time: Instant::now(),
        };

        let outcome = send_current_status_packet(&[], &socket, &mut status).await;

        assert_eq!(outcome, SendStatusOutcome::RESET_TIMEOUT);
        let IpV6PdState::Renew { server_unicast, .. } = status else {
            panic!("bound state should transition to renew");
        };
        assert_eq!(server_unicast, Some(server_unicast_addr));
    }

    #[test]
    fn release_target_follows_server_unicast_option() {
        // RFC 8415 §18.2/§21.12: 未授权 Server Unicast option 时,Release 走组播默认路径
        assert_eq!(release_target(None), None);
        // 授权后单播到 option 中的服务器地址
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            release_target(Some(addr)),
            Some(SocketAddr::new(IpAddr::V6(addr), LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT))
        );
    }

    #[test]
    fn extract_server_unicast_reads_option_from_message() {
        let mut msg = v6::Message::new(V6MessageType::Reply);
        assert_eq!(extract_server_unicast(&msg), None);

        let addr: Ipv6Addr = "2001:db8::2".parse().unwrap();
        msg.opts_mut().insert(DhcpOption::ServerUnicast(addr));
        assert_eq!(extract_server_unicast(&msg), Some(addr));
    }
}

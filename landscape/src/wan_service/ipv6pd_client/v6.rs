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
use landscape_ebpf::chain::wan_link::WanLinkDataplane;

use arc_swap::ArcSwap;
use socket2::{Domain, Protocol, Type};
use tokio::{net::UdpSocket, time::Instant};
use uuid::Uuid;

use crate::netlink::address::get_existing_linklocal;
use crate::{
    netlink::ipv6::{del_iface_ip, deprecate_iface_ip, set_iface_ip},
    sys_service::route::IpRouteService,
};
use landscape_common::flow::mark::{MarkType, SocketMark};

use landscape_common::{
    LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT,
    event::hub::IAPrefixEventSender,
    lan_service::lan_ipv6::checked_allocate_subnet,
    service::{ServiceHandle, ServiceStatus},
    utils::time::get_f64_timestamp,
    wan_link::runtime_status::{PdLease, PdRuntime, swap_if_changed},
    wan_link::{LinkStateHandle, WanV6Prefix},
    wan_service::ipv6_pd::LDIAPrefix,
};
use landscape_common::{
    concurrency::task_label,
    event::hub::IAPrefixEvent,
    net::MacAddr,
    sys_service::route_service::{RouteTargetInfo, WanRouteTarget},
};
use landscape_core::pd_prefix::IAPrefixMap;

pub const IPV6_TIMEOUT_DEFAULT_DURACTION: u64 = 10;
pub const IPV6_TIMEOUT_RENEW_DURACTION: u64 = 10;
pub const IPV6_TIMEOUT_REBIND_DURACTION: u64 = 20;
const MAX_CONNECT_RETRY_BACKOFF_SECS: u64 = 10 * 60;

/// How long a replaced PD /128 stays around (deprecated) so in-flight flows
/// can drain. Capped by the old prefix's remaining valid lifetime; the kernel
/// removes it when this lifetime expires.
const PD_PREFIX_RETIRE_GRACE: Duration = Duration::from_secs(5 * 60);

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

fn state_label(status: &IpV6PdState) -> &'static str {
    match status {
        IpV6PdState::Solicit { .. } => "Solicit",
        IpV6PdState::Request { .. } => "Request",
        IpV6PdState::Bound { .. } => "Bound",
        IpV6PdState::Confirm => "Confirm",
        IpV6PdState::Renew { .. } => "Renew",
        IpV6PdState::WaitToRebind { .. } => "WaitToRebind",
        IpV6PdState::Rebind { .. } => "Rebind",
        IpV6PdState::Release { .. } => "Release",
        IpV6PdState::Decline => "Decline",
        IpV6PdState::Stop => "Stop",
    }
}

fn gen_client_id(config_mac: MacAddr) -> Vec<u8> {
    let mut result = Vec::with_capacity(10);
    result.extend_from_slice(&[0x00, 0x03, 0x00, 0x01]);
    result.extend_from_slice(&config_mac.octets());
    result
}

/// Re-bind the session's IPv6CP link-local if anything (iface reset,
/// DAD conflict, an external manager) removed it; without it the socket
/// has no source address and the sends fail. Verified by read-back.
fn ensure_session_linklocal(iface_name: &str, session_ll: Option<Ipv6Addr>) -> bool {
    let Some(ll) = session_ll else { return true };
    if get_existing_linklocal(iface_name).as_ref() == Some(&ll) {
        return true;
    }
    tracing::warn!(iface = iface_name, linklocal = %ll, "session link-local missing; force re-binding");
    let _ = std::process::Command::new("ip")
        .args(["-6", "addr", "replace", &format!("{}/64", ll), "dev", iface_name])
        .output();
    match get_existing_linklocal(iface_name) {
        Some(current) if current == ll => true,
        current => {
            tracing::error!(
                iface = iface_name,
                expected = %ll,
                found = ?current,
                "session link-local force-bind failed; DHCPv6 has no stable source"
            );
            false
        }
    }
}

fn create_pd_socket(
    socket_addr: &SocketAddr,
    iface_name: &[u8],
    chain_id: u16,
) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    if let Err(err) = socket.set_reuse_port(true) {
        tracing::warn!("set_reuse_port failed (non-fatal): {err:?}");
    }
    // Scope the bind to this WAN device before claiming the wildcard port.
    // Otherwise a DHCPv6 client bound to another interface (e.g. dhcpcd on
    // the management NIC) makes bind() return EADDRINUSE.
    socket.bind_device(Some(iface_name))?;
    socket.bind(&(*socket_addr).into())?;
    socket.set_nonblocking(true)?;
    // All sends (Solicit / Renew / Release) carry the session's chain in
    // the HostDirect mark: the WAN egress entry hands the packet to the
    // link's chain root directly and every policy stage self-skips on
    // this mark, so the control plane rides the PPP terminal unfiltered.
    socket.set_mark(u32::from(SocketMark::new(MarkType::HostDirect { chain_id }, 0)))?;
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
    chain_id: u16,
    iface_name: String,
    ifindex: u32,
    // session's IPv6CP link-local (SessionIface::v6_linklocal); kept
    // bound on the iface as a stable DHCPv6 source (chain steering is
    // the HostDirect SO_MARK above, not the address)
    session_ll: Option<Ipv6Addr>,
    // for ebpf map setting
    mac_addr: Option<MacAddr>,
    // for pd request
    config_mac: MacAddr,
    expected_pd_len: u8,
    client_port: u16,
    service_status: ServiceHandle,
    wan_route_info: RouteTargetInfo,
    route_service: IpRouteService,
    chain_dataplane: Arc<WanLinkDataplane>,
    prefix_map: IAPrefixMap,
    shared_wan_iid: Arc<u64>,
    prefix_sender: IAPrefixEventSender,
    pd_runtime: Arc<ArcSwap<PdRuntime>>,
    link_state: LinkStateHandle,
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

    let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), client_port);

    let socket = match create_pd_socket(&socket_addr, iface_name.as_bytes(), chain_id) {
        Ok(socket) => socket,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                tracing::error!(
                    "failed to bind DHCPv6 PD socket on {iface_name}:{client_port}: UDP port already in use; \
                     another DHCPv6 client may hold it (check: ss -lunp 'sport = :{client_port}')"
                );
            } else {
                tracing::error!("failed to create DHCPv6 PD socket on {}: {e:?}", iface_name);
            }
            service_status.just_change_status(ServiceStatus::Failed);
            swap_if_changed(&pd_runtime, PdRuntime::Stopped);
            return;
        }
    };

    let send_socket = Arc::new(socket);

    let recive_socket_raw = send_socket.clone();

    let (message_tx, mut message_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    // 接收数据
    service_status.spawn_task(task_label::task::WAN_IPV6PD_CLIENT_RENEW, async move {
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

    let mut current_wan_addr: Option<Ipv6Addr> = None;
    let mut status = IpV6PdState::init_status();
    swap_if_changed(&pd_runtime, pd_runtime_projection(&status, current_wan_addr));
    #[cfg(debug_assertions)]
    let time = tokio::time::Instant::now();

    let stop_token = service_status.stop_token();
    let mut cleaned_up = false;
    ensure_session_linklocal(&iface_name, session_ll);
    loop {
        let status_before = state_label(&status);

        tokio::select! {
            // 超时激发重发
            _ = active_send.as_mut() => {
                #[cfg(debug_assertions)]
                {
                    tracing::error!("Timeout active at: {:?}",  time.elapsed());
                }
                tracing::info!(
                    iface = iface_name,
                    %link_id,
                    state = status_before,
                    timeout_times,
                    prefix_remaining_secs = ?active_prefix_remaining(&status).map(|d| d.as_secs_f64()),
                    "DHCPv6 PD timer fired"
                );
                if timeout_times > 4 && matches!(status, IpV6PdState::Solicit { .. }) {
                    // 如果当前状态是 Solicit 并且 超时 4 次 就退出
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
                } else {
                    ensure_session_linklocal(&iface_name, session_ll);
                    let send_outcome = send_current_status_packet(&client_id, &send_socket, &mut status).await;
                    if send_outcome.prefix_expired {
                        clear_active_pd_prefix(
                            link_id,
                            &iface_name,
                            &route_service,
                            chain_dataplane.as_ref(),
                            &prefix_map,
                            &prefix_sender,
                            &mut current_wan_addr,
                            &link_state,
                        )
                        .await;
                    }
                    if send_outcome.reset_timeout {
                        timeout_times = 0;
                    }
                    let (next_times, next_timeout) =
                        get_status_timeout_config(&status, timeout_times, active_send.as_mut());
                    timeout_times = next_times;
                    tracing::debug!(
                        iface = iface_name,
                        %link_id,
                        state = state_label(&status),
                        timeout_times,
                        next_timeout_secs = next_timeout.as_secs_f64(),
                        "DHCPv6 PD next timer armed"
                    );
                    swap_if_changed(&pd_runtime, pd_runtime_projection(&status, current_wan_addr));
                }
            },
            message_result = message_rx.recv() => {
                // 处理接收到的数据包
                match message_result {
                    Some(data) => {
                        let need_reset_time = handle_packet(
                            link_id,
                            chain_id,
                            &iface_name,
                            ifindex,
                            &client_id,
                            &mut status,
                            data,
                            &wan_route_info,
                            &route_service,
                            chain_dataplane.as_ref(),
                            &prefix_map,
                            &mac_addr,
                            shared_wan_iid.as_ref(),
                            &mut current_wan_addr,
                            &prefix_sender,
                            expected_pd_len,
                            &link_state,
                        )
                        .await;
                        if matches!(status, IpV6PdState::Bound { .. }) {
                            connect_failure_count = 0;
                        }
                        if need_reset_time {
                            let (next_times, next_timeout) =
                                get_status_timeout_config(&status, 0, active_send.as_mut());
                            timeout_times = next_times;
                            tracing::debug!(
                                iface = iface_name,
                                %link_id,
                                state = state_label(&status),
                                timeout_times,
                                next_timeout_secs = next_timeout.as_secs_f64(),
                                "DHCPv6 PD timer reset after lease message"
                            );
                        }
                        swap_if_changed(&pd_runtime, pd_runtime_projection(&status, current_wan_addr));
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
                    &route_service,
                    chain_dataplane.as_ref(),
                    &prefix_map,
                    &prefix_sender,
                    &mut current_wan_addr,
                    &link_state,
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

        let status_after = state_label(&status);
        if status_before != status_after {
            tracing::info!(
                iface = iface_name,
                %link_id,
                from = status_before,
                to = status_after,
                prefix_remaining_secs = ?active_prefix_remaining(&status).map(|d| d.as_secs_f64()),
                "DHCPv6 PD state transition"
            );
        }
    }

    if !cleaned_up {
        clear_active_pd_prefix(
            link_id,
            &iface_name,
            &route_service,
            chain_dataplane.as_ref(),
            &prefix_map,
            &prefix_sender,
            &mut current_wan_addr,
            &link_state,
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
    swap_if_changed(&pd_runtime, PdRuntime::Stopped);
}

#[allow(clippy::too_many_arguments)]
async fn clear_active_pd_prefix(
    link_id: Uuid,
    iface_name: &str,
    route_service: &IpRouteService,
    chain_dataplane: &WanLinkDataplane,
    prefix_map: &IAPrefixMap,
    prefix_sender: &IAPrefixEventSender,
    current_wan_addr: &mut Option<Ipv6Addr>,
    link_state: &LinkStateHandle,
) {
    let removed = prefix_map.remove(&link_id);
    if removed.is_some() || current_wan_addr.is_some() {
        tracing::info!(
            iface = iface_name,
            %link_id,
            prefix = ?removed.as_ref().map(|status| (
                status.actual_prefix.prefix_ip,
                status.actual_prefix.prefix_len,
            )),
            wan_addr = ?current_wan_addr,
            "Removing active DHCPv6 PD prefix and WAN address"
        );
    }
    if let Some(status) = removed.as_ref() {
        remove_ip_route(&status.actual_prefix, iface_name);
    }

    route_service.remove_ipv6_link_route(link_id).await;
    chain_dataplane.unbind_wan_ipv6();
    link_state.clear_v6_prefix();
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

fn lease_projection(iapd: &v6::IAPD, wan_addr: Option<Ipv6Addr>) -> Option<PdLease> {
    match iapd.opts.get(OptionCode::IAPrefix) {
        Some(DhcpOption::IAPrefix(p)) => Some(PdLease {
            prefix_ip: p.prefix_ip,
            prefix_len: p.prefix_len,
            valid_secs: p.valid_lifetime,
            preferred_secs: p.preferred_lifetime,
            wan_ip: wan_addr,
        }),
        _ => None,
    }
}

fn pd_runtime_projection(status: &IpV6PdState, wan_addr: Option<Ipv6Addr>) -> PdRuntime {
    match status {
        IpV6PdState::Solicit { .. } | IpV6PdState::Confirm => PdRuntime::Soliciting,
        IpV6PdState::Request { .. } => PdRuntime::Requesting,
        IpV6PdState::Bound { iapd, .. } => {
            lease_projection(iapd, wan_addr).map_or(PdRuntime::Soliciting, PdRuntime::Bound)
        }
        IpV6PdState::Renew { iapd, .. } | IpV6PdState::WaitToRebind { iapd, .. } => {
            lease_projection(iapd, wan_addr).map_or(PdRuntime::Soliciting, PdRuntime::Renewing)
        }
        IpV6PdState::Rebind { iapd, .. } => {
            lease_projection(iapd, wan_addr).map_or(PdRuntime::Soliciting, PdRuntime::Rebinding)
        }
        IpV6PdState::Release { .. } | IpV6PdState::Decline | IpV6PdState::Stop => {
            PdRuntime::Stopped
        }
    }
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

fn prefix_remaining_by_wall_clock(prefix: &LDIAPrefix) -> Duration {
    let elapsed = (get_f64_timestamp() - prefix.last_update_time).max(0.0);
    Duration::from_secs(prefix.valid_lifetime as u64)
        .saturating_sub(Duration::from_secs_f64(elapsed))
}

fn retirement_grace(remaining: Duration) -> Duration {
    remaining.min(PD_PREFIX_RETIRE_GRACE)
}

/// The old `/128` only needs a deprecation hint. Its `valid_lft` is set to the
/// grace period, so the kernel removes the address on its own when it expires.
fn plan_wan_addr_deprecation(
    previous_wan_addr: Option<Ipv6Addr>,
    new_wan_addr: Option<Ipv6Addr>,
    previous_remaining: Duration,
) -> Option<(Ipv6Addr, Duration)> {
    let old_addr = previous_wan_addr?;
    if new_wan_addr == Some(old_addr) {
        return None;
    }

    let grace = retirement_grace(previous_remaining);
    if grace.is_zero() {
        return None;
    }

    Some((old_addr, grace))
}

fn deprecate_previous_pd_address(
    previous_wan_addr: Option<Ipv6Addr>,
    new_wan_addr: Option<Ipv6Addr>,
    previous_remaining: Duration,
    iface_name: &str,
) {
    let Some((wan_addr, grace)) =
        plan_wan_addr_deprecation(previous_wan_addr, new_wan_addr, previous_remaining)
    else {
        return;
    };
    let valid_lifetime = grace.as_secs().clamp(1, u32::MAX as u64) as u32;
    deprecate_iface_ip(wan_addr, 128, iface_name, valid_lifetime);
    tracing::info!(
        iface = iface_name,
        %wan_addr,
        valid_lifetime,
        "Deprecated previous DHCPv6 PD WAN address; the kernel removes it when valid_lft expires"
    );
}

/// Send the packet for the current state and report state-machine side effects.
async fn send_current_status_packet(
    my_client_id: &[u8],
    send_socket: &UdpSocket,
    current_status: &mut IpV6PdState,
) -> SendStatusOutcome {
    if active_prefix_remaining(current_status).is_some_and(|remaining| remaining.is_zero()) {
        tracing::warn!(
            state = state_label(current_status),
            "DHCPv6 PD prefix valid lifetime expired; restarting solicitation"
        );
        *current_status = IpV6PdState::Solicit { xid: get_new_ipv6_xid() };
        return SendStatusOutcome::PREFIX_EXPIRED;
    }

    let remaining_before = active_prefix_remaining(current_status);
    match current_status {
        IpV6PdState::Solicit { xid } => {
            let mut msg = v6::Message::new(v6::MessageType::Solicit);
            msg.set_opts(get_solicit_options());
            msg.set_xid_num(*xid);
            msg.opts_mut().insert(v6::DhcpOption::ClientId(my_client_id.to_vec()));

            tracing::debug!(xid, "Sending DHCPv6 PD Solicit");
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

            tracing::debug!(
                xid = *xid,
                send_times = *send_times,
                server_id = ?service_id,
                "Sending DHCPv6 PD Request"
            );
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
            tracing::info!(
                t1 = iapd.t1,
                t2 = iapd.t2,
                bound_elapsed_secs = bound_time.elapsed().as_secs_f64(),
                remaining_secs = ?remaining_before.map(|d| d.as_secs_f64()),
                "DHCPv6 PD t1 reached; transitioning Bound -> Renew"
            );
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

            tracing::debug!(
                xid = *xid,
                server_id = ?service_id,
                t1 = iapd.t1,
                t2 = iapd.t2,
                bound_elapsed_secs = bound_time.elapsed().as_secs_f64(),
                remaining_secs = ?remaining_before.map(|d| d.as_secs_f64()),
                "Sending DHCPv6 PD Renew"
            );
            send_data(&send_msg, send_socket, None).await;

            let t2 = if iapd.t2 == 0 { IPV6_T2_DEFAULT } else { iapd.t2 as u64 };
            let t2 = t2 / 10 * 8;
            // Reach 80% wait to rebind
            if bound_time.elapsed().as_secs() >= t2 {
                tracing::warn!(
                    bound_elapsed_secs = bound_time.elapsed().as_secs_f64(),
                    rebind_threshold_secs = t2,
                    "Renew turn to WaitToRebind"
                );
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
            tracing::warn!(
                bound_elapsed_secs = bound_time.elapsed().as_secs_f64(),
                remaining_secs = ?remaining_before.map(|d| d.as_secs_f64()),
                "WaitToRebind turn to Rebind"
            );
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

            tracing::debug!(
                xid = *xid,
                rebind_elapsed_secs = rebind_time.elapsed().as_secs_f64(),
                remaining_secs = ?remaining_before.map(|d| d.as_secs_f64()),
                "Sending DHCPv6 PD Rebind"
            );
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
) -> (u64, Duration) {
    let current_timeout = status_timeout_duration(current_status, prev_timeout_times);

    timeout.set(tokio::time::sleep(current_timeout));
    (prev_timeout_times + 1, current_timeout)
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
    chain_id: u16,
    iface_name: &str,
    ifindex: u32,
    my_client_id: &[u8],
    current_status: &mut IpV6PdState,
    (msg, msg_addr): (Vec<u8>, SocketAddr),
    wan_route_info: &RouteTargetInfo,
    route_service: &IpRouteService,
    chain_dataplane: &WanLinkDataplane,
    prefix_map: &IAPrefixMap,
    mac_addr: &Option<MacAddr>,
    shared_wan_iid: &u64,
    current_wan_addr: &mut Option<Ipv6Addr>,
    prefix_sender: &IAPrefixEventSender,
    expected_pd_len: u8,
    link_state: &LinkStateHandle,
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
    tracing::debug!(
        iface = iface_name,
        %link_id,
        state = state_label(current_status),
        message_type = ?new_v6_msg.msg_type(),
        xid = new_v6_msg.xid_num(),
        from = %msg_addr,
        "DHCPv6 PD message received"
    );

    if new_v6_msg.xid_num() != current_status.get_xid() {
        tracing::debug!(
            iface = iface_name,
            %link_id,
            state = state_label(current_status),
            expected_xid = current_status.get_xid(),
            received_xid = new_v6_msg.xid_num(),
            "Ignoring DHCPv6 PD message with unmatched xid"
        );
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
                            let previous_prefix = prefix_map.load_actual(&link_id);
                            let previous_wan_addr = *current_wan_addr;
                            let previous_remaining = active_prefix_remaining(current_status)
                                .or_else(|| {
                                    previous_prefix.as_ref().map(prefix_remaining_by_wall_clock)
                                })
                                .unwrap_or(Duration::ZERO);
                            let previous_state = state_label(current_status);

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

                            let wan_addr = derive_wan_pd_addr(&ia_prefix, *shared_wan_iid);
                            let same_prefix = previous_prefix.as_ref().is_some_and(|old| {
                                old.prefix_ip == ia_prefix.prefix_ip
                                    && old.prefix_len == ia_prefix.prefix_len
                            });
                            let same_addr = previous_wan_addr == wan_addr;
                            let action = if previous_prefix.is_none() && previous_wan_addr.is_none()
                            {
                                "acquire"
                            } else if same_prefix && same_addr {
                                "refresh"
                            } else {
                                "replace"
                            };
                            tracing::info!(
                                iface = iface_name,
                                %link_id,
                                from = previous_state,
                                action,
                                old_prefix = ?previous_prefix
                                    .as_ref()
                                    .map(|p| (p.prefix_ip, p.prefix_len)),
                                new_prefix = %ia_prefix.prefix_ip,
                                new_prefix_len = ia_prefix.prefix_len,
                                old_wan_addr = ?previous_wan_addr,
                                new_wan_addr = ?wan_addr,
                                old_remaining_secs = previous_remaining.as_secs_f64(),
                                preferred_lifetime = ia_prefix.preferred_lifetime,
                                valid_lifetime = ia_prefix.valid_lifetime,
                                t1 = iapd.t1,
                                t2 = iapd.t2,
                                gateway = %ipv6addr,
                                "Applying DHCPv6 PD lease"
                            );

                            // Install the new lease first, then deprecate the old
                            // prefix. This avoids deleting the only usable address
                            // before the replacement is ready.
                            let mut info = wan_route_info.clone();
                            if let Some(wan_addr) = wan_addr {
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
                            route_service
                                .insert_ipv6_link_route(
                                    link_id,
                                    WanRouteTarget::link(chain_id, info),
                                )
                                .await;
                            replace_ip_route(
                                &ia_prefix,
                                ipv6addr,
                                iface_name,
                                ifindex,
                                mac_addr,
                                chain_dataplane,
                            );
                            let wan_v6_prefix = WanV6Prefix {
                                prefix_ip: ia_prefix.prefix_ip,
                                prefix_len: ia_prefix.prefix_len,
                            };
                            prefix_map.store(link_id, ia_prefix, expected_pd_len);
                            // Publish the bound prefix and derived WAN /128 so
                            // the nat6 section can start; unchanged renewals
                            // deduplicate.
                            link_state.set_v6_prefix(wan_v6_prefix, wan_addr);
                            *current_wan_addr = wan_addr;
                            let _ = prefix_sender.send(IAPrefixEvent::Updated { link_id }).await;
                            deprecate_previous_pd_address(
                                previous_wan_addr,
                                wan_addr,
                                previous_remaining,
                                iface_name,
                            );
                            tracing::info!(
                                iface = iface_name,
                                %link_id,
                                wan_addr = ?wan_addr,
                                action,
                                "DHCPv6 PD address and route update sequence completed"
                            );
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
    chain_dataplane: &WanLinkDataplane,
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

    chain_dataplane.bind_wan_ipv6(ifindex, iapd.prefix_ip, Some(route_ip), iapd.prefix_len, *mac);
    match result {
        Ok(output) if output.status.success() => {
            tracing::info!(
                iface = iface_name,
                prefix = %format!("{}/{}", iapd.prefix_ip, iapd.prefix_len),
                gateway = %route_ip,
                expires = iapd.valid_lifetime,
                "Replaced DHCPv6 PD source route"
            );
        }
        Ok(output) => {
            tracing::error!(
                iface = iface_name,
                prefix = %format!("{}/{}", iapd.prefix_ip, iapd.prefix_len),
                gateway = %route_ip,
                status = ?output.status,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "failed to replace DHCPv6 PD source route"
            );
        }
        Err(e) => tracing::error!(iface = iface_name, "{e:?}"),
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

    match result {
        Ok(output) if output.status.success() => {
            tracing::info!(
                iface = iface_name,
                prefix = %format!("{}/{}", iapd.prefix_ip, iapd.prefix_len),
                "Removed DHCPv6 PD source route"
            );
        }
        Ok(output) => {
            tracing::warn!(
                iface = iface_name,
                prefix = %format!("{}/{}", iapd.prefix_ip, iapd.prefix_len),
                status = ?output.status,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "failed to remove DHCPv6 PD source route"
            );
        }
        Err(err) => {
            tracing::error!(?err, "failed to remove expired IPv6 PD source route");
        }
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
    fn pd_runtime_projection_maps_fsm_phases() {
        let wan_ip: Ipv6Addr = "2001:db8:1200::8000:0:0:1234".parse().unwrap();
        assert!(matches!(
            pd_runtime_projection(&IpV6PdState::init_status(), None),
            PdRuntime::Soliciting
        ));

        let request = IpV6PdState::Request {
            xid: 1,
            service_id: Vec::new(),
            iapd: iapd(4, 8, 30),
            service_sock: "[::1]:547".parse().unwrap(),
            server_unicast: None,
            send_times: 0,
        };
        assert!(matches!(pd_runtime_projection(&request, None), PdRuntime::Requesting));

        let bound = IpV6PdState::Bound {
            xid: 1,
            service_id: Vec::new(),
            iapd: iapd(4, 8, 30),
            server_unicast: None,
            bound_time: Instant::now(),
        };
        assert_eq!(
            pd_runtime_projection(&bound, Some(wan_ip)),
            PdRuntime::Bound(PdLease {
                prefix_ip: "2001:db8:1200::".parse().unwrap(),
                prefix_len: 56,
                valid_secs: 30,
                preferred_secs: 30,
                wan_ip: Some(wan_ip),
            })
        );

        let renew = IpV6PdState::Renew {
            xid: 1,
            service_id: Vec::new(),
            iapd: iapd(4, 8, 30),
            server_unicast: None,
            renew_time: Instant::now(),
            bound_time: Instant::now(),
        };
        assert!(matches!(pd_runtime_projection(&renew, Some(wan_ip)), PdRuntime::Renewing(_)));

        let wait_to_rebind = IpV6PdState::WaitToRebind {
            xid: 1,
            service_id: Vec::new(),
            iapd: iapd(4, 8, 30),
            server_unicast: None,
            bound_time: Instant::now(),
        };
        assert!(matches!(
            pd_runtime_projection(&wait_to_rebind, Some(wan_ip)),
            PdRuntime::Renewing(_)
        ));

        let rebind = IpV6PdState::Rebind {
            xid: 1,
            service_id: Vec::new(),
            iapd: iapd(4, 8, 30),
            server_unicast: None,
            rebind_time: Instant::now(),
            bound_time: Instant::now(),
        };
        assert!(matches!(pd_runtime_projection(&rebind, Some(wan_ip)), PdRuntime::Rebinding(_)));

        assert!(matches!(pd_runtime_projection(&IpV6PdState::Stop, None), PdRuntime::Stopped));
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

    #[test]
    fn state_labels_are_distinct_for_every_phase() {
        let labels = [
            state_label(&IpV6PdState::init_status()),
            state_label(&IpV6PdState::Bound {
                xid: 1,
                service_id: Vec::new(),
                iapd: iapd(4, 8, 30),
                server_unicast: None,
                bound_time: Instant::now(),
            }),
            state_label(&IpV6PdState::Renew {
                xid: 1,
                service_id: Vec::new(),
                iapd: iapd(4, 8, 30),
                server_unicast: None,
                renew_time: Instant::now(),
                bound_time: Instant::now(),
            }),
            state_label(&IpV6PdState::WaitToRebind {
                xid: 1,
                service_id: Vec::new(),
                iapd: iapd(4, 8, 30),
                server_unicast: None,
                bound_time: Instant::now(),
            }),
            state_label(&IpV6PdState::Rebind {
                xid: 1,
                service_id: Vec::new(),
                iapd: iapd(4, 8, 30),
                server_unicast: None,
                rebind_time: Instant::now(),
                bound_time: Instant::now(),
            }),
        ];

        assert_eq!(labels, ["Solicit", "Bound", "Renew", "WaitToRebind", "Rebind"]);
    }

    #[test]
    fn address_change_deprecates_old_address_for_bounded_grace() {
        let old_wan: Ipv6Addr = "2001:db8:1000::1".parse().unwrap();
        let new_wan: Ipv6Addr = "2001:db8:2000::1".parse().unwrap();

        let (addr, grace) =
            plan_wan_addr_deprecation(Some(old_wan), Some(new_wan), Duration::from_secs(900))
                .expect("address change must deprecate the old address");

        assert_eq!(addr, old_wan);
        assert_eq!(grace, PD_PREFIX_RETIRE_GRACE);
    }

    #[test]
    fn deprecation_grace_never_exceeds_old_valid_lifetime() {
        let old_wan: Ipv6Addr = "2001:db8:1000::1".parse().unwrap();
        let new_wan: Ipv6Addr = "2001:db8:2000::1".parse().unwrap();

        let (_, grace) =
            plan_wan_addr_deprecation(Some(old_wan), Some(new_wan), Duration::from_secs(45))
                .expect("address change must deprecate the old address");

        assert_eq!(grace, Duration::from_secs(45));
    }

    #[test]
    fn unchanged_address_is_not_deprecated() {
        let wan_addr: Ipv6Addr = "2001:db8:1000::1".parse().unwrap();

        assert!(
            plan_wan_addr_deprecation(Some(wan_addr), Some(wan_addr), Duration::from_secs(300))
                .is_none()
        );
    }

    #[test]
    fn address_without_remaining_lifetime_is_not_deprecated() {
        let old_wan: Ipv6Addr = "2001:db8:1000::1".parse().unwrap();
        let new_wan: Ipv6Addr = "2001:db8:2000::1".parse().unwrap();

        assert!(plan_wan_addr_deprecation(Some(old_wan), Some(new_wan), Duration::ZERO).is_none());
    }
}

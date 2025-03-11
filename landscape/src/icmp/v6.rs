use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use landscape_common::error::LdResult;
use landscape_common::global_const::{LDIAPrefix, LD_PD_WATCHES};
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::dump::icmp::v6::option_codes::{
    IcmpV6Option, IcmpV6Options, PrefixInformation, RouteInformation,
};
use crate::dump::icmp::v6::options::{Icmpv6Message, RouterAdvertisement};
use crate::iface::ip::addresses_by_iface_name;
use crate::macaddr::MacAddr;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

static ICMPV6_MULTICAST_ROUTER: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x2);
static ICMPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1);
pub struct ICMPv6ConfigInfo {
    watch_ia_prefix: LDIAPrefix,
    subnet: Ipv6Addr,
    subnet_prefix: u8,
    subnet_router: Ipv6Addr,
}
pub async fn icmp_ra_server(
    // 子网前缀长度
    subnet_prefix: u8,
    // 子网索引
    subnet_index: u128,
    mac_addr: MacAddr,
    iface_name: String,
    depend_iface: String,
    service_status: DefaultWatchServiceStatus,
) -> LdResult<()> {
    // TODO: ip link set ens5 addrgenmode none
    // OR
    // # 禁用IPv6路由器请求
    // sudo sysctl -w net.ipv6.conf.ens5.router_solicitations=0
    // # 对所有接口禁用
    // sudo sysctl -w net.ipv6.conf.all.router_solicitations=0
    // sudo sysctl -w net.ipv6.conf.default.router_solicitations=0

    //  sysctl -w net.ipv6.conf.all.forwarding=1
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    //
    // socket.set_multicast_loop_v6(false)?;
    // 设置 IPv6 单播 Hop Limit 为 255
    socket.set_unicast_hops_v6(255)?;

    // 如果您发送多播消息，还需要设置多播 Hop Limit
    socket.set_multicast_hops_v6(255)?;
    socket.bind_device(Some(iface_name.as_bytes()))?;

    let address = addresses_by_iface_name(iface_name.to_string()).await;
    let mut link_ipv6_addr = None;
    let mut link_ifindex = 0;
    for addr in address.iter() {
        match addr.address {
            std::net::IpAddr::V4(_) => continue,
            std::net::IpAddr::V6(ipv6_addr) => {
                if ipv6_addr.is_unicast_link_local() {
                    link_ipv6_addr = Some(ipv6_addr);
                    link_ifindex = addr.ifindex;
                }
            }
        }
    }

    let Some(ipaddr) = link_ipv6_addr else {
        tracing::error!("can not find unicast_link_local");
        return Ok(());
    };
    tracing::info!("address {:?}", ipaddr);
    tracing::info!("link_ifindex {:?}", link_ifindex);

    socket.join_multicast_v6(&ICMPV6_MULTICAST_ROUTER, link_ifindex).unwrap();

    let udp_socket = UdpSocket::from_std(socket.into()).unwrap();
    let send_socket = Arc::new(udp_socket);

    let recive_socket_raw = send_socket.clone();

    let (message_tx, mut message_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    // let data = [133, 0, 199, 38, 0, 0, 0, 1];
    // let addr = SocketAddrV6::new(ICMPV6_MULTICAST, 0, 0, 4);
    // send_socket.send_to(&data, addr).await.unwrap();
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

        tracing::info!("ICMP recv loop down");
    });

    service_status.just_change_status(ServiceStatus::Running);
    let mut ia_config_watch = LD_PD_WATCHES.get_ia_prefix(&depend_iface).await;

    let mut advertised_ip: HashSet<Ipv6Addr> = HashSet::new();
    let mut current_config_info: Option<ICMPv6ConfigInfo> = None;
    // let mut count_down = LdCountdown::new(Duration::from_secs(0));

    let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));
    // init
    let ia_prefix = ia_config_watch.borrow().clone();
    if let Some(ia_prefix) = ia_prefix {
        current_config_info = Some(
            update_current_info(ia_prefix, subnet_prefix, subnet_index, expire_time.as_mut()).await,
        );
    }
    tracing::info!("ICMP v6 RA Server Running");
    let mut interval = tokio::time::interval(Duration::from_secs(500));

    loop {
        let mut service_status_subscribe = service_status.subscribe();
        tokio::select! {
            _ =interval.tick() => {
                interval_msg(
                    &mac_addr,
                    &current_config_info,
                    &send_socket,
                    expire_time.deadline()
                ).await;
            }
            // 发送时间为 0 的
            _ = expire_time.as_mut() => {
                current_config_info = None;
            }
            message_result = message_rx.recv() => {
                // 处理接收到的数据包
                match message_result {
                    Some(data) => {
                        // handle RS
                        handle_rs_msg(
                            &mac_addr,
                            &current_config_info,
                            data,
                            &send_socket,
                            &mut advertised_ip,
                            expire_time.deadline()
                        ).await;
                    }
                    // message_rx close
                    None => break
                }
            },
            // IA_PREFIX change
            change_result = ia_config_watch.changed() => {
                tracing::info!("IA_PREFIX update");
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }
                let ia_prefix = ia_config_watch.borrow().clone();
                if let Some(ia_prefix) = ia_prefix {
                    current_config_info = Some(
                        update_current_info(
                            ia_prefix,
                            subnet_prefix,
                            subnet_index,
                            expire_time.as_mut()
                        ).await
                    );
                }
            }
            // status change
            change_result = service_status_subscribe.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }

                if service_status.is_exit() {
                    service_status.just_change_status(ServiceStatus::Stop);
                    tracing::info!("release send and stop");
                    break;
                }
            }
        }
    }

    tracing::info!("ICMP v6 RA Server Stop: {:#?}", service_status);
    if !service_status.is_stop() {
        service_status.just_change_status(ServiceStatus::Stop);
    }
    Ok(())
}

async fn update_current_info(
    ia_prefix: LDIAPrefix,
    subnet_prefix: u8,
    subnet_index: u128,
    mut expire_time: Pin<&mut tokio::time::Sleep>,
) -> ICMPv6ConfigInfo {
    expire_time.set(tokio::time::sleep(Duration::from_secs(ia_prefix.valid_lifetime as u64)));
    let (subnet, route) = allocate_subnet(&ia_prefix, subnet_prefix, subnet_index);

    //  ip -6 addr add  fd00:abcd:1234::1/64 dev ens5

    // TODO: setting current router, default ::1
    // std::process::Command::new("ip").args(["-6", "addr", "add", format!(), status]).output();
    ICMPv6ConfigInfo {
        watch_ia_prefix: ia_prefix,
        subnet,
        subnet_prefix,
        subnet_router: route,
    }
}
async fn interval_msg(
    my_mac_addr: &MacAddr,
    current_config_info: &Option<ICMPv6ConfigInfo>,
    send_socket: &UdpSocket,
    current_deadline: Instant,
) {
    let Some(current_info) = current_config_info else {
        tracing::error!("current config_info is None, can not handle message");
        return;
    };
    let remain = (current_deadline - Instant::now()).as_secs() as u32;
    tracing::debug!("remain: {remain:?}");
    let valid_time = current_info.watch_ia_prefix.valid_lifetime
        - current_info.watch_ia_prefix.preferred_lifetime;
    let preferred_lifetime = if remain > valid_time { remain - valid_time } else { 0 };
    let mut opts = IcmpV6Options::new();
    opts.insert(IcmpV6Option::SourceLinkLayerAddress(my_mac_addr.octets().to_vec()));
    opts.insert(IcmpV6Option::PrefixInformation(PrefixInformation::new(
        current_info.subnet_prefix,
        remain,
        preferred_lifetime,
        current_info.subnet,
    )));
    opts.insert(IcmpV6Option::RouteInformation(RouteInformation::new(
        current_info.watch_ia_prefix.prefix_len,
        current_info.watch_ia_prefix.prefix_ip,
    )));
    opts.insert(IcmpV6Option::MTU(1500));
    opts.insert(IcmpV6Option::AdvertisementInterval(60_000));
    // opts.insert(IcmpV6Option::RecursiveDNSServer((60_000, current_info.subnet_router)));
    let msg = Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(opts));
    send_data(&msg, send_socket, SocketAddr::new(IpAddr::V6(ICMPV6_MULTICAST), 0)).await;
}

async fn handle_rs_msg(
    my_mac_addr: &MacAddr,
    current_config_info: &Option<ICMPv6ConfigInfo>,
    (msg, target_addr): (Vec<u8>, SocketAddr),
    send_socket: &UdpSocket,
    ips: &mut HashSet<Ipv6Addr>,
    current_deadline: Instant,
) {
    let Some(current_info) = current_config_info else {
        tracing::error!("current config_info is None, can not handle message");
        return;
    };

    let icmp_v6_msg = Icmpv6Message::decode(&mut Decoder::new(&msg));
    let icmp_v6_msg = match icmp_v6_msg {
        Ok(msg) => msg,
        Err(e) => {
            tracing::error!("decode msg error: {e:?}");
            return;
        }
    };

    let target_ip = match target_addr {
        SocketAddr::V4(socket_addr_v4) => {
            tracing::debug!("not ipv6 msg ignore: {socket_addr_v4:?}");
            return;
        }
        SocketAddr::V6(socket_addr_v6) => {
            // println!("scope_id {:?}", socket_addr_v6.scope_id());
            socket_addr_v6.ip().to_owned()
        }
    };

    match icmp_v6_msg {
        Icmpv6Message::RouterSolicitation(router_solicitation) => {
            tracing::debug!("router_solicitation: {router_solicitation:?}");
            let remain = (current_deadline - Instant::now()).as_secs() as u32;
            tracing::debug!("remain: {remain:?}");
            tracing::debug!("target_ip: {target_ip:?}");
            let valid_time = current_info.watch_ia_prefix.valid_lifetime
                - current_info.watch_ia_prefix.preferred_lifetime;
            let preferred_lifetime = if remain > valid_time { remain - valid_time } else { 0 };
            let mut opts = IcmpV6Options::new();
            opts.insert(IcmpV6Option::SourceLinkLayerAddress(my_mac_addr.octets().to_vec()));
            opts.insert(IcmpV6Option::PrefixInformation(PrefixInformation::new(
                current_info.subnet_prefix,
                remain,
                preferred_lifetime,
                current_info.subnet,
            )));
            opts.insert(IcmpV6Option::RouteInformation(RouteInformation::new(
                current_info.watch_ia_prefix.prefix_len,
                current_info.watch_ia_prefix.prefix_ip,
            )));
            opts.insert(IcmpV6Option::MTU(1500));
            opts.insert(IcmpV6Option::AdvertisementInterval(60_000));
            // opts.insert(IcmpV6Option::RecursiveDNSServer((60_000, current_info.subnet_router)));
            let msg = Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(opts));
            send_data(&msg, send_socket, target_addr).await;
        }
        Icmpv6Message::RouterAdvertisement(_) => {}
        Icmpv6Message::Unassigned(msg_type, _) => {
            tracing::error!("recv not handle Icmpv6Message msg_type: {msg_type:?}");
        }
    }
}

async fn send_data(msg: &Icmpv6Message, send_socket: &UdpSocket, target_sock: SocketAddr) {
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    if let Err(e) = msg.encode(&mut e) {
        tracing::error!("msg encode error: {e:?}");
        return;
    }
    match send_socket.send_to(&buf, &target_sock).await {
        Ok(len) => {
            tracing::debug!("send icmpv6 fram: {msg:?},  len: {len:?}");
        }
        Err(e) => {
            tracing::error!("error: {:?}", e);
        }
    }
}

/// 根据传入的前缀、目标子网前缀长度以及子网索引，返回对应子网的网络地址和一个路由器地址
fn allocate_subnet(
    prefix: &LDIAPrefix,
    sub_prefix_len: u8,
    subnet_index: u128,
) -> (Ipv6Addr, Ipv6Addr) {
    // 子网前缀长度必须大于等于原始前缀长度
    assert!(sub_prefix_len >= prefix.prefix_len, "子网前缀长度必须大于等于原始前缀长度");

    // 计算可划分的子网总数
    let max_subnets = 1u128 << (sub_prefix_len - prefix.prefix_len);
    assert!(subnet_index < max_subnets, "subnet_index 超出可用子网范围");

    // 将 IPv6 地址转换为 u128 类型进行位运算
    let prefix_u128 = u128::from(prefix.prefix_ip);

    // 计算父网络地址（假设 prefix_ip 已经对齐到 prefix_len）
    let parent_mask = (!0u128) << (128 - prefix.prefix_len);
    let parent_network = prefix_u128 & parent_mask;

    // 计算子网掩码：前 sub_prefix_len 位为 1，其余为 0
    let sub_mask = (!0u128) << (128 - sub_prefix_len);

    // 基础子网地址，对齐到子网前缀边界
    let base_network = parent_network & sub_mask;

    // 每个子网的地址块大小
    let subnet_size = 1u128 << (128 - sub_prefix_len);

    // 根据子网索引计算目标子网的网络地址
    let subnet_network = base_network + (subnet_index * subnet_size);

    // 选择该子网的第一个地址作为路由器地址
    let router_address = subnet_network + 1;

    (Ipv6Addr::from(subnet_network), Ipv6Addr::from(router_address))
}

#[cfg(test)]
mod tests {
    use crate::icmp::v6::allocate_subnet;
    use landscape_common::global_const::LDIAPrefix;

    #[test]
    fn test() {
        // 示例：假设原始前缀为 2001:db8::/48，我们希望划分出 /64 的子网，并选择第 2 个子网（索引从 0 开始）
        let ldia_prefix = LDIAPrefix {
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            prefix_len: 48,
            prefix_ip: "2001:db8::".parse().unwrap(),
        };
        let sub_prefix_len = 64;
        let subnet_index = 2; // 0 表示第一个子网，1 表示第二个子网，以此类推
        let (subnet_network, router_addr) =
            allocate_subnet(&ldia_prefix, sub_prefix_len, subnet_index);
        println!("子网网络地址: {}/{}", subnet_network, sub_prefix_len);
        println!("路由器地址: {}", router_addr);
    }
}

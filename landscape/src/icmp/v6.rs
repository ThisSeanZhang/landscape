use dhcproto::{Decodable, Decoder};
use landscape_common::error::LdResult;
use landscape_common::global_const::{LDIAPrefix, LD_PD_WATCHES};
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::dump::icmp::v6::options::Icmpv6Message;
use crate::iface::ip::addresses_by_iface_name;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

static ICMPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x2);

pub async fn icmp_ra_server(
    iface_name: String,
    service_status: DefaultWatchServiceStatus,
) -> LdResult<()> {
    // TODO: ip link set ens5 addrgenmode none
    // OR
    // # 禁用IPv6路由器请求
    // sudo sysctl -w net.ipv6.conf.ens5.router_solicitations=0
    // # 对所有接口禁用
    // sudo sysctl -w net.ipv6.conf.all.router_solicitations=0
    // sudo sysctl -w net.ipv6.conf.default.router_solicitations=0

    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    //
    // socket.set_multicast_loop_v6(false)?;
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

    socket.join_multicast_v6(&ICMPV6_MULTICAST, link_ifindex).unwrap();

    let udp_socket = UdpSocket::from_std(socket.into()).unwrap();
    let send_socket = Arc::new(udp_socket);

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

        tracing::info!("ICMP recv loop down");
    });

    service_status.just_change_status(ServiceStatus::Running);
    let mut ia_config_watch = LD_PD_WATCHES.get_ia_prefix(&iface_name).await;

    let mut advertised_ip: HashSet<Ipv6Addr> = HashSet::new();
    let mut cueernt_ia_prefix = None;
    // let mut count_down = LdCountdown::new(Duration::from_secs(0));

    let mut expire_time = Box::pin(tokio::time::sleep(Duration::from_secs(0)));
    tracing::info!("ICMP v6 RA Server Running");
    loop {
        let mut service_status_subscribe = service_status.subscribe();
        tokio::select! {
            // 发送时间为 0 的
            _ = expire_time.as_mut() => {

            }
            message_result = message_rx.recv() => {
                // 处理接收到的数据包
                match message_result {
                    Some(data) => {
                        // handle RS
                        handle_rs_msg(&cueernt_ia_prefix, data, &send_socket, &mut advertised_ip, expire_time.deadline()).await;
                    }
                    // message_rx close
                    None => break
                }
            },
            // IA_PREFIX change
            change_result = ia_config_watch.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }
                cueernt_ia_prefix = ia_config_watch.borrow().clone();
                if let Some(ia_prefix) = &cueernt_ia_prefix {
                    expire_time.set(tokio::time::sleep(Duration::from_secs(ia_prefix.valid_lifetime as u64)));
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

async fn handle_rs_msg(
    cueernt_ia_prefix: &Option<LDIAPrefix>,
    (msg, target_addr): (Vec<u8>, SocketAddr),
    send_socket: &UdpSocket,
    ips: &mut HashSet<Ipv6Addr>,
    current_deadline: Instant,
) {
    let Some(ia_prefix) = cueernt_ia_prefix else {
        tracing::error!("cueernt ia_prefix is None, can not handle message");
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
            let remain = (current_deadline - Instant::now()).as_secs();
            tracing::debug!("remain: {remain:?}");
            tracing::debug!("target_ip: {target_ip:?}");
        }
        Icmpv6Message::RouterAdvertisement(_) => {}
        Icmpv6Message::Unassigned(msg_type, _) => {
            tracing::error!("recv not handle Icmpv6Message msg_type: {msg_type:?}");
        }
    }
}

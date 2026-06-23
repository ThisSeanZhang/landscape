use bytes::BytesMut;
use landscape_common::error::LdResult;
use landscape_common::event::hub::{IPv6AssignEvent, IPv6AssignEventSender, IPv6AssignInfo};
use landscape_common::ipv6::ra::RouterFlags;
use landscape_common::lan_services::ipv6_ra::{IPv6NAInfo, IPv6NAInfoItem};
use landscape_common::net::MacAddr;
use landscape_common::net_proto::icmpv6::messages::{Icmpv6Message, RouterAdvertisement};
use landscape_common::net_proto::icmpv6::options::{IcmpV6Option, IcmpV6Options};
use landscape_common::net_proto::NetProtoCodec;
use landscape_common::service::{ServiceStatus, WatchService};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{watch, RwLock};
use uuid::Uuid;

use crate::ipv6::prefix::IPv6PrefixRuntime;
use crate::netlink::address::addresses_by_iface_name;
use dashmap::DashMap;

static ICMPV6_MULTICAST_ROUTER: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x2);
static ICMPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1);

#[tracing::instrument(skip(
    mac_addr,
    service_status,
    runtime,
    change_notify,
    assigned_ips,
    onlink_runtime,
    onlink_change_notify,
    ipv6_assign_sender,
    device_id_map
))]
pub async fn icmp_ra_server(
    ad_interval: u32,
    ra_flag: RouterFlags,
    mac_addr: MacAddr,
    iface_name: String,
    service_status: WatchService,
    runtime: &IPv6PrefixRuntime,
    mut change_notify: watch::Receiver<()>,
    assigned_ips: Arc<RwLock<IPv6NAInfo>>,
    autonomous: bool,
    // Optional: additional prefixes advertised with A=0 (on-link only, no SLAAC).
    // Used in SlaacDhcpv6 mode so clients can detect DHCPv6 prefix changes via RA.
    onlink_runtime: Option<&IPv6PrefixRuntime>,
    mut onlink_change_notify: Option<watch::Receiver<()>>,
    link_ifindex: u32,
    ipv6_assign_sender: IPv6AssignEventSender,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
) -> LdResult<()> {
    {
        let mut ips = assigned_ips.write().await;
        *ips = IPv6NAInfo::init();
        drop(ips);
    }
    // TODO: ip link set ens5 addrgenmode none
    // OR
    // # 禁用IPv6路由器请求
    // sudo sysctl -w net.ipv6.conf.ens5.router_solicitations=0
    // # 对所有接口禁用
    // sudo sysctl -w net.ipv6.conf.all.router_solicitations=0
    // sudo sysctl -w net.ipv6.conf.default.router_solicitations=0

    let ipv6_forwarding_path = format!("/proc/sys/net/ipv6/conf/{}/forwarding", iface_name);
    std::fs::write(&ipv6_forwarding_path, "1")
        .expect(&format!("set {} ipv6 forwarding error", iface_name));

    service_status.just_change_status(ServiceStatus::Staring);
    //  sysctl -w net.ipv6.conf.all.forwarding=1
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    //
    // socket.set_multicast_loop_v6(false)?;
    // 设置 IPv6 单播 Hop Limit 为 255
    socket.set_unicast_hops_v6(255)?;

    // 如果发送多播消息，还需要设置多播 Hop Limit
    socket.set_multicast_hops_v6(255)?;
    socket.bind_device(Some(iface_name.as_bytes()))?;

    let setting_result = crate::set_iface_ip_no_limit(
        &iface_name,
        std::net::IpAddr::V6(mac_addr.to_ipv6_link_local()),
        64,
    )
    .await;

    if !setting_result {
        tracing::error!("setting unicast_link_local error");
    }

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
        service_status.just_change_status(ServiceStatus::Failed);
        return Ok(());
    };
    tracing::info!("address {:?}", ipaddr);
    tracing::info!("link_ifindex {:?}", link_ifindex);

    socket.join_multicast_v6(&ICMPV6_MULTICAST_ROUTER, link_ifindex).unwrap();

    let udp_socket = UdpSocket::from_std(socket.into()).unwrap();
    let send_socket = Arc::new(udp_socket);

    let recive_socket_raw = send_socket.clone();

    let (message_tx, mut message_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    // Receive loop
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = recive_socket_raw.recv_from(&mut buf) => {
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

    // Consume the initial "unseen" state to prevent the first changed() call
    // from returning immediately in the select! loop
    change_notify.borrow_and_update();
    if let Some(ref mut rx) = onlink_change_notify {
        rx.borrow_and_update();
    }

    // RA main loop
    tracing::debug!("ICMP get IPv6 Prefix Watch");
    let ad_interval = ad_interval as u64;
    let mut interval = Box::pin(tokio::time::interval(Duration::from_secs(ad_interval)));

    let mut service_status_subscribe = service_status.subscribe();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                interval_msg(
                    &mac_addr,
                    &send_socket,
                    runtime,
                    ra_flag,
                    autonomous,
                    onlink_runtime,
                ).await;

                {
                    let relative_boot_time = runtime.relative_boot_time.elapsed().as_secs();
                    if relative_boot_time > ad_interval {
                        if let Ok(mut ips) = assigned_ips.try_write() {
                            let expired = ips.clean_expired_entries(relative_boot_time - ad_interval);
                            for item in expired {
                                let device_id = device_id_map.get(&item.mac).map(|r| *r.value());
                                let _ = ipv6_assign_sender.try_send(
                                    IPv6AssignEvent::Expired(IPv6AssignInfo {
                                        iface_name: iface_name.clone(),
                                        mac: item.mac,
                                        ip: item.ip,
                                        device_id,
                                    }),
                                );
                            }
                        }
                    }
                };
            }
            result = change_notify.changed() => {
                if result.is_err() {
                    tracing::warn!("prefix change sender dropped, no more notifications");
                    continue;
                }
                interval_msg(
                    &mac_addr,
                    &send_socket,
                    runtime,
                    ra_flag,
                    autonomous,
                    onlink_runtime,
                ).await;
            },
            result = async {
                match onlink_change_notify.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if result.is_err() {
                    tracing::warn!("onlink prefix change sender dropped");
                    continue;
                }
                interval_msg(
                    &mac_addr,
                    &send_socket,
                    runtime,
                    ra_flag,
                    autonomous,
                    onlink_runtime,
                ).await;
            },
            message_result = message_rx.recv() => {
                match message_result {
                    Some(data) => {
                        handle_rs_msg(
                            &mac_addr,
                            data,
                            &send_socket,
                            runtime,
                            ra_flag,
                            autonomous,
                            onlink_runtime,
                            assigned_ips.clone(),
                            link_ifindex,
                            &iface_name,
                            &ipv6_assign_sender,
                            &device_id_map,
                        ).await;
                    }
                    None => break
                }
            },
            change_result = service_status_subscribe.changed() => {
                tracing::debug!("ICMP v6 RA Service change");
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

    // Send deprecation RA: all current prefixes with lifetime=0 so clients
    // immediately stop using old prefixes (e.g., before service restarts with new config)
    send_deprecation_ra(&mac_addr, &send_socket, runtime, ra_flag, onlink_runtime).await;

    std::fs::write(&ipv6_forwarding_path, "0")
        .expect(&format!("set {} ipv6 forwarding error", iface_name));
    tracing::info!("ICMP v6 RA Server Stop: {:#?}", service_status);
    if !service_status.is_stop() {
        service_status.just_change_status(if service_status.is_exit() {
            ServiceStatus::Stop
        } else {
            ServiceStatus::Failed
        });
    }
    Ok(())
}

async fn interval_msg(
    my_mac_addr: &MacAddr,
    send_socket: &UdpSocket,
    runtime: &IPv6PrefixRuntime,
    ra_flag: RouterFlags,
    autonomous: bool,
    onlink_runtime: Option<&IPv6PrefixRuntime>,
) {
    build_and_send_ra(
        my_mac_addr,
        send_socket,
        SocketAddr::new(IpAddr::V6(ICMPV6_MULTICAST), 0),
        runtime,
        ra_flag,
        autonomous,
        onlink_runtime,
    )
    .await;
}

async fn handle_rs_msg(
    my_mac_addr: &MacAddr,
    (msg, target_addr): (Vec<u8>, SocketAddr),
    send_socket: &UdpSocket,
    runtime: &IPv6PrefixRuntime,
    ra_flag: RouterFlags,
    autonomous: bool,
    onlink_runtime: Option<&IPv6PrefixRuntime>,
    assigned_ips: Arc<RwLock<IPv6NAInfo>>,
    link_ifindex: u32,
    iface_name: &str,
    ipv6_assign_sender: &IPv6AssignEventSender,
    device_id_map: &DashMap<MacAddr, Uuid>,
) {
    let mut buf = BytesMut::from(msg.as_slice());
    let icmp_v6_msg = match Icmpv6Message::decode(&mut buf) {
        Ok(Some(msg)) => msg,
        Ok(None) => return,
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
        SocketAddr::V6(socket_addr_v6) => socket_addr_v6.ip().to_owned(),
    };

    match icmp_v6_msg {
        Icmpv6Message::RouterSolicitation(router_solicitation) => {
            tracing::debug!("router_solicitation: {router_solicitation:?}");
            tracing::debug!("target_ip: {target_ip:?}");
            build_and_send_ra(
                my_mac_addr,
                send_socket,
                target_addr,
                runtime,
                ra_flag,
                autonomous,
                onlink_runtime,
            )
            .await;
        }
        Icmpv6Message::RouterAdvertisement(_) => {}
        Icmpv6Message::NeighborAdvertisement(neighbor_advertisement) => {
            if let Some(IcmpV6Option::TargetLinkLayerAddress { addr, .. }) =
                neighbor_advertisement.opts.get(2)
            {
                let mac = MacAddr::from_arry(addr).unwrap();
                let data = IPv6NAInfoItem {
                    mac,
                    ip: target_ip,
                    relative_active_time: runtime.relative_boot_time.elapsed().as_secs(),
                };
                let mut write_lock = assigned_ips.write().await;
                write_lock.offered_ips.insert(data.get_cache_key(), data);
                drop(write_lock);

                let device_id = device_id_map.get(&mac).map(|r| *r.value());
                let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(IPv6AssignInfo {
                    iface_name: iface_name.to_string(),
                    mac,
                    ip: target_ip,
                    device_id,
                }));

                if let Err(e) = landscape_ebpf::base::ip_mac::upsert_ipv6_ip_mac(
                    link_ifindex,
                    target_ip,
                    mac,
                    *my_mac_addr,
                ) {
                    tracing::warn!("failed to prewarm ip_mac_v6 for ND {target_ip} -> {mac}: {e}");
                }
            } else {
                tracing::error!("read TargetLinkLayerAddress error: {neighbor_advertisement:?}");
            }
        }
        Icmpv6Message::Unassigned(msg_type, _) => {
            tracing::warn!("recv not handle Icmpv6Message msg_type: {msg_type:?}");
        }
    }
}

async fn send_data(msg: &Icmpv6Message, send_socket: &UdpSocket, target_sock: SocketAddr) {
    let mut buf = BytesMut::new();
    if let Err(e) = NetProtoCodec::encode(msg, &mut buf) {
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

/// Send a deprecation RA: all current prefixes with lifetime=0.
/// Tells clients to immediately deprecate old prefixes before service restarts with new config.
/// router_lifetime is kept normal so clients don't briefly lose their default router.
async fn send_deprecation_ra(
    my_mac_addr: &MacAddr,
    send_socket: &UdpSocket,
    runtime: &IPv6PrefixRuntime,
    ra_flag: RouterFlags,
    onlink_runtime: Option<&IPv6PrefixRuntime>,
) {
    let mut opts = IcmpV6Options::new();
    opts.insert(IcmpV6Option::source_link_layer_address(&my_mac_addr.octets()));

    let mut has_prefix = false;

    // Deprecate all main runtime prefixes
    for static_prefix in runtime.static_info.iter() {
        opts.insert(IcmpV6Option::prefix_information(
            static_prefix.sub_prefix_len,
            0,
            0,
            static_prefix.sub_prefix,
            false,
        ));
        has_prefix = true;
    }
    for (_, pd_prefix) in runtime.pd_info.iter() {
        let pd_prefix = pd_prefix.load();
        let Some(pd_prefix) = pd_prefix.as_ref() else {
            continue;
        };
        opts.insert(IcmpV6Option::prefix_information(
            pd_prefix.sub_prefix_len,
            0,
            0,
            pd_prefix.sub_prefix,
            false,
        ));
        has_prefix = true;
    }

    // Deprecate all onlink runtime prefixes
    if let Some(onlink_rt) = onlink_runtime {
        for static_prefix in onlink_rt.static_info.iter() {
            opts.insert(IcmpV6Option::prefix_information(
                static_prefix.sub_prefix_len,
                0,
                0,
                static_prefix.sub_prefix,
                false,
            ));
            has_prefix = true;
        }
        for (_, pd_prefix) in onlink_rt.pd_info.iter() {
            let pd_prefix = pd_prefix.load();
            let Some(pd_prefix) = pd_prefix.as_ref() else {
                continue;
            };
            opts.insert(IcmpV6Option::prefix_information(
                pd_prefix.sub_prefix_len,
                0,
                0,
                pd_prefix.sub_prefix,
                false,
            ));
            has_prefix = true;
        }
    }

    if !has_prefix {
        return;
    }

    tracing::info!("Sending deprecation RA (all prefixes lifetime=0)");

    // Use link-local as RDNSS — sub_router addresses are about to be removed,
    // but link-local is always reachable during the transition
    let link_local = my_mac_addr.to_ipv6_link_local();
    opts.insert(IcmpV6Option::recursive_dns_server(60_000, link_local));
    opts.insert(IcmpV6Option::mtu(1500));

    let msg = Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(ra_flag.into(), opts));
    send_data(&msg, send_socket, SocketAddr::new(IpAddr::V6(ICMPV6_MULTICAST), 0)).await;
}

async fn build_and_send_ra(
    my_mac_addr: &MacAddr,
    send_socket: &UdpSocket,
    target_addr: SocketAddr,
    runtime: &IPv6PrefixRuntime,
    ra_flag: RouterFlags,
    autonomous: bool,
    onlink_runtime: Option<&IPv6PrefixRuntime>,
) {
    let mut opts = IcmpV6Options::new();
    opts.insert(IcmpV6Option::source_link_layer_address(&my_mac_addr.octets()));

    // Link-local always FIRST (highly recommended for stability and SAS correctness)
    opts.insert(IcmpV6Option::recursive_dns_server(60_000, my_mac_addr.to_ipv6_link_local()));
    for static_prefix in runtime.static_info.iter() {
        opts.insert(IcmpV6Option::prefix_information(
            static_prefix.sub_prefix_len,
            600,
            300,
            static_prefix.sub_prefix,
            autonomous,
        ));

        opts.insert(IcmpV6Option::route_information(
            static_prefix.rt_prefix_len,
            static_prefix.rt_prefix,
        ));
        opts.insert(IcmpV6Option::recursive_dns_server(600, static_prefix.sub_router));
    }

    for (_, pd_prefix) in runtime.pd_info.iter() {
        let pd_prefix = pd_prefix.load();
        let Some(pd_prefix) = pd_prefix.as_ref() else {
            continue;
        };
        opts.insert(IcmpV6Option::prefix_information(
            pd_prefix.sub_prefix_len,
            600,
            300,
            pd_prefix.sub_prefix,
            autonomous,
        ));

        opts.insert(IcmpV6Option::route_information(pd_prefix.rt_prefix_len, pd_prefix.rt_prefix));
        opts.insert(IcmpV6Option::recursive_dns_server(60_000, pd_prefix.sub_router));
    }
    // On-link only prefixes (A=0): advertised so clients can detect DHCPv6 prefix changes
    if let Some(onlink_rt) = onlink_runtime {
        for static_prefix in onlink_rt.static_info.iter() {
            opts.insert(IcmpV6Option::prefix_information(
                static_prefix.sub_prefix_len,
                600,
                300,
                static_prefix.sub_prefix,
                false,
            ));
            opts.insert(IcmpV6Option::route_information(
                static_prefix.rt_prefix_len,
                static_prefix.rt_prefix,
            ));
        }
        for (_, pd_prefix) in onlink_rt.pd_info.iter() {
            let pd_prefix = pd_prefix.load();
            let Some(pd_prefix) = pd_prefix.as_ref() else {
                continue;
            };
            opts.insert(IcmpV6Option::prefix_information(
                pd_prefix.sub_prefix_len,
                600,
                300,
                pd_prefix.sub_prefix,
                false,
            ));
            opts.insert(IcmpV6Option::route_information(
                pd_prefix.rt_prefix_len,
                pd_prefix.rt_prefix,
            ));
        }
    }

    opts.insert(IcmpV6Option::mtu(1500));
    opts.insert(IcmpV6Option::advertisement_interval(60_000));

    let msg = Icmpv6Message::RouterAdvertisement(RouterAdvertisement::new(ra_flag.into(), opts));

    // Always send RA — in Stateful mode RA has no prefix info but still needs M=1 flag
    send_data(&msg, send_socket, target_addr).await;
}

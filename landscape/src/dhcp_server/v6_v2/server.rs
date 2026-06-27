use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use landscape_common::{
    error::LdResult,
    event::hub::{IPv6AssignEvent, IPv6AssignEventSender, IPv6AssignInfo},
    net::MacAddr,
    net_proto::icmpv6::messages::Icmpv6Message,
    route::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode},
    service::{ServiceStatus, WatchService},
};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{
    addresses_by_iface_name,
    dhcp_server::v6_v2::{
        connection::{get_dhcpv6_connect, get_icmp_connect},
        dhcpv6, icmpv6, Ipv6LanReplyParams, Ipv6ServerStatus,
    },
    ipv6::prefix::{add_route_via, del_route},
    route::IpRouteService,
};

const LEASE_EXPIRE_INTERVAL: u64 = 60 * 10;

async fn handle_ra_tick(
    share_status: &Arc<Mutex<Ipv6ServerStatus>>,
    params: &Ipv6LanReplyParams,
    mac_addr: &MacAddr,
    icmp_ad_interval: u32,
    icmp_sender: &Arc<UdpSocket>,
) {
    let status = share_status.lock().await;
    let ra = icmpv6::build_ra(&status, params, mac_addr, icmp_ad_interval * 1000);
    drop(status);
    let dst = SocketAddr::new(IpAddr::V6(icmpv6::ICMPV6_MULTICAST), 0);
    let _ = icmpv6::send_msg(icmp_sender, &ra, dst).await;
}

/// Returns `false` when the ICMP recv channel is closed and the loop should break.
async fn handle_icmp_msg(
    result: Option<(Vec<u8>, SocketAddr)>,
    iface_name: &str,
    service_status: &WatchService,
    share_status: &Arc<Mutex<Ipv6ServerStatus>>,
    params: &Ipv6LanReplyParams,
    mac_addr: &MacAddr,
    icmp_ad_interval: u32,
    icmp_sender: &Arc<UdpSocket>,
    ipv6_assign_sender: &IPv6AssignEventSender,
) -> bool {
    let Some((data, src_addr)) = result else {
        tracing::error!("ICMPv6 recv channel closed on {iface_name}");
        service_status.just_change_status(ServiceStatus::Failed);
        return false;
    };

    match icmpv6::parse(&data) {
        Some(Icmpv6Message::RouterSolicitation(_)) => {
            let status = share_status.lock().await;
            let ra = icmpv6::build_ra(&status, params, mac_addr, icmp_ad_interval * 1000);
            drop(status);
            let _ = icmpv6::send_msg(icmp_sender, &ra, src_addr).await;
        }
        Some(Icmpv6Message::NeighborAdvertisement(_)) => {
            let mut status = share_status.lock().await;
            if let icmpv6::SlaacActionResult::Allocated { mac, ip } =
                icmpv6::handle_na(&data, &mut status)
            {
                // TODO: eBPF upsert_ipv6_ip_mac(link_ifindex, ip, mac, mac_addr)
                let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(IPv6AssignInfo {
                    iface_name: iface_name.to_string(),
                    mac,
                    ip,
                    device_id: None,
                }));
            }
        }
        _ => {}
    }

    true
}

/// Returns `false` when the DHCP recv channel is closed and the loop should break.
#[allow(clippy::too_many_arguments)]
async fn handle_dhcp_msg(
    result: Option<(Vec<u8>, SocketAddr)>,
    iface_name: &str,
    mac_addr: MacAddr,
    link_ifindex: u32,
    service_status: &WatchService,
    share_status: &Arc<Mutex<Ipv6ServerStatus>>,
    server_duid: &[u8],
    params: &Ipv6LanReplyParams,
    dns_servers: &[Ipv6Addr],
    dhcp_sender: &Arc<UdpSocket>,
    ipv6_assign_sender: &IPv6AssignEventSender,
    route_service: &IpRouteService,
) -> bool {
    let Some((msg_bytes, msg_addr)) = result else {
        tracing::error!("DHCPv6 recv channel closed on {iface_name}");
        service_status.just_change_status(ServiceStatus::Failed);
        return false;
    };

    let client_ll = match msg_addr {
        SocketAddr::V6(v6) => *v6.ip(),
        _ => Ipv6Addr::UNSPECIFIED,
    };

    let pd_route_changes = {
        let mut status = share_status.lock().await;
        let result = dhcpv6::process_dhcpv6_msg(
            &mut status,
            &msg_bytes,
            msg_addr,
            server_duid,
            params,
            dns_servers,
        );

        // Send reply
        if let Some(reply) = result.reply_bytes {
            let _ = dhcp_sender.send_to(&reply, result.reply_dst).await;
        }

        // Emit allocation events
        for (mac, ip) in &result.allocated_ips {
            // TODO: eBPF upsert_ipv6_ip_mac(link_ifindex, *ip, *mac, mac_addr)
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(IPv6AssignInfo {
                iface_name: iface_name.to_string(),
                mac: *mac,
                ip: *ip,
                device_id: None,
            }));
        }

        // Emit expiry events
        for (mac, ip) in &result.expired_ips {
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                iface_name: iface_name.to_string(),
                mac: *mac,
                ip: *ip,
                device_id: None,
            }));
        }

        result.pd_route_changes
    };

    // PD route management (status lock released)
    for change in &pd_route_changes {
        for (prefix, len) in &change.old_routes {
            del_route(*prefix, *len, iface_name);
            let key = LanIPv6RouteKey {
                iface_name: iface_name.to_string(),
                subnet_index: pd_route_key_index(change.sub_index, prefix),
            };
            route_service.remove_ipv6_lan_route_by_key(&key).await;
        }
        for (prefix, len) in &change.new_routes {
            add_route_via(*prefix, *len, client_ll, iface_name, Some(change.valid_time));
            let lan_info = LanRouteInfo {
                ifindex: link_ifindex,
                iface_name: iface_name.to_string(),
                iface_ip: IpAddr::V6(*prefix),
                mac: Some(mac_addr),
                prefix: *len,
                mode: LanRouteMode::NextHop { next_hop_ip: IpAddr::V6(client_ll) },
            };
            let key = LanIPv6RouteKey {
                iface_name: iface_name.to_string(),
                subnet_index: pd_route_key_index(change.sub_index, prefix),
            };
            route_service.insert_ipv6_lan_route(key, lan_info).await;
        }
    }

    true
}

async fn handle_expire_tick(
    iface_name: &str,
    share_status: &Arc<Mutex<Ipv6ServerStatus>>,
    ipv6_assign_sender: &IPv6AssignEventSender,
    route_service: &IpRouteService,
    slaac_threshold_secs: u64,
) {
    let pd_cleanups = {
        let mut status = share_status.lock().await;

        let expired_na = status.clean_expired_na();
        for na in &expired_na {
            if let Some(mac) = na.mac {
                let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                    iface_name: iface_name.to_string(),
                    mac,
                    ip: na.ip,
                    device_id: None,
                }));
            }
        }

        let expired_pd = status.clean_expired_pd();

        let expired_slaac = status.clean_expired_slaac(slaac_threshold_secs);
        for (ip, mac) in &expired_slaac {
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                iface_name: iface_name.to_string(),
                mac: *mac,
                ip: *ip,
                device_id: None,
            }));
        }

        expired_pd.iter().map(|pd| (pd.sub_index, pd.active_routes.clone())).collect::<Vec<_>>()
    };

    // PD route cleanup outside status lock (needs .await)
    for (sub_index, routes) in &pd_cleanups {
        for (prefix, len) in routes {
            del_route(*prefix, *len, iface_name);
            let key = LanIPv6RouteKey {
                iface_name: iface_name.to_string(),
                subnet_index: pd_route_key_index(*sub_index, prefix),
            };
            route_service.remove_ipv6_lan_route_by_key(&key).await;
        }
    }
}

pub async fn start_ipv6_lan_server(
    ifindex: u32,
    iface_name: String,
    mac_addr: MacAddr,
    service_status: WatchService,
    icmp_ad_interval: u32,
    ipv6_assign_sender: &IPv6AssignEventSender,
    share_status: Arc<Mutex<Ipv6ServerStatus>>,
    params: Ipv6LanReplyParams,
    dns_servers: Vec<std::net::Ipv6Addr>,
    route_service: IpRouteService,
) -> LdResult<()> {
    let server_duid = gen_server_duid(&mac_addr);

    let setting_result = crate::set_iface_ip_no_limit(
        &iface_name,
        std::net::IpAddr::V6(mac_addr.to_ipv6_link_local()),
        64,
    )
    .await;

    if !setting_result {
        tracing::error!("setting unicast_link_local error");
        service_status.just_change_status(ServiceStatus::Failed);
    }

    let address = addresses_by_iface_name(iface_name.to_string()).await;
    let mut link_ifindex = 0;
    for addr in address.iter() {
        if let std::net::IpAddr::V6(ipv6_addr) = addr.address {
            if ipv6_addr.is_unicast_link_local() {
                link_ifindex = addr.ifindex;
                tracing::info!("address {:?}", ipv6_addr);
                break;
            }
        }
    }

    if link_ifindex == 0 {
        tracing::error!("can not find unicast_link_local");
        service_status.just_change_status(ServiceStatus::Failed);
        return Ok(());
    }
    tracing::info!("link_ifindex {:?}", link_ifindex);

    let Ok((mut dhcp_recv, dhcp_sender)) = get_dhcpv6_connect(ifindex, &iface_name).await else {
        tracing::error!("create dhcpv6 link error");
        service_status.just_change_status(ServiceStatus::Failed);
        return Ok(());
    };

    let Ok((mut icmp_recv, icmp_sender)) = get_icmp_connect(ifindex, &iface_name).await else {
        tracing::error!("create icmpv6 link error");
        service_status.just_change_status(ServiceStatus::Failed);
        return Ok(());
    };

    service_status.just_change_status(ServiceStatus::Running);

    let mut icmp_ra_interval =
        Box::pin(tokio::time::interval(Duration::from_secs(icmp_ad_interval as u64)));
    let mut dhcp_expire_timer =
        Box::pin(tokio::time::interval(Duration::from_secs(LEASE_EXPIRE_INTERVAL)));

    let mut service_status_subscribe = service_status.subscribe();

    loop {
        tokio::select! {
            _ = icmp_ra_interval.tick() => {
                handle_ra_tick(
                    &share_status, &params, &mac_addr, icmp_ad_interval, &icmp_sender,
                ).await;
            },
            result = icmp_recv.recv() => {
                if !handle_icmp_msg(
                    result, &iface_name, &service_status, &share_status,
                    &params, &mac_addr, icmp_ad_interval, &icmp_sender, ipv6_assign_sender,
                ).await {
                    break;
                }
            },
            result = dhcp_recv.recv() => {
                if !handle_dhcp_msg(
                    result, &iface_name, mac_addr, link_ifindex,
                    &service_status, &share_status, &server_duid,
                    &params, &dns_servers, &dhcp_sender, ipv6_assign_sender, &route_service,
                ).await {
                    break;
                }
            },
            _ = dhcp_expire_timer.tick() => {
                handle_expire_tick(
                    &iface_name, &share_status, ipv6_assign_sender, &route_service,
                    params.ra_valid_lifetime as u64,
                ).await;
            },
            result = service_status_subscribe.changed() => {
                tracing::debug!("LAN v6 Service change");
                if let Err(_) = result {
                    tracing::error!("get change result error. exit loop");
                    service_status.just_change_status(ServiceStatus::Failed);
                    break;
                }
                if service_status.is_exit() {
                    service_status.just_change_status(ServiceStatus::Stop);
                    tracing::info!("release send and stop");
                    break;
                }
            },
        }
    }

    // Clean up all remaining PD routes on exit
    let all_routes = {
        let mut status = share_status.lock().await;
        status.drain_all_pd_routes()
    };
    for (prefix, len) in &all_routes {
        del_route(*prefix, *len, &iface_name);
    }
    route_service.remove_ipv6_lan_route(&iface_name).await;

    return Ok(());
}

fn pd_route_key_index(sub_index: u32, delegated_prefix: &Ipv6Addr) -> u32 {
    let prefix_hash = (u128::from(*delegated_prefix) >> 64) as u32;
    0x8000_0000u32 | (sub_index.wrapping_mul(31).wrapping_add(prefix_hash))
}

fn gen_server_duid(mac: &MacAddr) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&[0x00, 0x03]);
    duid.extend_from_slice(&[0x00, 0x01]);
    duid.extend_from_slice(&mac.octets());
    duid
}

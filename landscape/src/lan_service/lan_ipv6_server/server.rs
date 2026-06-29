use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use landscape_common::{
    error::LdResult,
    event::hub::{IPv6AssignEvent, IPv6AssignEventSender, IPv6AssignInfo},
    ipv6::lan::LanPrefixGroupConfig,
    ipv6_pd::IAPrefixMap,
    net::MacAddr,
    net_proto::icmpv6::messages::Icmpv6Message,
    route::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode},
    service::{ServiceStatus, WatchService},
};
use tokio::sync::{mpsc, watch};
use tokio::{net::UdpSocket, sync::Mutex};

use dhcproto::v6::{Authentication, DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Encodable, Encoder};

use super::{
    compute_subnets,
    connection::{get_dhcpv6_connect, get_icmp_connect},
    dhcpv6, icmpv6, ra, Ipv6LanReplyParams, Ipv6ServerStatus,
};
use crate::{
    addresses_by_iface_name,
    netlink::ipv6::{add_route, add_route_via, del_iface_ip, del_route, set_iface_ip},
    sys_service::route::IpRouteService,
};
use dashmap::DashMap;
use uuid::Uuid;

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
    link_ifindex: u32,
    device_id_map: &DashMap<MacAddr, Uuid>,
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
            let action = icmpv6::handle_na(&data, &mut status);
            match &action {
                icmpv6::SlaacActionResult::Allocated { mac, .. }
                | icmpv6::SlaacActionResult::Conflict { mac, .. } => {
                    if let SocketAddr::V6(ref v6) = src_addr {
                        let ll = *v6.ip();
                        if ll.is_unicast_link_local() {
                            status.record_mac_link_local(*mac, ll);
                        }
                    }
                }
                _ => {}
            }
            match action {
                icmpv6::SlaacActionResult::Allocated { mac, ip } => {
                    if let Err(e) = landscape_ebpf::base::ip_mac::upsert_ipv6_ip_mac(
                        link_ifindex,
                        ip,
                        mac,
                        *mac_addr,
                    ) {
                        tracing::warn!("failed to prewarm ip_mac_v6 for ND {ip} -> {mac}: {e}");
                    }
                    let device_id = device_id_map.get(&mac).map(|r| *r.value());
                    if let Err(e) =
                        ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(IPv6AssignInfo {
                            iface_name: iface_name.to_string(),
                            mac,
                            ip,
                            device_id,
                        }))
                    {
                        tracing::error!("ND Allocated event FAILED for {mac} -> {ip}: {e:?}");
                    }
                }
                icmpv6::SlaacActionResult::Conflict { mac, ip } => {
                    let mac_was_none = status.update_na_lease_mac_from_slaac(ip, mac);
                    if mac_was_none {
                        if let Err(e) = landscape_ebpf::base::ip_mac::upsert_ipv6_ip_mac(
                            link_ifindex,
                            ip,
                            mac,
                            *mac_addr,
                        ) {
                            tracing::warn!(
                                "failed to prewarm ip_mac_v6 for DHCPv6-confirm {ip} -> {mac}: {e}"
                            );
                        }
                        let device_id = device_id_map.get(&mac).map(|r| *r.value());
                        if let Err(e) = ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(
                            IPv6AssignInfo {
                                iface_name: iface_name.to_string(),
                                mac,
                                ip,
                                device_id,
                            },
                        )) {
                            tracing::error!(
                                "NA-conflict Allocated event FAILED for {mac} -> {ip}: {e:?}"
                            );
                        }
                    }
                }
                _ => {}
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
    dhcp_sender: &Arc<UdpSocket>,
    ipv6_assign_sender: &IPv6AssignEventSender,
    route_service: &IpRouteService,
    device_id_map: &DashMap<MacAddr, Uuid>,
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
        let dns_servers = status.dns_servers().to_vec(mac_addr.to_ipv6_link_local());
        let result = dhcpv6::process_dhcpv6_msg(
            &mut status,
            &msg_bytes,
            msg_addr,
            server_duid,
            params,
            &dns_servers,
        );

        // Send reply
        if let Some(reply) = result.reply_bytes {
            let _ = dhcp_sender.send_to(&reply, result.reply_dst).await;
        }

        // Emit allocation events
        for (mac, ip) in &result.allocated_ips {
            if let Err(e) =
                landscape_ebpf::base::ip_mac::upsert_ipv6_ip_mac(link_ifindex, *ip, *mac, mac_addr)
            {
                tracing::warn!("failed to prewarm ip_mac_v6 for DHCPv6 {ip} -> {mac}: {e}");
            }
            let device_id = device_id_map.get(mac).map(|r| *r.value());
            if let Err(e) =
                ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(IPv6AssignInfo {
                    iface_name: iface_name.to_string(),
                    mac: *mac,
                    ip: *ip,
                    device_id,
                }))
            {
                tracing::error!("IPv6 assign event FAILED for {mac} -> {ip}: {e:?}");
            }
        }

        // Emit expiry events
        for (mac, ip) in &result.expired_ips {
            let device_id = device_id_map.get(mac).map(|r| *r.value());
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                iface_name: iface_name.to_string(),
                mac: *mac,
                ip: *ip,
                device_id,
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
    device_id_map: &DashMap<MacAddr, Uuid>,
) {
    let pd_cleanups = {
        let mut status = share_status.lock().await;

        let expired_na = status.clean_expired_na();
        for na in &expired_na {
            if let Some(mac) = na.mac {
                let device_id = device_id_map.get(&mac).map(|r| *r.value());
                let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                    iface_name: iface_name.to_string(),
                    mac,
                    ip: na.ip,
                    device_id,
                }));
            }
        }

        let expired_pd = status.clean_expired_pd();

        let expired_slaac = status.clean_expired_slaac(slaac_threshold_secs);
        for (ip, mac) in &expired_slaac {
            let device_id = device_id_map.get(mac).map(|r| *r.value());
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                iface_name: iface_name.to_string(),
                mac: *mac,
                ip: *ip,
                device_id,
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
    prefix_groups: Vec<LanPrefixGroupConfig>,
    prefix_map: IAPrefixMap,
    mut prefix_change_rx: watch::Receiver<()>,
    params: Ipv6LanReplyParams,
    route_service: IpRouteService,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
    mut reconf_rx: mpsc::UnboundedReceiver<MacAddr>,
) -> LdResult<()> {
    let server_duid = gen_server_duid(&mac_addr);

    // ── IPv6 forwarding ──
    let ipv6_forwarding_path = format!("/proc/sys/net/ipv6/conf/{}/forwarding", iface_name);
    let _ = std::fs::write(&ipv6_forwarding_path, "1");

    // ── Link-local address ──
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
        let _ = std::fs::write(&ipv6_forwarding_path, "0");
        return Ok(());
    }
    tracing::info!("link_ifindex {:?}", link_ifindex);

    // ── Initial subnets: set interface IPs + routes ──
    let initial_subnets = compute_subnets(&prefix_groups, &prefix_map);
    {
        let mut status = share_status.lock().await;
        status.update_prefix(&initial_subnets);
    }

    // System I/O for subnets (outside lock)
    for sn in &initial_subnets {
        if !sn.has_router() {
            continue;
        }
        set_iface_ip(sn.sub_router, sn.sub_prefix_len, &iface_name, None, None);
        add_route(sn.sub_prefix, sn.sub_prefix_len, &iface_name, None);
        let lan_info = LanRouteInfo {
            ifindex: link_ifindex as u32,
            iface_name: iface_name.clone(),
            iface_ip: IpAddr::V6(sn.sub_router),
            mac: Some(mac_addr),
            prefix: sn.sub_prefix_len,
            mode: LanRouteMode::Reachable,
        };
        let key = LanIPv6RouteKey {
            iface_name: iface_name.clone(),
            subnet_index: sn.pool_index,
        };
        route_service.insert_ipv6_lan_route(key, lan_info).await;
    }

    // ── DHCP connection (skipped for Slaac-only mode) ──
    let has_dhcp = params.ra_flags & 0x80 != 0; // M flag
    let (mut dhcp_recv, dhcp_sender) = if has_dhcp {
        match get_dhcpv6_connect(ifindex, &iface_name).await {
            Ok(v) => (Some(v.0), Some(v.1)),
            Err(_) => {
                tracing::error!("create dhcpv6 link error");
                service_status.just_change_status(ServiceStatus::Failed);
                let _ = std::fs::write(&ipv6_forwarding_path, "0");
                return Ok(());
            }
        }
    } else {
        (None, None)
    };

    let Ok((mut icmp_recv, icmp_sender)) = get_icmp_connect(ifindex, &iface_name).await else {
        tracing::error!("create icmpv6 link error");
        service_status.just_change_status(ServiceStatus::Failed);
        let _ = std::fs::write(&ipv6_forwarding_path, "0");
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
                    link_ifindex, &device_id_map,
                ).await {
                    break;
                }
            },
            result = async {
                match dhcp_recv.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(ref dhcp_sender) = dhcp_sender {
                    if !handle_dhcp_msg(
                        result, &iface_name, mac_addr, link_ifindex,
                        &service_status, &share_status, &server_duid,
                        &params, dhcp_sender, ipv6_assign_sender, &route_service,
                        &device_id_map,
                    ).await {
                        break;
                    }
                }
            },
            _ = dhcp_expire_timer.tick() => {
                handle_expire_tick(
                    &iface_name, &share_status, ipv6_assign_sender, &route_service,
                    params.ra_valid_lifetime as u64, &device_id_map,
                ).await;
            },
            mac = reconf_rx.recv() => {
                let Some(mac) = mac else {
                    tracing::warn!("reconf channel closed on {iface_name}");
                    break;
                };
                if let Some(ref dhcp_sender) = dhcp_sender {
                    let (duid, client_ip, reconf_key) = {
                        let status = share_status.lock().await;
                        let duid = status.lookup_na_duid_by_mac(&mac);
                        let ip = status.lookup_link_local_by_mac(&mac);
                        let key = status.lookup_reconfigure_key_by_mac(&mac);
                        (duid, ip, key)
                    };
                    // RFC 8415 §20.4: Reconfigure MUST be authenticated
                    match (duid, client_ip, reconf_key) {
                        (Some(duid), Some(ip), Some(key)) => {
                            let msg = build_reconfigure_msg(&server_duid, &duid, &key);
                            let dst = SocketAddr::new(IpAddr::V6(ip), 546);
                            if let Err(e) = dhcp_sender.send_to(&msg, dst).await {
                                tracing::warn!(
                                    "failed to send Reconfigure to {mac} at {ip}: {e}"
                                );
                            }
                        }
                        (None, _, _) => {
                            tracing::debug!(
                                "no DUID for {mac}; skipping Reconfigure"
                            );
                        }
                        (_, None, _) => {
                            tracing::debug!(
                                "no link-local for {mac}; skipping Reconfigure"
                            );
                        }
                        (_, _, None) => {
                            tracing::warn!(
                                "no reconfigure key for {mac}; skipping Reconfigure \
                                 (client may not support or hasn't completed DHCP exchange)"
                            );
                        }
                    }
                }
            },
            result = prefix_change_rx.changed() => {
                if result.is_err() {
                    tracing::warn!("prefix_change sender dropped, exiting loop");
                    break;
                }
                let diff = {
                    let mut status = share_status.lock().await;
                    status.recompute_and_diff(&prefix_groups, &prefix_map)
                };
                // Send deprecation RA for removed prefixes before tearing down routes
                if !diff.removed.is_empty() {
                    let deprecation_ra = ra::build_deprecation_ra_from_subnets(
                        &diff.removed,
                        &mac_addr,
                        params.ra_flags,
                        params.ra_autonomous,
                    );
                    let dst = SocketAddr::new(IpAddr::V6(icmpv6::ICMPV6_MULTICAST), 0);
                    let _ = icmpv6::send_msg(&icmp_sender, &deprecation_ra, dst).await;
                }
                // System I/O for removed subnets
                for sn in &diff.removed {
                    if !sn.has_router() {
                        continue;
                    }
                    del_iface_ip(sn.sub_router, sn.sub_prefix_len, &iface_name);
                    del_route(sn.sub_prefix, sn.sub_prefix_len, &iface_name);
                    let key = LanIPv6RouteKey {
                        iface_name: iface_name.clone(),
                        subnet_index: sn.pool_index,
                    };
                    route_service.remove_ipv6_lan_route_by_key(&key).await;
                }
                // System I/O for added subnets
                for sn in &diff.added {
                    if !sn.has_router() {
                        continue;
                    }
                    set_iface_ip(sn.sub_router, sn.sub_prefix_len, &iface_name, None, None);
                    add_route(sn.sub_prefix, sn.sub_prefix_len, &iface_name, None);
                    let lan_info = LanRouteInfo {
                        ifindex: link_ifindex as u32,
                        iface_name: iface_name.clone(),
                        iface_ip: IpAddr::V6(sn.sub_router),
                        mac: Some(mac_addr),
                        prefix: sn.sub_prefix_len,
                        mode: LanRouteMode::Reachable,
                    };
                    let key = LanIPv6RouteKey {
                        iface_name: iface_name.clone(),
                        subnet_index: sn.pool_index,
                    };
                    route_service.insert_ipv6_lan_route(key, lan_info).await;
                }
                // Reconcile PD routes after prefix change
                let cleanups = {
                    let mut status = share_status.lock().await;
                    status.reconcile_pd_routes()
                };
                for cleanup in &cleanups {
                    for (prefix, len) in &cleanup.routes {
                        del_route(*prefix, *len, &iface_name);
                        let key = LanIPv6RouteKey {
                            iface_name: iface_name.clone(),
                            subnet_index: pd_route_key_index(cleanup.sub_index, prefix),
                        };
                        route_service.remove_ipv6_lan_route_by_key(&key).await;
                    }
                }
                // Immediate RA after prefix change
                handle_ra_tick(
                    &share_status, &params, &mac_addr, icmp_ad_interval, &icmp_sender,
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

    // ── Deprecation RA ──
    {
        let status = share_status.lock().await;
        let deprecation_ra = icmpv6::build_deprecation_ra(&status, &mac_addr, params.ra_flags);
        let dst = SocketAddr::new(IpAddr::V6(icmpv6::ICMPV6_MULTICAST), 0);
        let _ = icmpv6::send_msg(&icmp_sender, &deprecation_ra, dst).await;
    }

    // ── Clean up ──
    let _ = std::fs::write(&ipv6_forwarding_path, "0");

    // Clean all subnet IPs and routes
    let current_subnets = {
        let status = share_status.lock().await;
        status.cached_subnets.clone()
    };
    for sn in &current_subnets {
        if sn.has_router() {
            del_iface_ip(sn.sub_router, sn.sub_prefix_len, &iface_name);
            del_route(sn.sub_prefix, sn.sub_prefix_len, &iface_name);
        }
    }

    // Clean PD delegate routes
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

/// Build an RFC 8415 §18.3.11 / §20.4 compliant Reconfigure message.
///
/// Requirements:
///  - XID set to 0 (§18.3.11)
///  - Authentication option with HMAC-MD5 computed over the entire message (§20.4.2)
fn build_reconfigure_msg(server_duid: &[u8], client_duid: &[u8], reconf_key: &[u8; 16]) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use md5::Md5;

    // First pass: build message with zero HMAC to compute the digest
    let mut zero_info = vec![2u8]; // Type=2: HMAC
    zero_info.extend_from_slice(&[0u8; 16]);
    let mut msg = Message::new_with_id(MessageType::Reconfigure, [0u8; 3]);
    msg.opts_mut().insert(DhcpOption::ClientId(client_duid.to_vec()));
    msg.opts_mut().insert(DhcpOption::ServerId(server_duid.to_vec()));
    msg.opts_mut().insert(DhcpOption::Authentication(Authentication {
        proto: 3,
        algo: 0,
        rdm: 0,
        replay_detection: 0,
        info: zero_info,
    }));
    msg.opts_mut().insert(DhcpOption::ReconfMsg(MessageType::Renew));

    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    msg.encode(&mut e).unwrap();

    // Compute HMAC-MD5 over the entire message (with zero HMAC field)
    let mut mac = Hmac::<Md5>::new_from_slice(reconf_key).expect("HMAC-MD5: 128-bit key");
    mac.update(&buf);
    let digest = mac.finalize().into_bytes();

    // Second pass: rebuild with real HMAC
    let mut real_info = vec![2u8];
    real_info.extend_from_slice(&digest);
    msg.opts_mut().remove(OptionCode::Authentication);
    msg.opts_mut().insert(DhcpOption::Authentication(Authentication {
        proto: 3,
        algo: 0,
        rdm: 0,
        replay_detection: 0,
        info: real_info,
    }));

    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    msg.encode(&mut e).unwrap();
    buf
}

fn gen_server_duid(mac: &MacAddr) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&[0x00, 0x03]);
    duid.extend_from_slice(&[0x00, 0x01]);
    duid.extend_from_slice(&mac.octets());
    duid
}

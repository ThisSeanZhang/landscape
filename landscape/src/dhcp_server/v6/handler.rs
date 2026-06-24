use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use dashmap::DashMap;
use landscape_common::dhcp::v6_server::config::DHCPv6ServerConfig;
use landscape_common::event::hub::IPv6AssignEventSender;
use landscape_common::event::hub::{IPv6AssignEvent, IPv6AssignInfo};
use landscape_common::net::MacAddr;
use landscape_common::net_proto::udp::dhcp::DhcpV6MessageType;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT;
use uuid::Uuid;

use dhcproto::v6::{self, IAAddr, IAPrefix, Status, StatusCode, IANA, IAPD};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};

use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;

use landscape_common::route::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode};

use super::dhcp_v6_status::DhcpV6AssignStatus;
use crate::ipv6::prefix::{
    add_route_via, del_route, Assignment, ICMPv6ConfigInfo, PdDelegationParent,
};
use crate::route::IpRouteService;

use super::server::DHCPv6Server;
use super::utils::{
    combine_prefix_suffix, compute_delegated_prefix, extract_mac_from_duid, gen_server_duid,
};

/// Collect DNS server addresses dynamically from prefix sources.
/// Strategy: sub_router addresses first (preferred), link-local always appended as fallback.
fn collect_dns_servers(
    assignment: &Assignment<ICMPv6ConfigInfo>,
    link_local: Ipv6Addr,
) -> Vec<Ipv6Addr> {
    let mut dns = Vec::new();
    dns.push(link_local);

    for info in &assignment.statics {
        if !dns.contains(&info.sub_router) {
            dns.push(info.sub_router);
        }
    }
    for src in &assignment.dynamics {
        if let Some(info) = src.load().as_ref() {
            if !dns.contains(&info.sub_router) {
                dns.push(info.sub_router);
            }
        }
    }
    dns
}

const LEASE_EXPIRE_INTERVAL: u64 = 60 * 10;
static DHCPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2);

/// Main DHCPv6 server function
#[tracing::instrument(skip(
    dhcpv6_config,
    na,
    pd,
    service_status,
    status,
    route_service,
    ipv6_assign_sender,
    device_id_map
))]
pub async fn dhcp_v6_server(
    link_ifindex: u32,
    iface_name: String,
    mac: MacAddr,
    link_local: Ipv6Addr,
    dhcpv6_config: DHCPv6ServerConfig,
    na: Assignment<ICMPv6ConfigInfo>,
    pd: Assignment<PdDelegationParent>,
    service_status: WatchService,
    status: Arc<tokio::sync::Mutex<DhcpV6AssignStatus>>,
    route_service: IpRouteService,
    ipv6_assign_sender: IPv6AssignEventSender,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
) {
    let server_duid = gen_server_duid(&mac);

    let dhcp_server = DHCPv6Server::init(&dhcpv6_config, server_duid.clone(), status);

    let socket_addr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT);

    let socket2 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    socket2.set_only_v6(true).unwrap();
    socket2.set_reuse_address(true).unwrap();
    socket2.set_reuse_port(true).unwrap();

    socket2.bind(&socket_addr.into()).unwrap();
    socket2.set_nonblocking(true).unwrap();

    if let Err(e) = socket2.bind_device(Some(iface_name.as_bytes())) {
        tracing::error!("DHCPv6 bind_device error: {e:?}");
        service_status.just_change_status(ServiceStatus::Failed);
        return;
    }

    socket2.join_multicast_v6(&DHCPV6_MULTICAST, link_ifindex).unwrap();

    let socket = UdpSocket::from_std(socket2.into()).unwrap();
    let send_socket = Arc::new(socket);
    let recv_socket = send_socket.clone();

    let (message_tx, mut message_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    // Receive loop
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        // TODO: Consider also listening on a prefix_change_notify channel here.
        // When upstream PD prefixes change, the RA server picks it up immediately
        // via the notify channel and re-advertises. But DHCPv6 only refreshes its
        // last_offer_info snapshot on the next client message or timeout tick.
        // Adding a 4th branch with a Receiver<()> would let us recompute the
        // snapshot instantly on prefix changes, closing the brief stale window
        // between the RA refresh and the next DHCPv6 client exchange.
        loop {
            tokio::select! {
                result = recv_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            tracing::debug!("DHCPv6 received {} bytes from {}", len, addr);
                            let message = buf[..len].to_vec();
                            if let Err(e) = message_tx.try_send((message, addr)) {
                                tracing::error!("DHCPv6 channel send error: {:?}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("DHCPv6 recv error: {:?}", e);
                        }
                    }
                },
                _ = message_tx.closed() => {
                    break;
                }
            }
        }
        tracing::info!("DHCPv6 recv loop down");
    });

    tracing::info!("DHCPv6 Server Running on {iface_name}");

    let mut service_status_subscribe = service_status.subscribe();
    let timeout_timer = tokio::time::sleep(tokio::time::Duration::from_secs(LEASE_EXPIRE_INTERVAL));
    tokio::pin!(timeout_timer);

    loop {
        tokio::select! {
            message = message_rx.recv() => {
                match message {
                    Some((msg_bytes, msg_addr)) => {
                        let need_update = handle_dhcpv6_message(
                            &dhcp_server,
                            &send_socket,
                            &server_duid,
                            mac,
                            (msg_bytes, msg_addr),
                            &na,
                            &pd,
                            link_local,
                            &iface_name,
                            link_ifindex,
                            &route_service,
                            &ipv6_assign_sender,
                            &device_id_map,
                        ).await;
                        if need_update {
                            dhcp_server.refresh_offer_info(&na, &pd).await;
                        }
                    },
                    None => {
                        tracing::error!("DHCPv6 message channel closed");
                        break;
                    }
                }
            }
            _ = &mut timeout_timer => {
                let expired_na = dhcp_server.clean_expired_na().await;
                if !expired_na.is_empty() {
                    let na_prefixes = dhcp_server.get_qualifying_na_prefixes(&na).await;
                    for cache in &expired_na {
                        if let Some(mac) = cache.mac {
                            let device_id = device_id_map.get(&mac).map(|r| *r.value());
                            for (prefix, prefix_len) in &na_prefixes {
                                let ip = combine_prefix_suffix(*prefix, *prefix_len, cache.suffix);
                                let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                                    iface_name: iface_name.clone(),
                                    mac,
                                    ip,
                                    device_id,
                                }));
                            }
                        }
                    }
                }
                let expired_pd = dhcp_server.clean_expired_pd().await;
                for cache in &expired_pd {
                    cleanup_pd_routes(cache, &iface_name, &route_service).await;
                }
                timeout_timer.as_mut().reset(
                    tokio::time::Instant::now() + tokio::time::Duration::from_secs(LEASE_EXPIRE_INTERVAL)
                );
                dhcp_server.refresh_offer_info(&na, &pd).await;
            }
            change_result = service_status_subscribe.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("DHCPv6 service status channel error");
                    break;
                }
                if service_status.is_exit() {
                    break;
                }
            }
        }
    }

    tracing::info!("DHCPv6 Server Stop on {iface_name}");
    na.token.cancel();
    pd.token.cancel();
    if !service_status.is_stop() {
        service_status.just_change_status(if service_status.is_exit() {
            ServiceStatus::Stop
        } else {
            ServiceStatus::Failed
        });
    }
}

async fn assigned_client_na_ips(
    server: &DHCPv6Server,
    client_duid: &[u8],
    na_prefixes: &[(Ipv6Addr, u8)],
) -> Option<Vec<Ipv6Addr>> {
    let cache = server.get_na_offer(client_duid).await?;
    Some(
        na_prefixes
            .iter()
            .map(|(prefix, prefix_len)| combine_prefix_suffix(*prefix, *prefix_len, cache.suffix))
            .collect(),
    )
}

async fn handle_dhcpv6_message(
    server: &DHCPv6Server,
    send_socket: &Arc<UdpSocket>,
    server_duid: &[u8],
    dev_mac: MacAddr,
    (msg_bytes, msg_addr): (Vec<u8>, SocketAddr),
    na: &Assignment<ICMPv6ConfigInfo>,
    pd: &Assignment<PdDelegationParent>,
    link_local: Ipv6Addr,
    iface_name: &str,
    link_ifindex: u32,
    route_service: &IpRouteService,
    ipv6_assign_sender: &IPv6AssignEventSender,
    device_id_map: &DashMap<MacAddr, Uuid>,
) -> bool {
    let msg = match v6::Message::decode(&mut Decoder::new(&msg_bytes)) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("DHCPv6 decode error: {e:?}");
            return false;
        }
    };

    // Extract client ID
    let client_duid = match msg.opts().get(v6::OptionCode::ClientId) {
        Some(v6::DhcpOption::ClientId(duid)) => duid.clone(),
        _ => {
            tracing::warn!("DHCPv6 message without ClientId");
            return false;
        }
    };

    let mac = extract_mac_from_duid(&client_duid);

    // Extract IANA ID if present
    let iana_id = msg.opts().get(v6::OptionCode::IANA).and_then(|opt| {
        if let v6::DhcpOption::IANA(iana) = opt {
            Some(iana.id)
        } else {
            None
        }
    });

    // Extract IAPD ID if present
    let iapd_id = msg.opts().get(v6::OptionCode::IAPD).and_then(|opt| {
        if let v6::DhcpOption::IAPD(iapd) = opt {
            Some(iapd.id)
        } else {
            None
        }
    });

    match msg.msg_type() {
        DhcpV6MessageType::Solicit => {
            tracing::info!(
                "DHCPv6 SOLICIT from {:?}, IANA ID: {:?}, IAPD ID: {:?}",
                mac,
                iana_id,
                iapd_id
            );
            tracing::info!(
                "DHCPv6 Server config - NA: {:?}, PD: {:?}",
                server.na_config.is_some(),
                server.pd_config.is_some()
            );
            tracing::info!(
                "DHCPv6 statics count: {}, dynamics count: {}",
                na.statics.len(),
                na.dynamics.len()
            );

            // Allocate addresses/prefixes
            if let Some(_) = &server.na_config {
                if iana_id.is_some() {
                    server.offer_na_suffix(&client_duid, mac, None).await;
                }
            }

            // Build ADVERTISE
            let mut reply = v6::Message::new(DhcpV6MessageType::Advertise);
            reply.set_xid(msg.xid());
            reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid.clone()));
            reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));
            reply.opts_mut().insert(v6::DhcpOption::Preference(255));

            if let Some(iana_id) = iana_id {
                if server.na_config.is_some() {
                    let na_prefixes = server.get_qualifying_na_prefixes(na).await;
                    tracing::info!(
                        "DHCPv6 IANA - qualifying prefixes count: {}",
                        na_prefixes.len()
                    );
                    for (prefix, len) in &na_prefixes {
                        tracing::info!("  - Prefix: {}/{}", prefix, len);
                    }
                    if !na_prefixes.is_empty() {
                        let iana =
                            build_iana_options(server, &client_duid, iana_id, &na_prefixes).await;
                        reply.opts_mut().insert(v6::DhcpOption::IANA(iana));
                    } else {
                        tracing::warn!("DHCPv6 IANA: No qualifying prefixes available!");
                    }
                }
            }

            if let Some(iapd_id) = iapd_id {
                if server.pd_config.is_some() {
                    let pd_prefixes = server.get_qualifying_pd_prefixes(pd).await;
                    if !pd_prefixes.is_empty() {
                        server.offer_pd_index(&client_duid, &pd_prefixes).await;
                        let iapd =
                            build_iapd_options(server, &client_duid, iapd_id, &pd_prefixes).await;
                        reply.opts_mut().insert(v6::DhcpOption::IAPD(iapd));
                    } else {
                        // No qualifying prefixes available - return NOT_ON_LINK to signal client
                        let mut iapd_opts = v6::DhcpOptions::new();
                        iapd_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
                            status: Status::NotOnLink,
                            msg: "Prefix delegation not available, please request new prefix"
                                .to_string(),
                        }));
                        let iapd = v6::IAPD { id: iapd_id, t1: 0, t2: 0, opts: iapd_opts };
                        reply.opts_mut().insert(v6::DhcpOption::IAPD(iapd));
                    }
                }
            }

            let dns = collect_dns_servers(na, link_local);
            reply.opts_mut().insert(v6::DhcpOption::DomainNameServers(dns));

            send_dhcpv6_reply(&reply, send_socket, msg_addr).await;
            return true;
        }

        DhcpV6MessageType::Request | DhcpV6MessageType::Renew | DhcpV6MessageType::Rebind => {
            // Verify server ID for Request and Renew (not Rebind)
            if msg.msg_type() != DhcpV6MessageType::Rebind {
                match msg.opts().get(v6::OptionCode::ServerId) {
                    Some(v6::DhcpOption::ServerId(sid)) if sid == server_duid => {}
                    _ => {
                        tracing::debug!("DHCPv6 message not for us (wrong ServerId)");
                        return false;
                    }
                }
            }

            tracing::debug!("DHCPv6 {:?} from {:?}", msg.msg_type(), mac);

            // Confirm/allocate
            if server.na_config.is_some() && iana_id.is_some() {
                if !server.confirm_na(&client_duid).await {
                    // New client during REBIND or first REQUEST
                    server.offer_na_suffix(&client_duid, mac, None).await;
                    server.confirm_na(&client_duid).await;
                }
            }

            // Build REPLY
            let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
            reply.set_xid(msg.xid());
            reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid.clone()));
            reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));

            if let Some(iana_id) = iana_id {
                if server.na_config.is_some() {
                    let na_prefixes = server.get_qualifying_na_prefixes(na).await;
                    if !na_prefixes.is_empty() {
                        if let Some(client_mac) = mac {
                            if let Some(ips) =
                                assigned_client_na_ips(server, &client_duid, &na_prefixes).await
                            {
                                for ip in &ips {
                                    if let Err(e) = landscape_ebpf::base::ip_mac::upsert_ipv6_ip_mac(
                                        link_ifindex,
                                        *ip,
                                        client_mac,
                                        dev_mac,
                                    ) {
                                        tracing::warn!(
                                            "failed to prewarm ip_mac_v6 for DHCPv6 lease {ip} -> {client_mac}: {e}"
                                        );
                                    }
                                }
                                for &ip in &ips {
                                    let device_id =
                                        device_id_map.get(&client_mac).map(|r| *r.value());
                                    let _ = ipv6_assign_sender.try_send(
                                        IPv6AssignEvent::Allocated(IPv6AssignInfo {
                                            iface_name: iface_name.to_string(),
                                            mac: client_mac,
                                            ip,
                                            device_id,
                                        }),
                                    );
                                }
                            }
                        }

                        // For Renew: ensure we have a cached address, or re-allocate if needed
                        if !server.has_na_offer(&client_duid).await {
                            // Client has no cached address - allocate new one
                            tracing::debug!(
                                "DHCPv6 Renew: no cached address for client, allocating new"
                            );
                            server.offer_na_suffix(&client_duid, mac, None).await;
                        }
                        let mut iana =
                            build_iana_options(server, &client_duid, iana_id, &na_prefixes).await;

                        // RFC 8415 §18.4.3: For Rebind/Renew, if the prefix changed,
                        // return old addresses with lifetime=0 so the client deprecates them.
                        if msg.msg_type() == DhcpV6MessageType::Rebind
                            || msg.msg_type() == DhcpV6MessageType::Renew
                        {
                            let mut server_addrs: Vec<Ipv6Addr> = Vec::new();
                            if let Some(cache) = server.get_na_offer(&client_duid).await {
                                for (prefix, prefix_len) in &na_prefixes {
                                    server_addrs.push(combine_prefix_suffix(
                                        *prefix,
                                        *prefix_len,
                                        cache.suffix,
                                    ));
                                }
                            }
                            if let Some(v6::DhcpOption::IANA(client_iana)) =
                                msg.opts().get(v6::OptionCode::IANA)
                            {
                                if let Some(ia_addrs) =
                                    client_iana.opts.get_all(v6::OptionCode::IAAddr)
                                {
                                    for ia_opt in ia_addrs {
                                        if let v6::DhcpOption::IAAddr(ia_addr) = ia_opt {
                                            if !server_addrs.contains(&ia_addr.addr) {
                                                tracing::info!(
                                                    "DHCPv6 deprecating old address {} (prefix changed)",
                                                    ia_addr.addr
                                                );
                                                iana.opts.insert(v6::DhcpOption::IAAddr(IAAddr {
                                                    addr: ia_addr.addr,
                                                    preferred_life: 0,
                                                    valid_life: 0,
                                                    opts: v6::DhcpOptions::new(),
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        reply.opts_mut().insert(v6::DhcpOption::IANA(iana));
                    } else {
                        // No qualifying prefixes available - return NOT_ON_LINK to signal client
                        // that it should request a new address
                        let mut iana_opts = v6::DhcpOptions::new();
                        iana_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
                            status: Status::NotOnLink,
                            msg: "Prefix no longer available, please request new address"
                                .to_string(),
                        }));
                        let iana = v6::IANA { id: iana_id, t1: 0, t2: 0, opts: iana_opts };
                        reply.opts_mut().insert(v6::DhcpOption::IANA(iana));
                    }
                }
            }

            if let Some(iapd_id) = iapd_id {
                if server.pd_config.is_some() {
                    let pd_prefixes = server.get_qualifying_pd_prefixes(pd).await;
                    if !pd_prefixes.is_empty() {
                        // Confirm existing allocation, or allocate new
                        if !server.confirm_pd(&client_duid).await {
                            server.offer_pd_index(&client_duid, &pd_prefixes).await;
                            server.confirm_pd(&client_duid).await;
                        }
                        // For Renew/Rebind: re-allocate if cache lost
                        if !server.has_pd_offer(&client_duid).await {
                            tracing::debug!(
                                "DHCPv6 Renew/Rebind: no cached prefix, allocating new"
                            );
                            server.offer_pd_index(&client_duid, &pd_prefixes).await;
                        }

                        let mut iapd =
                            build_iapd_options(server, &client_duid, iapd_id, &pd_prefixes).await;

                        // RFC 8415 §18.4.3: deprecate old delegated prefixes no longer valid
                        if msg.msg_type() == DhcpV6MessageType::Rebind
                            || msg.msg_type() == DhcpV6MessageType::Renew
                        {
                            let mut server_prefixes: Vec<Ipv6Addr> = Vec::new();
                            if let Some(cache) = server.get_pd_offer(&client_duid).await {
                                if let Some((base_prefix, base_prefix_len)) =
                                    pd_prefixes.get(cache.sub_index as usize)
                                {
                                    server_prefixes.push(compute_delegated_prefix(
                                        *base_prefix,
                                        *base_prefix_len,
                                        *base_prefix_len,
                                        0,
                                    ));
                                }
                            }
                            if let Some(v6::DhcpOption::IAPD(client_iapd)) =
                                msg.opts().get(v6::OptionCode::IAPD)
                            {
                                if let Some(ia_prefixes) =
                                    client_iapd.opts.get_all(v6::OptionCode::IAPrefix)
                                {
                                    for ia_opt in ia_prefixes {
                                        if let v6::DhcpOption::IAPrefix(ia_prefix) = ia_opt {
                                            if !server_prefixes.contains(&ia_prefix.prefix_ip) {
                                                tracing::info!(
                                                    "DHCPv6 deprecating old prefix {}/{} (prefix changed)",
                                                    ia_prefix.prefix_ip,
                                                    ia_prefix.prefix_len
                                                );
                                                iapd.opts.insert(v6::DhcpOption::IAPrefix(
                                                    IAPrefix {
                                                        preferred_lifetime: 0,
                                                        valid_lifetime: 0,
                                                        prefix_len: ia_prefix.prefix_len,
                                                        prefix_ip: ia_prefix.prefix_ip,
                                                        opts: v6::DhcpOptions::new(),
                                                    },
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        reply.opts_mut().insert(v6::DhcpOption::IAPD(iapd));

                        // Add routes for delegated prefix (system + eBPF)
                        let route_info = {
                            let guard = server.status.lock().await;
                            guard.pd_offered.get(&client_duid).map(|cache| {
                                (cache.active_routes.clone(), cache.sub_index, cache.valid_time)
                            })
                        };
                        if let Some((old_routes, sub_index, valid_time)) = route_info {
                            // Remove old routes
                            for (prefix, len) in &old_routes {
                                del_route(*prefix, *len, iface_name);
                                let key = LanIPv6RouteKey {
                                    iface_name: iface_name.to_string(),
                                    subnet_index: pd_route_key_index(sub_index, prefix),
                                };
                                route_service.remove_ipv6_lan_route_by_key(&key).await;
                            }
                            // Add new route for the allocated block
                            let client_ll = match msg_addr {
                                SocketAddr::V6(v6) => *v6.ip(),
                                _ => Ipv6Addr::UNSPECIFIED,
                            };
                            let mut new_routes = Vec::new();
                            if let Some((base_prefix, base_prefix_len)) =
                                pd_prefixes.get(sub_index as usize)
                            {
                                let delegated = compute_delegated_prefix(
                                    *base_prefix,
                                    *base_prefix_len,
                                    *base_prefix_len,
                                    0,
                                );
                                add_route_via(
                                    delegated,
                                    *base_prefix_len,
                                    client_ll,
                                    iface_name,
                                    Some(valid_time),
                                );
                                let lan_info = LanRouteInfo {
                                    ifindex: link_ifindex,
                                    iface_name: iface_name.to_string(),
                                    iface_ip: IpAddr::V6(delegated),
                                    mac: Some(dev_mac),
                                    prefix: *base_prefix_len,
                                    mode: LanRouteMode::NextHop {
                                        next_hop_ip: IpAddr::V6(client_ll),
                                    },
                                };
                                let key = LanIPv6RouteKey {
                                    iface_name: iface_name.to_string(),
                                    subnet_index: pd_route_key_index(sub_index, &delegated),
                                };
                                route_service.insert_ipv6_lan_route(key, lan_info).await;
                                new_routes.push((delegated, *base_prefix_len));
                            }
                            // Update cache with new routes
                            {
                                let mut guard = server.status.lock().await;
                                if let Some(cache) = guard.pd_offered.get_mut(&client_duid) {
                                    cache.client_addr = client_ll;
                                    cache.active_routes = new_routes;
                                } else {
                                    drop(guard);
                                    tracing::warn!(
                                        "DHCPv6 PD cache entry removed before route update, rolling back {} new routes",
                                        new_routes.len()
                                    );
                                    for (prefix, len) in &new_routes {
                                        del_route(*prefix, *len, iface_name);
                                        let key = LanIPv6RouteKey {
                                            iface_name: iface_name.to_string(),
                                            subnet_index: pd_route_key_index(sub_index, prefix),
                                        };
                                        route_service.remove_ipv6_lan_route_by_key(&key).await;
                                    }
                                }
                            }
                        }
                    } else {
                        // No qualifying prefixes available - return NOT_ON_LINK to signal client
                        let mut iapd_opts = v6::DhcpOptions::new();
                        iapd_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
                            status: Status::NotOnLink,
                            msg: "Prefix delegation not available, please request new prefix"
                                .to_string(),
                        }));
                        let iapd = v6::IAPD { id: iapd_id, t1: 0, t2: 0, opts: iapd_opts };
                        reply.opts_mut().insert(v6::DhcpOption::IAPD(iapd));
                    }
                }
            }

            let dns = collect_dns_servers(na, link_local);
            reply.opts_mut().insert(v6::DhcpOption::DomainNameServers(dns));

            server.consume_prev_suffix(&client_duid).await;

            send_dhcpv6_reply(&reply, send_socket, msg_addr).await;
            return true;
        }

        DhcpV6MessageType::Release => {
            match msg.opts().get(v6::OptionCode::ServerId) {
                Some(v6::DhcpOption::ServerId(sid)) if sid == server_duid => {}
                _ => return false,
            }

            tracing::info!("DHCPv6 RELEASE from {:?}", mac);
            let released_na = server.release_na(&client_duid).await;
            if let Some(cache) = &released_na {
                if let Some(client_mac) = cache.mac {
                    let device_id = device_id_map.get(&client_mac).map(|r| *r.value());
                    let na_prefixes = server.get_qualifying_na_prefixes(na).await;
                    for (prefix, prefix_len) in &na_prefixes {
                        let ip = combine_prefix_suffix(*prefix, *prefix_len, cache.suffix);
                        let _ =
                            ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                                iface_name: iface_name.to_string(),
                                mac: client_mac,
                                ip,
                                device_id,
                            }));
                    }
                }
            }
            if let Some(released_pd) = server.release_pd(&client_duid).await {
                cleanup_pd_routes(&released_pd, iface_name, route_service).await;
            }

            let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
            reply.set_xid(msg.xid());
            reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid));
            reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));
            reply.opts_mut().insert(v6::DhcpOption::StatusCode(StatusCode {
                status: Status::Success,
                msg: String::new(),
            }));

            send_dhcpv6_reply(&reply, send_socket, msg_addr).await;
            return true;
        }

        DhcpV6MessageType::Decline => {
            tracing::info!("DHCPv6 DECLINE from {:?}", mac);
            // Mark declined, remove from offered
            let released_na = server.release_na(&client_duid).await;
            if let Some(cache) = &released_na {
                if let Some(client_mac) = cache.mac {
                    let device_id = device_id_map.get(&client_mac).map(|r| *r.value());
                    let na_prefixes = server.get_qualifying_na_prefixes(na).await;
                    for (prefix, prefix_len) in &na_prefixes {
                        let ip = combine_prefix_suffix(*prefix, *prefix_len, cache.suffix);
                        let _ =
                            ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                                iface_name: iface_name.to_string(),
                                mac: client_mac,
                                ip,
                                device_id,
                            }));
                    }
                }
            }
            return true;
        }

        DhcpV6MessageType::Confirm => {
            // RFC 8415 §18.4.2: Check if client's addresses are still on-link.
            // If any address is not appropriate for the link, return NotOnLink
            // to force the client to restart with Solicit.
            let na_prefixes = server.get_qualifying_na_prefixes(na).await;

            let mut all_on_link = true;
            if let Some(v6::DhcpOption::IANA(client_iana)) = msg.opts().get(v6::OptionCode::IANA) {
                if let Some(ia_addrs) = client_iana.opts.get_all(v6::OptionCode::IAAddr) {
                    for ia_opt in ia_addrs {
                        if let v6::DhcpOption::IAAddr(ia_addr) = ia_opt {
                            let on_link = na_prefixes.iter().any(|(prefix, prefix_len)| {
                                let mask = if *prefix_len >= 128 {
                                    !0u128
                                } else {
                                    !0u128 << (128 - prefix_len)
                                };
                                (u128::from(ia_addr.addr) & mask) == (u128::from(*prefix) & mask)
                            });
                            if !on_link {
                                tracing::info!(
                                    "DHCPv6 Confirm: address {} is NOT on-link, rejecting",
                                    ia_addr.addr
                                );
                                all_on_link = false;
                                break;
                            }
                        }
                    }
                }
            }

            let status = if all_on_link {
                tracing::debug!("DHCPv6 Confirm: all addresses on-link, returning Success");
                StatusCode { status: Status::Success, msg: String::new() }
            } else {
                tracing::info!("DHCPv6 Confirm: returning NotOnLink, client should Solicit");
                StatusCode {
                    status: Status::NotOnLink,
                    msg: "Address not appropriate for link".to_string(),
                }
            };

            let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
            reply.set_xid(msg.xid());
            reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid));
            reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));
            reply.opts_mut().insert(v6::DhcpOption::StatusCode(status));

            send_dhcpv6_reply(&reply, send_socket, msg_addr).await;
            return false;
        }

        DhcpV6MessageType::InformationRequest => {
            let mut reply = v6::Message::new(DhcpV6MessageType::Reply);
            reply.set_xid(msg.xid());
            reply.opts_mut().insert(v6::DhcpOption::ClientId(client_duid));
            reply.opts_mut().insert(v6::DhcpOption::ServerId(server_duid.to_vec()));

            let dns = collect_dns_servers(na, link_local);
            reply.opts_mut().insert(v6::DhcpOption::DomainNameServers(dns));

            send_dhcpv6_reply(&reply, send_socket, msg_addr).await;
            return false;
        }

        other => {
            tracing::debug!("DHCPv6 ignoring message type: {:?}", other);
            return false;
        }
    }
}

/// Build IA_NA options for a reply message
async fn build_iana_options(
    server: &DHCPv6Server,
    client_duid: &[u8],
    iana_id: u32,
    qualifying_prefixes: &[(Ipv6Addr, u8)],
) -> v6::IANA {
    let na_config = match server.na_config.as_ref() {
        Some(c) => c,
        None => {
            tracing::warn!("build_iana_options called with na_config=None");
            let mut iana_opts = v6::DhcpOptions::new();
            iana_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
                status: Status::NoAddrsAvail,
                msg: "IA_NA not configured".to_string(),
            }));
            return IANA { id: iana_id, t1: 0, t2: 0, opts: iana_opts };
        }
    };
    let mut iana_opts = v6::DhcpOptions::new();

    if let Some(cache) = server.get_na_offer(client_duid).await {
        for (prefix, prefix_len) in qualifying_prefixes {
            let addr = combine_prefix_suffix(*prefix, *prefix_len, cache.suffix);
            iana_opts.insert(v6::DhcpOption::IAAddr(IAAddr {
                addr,
                preferred_life: cache.preferred_time,
                valid_life: cache.valid_time,
                opts: v6::DhcpOptions::new(),
            }));
        }
    }

    iana_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
        status: Status::Success,
        msg: String::new(),
    }));

    IANA {
        id: iana_id,
        t1: na_config.preferred_lifetime / 2,
        t2: (na_config.preferred_lifetime * 4) / 5,
        opts: iana_opts,
    }
}

/// Build IA_PD options for a reply message.
/// Allocates ONE IAPrefix from the pool block indexed by `cache.sub_index`.
async fn build_iapd_options(
    server: &DHCPv6Server,
    client_duid: &[u8],
    iapd_id: u32,
    qualifying_prefixes: &[(Ipv6Addr, u8)],
) -> v6::IAPD {
    let pd_config = match server.pd_config.as_ref() {
        Some(c) => c,
        None => {
            tracing::warn!("build_iapd_options called with pd_config=None");
            let mut iapd_opts = v6::DhcpOptions::new();
            iapd_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
                status: Status::NoPrefixAvail,
                msg: "IA_PD not configured".to_string(),
            }));
            return IAPD { id: iapd_id, t1: 0, t2: 0, opts: iapd_opts };
        }
    };
    let mut iapd_opts = v6::DhcpOptions::new();

    let mut has_prefix = false;
    if let Some(cache) = server.get_pd_offer(client_duid).await {
        if let Some((base_prefix, base_prefix_len)) =
            qualifying_prefixes.get(cache.sub_index as usize)
        {
            let delegated =
                compute_delegated_prefix(*base_prefix, *base_prefix_len, *base_prefix_len, 0);
            iapd_opts.insert(v6::DhcpOption::IAPrefix(IAPrefix {
                preferred_lifetime: cache.preferred_time,
                valid_lifetime: cache.valid_time,
                prefix_len: *base_prefix_len,
                prefix_ip: delegated,
                opts: v6::DhcpOptions::new(),
            }));
            has_prefix = true;
        }
    }

    iapd_opts.insert(v6::DhcpOption::StatusCode(StatusCode {
        status: if has_prefix { Status::Success } else { Status::NoPrefixAvail },
        msg: if has_prefix { String::new() } else { "No PD prefixes available".to_string() },
    }));

    IAPD {
        id: iapd_id,
        t1: pd_config.preferred_lifetime / 2,
        t2: (pd_config.preferred_lifetime * 4) / 5,
        opts: iapd_opts,
    }
}

async fn send_dhcpv6_reply(msg: &v6::Message, send_socket: &UdpSocket, target: SocketAddr) {
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    if let Err(e) = msg.encode(&mut e) {
        tracing::error!("DHCPv6 encode error: {e:?}");
        return;
    }
    match send_socket.send_to(&buf, &target).await {
        Ok(len) => {
            tracing::debug!("DHCPv6 sent {} bytes to {}", len, target);
        }
        Err(e) => {
            tracing::error!("DHCPv6 send error: {:?}", e);
        }
    }
}

/// Generate a unique subnet_index for PD delegation routes in LanIPv6RouteKey.
/// Uses a high offset (0x8000_0000) + hash to avoid collision with regular RA/NA routes.
fn pd_route_key_index(sub_index: u32, delegated_prefix: &Ipv6Addr) -> u32 {
    let prefix_hash = (u128::from(*delegated_prefix) >> 64) as u32;
    0x8000_0000u32 | (sub_index.wrapping_mul(31).wrapping_add(prefix_hash))
}

use super::types::DHCPv6PDCache;

/// Clean up system and eBPF routes for a released/expired PD cache entry.
async fn cleanup_pd_routes(
    cache: &DHCPv6PDCache,
    iface_name: &str,
    route_service: &IpRouteService,
) {
    for (prefix, len) in &cache.active_routes {
        del_route(*prefix, *len, iface_name);
        let key = LanIPv6RouteKey {
            iface_name: iface_name.to_string(),
            subnet_index: pd_route_key_index(cache.sub_index, prefix),
        };
        route_service.remove_ipv6_lan_route_by_key(&key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use landscape_common::dhcp::v6_server::config::{
        DHCPv6IANAConfig, DHCPv6IAPDConfig, DHCPv6ServerConfig,
    };
    use landscape_common::net::MacAddr;
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_server(config: &DHCPv6ServerConfig) -> DHCPv6Server {
        let status =
            Arc::new(Mutex::new(DhcpV6AssignStatus::from_config_and_devices(config, vec![])));
        DHCPv6Server::init(config, Vec::new(), status)
    }

    #[tokio::test]
    async fn test_renew_with_new_prefix_and_cached_address() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        };

        let mut server = make_server(&server_config);
        let server_duid = vec![1, 2, 3, 4, 5, 6];
        server.server_duid = server_duid;

        let client_duid = b"test-client-1".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        server.offer_na_suffix(&client_duid, Some(mac), None).await;
        assert!(server.has_na_offer(&client_duid).await, "Client should have cached address");

        let new_prefix = Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x3301, 0, 0, 0, 0);
        let qualifying_prefixes = vec![(new_prefix, 64)];

        let iana = build_iana_options(&server, &client_duid, 1, &qualifying_prefixes).await;

        assert_eq!(iana.id, 1, "IANA ID should match");
        assert!(iana.t1 > 0, "IANA T1 should be greater than 0 for valid lease");
        assert!(iana.t2 > iana.t1, "IANA T2 should be greater than T1");
    }

    #[test]
    fn test_iana_lifetime_calculation() {
        let config = DHCPv6IANAConfig {
            max_prefix_len: 64,
            pool_start: 256,
            pool_end: None,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        };

        let t1 = config.preferred_lifetime / 2;
        let t2 = (config.preferred_lifetime * 4) / 5;

        assert_eq!(t1, 1800, "T1 should be half of preferred_lifetime");
        assert_eq!(t2, 2880, "T2 should be 4/5 of preferred_lifetime");
    }

    #[test]
    fn test_server_initialization() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 61,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        };

        let server = make_server(&server_config);

        assert!(server.na_config.is_some(), "NA config should be set");
        assert!(server.pd_config.is_some(), "PD config should be set");
        assert_eq!(
            server.na_config.as_ref().unwrap().max_prefix_len,
            64,
            "NA max_prefix_len should be 64"
        );
    }

    #[tokio::test]
    async fn test_address_allocation_for_client() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        };

        let server = make_server(&server_config);
        let client_duid = b"test-client-new".to_vec();
        let mac = MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        server.offer_na_suffix(&client_duid, Some(mac), None).await;

        assert!(
            server.has_na_offer(&client_duid).await,
            "Client should be in na_offered cache after allocation"
        );
    }

    #[tokio::test]
    async fn test_assigned_client_na_ips_use_cached_suffix() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        };

        let server = make_server(&server_config);
        let client_duid = b"test-client-current-ip".to_vec();
        let mac = MacAddr::from([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        server.offer_na_suffix(&client_duid, Some(mac), None).await;

        let prefix = Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0);
        let cache = server.get_na_offer(&client_duid).await.expect("missing NA cache entry");
        let expected = combine_prefix_suffix(prefix, 64, cache.suffix);

        assert_eq!(
            assigned_client_na_ips(&server, &client_duid, &[(prefix, 64)]).await,
            Some(vec![expected])
        );
    }

    #[tokio::test]
    async fn test_assigned_client_na_ips_include_all_prefixes() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        };

        let server = make_server(&server_config);
        let client_duid = b"test-client-multi-prefix-ip".to_vec();
        let mac = MacAddr::from([0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
        server.offer_na_suffix(&client_duid, Some(mac), None).await;

        let prefixes = vec![
            (Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0), 64),
            (Ipv6Addr::new(0xfd55, 0x6666, 0x7777, 0x8888, 0, 0, 0, 0), 64),
        ];
        let cache = server.get_na_offer(&client_duid).await.expect("missing NA cache entry");
        let expected: Vec<Ipv6Addr> = prefixes
            .iter()
            .map(|(prefix, prefix_len)| combine_prefix_suffix(*prefix, *prefix_len, cache.suffix))
            .collect();

        assert_eq!(assigned_client_na_ips(&server, &client_duid, &prefixes).await, Some(expected));
    }

    #[tokio::test]
    async fn test_prefix_delegation_allocation() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: None,
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 61,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        };

        let server = make_server(&server_config);
        let client_duid = b"test-client-pd".to_vec();

        let qualifying = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];
        server.offer_pd_index(&client_duid, &qualifying).await;

        assert!(
            server.has_pd_offer(&client_duid).await,
            "Client should be in pd_offered cache after PD allocation"
        );
    }

    #[tokio::test]
    async fn test_pd_one_block_per_client() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: None,
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 60,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        };
        let server = make_server(&server_config);
        let client_duid = b"one-block-client".to_vec();

        let qualifying = [
            (Ipv6Addr::new(0xfd99, 0, 0, 0x39a0, 0, 0, 0, 0), 60),
            (Ipv6Addr::new(0xfd99, 0, 0, 0x39b0, 0, 0, 0, 0), 60),
            (Ipv6Addr::new(0xfd99, 0, 0, 0x39c0, 0, 0, 0, 0), 60),
        ];
        server.offer_pd_index(&client_duid, &qualifying).await;

        let iapd = build_iapd_options(&server, &client_duid, 1, &qualifying).await;

        let prefixes: Vec<_> = iapd
            .opts
            .into_iter()
            .filter_map(|o| if let v6::DhcpOption::IAPrefix(p) = o { Some(p) } else { None })
            .collect();

        assert_eq!(
            prefixes.len(),
            1,
            "one block per client: expected 1 IAPrefix, got {}",
            prefixes.len()
        );
        assert_eq!(
            prefixes[0].prefix_len, 60,
            "prefix_len should come from block, not delegate_prefix_len"
        );
        assert_eq!(prefixes[0].prefix_ip, Ipv6Addr::new(0xfd99, 0, 0, 0x39a0, 0, 0, 0, 0));
    }

    #[tokio::test]
    async fn test_pd_pool_exhausted() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: None,
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 60,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        };
        let server = make_server(&server_config);

        let qualifying = [
            (Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 0), 60),
            (Ipv6Addr::new(0xfd99, 0, 0, 1, 0, 0, 0, 0), 60),
        ];

        let r1 = server.offer_pd_index(b"client-a", &qualifying).await;
        let r2 = server.offer_pd_index(b"client-b", &qualifying).await;
        assert!(r1.is_some(), "client-a should get a block");
        assert!(r2.is_some(), "client-b should get a block");
        assert_ne!(r1.unwrap(), r2.unwrap(), "different clients get different pool indices");

        let r3 = server.offer_pd_index(b"client-c", &qualifying).await;
        assert!(r3.is_none(), "pool exhausted: third client should get None");
    }

    #[tokio::test]
    async fn test_pd_pool_exhausted_returns_no_prefix_avail() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: None,
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 60,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        };
        let server = make_server(&server_config);

        let qualifying = [(Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 0), 60)];
        server.offer_pd_index(b"client-a", &qualifying).await;

        let iapd = build_iapd_options(&server, b"client-b", 1, &qualifying).await;

        let status = iapd.opts.iter().find_map(|o| {
            if let v6::DhcpOption::StatusCode(ref sc) = o {
                Some(sc.status)
            } else {
                None
            }
        });
        assert_eq!(status, Some(Status::NoPrefixAvail));
    }

    #[tokio::test]
    async fn test_pd_qualifying_filter_blocks_too_long_prefix() {
        let server_config = DHCPv6ServerConfig {
            enable: true,
            ia_na: None,
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 56,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        };
        let server = make_server(&server_config);

        let (_, rx) = tokio::sync::watch::channel(());
        let pd = crate::ipv6::prefix::Assignment {
            statics: vec![
                crate::ipv6::prefix::PdDelegationParent {
                    prefix: Ipv6Addr::new(0xfd99, 0, 0, 0x3900, 0, 0, 0, 0),
                    prefix_len: 48,
                },
                crate::ipv6::prefix::PdDelegationParent {
                    prefix: Ipv6Addr::new(0xfd99, 0, 0, 0x39a0, 0, 0, 0, 0),
                    prefix_len: 60,
                },
                crate::ipv6::prefix::PdDelegationParent {
                    prefix: Ipv6Addr::new(0xfd99, 0, 0, 0x39b0, 0, 0, 0, 0),
                    prefix_len: 56,
                },
            ],
            dynamics: vec![],
            token: tokio_util::sync::CancellationToken::new(),
            notify: rx,
            boot_time: tokio::time::Instant::now(),
        };

        let result = server.get_qualifying_pd_prefixes(&pd).await;

        assert_eq!(
            result.len(),
            2,
            "/48 and /56 qualify under delegate_prefix_len=56, /60 should be filtered"
        );
        assert!(result.iter().all(|(_, len)| *len <= 56));
    }

    #[test]
    fn test_collect_dns_servers_link_local_first() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x00aa, 0xbbff, 0xfecc, 0xdd00);
        let (_, rx) = tokio::sync::watch::channel(());
        let na = Assignment {
            statics: vec![],
            dynamics: vec![],
            token: tokio_util::sync::CancellationToken::new(),
            notify: rx,
            boot_time: tokio::time::Instant::now(),
        };
        let dns = collect_dns_servers(&na, link_local);
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0], link_local);
    }

    #[test]
    fn test_collect_dns_servers_deduplicates() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x00aa, 0xbbff, 0xfecc, 0xdd00);
        let sub_router = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

        let info = ICMPv6ConfigInfo {
            rt_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            rt_prefix_len: 48,
            sub_router,
            sub_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            sub_prefix_len: 64,
            ra_preferred_lifetime: 300,
            ra_valid_lifetime: 600,
        };

        let (_, rx) = tokio::sync::watch::channel(());
        let na = Assignment {
            statics: vec![info.clone()],
            dynamics: vec![],
            token: tokio_util::sync::CancellationToken::new(),
            notify: rx,
            boot_time: tokio::time::Instant::now(),
        };
        let dns = collect_dns_servers(&na, link_local);
        assert_eq!(dns.len(), 2);
        assert_eq!(dns[0], link_local);
        assert_eq!(dns[1], sub_router);

        // Duplicate sub_router from static + runtime should be deduped
        let runtime_src: Arc<ArcSwap<Option<ICMPv6ConfigInfo>>> =
            Arc::new(ArcSwap::new(Arc::new(Some(info.clone()))));
        let (_, rx2) = tokio::sync::watch::channel(());
        let na2 = Assignment {
            statics: vec![info.clone()],
            dynamics: vec![runtime_src],
            token: tokio_util::sync::CancellationToken::new(),
            notify: rx2,
            boot_time: tokio::time::Instant::now(),
        };
        let dns2 = collect_dns_servers(&na2, link_local);
        assert_eq!(dns2.len(), 2);
    }

    #[test]
    fn test_collect_dns_servers_from_runtime() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x00aa, 0xbbff, 0xfecc, 0xdd00);
        let sub_router = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

        let info = ICMPv6ConfigInfo {
            rt_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            rt_prefix_len: 48,
            sub_router,
            sub_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            sub_prefix_len: 64,
            ra_preferred_lifetime: 300,
            ra_valid_lifetime: 600,
        };
        let runtime_src: Arc<ArcSwap<Option<ICMPv6ConfigInfo>>> =
            Arc::new(ArcSwap::new(Arc::new(Some(info))));

        let (_, rx) = tokio::sync::watch::channel(());
        let na = Assignment {
            statics: vec![],
            dynamics: vec![runtime_src],
            token: tokio_util::sync::CancellationToken::new(),
            notify: rx,
            boot_time: tokio::time::Instant::now(),
        };
        let dns = collect_dns_servers(&na, link_local);
        assert_eq!(dns.len(), 2);
        assert_eq!(dns[0], link_local);
        assert_eq!(dns[1], sub_router);
    }

    #[tokio::test]
    async fn test_build_iana_options_no_config_returns_no_addrs_avail() {
        let config = DHCPv6ServerConfig { enable: true, ia_na: None, ia_pd: None };
        let server = make_server(&config);
        let prefixes = [(Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0), 64)];

        let iana = build_iana_options(&server, b"client", 1, &prefixes).await;
        assert_eq!(iana.id, 1);
        assert_eq!(iana.t1, 0);
        assert_eq!(iana.t2, 0);
        let status = iana.opts.iter().find_map(|o| {
            if let v6::DhcpOption::StatusCode(ref sc) = o {
                Some(sc.status)
            } else {
                None
            }
        });
        assert_eq!(status, Some(Status::NoAddrsAvail));
    }

    #[tokio::test]
    async fn test_build_iapd_options_no_config_returns_no_prefix_avail() {
        let config = DHCPv6ServerConfig { enable: true, ia_na: None, ia_pd: None };
        let server = make_server(&config);
        let prefixes = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];

        let iapd = build_iapd_options(&server, b"client", 1, &prefixes).await;
        assert_eq!(iapd.id, 1);
        assert_eq!(iapd.t1, 0);
        assert_eq!(iapd.t2, 0);
        let status = iapd.opts.iter().find_map(|o| {
            if let v6::DhcpOption::StatusCode(ref sc) = o {
                Some(sc.status)
            } else {
                None
            }
        });
        assert_eq!(status, Some(Status::NoPrefixAvail));
    }

    #[tokio::test]
    async fn test_assigned_client_na_ips_missing_cache_returns_none() {
        let config = DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        };
        let server = make_server(&config);
        let prefixes = [(Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0), 64)];
        assert!(assigned_client_na_ips(&server, b"missing", &prefixes).await.is_none());
    }

    #[test]
    fn test_pd_route_key_index() {
        let prefix = Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 1);
        let key = pd_route_key_index(5, &prefix);
        assert_ne!(key, 0);
        // Same sub_index + prefix should produce same key
        let key2 = pd_route_key_index(5, &prefix);
        assert_eq!(key, key2);
        // Different sub_index should produce different key
        let key3 = pd_route_key_index(6, &prefix);
        assert_ne!(key, key3);
    }
}

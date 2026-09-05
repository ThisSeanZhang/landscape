use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use landscape_common::{
    database::error::DbError,
    event::hub::{IPv6AssignEvent, IPv6AssignEventSender, IPv6AssignInfo},
    lan_service::lan_ipv6::LanPrefixGroupConfig,
    net::MacAddr,
    net_proto::icmpv6::messages::Icmpv6Message,
    service::{ServiceStatus, WatchService},
    sys_service::route_service::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode},
    wan_service::ipv6_pd::IAPrefixMap,
};
use tokio::sync::{mpsc, watch};
use tokio::{net::UdpSocket, sync::Mutex};

use landscape_common::net_proto::udp::dhcp::v6::{
    Authentication, DhcpOption, Message, MessageType, OptionCode,
};
use landscape_common::net_proto::udp::dhcp::{Encodable, Encoder};

use super::{
    compute_subnets,
    connection::{get_dhcpv6_connect, get_icmp_connect},
    dhcpv6, icmpv6, ra, Ipv6LanReplyParams, Ipv6ServerStatus,
};
use crate::{
    addresses_by_iface_name,
    lan_service::lan_ipv6_service::MacLinkMapCache,
    netlink::ipv6::{add_route, add_route_via, del_iface_ip, del_route, set_iface_ip},
    sys_service::route::IpRouteService,
};
use dashmap::DashMap;
use landscape_common::lan_service::mac_binding::MacBindingDataplane;

use landscape_ebpf::chain::ip6_dao_event::Ip6DaoEvent;
use uuid::Uuid;

const LEASE_EXPIRE_INTERVAL: u64 = 60 * 10;
const SLAAC_VERIFICATION_CAPACITY: usize = 1024;
const SLAAC_VERIFICATION_PROBES_PER_SECOND: usize = 32;
const SLAAC_VERIFICATION_WARNING_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
enum SlaacVerificationState {
    Pending { probe_at: Instant },
    Cooldown { expires_at: Instant },
}

#[derive(Debug)]
struct SlaacVerificationQueue {
    entries: HashMap<Ipv6Addr, SlaacVerificationState>,
    rate_window_started_at: Instant,
    probes_taken_in_window: usize,
    last_capacity_warning: Option<Instant>,
}

impl SlaacVerificationQueue {
    fn new(now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            rate_window_started_at: now,
            probes_taken_in_window: 0,
            last_capacity_warning: None,
        }
    }

    fn enqueue(&mut self, ip: Ipv6Addr, now: Instant, delay: Duration, iface_name: &str) {
        self.remove_expired_cooldowns(now);
        if self.entries.contains_key(&ip) {
            return;
        }
        if self.entries.len() >= SLAAC_VERIFICATION_CAPACITY {
            if self.last_capacity_warning.is_none_or(|last| {
                now.saturating_duration_since(last) >= SLAAC_VERIFICATION_WARNING_INTERVAL
            }) {
                tracing::warn!(
                    "SLAAC verification queue is full on {iface_name}; dropping candidate {ip}"
                );
                self.last_capacity_warning = Some(now);
            }
            return;
        }
        self.entries.insert(ip, SlaacVerificationState::Pending { probe_at: now + delay });
    }

    fn remove(&mut self, ip: Ipv6Addr) {
        self.entries.remove(&ip);
    }

    fn take_due(&mut self, now: Instant) -> Vec<Ipv6Addr> {
        self.remove_expired_cooldowns(now);
        if now.saturating_duration_since(self.rate_window_started_at) >= Duration::from_secs(1) {
            self.rate_window_started_at = now;
            self.probes_taken_in_window = 0;
        }

        let remaining =
            SLAAC_VERIFICATION_PROBES_PER_SECOND.saturating_sub(self.probes_taken_in_window);
        if remaining == 0 {
            return Vec::new();
        }

        let mut due: Vec<(Ipv6Addr, Instant)> = self
            .entries
            .iter()
            .filter_map(|(ip, state)| match state {
                SlaacVerificationState::Pending { probe_at } if *probe_at <= now => {
                    Some((*ip, *probe_at))
                }
                _ => None,
            })
            .collect();
        due.sort_unstable_by_key(|(ip, probe_at)| (*probe_at, *ip));
        due.truncate(remaining);

        let ips: Vec<Ipv6Addr> = due.into_iter().map(|(ip, _)| ip).collect();
        for ip in &ips {
            self.entries.remove(ip);
        }
        self.probes_taken_in_window += ips.len();
        ips
    }

    fn mark_probed(&mut self, ip: Ipv6Addr, now: Instant, cooldown: Duration) {
        self.entries.insert(ip, SlaacVerificationState::Cooldown { expires_at: now + cooldown });
    }

    fn remove_expired_cooldowns(&mut self, now: Instant) {
        self.entries.retain(|_, state| {
            !matches!(state, SlaacVerificationState::Cooldown { expires_at } if *expires_at <= now)
        });
    }
}

/// Awaits the next DAD event; once the channel is gone, the future never
/// resolves so the enclosing select simply stops serving this arm.
async fn dad_recv(rx: &mut Option<mpsc::Receiver<Ip6DaoEvent>>) -> Option<Ip6DaoEvent> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

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
#[allow(clippy::too_many_arguments)]
async fn handle_icmp_msg(
    result: Option<(Vec<u8>, SocketAddr)>,
    iface_name: &str,
    service_status: &WatchService,
    share_status: &Arc<Mutex<Ipv6ServerStatus>>,
    mac_link_cache: &Arc<MacLinkMapCache>,
    params: &Ipv6LanReplyParams,
    mac_addr: &MacAddr,
    icmp_ad_interval: u32,
    icmp_sender: &Arc<UdpSocket>,
    ipv6_assign_sender: &IPv6AssignEventSender,
    link_ifindex: u32,
    device_id_map: &DashMap<MacAddr, Uuid>,
    slaac_verifications: &mut SlaacVerificationQueue,
    dataplane: &dyn MacBindingDataplane,
) -> bool {
    let Some((data, src_addr)) = result else {
        tracing::error!("ICMPv6 recv channel closed on {iface_name}");
        service_status.just_change_status(ServiceStatus::Failed);
        return false;
    };

    match icmpv6::parse(&data) {
        Some(Icmpv6Message::RouterSolicitation(_)) => {
            if let Some(mac) = icmpv6::extract_mac_from_rs(&data) {
                record_link_local_mac(&src_addr, mac, mac_link_cache, link_ifindex);
            }
            let status = share_status.lock().await;
            let ra = icmpv6::build_ra(&status, params, mac_addr, icmp_ad_interval * 1000);
            drop(status);
            let _ = icmpv6::send_msg(icmp_sender, &ra, src_addr).await;
        }
        Some(Icmpv6Message::NeighborSolicitation(_)) => {
            if let Some(mac) = icmpv6::extract_mac_from_ns(&data) {
                if let Some(ll) =
                    record_link_local_mac(&src_addr, mac, mac_link_cache, link_ifindex)
                {
                    tracing::debug!(
                        "recorded IPv6 client link-local mapping from NS: {ll} -> {mac}"
                    );
                }

                if let SocketAddr::V6(src_v6) = src_addr {
                    let ip = *src_v6.ip();
                    if is_usable_slaac_source(ip) {
                        let mut status = share_status.lock().await;
                        if status.touch_slaac_addr(mac, ip) {
                            tracing::debug!("refreshed SLAAC activity from NS: {ip} -> {mac}");
                        }
                    }
                }
            }
        }
        Some(Icmpv6Message::NeighborAdvertisement(_)) => {
            let mut status = share_status.lock().await;
            let action = icmpv6::handle_na(&data, src_addr, &mut status);
            match &action {
                icmpv6::SlaacActionResult::VerificationCandidate { ip }
                    if params.ra_autonomous
                        && is_usable_slaac_source(*ip)
                        && status.should_verify_slaac_addr(*ip) =>
                {
                    slaac_verifications.enqueue(
                        *ip,
                        Instant::now(),
                        Duration::from_secs(u64::from(icmp_ad_interval) / 2),
                        iface_name,
                    );
                }
                icmpv6::SlaacActionResult::Allocated { ip, .. }
                | icmpv6::SlaacActionResult::Refreshed { ip, .. }
                | icmpv6::SlaacActionResult::Conflict { ip, .. } => {
                    slaac_verifications.remove(*ip);
                }
                _ => {}
            }
            match &action {
                icmpv6::SlaacActionResult::Allocated { mac, .. }
                | icmpv6::SlaacActionResult::Conflict { mac, .. } => {
                    record_link_local_mac(&src_addr, *mac, mac_link_cache, link_ifindex);
                }
                _ => {}
            }
            if let icmpv6::SlaacActionResult::Allocated { mac, ip } = &action {
                dataplane.learn_ipv6(link_ifindex, *ip, *mac, *mac_addr);
            }

            match action {
                icmpv6::SlaacActionResult::Allocated { mac, ip } => {
                    let device_id = device_id_map.get(&mac).map(|r| *r.value());
                    if let Err(e) =
                        ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(IPv6AssignInfo {
                            iface_name: iface_name.to_string(),
                            mac,
                            ips: vec![ip],
                            device_id,
                        }))
                    {
                        tracing::error!("ND Allocated event FAILED for {mac} -> {ip}: {e:?}");
                    }
                }
                icmpv6::SlaacActionResult::Conflict { .. } => {
                    // MAC is now always known at DHCPv6 allocation time,
                    // so Conflict only implies the NA refreshed reachability.
                    // No event needed – the lease's activity time is handled
                    // by icmpv6::handle_na internally.
                }
                icmpv6::SlaacActionResult::Refreshed { .. } => {
                    // Refreshed only updates SLAAC activity time and probe
                    // state; it intentionally has no event or prewarm side effect.
                }
                icmpv6::SlaacActionResult::VerificationCandidate { .. } => {}
                _ => {}
            }
        }
        _ => {}
    }

    true
}

fn record_link_local_mac(
    src_addr: &SocketAddr,
    mac: MacAddr,
    mac_link_cache: &Arc<MacLinkMapCache>,
    link_ifindex: u32,
) -> Option<Ipv6Addr> {
    let SocketAddr::V6(v6) = src_addr else {
        return None;
    };

    let ll = *v6.ip();
    if !ll.is_unicast_link_local() {
        return None;
    }

    mac_link_cache.record(link_ifindex, mac, ll);
    Some(ll)
}

fn is_usable_slaac_source(ip: Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_unicast_link_local())
}

/// Returns `false` when the DHCP recv channel is closed and the loop should break.
#[allow(clippy::too_many_arguments)]
async fn handle_dhcp_msg(
    result: Option<(Vec<u8>, SocketAddr)>,
    iface_name: &str,
    mac_addr: MacAddr,
    link_ifindex: u32,
    mac_link_cache: &Arc<MacLinkMapCache>,
    service_status: &WatchService,
    share_status: &Arc<Mutex<Ipv6ServerStatus>>,
    server_duid: &[u8],
    params: &Ipv6LanReplyParams,
    dhcp_sender: &Arc<UdpSocket>,
    ipv6_assign_sender: &IPv6AssignEventSender,
    route_service: &IpRouteService,
    device_id_map: &DashMap<MacAddr, Uuid>,
    dataplane: &dyn MacBindingDataplane,
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
            mac_link_cache,
            link_ifindex,
        );

        // Send reply
        if let Some(reply) = result.reply_bytes {
            let _ = dhcp_sender.send_to(&reply, result.reply_dst).await;
        }

        // Emit allocation events — grouped by MAC
        if !result.allocated_ips.is_empty() {
            let mut alloc_by_mac: std::collections::HashMap<MacAddr, Vec<Ipv6Addr>> =
                std::collections::HashMap::new();
            for (mac, ip) in &result.allocated_ips {
                dataplane.learn_ipv6(link_ifindex, *ip, *mac, mac_addr);
                alloc_by_mac.entry(*mac).or_default().push(*ip);
            }
            for (mac, grouped_ips) in alloc_by_mac {
                let device_id = device_id_map.get(&mac).map(|r| *r.value());
                if let Err(e) =
                    ipv6_assign_sender.try_send(IPv6AssignEvent::Allocated(IPv6AssignInfo {
                        iface_name: iface_name.to_string(),
                        mac,
                        ips: grouped_ips,
                        device_id,
                    }))
                {
                    tracing::error!("IPv6 assign event FAILED for {mac}: {e:?}");
                }
            }
        }

        // Emit expiry events — grouped by MAC
        if !result.expired_ips.is_empty() {
            let mut exp_by_mac: std::collections::HashMap<MacAddr, Vec<Ipv6Addr>> =
                std::collections::HashMap::new();
            for (mac, ip) in &result.expired_ips {
                exp_by_mac.entry(*mac).or_default().push(*ip);
            }
            for (mac, grouped_ips) in exp_by_mac {
                let device_id = device_id_map.get(&mac).map(|r| *r.value());
                let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                    iface_name: iface_name.to_string(),
                    mac,
                    ips: grouped_ips,
                    device_id,
                }));
            }
        }

        result.pd_route_changes
    };

    // PD route management (status lock released)
    for change in &pd_route_changes {
        for (prefix, len) in &change.old_routes {
            del_route(*prefix, *len, iface_name);
            let key = LanIPv6RouteKey {
                iface_name: iface_name.to_string(),
                subnet: *prefix,
                prefix_len: *len,
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
                subnet: *prefix,
                prefix_len: *len,
            };
            route_service.insert_ipv6_lan_route(key, lan_info).await;
        }
    }

    true
}

#[allow(clippy::too_many_arguments)]
async fn handle_expire_tick(
    iface_name: &str,
    share_status: &Arc<Mutex<Ipv6ServerStatus>>,
    ipv6_assign_sender: &IPv6AssignEventSender,
    route_service: &IpRouteService,
    slaac_probe_t1: u64,
    slaac_probe_t2: u64,
    icmp_sender: &Arc<UdpSocket>,
    mac_addr: &MacAddr,
    device_id_map: &DashMap<MacAddr, Uuid>,
) {
    let (pd_cleanups, slaac_probes) = {
        let mut status = share_status.lock().await;

        let expired_na = status.clean_expired_na();
        for na in &expired_na {
            let device_id = device_id_map.get(&na.mac).map(|r| *r.value());
            let ips = status.suffix_to_addrs(na.suffix);
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                iface_name: iface_name.to_string(),
                mac: na.mac,
                ips,
                device_id,
            }));
        }

        let expired_pd = status.clean_expired_pd();
        let pd_cleanups = expired_pd
            .iter()
            .map(|pd| (pd.sub_index, pd.active_routes.clone()))
            .collect::<Vec<_>>();

        let sweep = status.slaac_expire_sweep(slaac_probe_t1, slaac_probe_t2);
        for (ip, mac) in &sweep.expired {
            let device_id = device_id_map.get(mac).map(|r| *r.value());
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Expired(IPv6AssignInfo {
                iface_name: iface_name.to_string(),
                mac: *mac,
                ips: vec![*ip],
                device_id,
            }));
        }

        (pd_cleanups, sweep.to_probe)
    };

    // Send liveness probes (unicast NS) outside the status lock (needs .await).
    // A live device replies with NA, which refreshes its entry via handle_na.
    for ip in slaac_probes {
        let dst = SocketAddr::new(IpAddr::V6(ip), 0);
        if !icmpv6::send_msg(icmp_sender, &icmpv6::build_ns(ip, mac_addr), dst).await {
            tracing::warn!("best-effort SLAAC liveness probe failed for {ip}");
        }
    }

    // PD route cleanup outside status lock (needs .await)
    for (_sub_index, routes) in &pd_cleanups {
        for (prefix, len) in routes {
            del_route(*prefix, *len, iface_name);
            let key = LanIPv6RouteKey {
                iface_name: iface_name.to_string(),
                subnet: *prefix,
                prefix_len: *len,
            };
            route_service.remove_ipv6_lan_route_by_key(&key).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_ipv6_lan_server(
    ifindex: u32,
    iface_name: String,
    mac_addr: MacAddr,
    service_status: WatchService,
    icmp_ad_interval: u32,
    ipv6_assign_sender: &IPv6AssignEventSender,
    share_status: Arc<Mutex<Ipv6ServerStatus>>,
    mac_link_cache: Arc<MacLinkMapCache>,
    prefix_groups: Vec<LanPrefixGroupConfig>,
    prefix_map: IAPrefixMap,
    mut prefix_change_rx: watch::Receiver<()>,
    params: Ipv6LanReplyParams,
    route_service: IpRouteService,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
    mut reconf_rx: mpsc::UnboundedReceiver<MacAddr>,
    dad_rx: mpsc::Receiver<Ip6DaoEvent>,
    dataplane: Arc<dyn MacBindingDataplane>,
) -> Result<(), DbError> {
    let mut dad_rx = Some(dad_rx);
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
    let initial_subnets = compute_subnets(&prefix_groups, &prefix_map, params.preferred_lifetime);
    {
        let mut status = share_status.lock().await;
        status.preferred_lifetime = params.preferred_lifetime;
        status.valid_lifetime = params.valid_lifetime;
        status.update_prefix(&initial_subnets);

        let static_macs: Vec<MacAddr> = status.na_static_by_mac.keys().cloned().collect();
        for mac in &static_macs {
            let ips = status.all_ips_for_mac(mac);
            let device_id = device_id_map.get(mac).map(|r| *r.value());
            let _ = ipv6_assign_sender.try_send(IPv6AssignEvent::Flush(IPv6AssignInfo {
                iface_name: iface_name.clone(),
                mac: *mac,
                ips,
                device_id,
            }));
        }
    }

    // System I/O for subnets (outside lock)
    for sn in &initial_subnets {
        if !sn.has_router() {
            continue;
        }
        set_iface_ip(sn.sub_router, sn.sub_prefix_len, &iface_name, None, None);
        add_route(sn.sub_prefix, sn.sub_prefix_len, &iface_name, None);
        let lan_info = LanRouteInfo {
            ifindex: link_ifindex,
            iface_name: iface_name.clone(),
            iface_ip: IpAddr::V6(sn.sub_router),
            mac: Some(mac_addr),
            prefix: sn.sub_prefix_len,
            mode: LanRouteMode::Reachable,
        };
        let key = LanIPv6RouteKey {
            iface_name: iface_name.clone(),
            subnet: sn.sub_prefix,
            prefix_len: sn.sub_prefix_len,
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
    icmp_ra_interval.reset_immediately();
    let mut dhcp_expire_timer =
        Box::pin(tokio::time::interval(Duration::from_secs(LEASE_EXPIRE_INTERVAL)));
    let mut slaac_verification_timer = Box::pin(tokio::time::interval(Duration::from_secs(1)));
    slaac_verification_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut slaac_verifications = SlaacVerificationQueue::new(Instant::now());

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
                    &mac_link_cache, &params, &mac_addr, icmp_ad_interval, &icmp_sender,
                    ipv6_assign_sender, link_ifindex, &device_id_map,
                    &mut slaac_verifications, dataplane.as_ref(),
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
                        &mac_link_cache, &service_status, &share_status,
                        &server_duid, &params, dhcp_sender,
                        ipv6_assign_sender, &route_service, &device_id_map,
                        dataplane.as_ref(),
                    ).await {
                        break;
                    }
                }
            },
            _ = dhcp_expire_timer.tick() => {
                handle_expire_tick(
                    &iface_name, &share_status, ipv6_assign_sender, &route_service,
                    params.valid_lifetime as u64,
                    params.valid_lifetime as u64 + LEASE_EXPIRE_INTERVAL,
                    &icmp_sender, &mac_addr, &device_id_map,
                ).await;
            },
            _ = slaac_verification_timer.tick() => {
                let now = Instant::now();
                let due = slaac_verifications.take_due(now);
                for ip in due {
                    if !params.ra_autonomous {
                        continue;
                    }

                    let multicast = icmpv6::solicited_node_multicast(ip);
                    let dst = SocketAddr::new(IpAddr::V6(multicast), 0);
                    let _ = icmpv6::send_msg(
                        &icmp_sender,
                        &icmpv6::build_ns(ip, &mac_addr),
                        dst,
                    ).await;
                    slaac_verifications.mark_probed(
                        ip,
                        now,
                        Duration::from_secs(u64::from(icmp_ad_interval)),
                    );
                }
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
                        let ip = mac_link_cache.lookup_ll_by_mac(link_ifindex, &mac);
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
                    let diff = status.recompute_and_diff(&prefix_groups, &prefix_map);

                    // Flush all MACs after prefix change — new prefix means new IPs
                    let macs: HashSet<MacAddr> = status
                        .na_leases_by_duid
                        .values()
                        .map(|l| l.mac)
                        .chain(status.slaac_entries.values().map(|e| e.mac))
                        .collect();
                    for mac in &macs {
                        let ips = status.all_ips_for_mac(mac);
                        let device_id = device_id_map.get(mac).map(|r| *r.value());
                        let _ =
                            ipv6_assign_sender.try_send(IPv6AssignEvent::Flush(IPv6AssignInfo {
                                iface_name: iface_name.clone(),
                                mac: *mac,
                                ips,
                                device_id,
                            }));
                    }

                    diff
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
                        subnet: sn.sub_prefix,
                        prefix_len: sn.sub_prefix_len,
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
                        ifindex: link_ifindex,
                        iface_name: iface_name.clone(),
                        iface_ip: IpAddr::V6(sn.sub_router),
                        mac: Some(mac_addr),
                        prefix: sn.sub_prefix_len,
                        mode: LanRouteMode::Reachable,
                    };
                    let key = LanIPv6RouteKey {
                        iface_name: iface_name.clone(),
                        subnet: sn.sub_prefix,
                        prefix_len: sn.sub_prefix_len,
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
                            subnet: *prefix,
                            prefix_len: *len,
                        };
                        route_service.remove_ipv6_lan_route_by_key(&key).await;
                    }
                }
                // Immediate RA after prefix change
                icmp_ra_interval.reset_immediately();
            },
            ev = dad_recv(&mut dad_rx) => {
                let Some(ev) = ev else {
                    // Only happens if the per-iface DAD channel was removed
                    // (service restart race or shutdown); keep serving
                    // RA/DHCPv6, just stop learning DAD events.
                    tracing::warn!("DAD event channel closed on {iface_name}; DAD learning disabled");
                    dad_rx = None;
                    continue;
                };
                let ip = ev.ipv6();
                // No RA-prefix re-check: the eBPF rt6_lan_map guard already
                // bounds the event to this interface's served subnets.
                if params.ra_autonomous {
                    slaac_verifications.enqueue(
                        ip,
                        Instant::now(),
                        Duration::from_secs(u64::from(icmp_ad_interval) / 2),
                        &iface_name,
                    );
                }
            },
            result = service_status_subscribe.changed() => {
                tracing::debug!("LAN v6 Service change");
                if result.is_err() {
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

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn verification_queue(now: Instant) -> SlaacVerificationQueue {
        SlaacVerificationQueue::new(now)
    }

    #[test]
    fn record_link_local_mac_updates_cache_for_link_local_source() {
        let cache = Arc::new(MacLinkMapCache::new());
        let ifindex = 7;
        let ll = "fe80::1234:5678:9abc:def0".parse().unwrap();
        let mac = MacAddr::from([0x02, 0x00, 0x00, 0x12, 0x34, 0x56]);
        let src = SocketAddr::new(IpAddr::V6(ll), 0);

        assert_eq!(record_link_local_mac(&src, mac, &cache, ifindex), Some(ll));
        assert_eq!(cache.lookup_mac_by_ll(ifindex, &ll), Some(mac));
    }

    #[test]
    fn record_link_local_mac_ignores_non_link_local_source() {
        let cache = Arc::new(MacLinkMapCache::new());
        let ifindex = 7;
        let global = "2001:db8::1".parse().unwrap();
        let mac = MacAddr::from([0x02, 0x00, 0x00, 0x12, 0x34, 0x56]);
        let src = SocketAddr::new(IpAddr::V6(global), 0);

        assert_eq!(record_link_local_mac(&src, mac, &cache, ifindex), None);
        assert_eq!(cache.lookup_mac_by_ll(ifindex, &global), None);
    }

    #[test]
    fn slaac_touch_rejects_dad_and_link_local_sources() {
        assert!(!is_usable_slaac_source(Ipv6Addr::UNSPECIFIED));
        assert!(!is_usable_slaac_source("fe80::1".parse().unwrap()));
    }

    #[test]
    fn slaac_touch_accepts_ula_and_global_sources() {
        assert!(is_usable_slaac_source("fd00::1".parse().unwrap()));
        assert!(is_usable_slaac_source("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn verification_queue_deduplicates_without_moving_deadline() {
        let now = Instant::now();
        let ip = "fd00::1".parse().unwrap();
        let mut queue = verification_queue(now);

        queue.enqueue(ip, now, Duration::from_secs(30), "lan0");
        queue.enqueue(ip, now + Duration::from_secs(10), Duration::from_secs(30), "lan0");

        assert!(queue.take_due(now + Duration::from_secs(29)).is_empty());
        assert_eq!(queue.take_due(now + Duration::from_secs(30)), vec![ip]);
    }

    #[test]
    fn verification_queue_limits_each_rate_window() {
        let now = Instant::now();
        let mut queue = verification_queue(now);
        for suffix in 1..=40u16 {
            queue.enqueue(
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, suffix),
                now,
                Duration::ZERO,
                "lan0",
            );
        }

        assert_eq!(queue.take_due(now).len(), SLAAC_VERIFICATION_PROBES_PER_SECOND);
        assert!(queue.take_due(now).is_empty());
        assert_eq!(queue.take_due(now + Duration::from_secs(1)).len(), 8);
    }

    #[test]
    fn verification_queue_cooldown_blocks_until_expiry() {
        let now = Instant::now();
        let ip = "fd00::1".parse().unwrap();
        let mut queue = verification_queue(now);

        queue.mark_probed(ip, now, Duration::from_secs(60));
        queue.enqueue(ip, now + Duration::from_secs(30), Duration::ZERO, "lan0");
        assert!(queue.take_due(now + Duration::from_secs(30)).is_empty());

        queue.enqueue(ip, now + Duration::from_secs(60), Duration::ZERO, "lan0");
        assert_eq!(queue.take_due(now + Duration::from_secs(60)), vec![ip]);
    }

    #[test]
    fn verification_queue_capacity_counts_cooldown_entries() {
        let now = Instant::now();
        let mut queue = verification_queue(now);
        for suffix in 0..SLAAC_VERIFICATION_CAPACITY {
            let ip = Ipv6Addr::from(u128::from(0xfd00u16) << 112 | suffix as u128);
            queue.mark_probed(ip, now, Duration::from_secs(60));
        }

        let extra = "fd00::ffff".parse().unwrap();
        queue.enqueue(extra, now, Duration::ZERO, "lan0");
        assert!(!queue.entries.contains_key(&extra));
        assert_eq!(queue.entries.len(), SLAAC_VERIFICATION_CAPACITY);
    }
}

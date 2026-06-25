use landscape_common::client::{CallerLookupMatch, CallerLookupSource};
use landscape_common::database::LandscapeStore as LandscapeDBStore;
use landscape_common::dhcp::v6_server::config::DHCPv6ServerConfig;
use landscape_common::dhcp::v6_server::status::DHCPv6OfferInfo;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IAPrefixEvent, IPv6AssignEventSender,
    IfaceEventReader,
};
use landscape_common::ipv6::lan::{IPv6ServiceMode, LanIPv6ConfigV2, LanIPv6ServiceConfigV2};
use landscape_common::ipv6_pd::IAPrefixMap;
use landscape_common::lan_services::ipv6_ra::IPv6NAInfo;
use landscape_common::observer::IfaceObserverAction;
use landscape_common::route::LanRouteInfo;
use landscape_common::route::LanRouteMode;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::manager::ServiceManager;
use landscape_common::service::manager::ServiceStarterTrait;
use landscape_common::service::WatchService;
use landscape_common::store::storev2::LandscapeStore;
use landscape_database::enrolled_device::repository::EnrolledDeviceRepository;
use landscape_database::lan_ipv6_v2::repository::LanIPv6V2ServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::dhcp_server::v6::DhcpV6LeaseAllocator;
use crate::iface::get_iface_by_name;
use crate::ipv6::prefix::{cleanup_prefix_sources, setup_lan_prefixes};
use crate::route::IpRouteService;
use dashmap::DashMap;

/// LAN IPv6 service: manages RA + DHCPv6 per interface with mode-aware orchestration

#[derive(Clone)]
pub struct LanIPv6Service {
    route_service: IpRouteService,
    prefix_map: IAPrefixMap,
    prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
    iface_lease_map: Arc<RwLock<HashMap<String, Arc<RwLock<IPv6NAInfo>>>>>,
    iface_dhcpv6_allocator_map: Arc<RwLock<HashMap<String, Arc<Mutex<DhcpV6LeaseAllocator>>>>>,
    enrolled_device_store: EnrolledDeviceRepository,
    ipv6_assign_sender: IPv6AssignEventSender,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
}

impl LanIPv6Service {
    pub fn new(
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
        enrolled_device_store: EnrolledDeviceRepository,
        ipv6_assign_sender: IPv6AssignEventSender,
    ) -> Self {
        Self {
            route_service,
            prefix_map,
            prefix_broadcast_tx,
            iface_lease_map: Arc::new(RwLock::new(HashMap::new())),
            iface_dhcpv6_allocator_map: Arc::new(RwLock::new(HashMap::new())),
            enrolled_device_store,
            ipv6_assign_sender,
            device_id_map: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for LanIPv6Service {
    type Config = LanIPv6ServiceConfigV2;

    async fn start(&self, config: LanIPv6ServiceConfigV2) -> WatchService {
        let service_status = WatchService::new();
        if config.enable {
            let route_service = self.route_service.clone();
            let prefix_map = self.prefix_map.clone();
            let prefix_broadcast_tx = self.prefix_broadcast_tx.clone();
            let status_clone = service_status.clone();
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let store_key = config.get_store_key();
                let assigned_ips = {
                    let mut write = self.iface_lease_map.write().await;
                    let entry = write
                        .entry(store_key.clone())
                        .or_insert_with(|| Arc::new(RwLock::new(IPv6NAInfo::init())));
                    *entry.write().await = IPv6NAInfo::init();
                    entry.clone()
                };

                // DHCPv6 setup
                let dhcpv6_config = config.config.dhcpv6.clone();
                let dhcpv6_enabled = dhcpv6_config.as_ref().map_or(false, |c| c.enable);

                // Query enrolled devices for IPv6 bindings
                let devices = self
                    .enrolled_device_store
                    .find_ipv6_bindings(config.iface_name.clone())
                    .await
                    .unwrap_or_default();

                for d in &devices {
                    self.device_id_map.insert(d.mac, d.id);
                }

                let dhcpv6_allocator: Option<Arc<Mutex<DhcpV6LeaseAllocator>>> = if dhcpv6_enabled {
                    let dhcpv6_cfg = dhcpv6_config.as_ref().unwrap();
                    let allocator =
                        DhcpV6LeaseAllocator::from_config_and_devices(dhcpv6_cfg, devices);
                    let allocator_arc = Arc::new(Mutex::new(allocator));
                    {
                        let mut write = self.iface_dhcpv6_allocator_map.write().await;
                        write.insert(store_key.clone(), allocator_arc.clone());
                    }
                    Some(allocator_arc)
                } else {
                    None
                };

                if let Some(mac) = iface.mac {
                    let link_ifindex = iface.index;
                    let lan_info = LanRouteInfo {
                        ifindex: iface.index,
                        iface_name: config.iface_name.clone(),
                        iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        mac: Some(mac.clone()),
                        prefix: 128,
                        mode: LanRouteMode::Reachable,
                    };
                    let ipv6_assign_sender = self.ipv6_assign_sender.clone();
                    let device_id_map = self.device_id_map.clone();
                    tokio::spawn(async move {
                        let mode = config.config.mode;
                        let LanIPv6ConfigV2 { ad_interval, ra_flag, prefix_groups, dhcpv6, .. } =
                            config.config;
                        let iface_name = config.iface_name;

                        run_mode(
                            mode,
                            &prefix_groups,
                            dhcpv6,
                            &iface_name,
                            &lan_info,
                            &route_service,
                            &prefix_map,
                            &prefix_broadcast_tx,
                            ad_interval,
                            ra_flag,
                            mac,
                            link_ifindex,
                            status_clone,
                            assigned_ips,
                            dhcpv6_allocator,
                            ipv6_assign_sender,
                            device_id_map,
                        )
                        .await;
                    });
                }
            }
        }

        service_status
    }
}

use landscape_common::ipv6::ra::RouterFlags;
use landscape_common::net::MacAddr;

/// Single unified function for all three IPv6 service modes.
///
/// Calls `setup_lan_prefixes` once — no `filter_kinds`, no double invocation.
/// Each mode picks the assignments it needs from the result.
async fn run_mode(
    mode: IPv6ServiceMode,
    groups: &[landscape_common::ipv6::lan::LanPrefixGroupConfig],
    dhcpv6: Option<DHCPv6ServerConfig>,
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    prefix_broadcast_tx: &broadcast::Sender<IAPrefixEvent>,
    ad_interval: u32,
    ra_flag: RouterFlags,
    mac: MacAddr,
    link_ifindex: u32,
    status: WatchService,
    assigned_ips: Arc<RwLock<IPv6NAInfo>>,
    dhcpv6_allocator: Option<Arc<Mutex<DhcpV6LeaseAllocator>>>,
    ipv6_assign_sender: IPv6AssignEventSender,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
) {
    let setup = setup_lan_prefixes(
        groups,
        iface_name,
        lan_info,
        route_service,
        prefix_map,
        prefix_broadcast_tx,
    )
    .await;

    match mode {
        IPv6ServiceMode::Slaac => {
            // RA only: SLAAC clients auto-configure from RA prefixes.
            // Cancel DHCPv6-related tokens — no DHCPv6 in this mode.
            setup.na.token.cancel();
            setup.pd.token.cancel();

            let _ = crate::icmp::v6::icmp_ra_server(
                ad_interval,
                ra_flag,
                mac,
                iface_name.to_string(),
                status,
                setup.ra,
                assigned_ips,
                true, // autonomous: SLAAC clients auto-configure
                None, // no onlink
                link_ifindex,
                ipv6_assign_sender,
                device_id_map,
            )
            .await;
        }

        IPv6ServiceMode::Stateful => {
            let dhcpv6_config = match dhcpv6 {
                Some(c) if c.enable => c,
                _ => {
                    tracing::error!("Stateful mode but DHCPv6 not enabled");
                    status.just_change_status(landscape_common::service::ServiceStatus::Failed);
                    return;
                }
            };

            // RA doesn't need prefix data for itself in Stateful mode
            setup.ra.token.cancel();

            if let Some(ref allocator) = dhcpv6_allocator {
                let dhcpv6_iface = iface_name.to_string();
                let dhcpv6_mac = mac.clone();
                let dhcpv6_status = status.clone();
                let dhcpv6_route = route_service.clone();
                let link_local = mac.to_ipv6_link_local();
                let s = allocator.clone();
                let snd = ipv6_assign_sender.clone();
                let dmap = device_id_map.clone();
                let na_clone = setup.na.clone();
                let pd_clone = setup.pd.clone();

                tokio::spawn(async move {
                    crate::dhcp_server::v6::dhcp_v6_server(
                        link_ifindex,
                        dhcpv6_iface,
                        dhcpv6_mac,
                        link_local,
                        dhcpv6_config,
                        na_clone,
                        pd_clone,
                        dhcpv6_status,
                        s,
                        dhcpv6_route,
                        snd,
                        dmap,
                    )
                    .await;
                });
            }

            // RA: advertise prefixes with A=0 (clients use DHCPv6)
            let _ = crate::icmp::v6::icmp_ra_server(
                ad_interval,
                ra_flag,
                mac,
                iface_name.to_string(),
                status,
                setup.na,
                assigned_ips,
                false, // autonomous=false
                None,  // no onlink
                link_ifindex,
                ipv6_assign_sender,
                device_id_map,
            )
            .await;
            setup.pd.token.cancel();
        }

        IPv6ServiceMode::SlaacDhcpv6 => {
            let dhcpv6_config = match dhcpv6 {
                Some(c) if c.enable => c,
                _ => {
                    tracing::error!("SlaacDhcpv6 mode but DHCPv6 not enabled");
                    status.just_change_status(landscape_common::service::ServiceStatus::Failed);
                    return;
                }
            };

            if let Some(ref allocator) = dhcpv6_allocator {
                let dhcpv6_iface = iface_name.to_string();
                let dhcpv6_mac = mac.clone();
                let dhcpv6_status = status.clone();
                let dhcpv6_route = route_service.clone();
                let link_local = mac.to_ipv6_link_local();
                let s = allocator.clone();
                let snd = ipv6_assign_sender.clone();
                let dmap = device_id_map.clone();
                // Clone: one copy for DHCPv6 server, original used as RA onlink
                let na_dhcp = setup.na.clone();
                let pd_dhcp = setup.pd.clone();

                tokio::spawn(async move {
                    crate::dhcp_server::v6::dhcp_v6_server(
                        link_ifindex,
                        dhcpv6_iface,
                        dhcpv6_mac,
                        link_local,
                        dhcpv6_config,
                        na_dhcp,
                        pd_dhcp,
                        dhcpv6_status,
                        s,
                        dhcpv6_route,
                        snd,
                        dmap,
                    )
                    .await;
                });
            }

            // RA: ULA prefixes with A=1 + DHCPv6 GUA prefixes as onlink (A=0)
            let _ = crate::icmp::v6::icmp_ra_server(
                ad_interval,
                ra_flag,
                mac,
                iface_name.to_string(),
                status,
                setup.ra,
                assigned_ips,
                true,           // autonomous: clients SLAAC from ULA prefixes
                Some(setup.na), // onlink: NA prefixes as A=0 on-link only
                link_ifindex,
                ipv6_assign_sender,
                device_id_map,
            )
            .await;
            setup.pd.token.cancel();
        }
    }

    cleanup_prefix_sources(setup.cleanup_ips, iface_name, route_service).await;
}

#[derive(Clone)]
pub struct LanIPv6ManagerService {
    store: LanIPv6V2ServiceRepository,
    service: ServiceManager<LanIPv6Service>,
    server_starter: LanIPv6Service,
}

impl ControllerService for LanIPv6ManagerService {
    type Id = String;
    type Config = LanIPv6ServiceConfigV2;
    type DatabseAction = LanIPv6V2ServiceRepository;
    type H = LanIPv6Service;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl LanIPv6ManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        mut device_reader: EnrolledDeviceEventReader,
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
        ipv6_assign_sender: IPv6AssignEventSender,
    ) -> Self {
        let store = store_service.lan_ipv6_v2_service_store();
        let enrolled_device_store = store_service.enrolled_device_store();
        let server_starter = LanIPv6Service::new(
            route_service,
            prefix_map,
            prefix_broadcast_tx,
            enrolled_device_store,
            ipv6_assign_sender,
        );
        let service =
            ServiceManager::init(store.list().await.unwrap(), server_starter.clone()).await;

        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} LAN IPv6 service");
                        let service_config = if let Some(service_config) =
                            store.find_by_id(iface_name.clone()).await.unwrap()
                        {
                            service_config
                        } else {
                            continue;
                        };

                        let _ = service_clone.update_service(service_config).await;
                    }
                    IfaceObserverAction::Down(_) => {}
                }
            }
        });

        let allocator_map = server_starter.iface_dhcpv6_allocator_map.clone();
        let device_id_map = server_starter.device_id_map.clone();
        tokio::spawn(async move {
            while let Ok(event) = device_reader.recv().await {
                let affected = extract_binding_ifaces_v6(&event);
                let targets: Vec<String> = {
                    let guard = allocator_map.read().await;
                    if affected.is_empty() {
                        guard.keys().cloned().collect()
                    } else {
                        affected.into_iter().filter(|i| guard.contains_key(i)).collect()
                    }
                };
                for iface in &targets {
                    let allocator = {
                        let guard = allocator_map.read().await;
                        guard.get(iface).cloned()
                    };
                    if let Some(allocator) = allocator {
                        let mut allocator = allocator.lock().await;
                        match &event {
                            EnrolledDeviceEvent::Updated { old, new } => {
                                if let Some(d) = old.as_ref() {
                                    allocator.remove_binding(&d.mac);
                                }
                                if let Some(ipv6) = new.ipv6 {
                                    allocator.add_or_update_binding(new.mac, ipv6);
                                }
                            }
                            EnrolledDeviceEvent::Deleted { old } => {
                                allocator.remove_binding(&old.mac);
                            }
                        }
                    }
                }
                match &event {
                    EnrolledDeviceEvent::Updated { old, new } => {
                        if let Some(d) = old.as_ref() {
                            if d.mac != new.mac || new.ipv6.is_none() {
                                device_id_map.remove(&d.mac);
                            }
                        }
                        if new.ipv6.is_some() {
                            device_id_map.insert(new.mac, new.id);
                        }
                    }
                    EnrolledDeviceEvent::Deleted { old } => {
                        device_id_map.remove(&old.mac);
                    }
                }
            }
        });

        let store = store_service.lan_ipv6_v2_service_store();
        Self { service, store, server_starter }
    }

    pub async fn refresh_iface_service(&self, iface_name: String) {
        let Some(service_config) = self.get_config_by_name(iface_name).await else {
            return;
        };
        let _ = self.get_service().update_service(service_config).await;
    }

    pub async fn get_assigned_ips_by_iface_name(&self, iface_name: String) -> Option<IPv6NAInfo> {
        let info = {
            let read_lock = self.server_starter.iface_lease_map.read().await;
            read_lock.get(&iface_name).map(Clone::clone)
        };

        let Some(offer_info) = info else { return None };

        let data = offer_info.read().await.clone();
        return Some(data);
    }

    pub async fn get_assigned_ips(&self) -> HashMap<String, IPv6NAInfo> {
        let mut result = HashMap::new();

        let map = {
            let read_lock = self.server_starter.iface_lease_map.read().await;
            read_lock.clone()
        };

        for (iface_name, assigned_ips) in map {
            if let Ok(read) = assigned_ips.try_read() {
                result.insert(iface_name, read.clone());
            }
        }

        result
    }

    pub async fn get_dhcpv6_assigned_by_iface_name(
        &self,
        iface_name: String,
    ) -> Option<DHCPv6OfferInfo> {
        let status_arc = {
            let guard = self.server_starter.iface_dhcpv6_allocator_map.read().await;
            guard.get(&iface_name).cloned()
        }?;
        let allocator = status_arc.lock().await;
        Some(allocator.lease_view_with_last_prefixes())
    }

    pub async fn get_dhcpv6_assigned(&self) -> HashMap<String, DHCPv6OfferInfo> {
        let mut result = HashMap::new();
        let allocators: Vec<(String, Arc<Mutex<DhcpV6LeaseAllocator>>)> = {
            let guard = self.server_starter.iface_dhcpv6_allocator_map.read().await;
            guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (name, allocator_arc) in allocators {
            let allocator = allocator_arc.lock().await;
            result.insert(name, allocator.lease_view_with_last_prefixes());
        }
        result
    }

    pub async fn resolve_client_match_by_ipv6(&self, ip: Ipv6Addr) -> Option<CallerLookupMatch> {
        for (iface_name, assigned_ips) in self.get_assigned_ips().await {
            for item in assigned_ips.offered_ips.into_values() {
                if item.ip == ip {
                    return Some(CallerLookupMatch {
                        iface_name,
                        mac: Some(item.mac),
                        hostname: None,
                        source: CallerLookupSource::Ipv6Ra,
                    });
                }
            }
        }

        for (iface_name, assigned_ips) in self.get_dhcpv6_assigned().await {
            for item in assigned_ips.offered_addresses {
                if item.ip == ip {
                    return Some(CallerLookupMatch {
                        iface_name,
                        mac: item.mac,
                        hostname: item.hostname,
                        source: CallerLookupSource::DhcpV6,
                    });
                }
            }
        }

        None
    }

    pub async fn get_device_ipv6_map(&self) -> HashMap<Uuid, Ipv6Addr> {
        let mut result = HashMap::new();

        for (_, assigned_ips) in self.get_assigned_ips().await {
            for item in assigned_ips.offered_ips.into_values() {
                if let Some(device_id) = self.server_starter.device_id_map.get(&item.mac) {
                    result.insert(*device_id, item.ip);
                }
            }
        }

        for (_, offer) in self.get_dhcpv6_assigned().await {
            for addr in offer.offered_addresses {
                if let Some(mac) = addr.mac {
                    if let Some(device_id) = self.server_starter.device_id_map.get(&mac) {
                        result.entry(*device_id).or_insert(addr.ip);
                    }
                }
            }
        }

        let allocator_map = self.server_starter.iface_dhcpv6_allocator_map.read().await;
        for allocator_arc in allocator_map.values() {
            let allocator = allocator_arc.lock().await;
            for (mac, ip) in allocator.static_binding_view_with_last_prefixes() {
                if let Some(device_id) = self.server_starter.device_id_map.get(&mac) {
                    result.entry(*device_id).or_insert(ip);
                }
            }
        }

        result
    }
}

fn extract_binding_ifaces_v6(event: &EnrolledDeviceEvent) -> HashSet<String> {
    let mut set = HashSet::new();
    match event {
        EnrolledDeviceEvent::Updated { old, new } => {
            if let Some(d) = old.as_ref() {
                if let Some(ref iface) = d.iface_name {
                    set.insert(iface.clone());
                }
            }
            if let Some(ref iface) = new.iface_name {
                set.insert(iface.clone());
            }
        }
        EnrolledDeviceEvent::Deleted { old } => {
            if let Some(ref iface) = old.iface_name {
                set.insert(iface.clone());
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::enrolled_device::EnrolledDevice;
    use landscape_common::event::hub::EnrolledDeviceEvent;
    use landscape_common::net::MacAddr;

    fn make_device(mac: &str, iface: Option<&str>, ipv6_addr: Option<u16>) -> EnrolledDevice {
        let mac_bytes: Vec<u8> =
            mac.split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect();
        let mac = MacAddr::from([
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        ]);
        let ipv6 = ipv6_addr.map(|suffix| std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, suffix));

        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "mac": mac.to_string(),
            "name": "test-device",
            "iface_name": iface,
            "ipv4": null,
            "ipv6": ipv6.map(|ip| ip.to_string()),
        }))
        .unwrap()
    }

    #[test]
    fn test_extract_deleted_has_iface() {
        let old = make_device("00:11:22:33:44:55", Some("eth0"), None);
        let event = EnrolledDeviceEvent::Deleted { old };
        let result = extract_binding_ifaces_v6(&event);
        assert_eq!(result.len(), 1);
        assert!(result.contains("eth0"));
    }

    #[test]
    fn test_extract_deleted_no_iface() {
        let old = make_device("00:11:22:33:44:55", None, None);
        let event = EnrolledDeviceEvent::Deleted { old };
        let result = extract_binding_ifaces_v6(&event);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_updated_iface_changed() {
        let old = make_device("00:11:22:33:44:55", Some("eth0"), None);
        let new = make_device("00:11:22:33:44:55", Some("eth1"), Some(0x100));
        let event = EnrolledDeviceEvent::Updated { old: Some(old), new };
        let result = extract_binding_ifaces_v6(&event);
        assert_eq!(result.len(), 2);
        assert!(result.contains("eth0"));
        assert!(result.contains("eth1"));
    }

    #[test]
    fn test_extract_updated_new_no_iface() {
        let old = make_device("00:11:22:33:44:55", Some("eth0"), None);
        let new = make_device("00:11:22:33:44:55", None, Some(0x100));
        let event = EnrolledDeviceEvent::Updated { old: Some(old), new };
        let result = extract_binding_ifaces_v6(&event);
        assert_eq!(result.len(), 1);
        assert!(result.contains("eth0"));
    }

    #[test]
    fn test_extract_updated_no_old() {
        let new = make_device("00:11:22:33:44:55", Some("eth0"), Some(0x100));
        let event = EnrolledDeviceEvent::Updated { old: None, new };
        let result = extract_binding_ifaces_v6(&event);
        assert_eq!(result.len(), 1);
        assert!(result.contains("eth0"));
    }

    #[test]
    fn test_extract_updated_same_iface() {
        let old = make_device("00:11:22:33:44:55", Some("eth0"), Some(0x100));
        let new = make_device("00:11:22:33:44:55", Some("eth0"), Some(0x200));
        let event = EnrolledDeviceEvent::Updated { old: Some(old), new };
        let result = extract_binding_ifaces_v6(&event);
        assert_eq!(result.len(), 1);
        assert!(result.contains("eth0"));
    }
}

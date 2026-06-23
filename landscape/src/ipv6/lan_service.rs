use landscape_common::client::{CallerLookupMatch, CallerLookupSource};
use landscape_common::database::LandscapeStore as LandscapeDBStore;
use landscape_common::dhcp::v6_server::config::DHCPv6ServerConfig;
use landscape_common::dhcp::v6_server::status::DHCPv6OfferInfo;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IfaceEventReader,
};
use landscape_common::ipv6::lan::{
    IPv6ServiceMode, LanIPv6ConfigV2, LanIPv6ServiceConfigV2, LanPrefixGroupConfig,
    PrefixGroupServiceKind,
};
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
use tokio::sync::{Mutex, RwLock};

use crate::dhcp_server::v6::DhcpV6AssignStatus;
use crate::iface::get_iface_by_name;
use crate::ipv6::prefix::{cleanup_prefix_sources, setup_prefix_groups, PrefixSetupResult};
use crate::route::IpRouteService;

/// LAN IPv6 service: manages RA + DHCPv6 per interface with mode-aware orchestration

#[derive(Clone)]
pub struct LanIPv6Service {
    route_service: IpRouteService,
    prefix_map: IAPrefixMap,
    iface_lease_map: Arc<RwLock<HashMap<String, Arc<RwLock<IPv6NAInfo>>>>>,
    iface_dhcpv6_status_map: Arc<RwLock<HashMap<String, Arc<Mutex<DhcpV6AssignStatus>>>>>,
    enrolled_device_store: EnrolledDeviceRepository,
}

impl LanIPv6Service {
    pub fn new(
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        enrolled_device_store: EnrolledDeviceRepository,
    ) -> Self {
        Self {
            route_service,
            prefix_map,
            iface_lease_map: Arc::new(RwLock::new(HashMap::new())),
            iface_dhcpv6_status_map: Arc::new(RwLock::new(HashMap::new())),
            enrolled_device_store,
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
            let status_clone = service_status.clone();
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let store_key = config.get_store_key();
                let assigned_ips = {
                    let mut write = self.iface_lease_map.write().await;
                    let entry = write
                        .entry(store_key.clone())
                        .or_insert_with(|| Arc::new(RwLock::new(IPv6NAInfo::init())));
                    // Clear stale data from previous service run
                    *entry.write().await = IPv6NAInfo::init();
                    entry.clone()
                };

                // DHCPv6 setup
                let dhcpv6_config = config.config.dhcpv6.clone();
                let dhcpv6_enabled = dhcpv6_config.as_ref().map_or(false, |c| c.enable);

                let dhcpv6_assign_status: Option<Arc<Mutex<DhcpV6AssignStatus>>> = if dhcpv6_enabled
                {
                    let dhcpv6_cfg = dhcpv6_config.as_ref().unwrap();
                    let devices = self
                        .enrolled_device_store
                        .find_dhcpv6_bindings(config.iface_name.clone())
                        .await
                        .unwrap_or_default();
                    let status = DhcpV6AssignStatus::from_config_and_devices(dhcpv6_cfg, devices);
                    let status_arc = Arc::new(Mutex::new(status));
                    {
                        let mut write = self.iface_dhcpv6_status_map.write().await;
                        write.insert(store_key.clone(), status_arc.clone());
                    }
                    Some(status_arc)
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
                    tokio::spawn(async move {
                        let mode = config.config.mode;
                        let LanIPv6ConfigV2 { ad_interval, ra_flag, prefix_groups, dhcpv6, .. } =
                            config.config;
                        let iface_name = config.iface_name;

                        match mode {
                            IPv6ServiceMode::Slaac => {
                                run_slaac(
                                    &prefix_groups,
                                    &iface_name,
                                    &lan_info,
                                    &route_service,
                                    &prefix_map,
                                    ad_interval,
                                    ra_flag,
                                    mac,
                                    lan_info.ifindex,
                                    status_clone,
                                    assigned_ips,
                                )
                                .await;
                            }
                            IPv6ServiceMode::Stateful => {
                                run_stateful(
                                    &prefix_groups,
                                    dhcpv6,
                                    &iface_name,
                                    &lan_info,
                                    &route_service,
                                    &prefix_map,
                                    ad_interval,
                                    ra_flag,
                                    mac.clone(),
                                    link_ifindex,
                                    status_clone,
                                    assigned_ips,
                                    dhcpv6_assign_status,
                                )
                                .await;
                            }
                            IPv6ServiceMode::SlaacDhcpv6 => {
                                run_slaac_dhcpv6(
                                    &prefix_groups,
                                    dhcpv6,
                                    &iface_name,
                                    &lan_info,
                                    &route_service,
                                    &prefix_map,
                                    ad_interval,
                                    ra_flag,
                                    mac.clone(),
                                    link_ifindex,
                                    status_clone,
                                    assigned_ips,
                                    dhcpv6_assign_status,
                                )
                                .await;
                            }
                        }
                    });
                }
            }
        }

        service_status
    }
}

use landscape_common::ipv6::ra::RouterFlags;
use landscape_common::net::MacAddr;

/// Mode 1 (Slaac): RA with prefix info, no DHCPv6
async fn run_slaac(
    groups: &[LanPrefixGroupConfig],
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    ad_interval: u32,
    ra_flag: RouterFlags,
    mac: MacAddr,
    link_ifindex: u32,
    status: WatchService,
    assigned_ips: Arc<RwLock<IPv6NAInfo>>,
) {
    let PrefixSetupResult {
        runtime,
        ra_token,
        dhcpv6_token,
        change_notify,
        cleanup_ips,
    } = setup_prefix_groups(
        groups,
        &[PrefixGroupServiceKind::Ra],
        iface_name,
        lan_info,
        route_service,
        prefix_map,
    )
    .await;

    // No DHCPv6 in Slaac mode
    dhcpv6_token.cancel();

    // Run RA (blocks until exit)
    let _ = crate::icmp::v6::icmp_ra_server(
        ad_interval,
        ra_flag,
        mac,
        iface_name.to_string(),
        status,
        &runtime,
        change_notify,
        assigned_ips,
        true, // autonomous: SLAAC clients auto-configure addresses from RA prefixes
        None,
        None,
        link_ifindex,
    )
    .await;

    ra_token.cancel();
    cleanup_prefix_sources(cleanup_ips, iface_name, route_service).await;
}

/// Mode 2 (Stateful): RA sends M=1 without prefix info, DHCPv6 assigns addresses
async fn run_stateful(
    groups: &[LanPrefixGroupConfig],
    dhcpv6: Option<DHCPv6ServerConfig>,
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    ad_interval: u32,
    ra_flag: RouterFlags,
    mac: MacAddr,
    link_ifindex: u32,
    status: WatchService,
    assigned_ips: Arc<RwLock<IPv6NAInfo>>,
    dhcpv6_assign_status: Option<Arc<Mutex<DhcpV6AssignStatus>>>,
) {
    let dhcpv6_config = match dhcpv6 {
        Some(c) if c.enable => c,
        _ => {
            tracing::error!("Stateful mode but DHCPv6 not enabled");
            status.just_change_status(landscape_common::service::ServiceStatus::Failed);
            return;
        }
    };

    // Setup prefix sources for DHCPv6 (Na + IaPd sources)
    let PrefixSetupResult {
        runtime: dhcpv6_runtime,
        ra_token: dhcpv6_ra_token,
        dhcpv6_token,
        change_notify: dhcpv6_change_notify,
        cleanup_ips: dhcpv6_cleanup_ips,
    } = setup_prefix_groups(
        groups,
        &[PrefixGroupServiceKind::Na, PrefixGroupServiceKind::IaPd],
        iface_name,
        lan_info,
        route_service,
        prefix_map,
    )
    .await;

    // PD tasks only watch dhcpv6_token, cancel ra_token since there's no RA prefix setup
    dhcpv6_ra_token.cancel();

    // Spawn DHCPv6 server
    if let Some(ref assign_status) = dhcpv6_assign_status {
        let pd_sources = dhcpv6_runtime.pd_info.values().cloned().collect();
        let static_infos = dhcpv6_runtime.static_info.clone();
        let pd_delegation_static = dhcpv6_runtime.pd_delegation_static.clone();
        let pd_delegation_dynamic = dhcpv6_runtime.pd_delegation_dynamic.clone();
        let dhcpv6_iface = iface_name.to_string();
        let dhcpv6_mac = mac.clone();
        let dhcpv6_status = status.clone();
        let dhcpv6_route_service = route_service.clone();

        let link_local = mac.to_ipv6_link_local();
        let assign_status = assign_status.clone();
        tokio::spawn(async move {
            crate::dhcp_server::v6::dhcp_v6_server(
                link_ifindex,
                dhcpv6_iface,
                dhcpv6_mac,
                link_local,
                dhcpv6_config,
                pd_sources,
                static_infos,
                pd_delegation_static,
                pd_delegation_dynamic,
                dhcpv6_status,
                assign_status,
                dhcpv6_route_service,
            )
            .await;
            dhcpv6_token.cancel();
        });
    } else {
        dhcpv6_token.cancel();
    }

    // RA with DHCPv6 runtime: advertise prefixes with A=0 (no SLAAC) so clients
    // can detect prefix changes via RA and re-initiate DHCPv6
    let _ = crate::icmp::v6::icmp_ra_server(
        ad_interval,
        ra_flag,
        mac,
        iface_name.to_string(),
        status,
        &dhcpv6_runtime,
        dhcpv6_change_notify,
        assigned_ips,
        false, // autonomous=false: clients should NOT SLAAC, only use DHCPv6
        None,
        None,
        link_ifindex,
    )
    .await;

    cleanup_prefix_sources(dhcpv6_cleanup_ips, iface_name, route_service).await;
}

/// Mode 3 (SlaacDhcpv6): RA sends ULA prefixes, DHCPv6 assigns GUA addresses
async fn run_slaac_dhcpv6(
    groups: &[LanPrefixGroupConfig],
    dhcpv6: Option<DHCPv6ServerConfig>,
    iface_name: &str,
    lan_info: &LanRouteInfo,
    route_service: &IpRouteService,
    prefix_map: &IAPrefixMap,
    ad_interval: u32,
    ra_flag: RouterFlags,
    mac: MacAddr,
    link_ifindex: u32,
    status: WatchService,
    assigned_ips: Arc<RwLock<IPv6NAInfo>>,
    dhcpv6_assign_status: Option<Arc<Mutex<DhcpV6AssignStatus>>>,
) {
    let dhcpv6_config = match dhcpv6 {
        Some(c) if c.enable => c,
        _ => {
            tracing::error!("SlaacDhcpv6 mode but DHCPv6 not enabled");
            status.just_change_status(landscape_common::service::ServiceStatus::Failed);
            return;
        }
    };

    // Setup RA prefix sources (Ra kind only)
    let PrefixSetupResult {
        runtime: ra_runtime,
        ra_token,
        dhcpv6_token: ra_dhcpv6_token,
        change_notify: ra_change_notify,
        cleanup_ips: ra_cleanup_ips,
    } = setup_prefix_groups(
        groups,
        &[PrefixGroupServiceKind::Ra],
        iface_name,
        lan_info,
        route_service,
        prefix_map,
    )
    .await;

    // RA sources only watch ra_token
    ra_dhcpv6_token.cancel();

    // Setup DHCPv6 prefix sources (Na + IaPd kinds)
    let PrefixSetupResult {
        runtime: dhcpv6_runtime,
        ra_token: dhcpv6_ra_token,
        dhcpv6_token,
        change_notify: dhcpv6_change_notify,
        cleanup_ips: dhcpv6_cleanup_ips,
    } = setup_prefix_groups(
        groups,
        &[PrefixGroupServiceKind::Na, PrefixGroupServiceKind::IaPd],
        iface_name,
        lan_info,
        route_service,
        prefix_map,
    )
    .await;

    // DHCPv6 sources only watch dhcpv6_token
    dhcpv6_ra_token.cancel();

    // Spawn DHCPv6 server
    if let Some(ref assign_status) = dhcpv6_assign_status {
        let pd_sources = dhcpv6_runtime.pd_info.values().cloned().collect();
        let static_infos = dhcpv6_runtime.static_info.clone();
        let pd_delegation_static = dhcpv6_runtime.pd_delegation_static.clone();
        let pd_delegation_dynamic = dhcpv6_runtime.pd_delegation_dynamic.clone();
        let dhcpv6_iface = iface_name.to_string();
        let dhcpv6_mac = mac.clone();
        let dhcpv6_status = status.clone();
        let dhcpv6_route_service = route_service.clone();
        let link_local = mac.to_ipv6_link_local();
        let assign_status = assign_status.clone();

        tokio::spawn(async move {
            crate::dhcp_server::v6::dhcp_v6_server(
                link_ifindex,
                dhcpv6_iface,
                dhcpv6_mac,
                link_local,
                dhcpv6_config,
                pd_sources,
                static_infos,
                pd_delegation_static,
                pd_delegation_dynamic,
                dhcpv6_status,
                assign_status,
                dhcpv6_route_service,
            )
            .await;
            dhcpv6_token.cancel();
        });
    } else {
        dhcpv6_token.cancel();
    }

    // Run RA with ULA prefixes (A=1) + DHCPv6 GUA prefixes (A=0 on-link only)
    let _ = crate::icmp::v6::icmp_ra_server(
        ad_interval,
        ra_flag,
        mac,
        iface_name.to_string(),
        status,
        &ra_runtime,
        ra_change_notify,
        assigned_ips,
        true, // autonomous: SLAAC clients auto-configure from RA ULA prefixes
        Some(&dhcpv6_runtime),
        Some(dhcpv6_change_notify),
        link_ifindex,
    )
    .await;

    ra_token.cancel();

    // Cleanup both sets
    cleanup_prefix_sources(ra_cleanup_ips, iface_name, route_service).await;
    cleanup_prefix_sources(dhcpv6_cleanup_ips, iface_name, route_service).await;
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
    ) -> Self {
        let store = store_service.lan_ipv6_v2_service_store();
        let enrolled_device_store = store_service.enrolled_device_store();
        let server_starter = LanIPv6Service::new(route_service, prefix_map, enrolled_device_store);
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

        let status_map = server_starter.iface_dhcpv6_status_map.clone();
        tokio::spawn(async move {
            while let Ok(event) = device_reader.recv().await {
                let affected = extract_binding_ifaces_v6(&event);
                let targets: Vec<String> = {
                    let guard = status_map.read().await;
                    if affected.is_empty() {
                        guard.keys().cloned().collect()
                    } else {
                        affected.into_iter().filter(|i| guard.contains_key(i)).collect()
                    }
                };
                for iface in &targets {
                    let s = {
                        let guard = status_map.read().await;
                        guard.get(iface).cloned()
                    };
                    if let Some(s) = s {
                        let mut status = s.lock().await;
                        match &event {
                            EnrolledDeviceEvent::Updated { old, new } => {
                                if let Some(d) = old.as_ref() {
                                    status.remove_binding(&d.mac);
                                }
                                if let Some(ipv6) = new.ipv6 {
                                    status.add_or_update_binding(new.mac, ipv6);
                                }
                                // TODO: After binding update, sending a unicast RA to the
                                // affected client (via mac.to_ipv6_link_local()) would trigger
                                // it to re-initiate DHCPv6 immediately, allowing the old IP
                                // to be released faster instead of waiting for the next
                                // periodic RA or client retry timeout.
                            }
                            EnrolledDeviceEvent::Deleted { old } => {
                                status.remove_binding(&old.mac);
                            }
                        }
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
            let guard = self.server_starter.iface_dhcpv6_status_map.read().await;
            guard.get(&iface_name).cloned()
        }?;
        let s = status_arc.lock().await;
        Some(s.last_offer_info.clone())
    }

    pub async fn get_dhcpv6_assigned(&self) -> HashMap<String, DHCPv6OfferInfo> {
        let mut result = HashMap::new();
        let statuses: Vec<(String, Arc<Mutex<DhcpV6AssignStatus>>)> = {
            let guard = self.server_starter.iface_dhcpv6_status_map.read().await;
            guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (name, status_arc) in statuses {
            let s = status_arc.lock().await;
            result.insert(name, s.last_offer_info.clone());
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

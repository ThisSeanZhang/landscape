use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::client::{CallerLookupMatch, CallerLookupSource};
use landscape_common::database::LandscapeStore as LandscapeDBStore;
use landscape_common::dhcp::v4_server::status::ArpScanInfo;
use landscape_common::dhcp::v4_server::status::ArpScanStatus;
use landscape_common::dhcp::v4_server::status::DHCPv4OfferInfo;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::route::LanRouteInfo;
use landscape_common::route::LanRouteMode;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::WatchService;
use landscape_common::store::storev2::LandscapeStore;
use landscape_common::LAND_ARP_SCAN_INTERVAL;
use landscape_common::{
    dhcp::v4_server::config::DHCPv4ServiceConfig,
    observer::IfaceObserverAction,
    service::manager::{ServiceManager, ServiceStarterTrait},
};
use landscape_database::dhcp_v4_server::repository::DHCPv4ServerRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::cert::SharedSniResolver;
use crate::dhcp_server::dhcp_server_new::DhcpV4DnrRuntimeContext;
use crate::iface::get_iface_by_name;
use crate::route::IpRouteService;
use crate::LandscapeSingleIpInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IfaceIpv4Cleanup {
    addr: Ipv4Addr,
    prefix: u8,
}

impl IfaceIpv4Cleanup {
    fn from_dhcp_v4_config(config: &DHCPv4ServiceConfig) -> Self {
        Self {
            addr: config.config.server_ip_addr,
            prefix: config.config.network_mask,
        }
    }

    fn matches(&self, addr: &LandscapeSingleIpInfo) -> bool {
        matches!(addr.address, IpAddr::V4(ipv4) if ipv4 == self.addr)
            && addr.prefix_len == self.prefix
    }

    fn delete_args(&self, iface_name: &str) -> Vec<String> {
        vec![
            "addr".to_string(),
            "del".to_string(),
            format!("{}/{}", self.addr, self.prefix),
            "dev".to_string(),
            iface_name.to_string(),
        ]
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct DHCPv4ServerStarter {
    iface_lease_map: Arc<RwLock<HashMap<String, Arc<RwLock<DHCPv4OfferInfo>>>>>,
    iface_scan_map: Arc<RwLock<HashMap<String, Arc<RwLock<ArpScanStatus>>>>>,
    route_service: IpRouteService,
    db_provider: LandscapeDBServiceProvider,
    api_tls_resolver: SharedSniResolver,
    dns_runtime_config: landscape_common::config::DnsRuntimeConfig,
}

impl DHCPv4ServerStarter {
    pub fn new(
        route_service: IpRouteService,
        db_provider: LandscapeDBServiceProvider,
        api_tls_resolver: SharedSniResolver,
        dns_runtime_config: landscape_common::config::DnsRuntimeConfig,
    ) -> DHCPv4ServerStarter {
        DHCPv4ServerStarter {
            route_service,
            db_provider,
            api_tls_resolver,
            dns_runtime_config,
            iface_lease_map: Arc::new(RwLock::new(HashMap::new())),
            iface_scan_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for DHCPv4ServerStarter {
    type Config = DHCPv4ServiceConfig;

    async fn start(&self, config: DHCPv4ServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if !config.enable {
            self.route_service.remove_ipv4_lan_route(&config.iface_name).await;
            return service_status;
        }

        if let Some(iface) = get_iface_by_name(&config.iface_name).await {
            let info = LanRouteInfo {
                ifindex: iface.index,
                iface_name: config.iface_name.clone(),
                mac: iface.mac,
                iface_ip: std::net::IpAddr::V4(config.config.server_ip_addr),
                prefix: config.config.network_mask,
                mode: LanRouteMode::Reachable,
            };
            self.route_service.insert_ipv4_lan_route(&config.iface_name, info).await;

            let bindings = self
                .db_provider
                .enrolled_device_store()
                .find_dhcp_bindings(
                    config.iface_name.clone(),
                    config.config.server_ip_addr,
                    config.config.network_mask,
                )
                .await
                .unwrap_or_default();

            let store_key = config.get_store_key();
            let assigned_ips = {
                let mut write = self.iface_lease_map.write().await;
                write
                    .entry(store_key.clone())
                    .or_insert_with(|| Arc::new(RwLock::new(DHCPv4OfferInfo::default())))
                    .clone()
            };

            let status = service_status.clone();
            let stop_dhcp_server = CancellationToken::new();
            let stop_dhcp_server_child = stop_dhcp_server.child_token();
            let server_addr = config.config.server_ip_addr;
            let network_mask = config.config.network_mask;
            let iface_ifindex = iface.index;
            let iface_mac = iface.mac;
            let dnr_context = Some(DhcpV4DnrRuntimeContext {
                local_domains: self.api_tls_resolver.advertised_domains_state(),
                // Intentionally fixed per DHCP server start: local DNR advertisements
                // should keep using the configured DoH port/path rather than tracking
                // later runtime DNS config updates.
                // Product policy: users may choose DNR domains/IPs, but the local DoH
                // port/path are controlled by system DNS config and are not user-overridable.
                doh_port: self.dns_runtime_config.doh_listen_port,
                doh_path: self.dns_runtime_config.doh_http_endpoint.clone(),
            });
            tokio::spawn(async move {
                crate::dhcp_server::dhcp_server_new::dhcp_v4_server(
                    config.iface_name,
                    iface_ifindex,
                    iface_mac,
                    config.config,
                    dnr_context,
                    bindings,
                    status,
                    assigned_ips,
                )
                .await;
                stop_dhcp_server.cancel();
            });

            if let Some(mac) = iface.mac {
                // start arp scan
                let scand_arp_info = {
                    let mut write = self.iface_scan_map.write().await;
                    write
                        .entry(store_key)
                        .or_insert_with(|| Arc::new(RwLock::new(ArpScanStatus::new())))
                        .clone()
                };

                tokio::spawn(async move {
                    let mut scan_interval =
                        tokio::time::interval(Duration::from_millis(LAND_ARP_SCAN_INTERVAL));
                    loop {
                        tokio::select! {
                            _ = stop_dhcp_server_child.cancelled() => {
                                break;
                            }
                            _ = scan_interval.tick() => {
                                let result = crate::arp::scan::scan_ip_info(
                                    iface.index,
                                    mac,
                                    server_addr,
                                    network_mask,
                                ).await;

                                let mut arp_infos = scand_arp_info.write().await;
                                arp_infos.insert_new_info(ArpScanInfo::new(result));
                            }
                        }
                    }

                    tracing::info!("DHCPv4 Server ARP scan stop");
                });
            }
        } else {
            tracing::error!("Interface {} not found", config.iface_name);
            service_status.just_change_status(landscape_common::service::ServiceStatus::Failed);
        }

        service_status
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct DHCPv4ServerManagerService {
    service: ServiceManager<DHCPv4ServerStarter>,
    store: DHCPv4ServerRepository,
    server_starter: DHCPv4ServerStarter,
}

#[async_trait::async_trait]
impl ControllerService for DHCPv4ServerManagerService {
    type Id = String;

    type Config = DHCPv4ServiceConfig;

    type DatabseAction = DHCPv4ServerRepository;

    type H = DHCPv4ServerStarter;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn delete_and_stop_iface_service(&self, iface_name: Self::Id) -> Option<WatchService> {
        self.get_repository().delete(iface_name.clone()).await.unwrap();
        let result = self.get_service().stop_service(iface_name.clone()).await;
        self.server_starter.route_service.remove_ipv4_lan_route(&iface_name).await;
        result
    }
}

impl DHCPv4ServerManagerService {
    pub async fn new(
        route_service: IpRouteService,
        store_service: LandscapeDBServiceProvider,
        api_tls_resolver: SharedSniResolver,
        dns_runtime_config: landscape_common::config::DnsRuntimeConfig,
        mut dev_observer: IfaceEventReader,
    ) -> Self {
        let store = store_service.dhcp_v4_server_store();
        let server_starter = DHCPv4ServerStarter::new(
            route_service,
            store_service.clone(),
            api_tls_resolver,
            dns_runtime_config,
        );
        let service =
            ServiceManager::init(store.list().await.unwrap(), server_starter.clone()).await;

        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} Firewall service");
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

        let store = store_service.dhcp_v4_server_store();
        Self { service, store, server_starter }
    }

    pub async fn check_ip_range_conflict(
        &self,
        new_config: &DHCPv4ServiceConfig,
    ) -> Result<(), String> {
        if let Some(conflict_iface) = self
            .get_repository()
            .check_ip_range_conflict(
                new_config.iface_name.clone(),
                new_config.config.server_ip_addr,
                new_config.config.network_mask,
            )
            .await
            .map_err(|e| format!("Failed to check IP range conflict: {}", e))?
        {
            let (start, end) = new_config.config.get_ip_range();
            return Err(format!(
                "IP range conflict detected with interface '{}'. New range: {}-{}",
                conflict_iface, start, end
            ));
        }

        Ok(())
    }

    pub async fn refresh_iface_service(&self, iface_name: String) {
        let Some(service_config) = self.get_config_by_name(iface_name).await else {
            return;
        };
        let _ = self.get_service().update_service(service_config).await;
    }

    pub fn listen_device_events(
        &self,
        mut rx: landscape_common::event::hub::EnrolledDeviceEventReader,
    ) {
        tokio::spawn(async move {
            while let Ok(_event) = rx.recv().await {
                // TODO: reload static bindings from DB and notify DHCPv4 server to reconcile
            }
        });
    }

    pub async fn cleanup_lingering_iface_addr_if_present(&self, config: &DHCPv4ServiceConfig) {
        let cleanup = IfaceIpv4Cleanup::from_dhcp_v4_config(config);
        let iface_name = &config.iface_name;
        let has_addr = crate::addresses_by_iface_name(iface_name.clone())
            .await
            .into_iter()
            .any(|addr| cleanup.matches(&addr));

        if !has_addr {
            return;
        }

        let args = cleanup.delete_args(iface_name);
        match Command::new("ip").args(&args).output() {
            Ok(output) if output.status.success() => {
                tracing::info!(
                    "Removed lingering DHCPv4 address {}/{} from {} during zone change",
                    cleanup.addr,
                    cleanup.prefix,
                    iface_name
                );
            }
            Ok(output) => {
                tracing::warn!(
                    "Failed to remove lingering DHCPv4 address {}/{} from {}: {}",
                    cleanup.addr,
                    cleanup.prefix,
                    iface_name,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to spawn ip addr cleanup for {}/{} on {}: {error}",
                    cleanup.addr,
                    cleanup.prefix,
                    iface_name
                );
            }
        }
    }

    pub async fn get_assigned_ips(&self) -> HashMap<String, DHCPv4OfferInfo> {
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

    pub async fn get_assigned_ips_by_iface_name(
        &self,
        iface_name: String,
    ) -> Option<DHCPv4OfferInfo> {
        let info = {
            let read_lock = self.server_starter.iface_lease_map.read().await;
            read_lock.get(&iface_name).map(Clone::clone)
        };

        let Some(offer_info) = info else { return None };

        let data = offer_info.read().await.clone();
        return Some(data);
    }

    pub async fn get_arp_scan_info(&self) -> HashMap<String, Vec<ArpScanInfo>> {
        let mut result = HashMap::new();

        let map = {
            let read_lock = self.server_starter.iface_scan_map.read().await;
            read_lock.clone()
        };

        for (iface_name, assigned_ips) in map {
            if let Ok(read) = assigned_ips.try_read() {
                result.insert(iface_name, read.get_arp_info());
            }
        }

        result
    }

    pub async fn get_arp_scan_ips_by_iface_name(
        &self,
        iface_name: String,
    ) -> Option<Vec<ArpScanInfo>> {
        let info = {
            let read_lock = self.server_starter.iface_scan_map.read().await;
            read_lock.get(&iface_name).map(Clone::clone)
        };

        let Some(offer_info) = info else { return None };

        let data = offer_info.read().await.get_arp_info();
        return Some(data);
    }

    pub async fn resolve_client_match_by_ipv4(&self, ip: Ipv4Addr) -> Option<CallerLookupMatch> {
        for (iface_name, assigned_ips) in self.get_assigned_ips().await {
            for item in assigned_ips.offered_ips {
                if item.ip == ip {
                    return Some(CallerLookupMatch {
                        iface_name,
                        mac: Some(item.mac),
                        hostname: item.hostname,
                        source: CallerLookupSource::DhcpV4,
                    });
                }
            }
        }

        for (iface_name, scan_infos) in self.get_arp_scan_info().await {
            for scan_info in scan_infos {
                for item in scan_info.infos() {
                    if item.ip == ip {
                        return Some(CallerLookupMatch {
                            iface_name,
                            mac: Some(item.mac),
                            hostname: None,
                            source: CallerLookupSource::Arp,
                        });
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_ipv4_cleanup_uses_dhcp_server_addr_and_mask() {
        let cleanup = IfaceIpv4Cleanup::from_dhcp_v4_config(&DHCPv4ServiceConfig::default());

        assert_eq!(cleanup.addr, Ipv4Addr::new(192, 168, 5, 1));
        assert_eq!(cleanup.prefix, 24);
    }

    #[test]
    fn iface_ipv4_cleanup_matches_only_exact_ipv4_and_prefix() {
        let cleanup = IfaceIpv4Cleanup { addr: Ipv4Addr::new(192, 168, 5, 1), prefix: 24 };
        let exact = LandscapeSingleIpInfo {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 5, 1)),
            is_permanent: true,
            prefix_len: 24,
            ifindex: 7,
        };
        let wrong_prefix = LandscapeSingleIpInfo { prefix_len: 16, ..exact.clone() };
        let wrong_ip = LandscapeSingleIpInfo {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)),
            ..exact.clone()
        };

        assert!(cleanup.matches(&exact));
        assert!(!cleanup.matches(&wrong_prefix));
        assert!(!cleanup.matches(&wrong_ip));
    }

    #[test]
    fn iface_ipv4_cleanup_builds_delete_args() {
        let cleanup = IfaceIpv4Cleanup { addr: Ipv4Addr::new(10, 0, 0, 1), prefix: 24 };

        assert_eq!(
            cleanup.delete_args("br_lan"),
            vec![
                "addr".to_string(),
                "del".to_string(),
                "10.0.0.1/24".to_string(),
                "dev".to_string(),
                "br_lan".to_string(),
            ]
        );
    }
}

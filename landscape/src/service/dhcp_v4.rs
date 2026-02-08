use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::database::LandscapeDBTrait;
use landscape_common::database::LandscapeServiceDBTrait;
use landscape_common::dhcp::v4_server::status::ArpScanInfo;
use landscape_common::dhcp::v4_server::status::ArpScanStatus;
use landscape_common::dhcp::v4_server::status::DHCPv4OfferInfo;
use landscape_common::route::LanRouteInfo;
use landscape_common::route::LanRouteMode;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::DefaultServiceStatus;
use landscape_common::service::DefaultWatchServiceStatus;
use landscape_common::store::storev2::LandscapeStore;
use landscape_common::LAND_ARP_SCAN_INTERVAL;
use landscape_common::{
    dhcp::v4_server::config::DHCPv4ServiceConfig,
    observer::IfaceObserverAction,
    service::service_manager_v2::{ServiceManager, ServiceStarterTrait},
};
use landscape_database::dhcp_v4_server::repository::DHCPv4ServerRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::iface::get_iface_by_name;
use crate::route::IpRouteService;

#[derive(Clone)]
#[allow(dead_code)]
pub struct DHCPv4ServerStarter {
    iface_lease_map: Arc<RwLock<HashMap<String, Arc<RwLock<DHCPv4OfferInfo>>>>>,
    iface_scan_map: Arc<RwLock<HashMap<String, Arc<RwLock<ArpScanStatus>>>>>,
    route_service: IpRouteService,
    db_provider: LandscapeDBServiceProvider,
}

impl DHCPv4ServerStarter {
    pub fn new(
        route_service: IpRouteService,
        db_provider: LandscapeDBServiceProvider,
    ) -> DHCPv4ServerStarter {
        DHCPv4ServerStarter {
            route_service,
            db_provider,
            iface_lease_map: Arc::new(RwLock::new(HashMap::new())),
            iface_scan_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for DHCPv4ServerStarter {
    type Status = DefaultServiceStatus;
    type Config = DHCPv4ServiceConfig;

    async fn start(&self, mut config: DHCPv4ServiceConfig) -> DefaultWatchServiceStatus {
        let service_status = DefaultWatchServiceStatus::new();

        if config.enable {
            // 获取全局及本接口的 IP-MAC 绑定信息, 并同步到当前 DHCP 服务的静态绑定中
            use landscape_common::dhcp::v4_server::config::MacBindingRecord;

            let bindings = self
                .db_provider
                .ip_mac_binding_store()
                .find_dhcp_bindings(
                    config.iface_name.clone(),
                    config.config.server_ip_addr,
                    config.config.network_mask,
                )
                .await
                .unwrap_or_default();

            // 清理原有的静态绑定信息（已迁移到全局设备管理），以全局设备管理库为准
            config.config.mac_binding_records.clear();

            for binding in bindings {
                if let Some(ipv4) = binding.ipv4 {
                    config.config.mac_binding_records.push(MacBindingRecord {
                        mac: binding.mac,
                        ip: ipv4,
                        expire_time: 86400,
                    });
                }
            }
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let store_key = config.get_store_key();
                let assigned_ips = {
                    let mut write = self.iface_lease_map.write().await;
                    write
                        .entry(store_key.clone())
                        .or_insert_with(|| Arc::new(RwLock::new(DHCPv4OfferInfo::default())))
                        .clone()
                };

                let route_service = self.route_service.clone();
                let status = service_status.clone();
                let stop_dhcp_server = CancellationToken::new();
                let stop_dhcp_server_child = stop_dhcp_server.child_token();
                let server_addr = config.config.server_ip_addr;
                let network_mask = config.config.network_mask;
                tokio::spawn(async move {
                    let info = LanRouteInfo {
                        ifindex: iface.index,
                        iface_name: config.iface_name.clone(),
                        mac: iface.mac,
                        iface_ip: std::net::IpAddr::V4(config.config.server_ip_addr.clone()),
                        prefix: config.config.network_mask,
                        mode: LanRouteMode::Reachable,
                    };
                    let iface_name = config.iface_name.clone();
                    route_service.insert_ipv4_lan_route(&iface_name, info.clone()).await;
                    crate::dhcp_server::dhcp_server_new::dhcp_v4_server(
                        config.iface_name,
                        config.config,
                        status,
                        assigned_ips,
                    )
                    .await;
                    route_service.remove_ipv4_lan_route(&iface_name).await;
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
            }
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
}

impl DHCPv4ServerManagerService {
    pub async fn new(
        route_service: IpRouteService,
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: broadcast::Receiver<IfaceObserverAction>,
    ) -> Self {
        let store = store_service.dhcp_v4_server_store();
        let server_starter = DHCPv4ServerStarter::new(route_service, store_service.clone());
        let service =
            ServiceManager::init(store.list().await.unwrap(), server_starter.clone()).await;

        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} Firewall service");
                        let service_config = if let Some(service_config) =
                            store.find_by_iface_name(iface_name.clone()).await.unwrap()
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
}

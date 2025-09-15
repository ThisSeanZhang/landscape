use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;

use landscape_common::ipv6_pd::IAPrefixMap;
use landscape_common::ipv6_pd::LDIAPrefix;
use landscape_common::route::RouteTargetInfo;
use landscape_common::service::service_manager_v2::ServiceStarterTrait;
use tokio::sync::broadcast;

use landscape_common::database::LandscapeDBTrait;
use landscape_common::database::LandscapeServiceDBTrait;
use landscape_common::{
    config::dhcp_v6_client::IPV6PDServiceConfig,
    observer::IfaceObserverAction,
    service::{
        controller_service_v2::ControllerService, service_manager_v2::ServiceManager,
        DefaultServiceStatus, DefaultWatchServiceStatus,
    },
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use landscape_database::{
    dhcp_v6_client::repository::DHCPv6ClientRepository, provider::LandscapeDBServiceProvider,
};

use crate::iface::get_iface_by_name;
use crate::route::IpRouteService;

#[derive(Clone)]
pub struct IPV6PDService {
    route_service: IpRouteService,
    prefix_map: IAPrefixMap,
}

impl IPV6PDService {
    pub fn new(route_service: IpRouteService, prefix_map: IAPrefixMap) -> Self {
        Self { route_service, prefix_map }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for IPV6PDService {
    type Status = DefaultServiceStatus;
    type Config = IPV6PDServiceConfig;

    async fn start(&self, config: IPV6PDServiceConfig) -> DefaultWatchServiceStatus {
        let service_status = DefaultWatchServiceStatus::new();
        if config.enable {
            let route_service = self.route_service.clone();
            let prefix_map = self.prefix_map.clone();
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let route_info = RouteTargetInfo {
                    ifindex: iface.index,
                    weight: 1,
                    has_mac: iface.mac.is_some(),
                    is_docker: false,
                    iface_name: iface.name.clone(),
                    iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    default_route: true,
                    gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                };
                let status_clone = service_status.clone();
                tokio::spawn(async move {
                    crate::dhcp_client::v6::dhcp_v6_pd_client(
                        config.iface_name,
                        config.config.mac,
                        LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
                        status_clone,
                        route_info,
                        route_service,
                        prefix_map,
                    )
                    .await;
                });
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

#[derive(Clone)]
pub struct DHCPv6ClientManagerService {
    store: DHCPv6ClientRepository,
    service: ServiceManager<IPV6PDService>,
    prefix_map: IAPrefixMap,
}

impl ControllerService for DHCPv6ClientManagerService {
    type Id = String;
    type Config = IPV6PDServiceConfig;
    type DatabseAction = DHCPv6ClientRepository;
    type H = IPV6PDService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl DHCPv6ClientManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: broadcast::Receiver<IfaceObserverAction>,
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
    ) -> Self {
        let store = store_service.dhcp_v6_client_store();
        let server_starter = IPV6PDService::new(route_service, prefix_map.clone());
        let service = ServiceManager::init(store.list().await.unwrap(), server_starter).await;

        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} IPv6PD service");
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

        let store = store_service.dhcp_v6_client_store();
        Self { service, store, prefix_map }
    }

    pub async fn get_ipv6_prefix_infos(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.prefix_map.get_info().await
    }
}

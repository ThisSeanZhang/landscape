use std::net::IpAddr;

use landscape_common::database::LandscapeStore;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::route::{LanRouteInfo, LanRouteMode, RouteTargetInfo};
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT;
use landscape_common::{
    args::LAND_HOSTNAME,
    global_const::default_router::{RouteInfo, RouteType, LD_ALL_ROUTERS},
    iface::{
        config::IfaceZoneType,
        ip_config::{IfaceIpModelConfig, IfaceIpServiceConfig},
    },
    observer::IfaceObserverAction,
    service::{
        controller::ControllerService,
        manager::{ServiceManager, ServiceStarterTrait},
        ServiceStatus, WatchService,
    },
};
use landscape_database::{
    iface_ip::repository::IfaceIpServiceRepository, provider::LandscapeDBServiceProvider,
};

use crate::get_iface_by_name;
use crate::pppoe_client::PPPoEClientConfig;
use crate::sys_service::route::IpRouteService;
use landscape_common::dev::LandscapeInterface;

#[derive(Clone)]
#[allow(dead_code)]
pub struct IPConfigService {
    route_service: IpRouteService,
}

impl IPConfigService {
    pub fn new(route_service: IpRouteService) -> Self {
        IPConfigService { route_service }
    }
}
#[async_trait::async_trait]
impl ServiceStarterTrait for IPConfigService {
    type Config = IfaceIpServiceConfig;

    async fn start(&self, config: IfaceIpServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();

                let route_service = self.route_service.clone();
                tokio::spawn(async move {
                    init_service_from_config(iface, config.ip_model, status_clone, route_service)
                        .await
                });
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

async fn init_service_from_config(
    iface: LandscapeInterface,
    service_config: IfaceIpModelConfig,
    service_status: WatchService,
    route_service: IpRouteService,
) {
    match service_config {
        IfaceIpModelConfig::Nothing => {}
        IfaceIpModelConfig::Static {
            default_router, default_router_ip, ipv4, ipv4_mask, ..
        } => {
            // TODO: IPV6 的设置
            if let Some(ipv4) = ipv4 {
                service_status.just_change_status(ServiceStatus::Staring);
                let iface_name = iface.name;
                tracing::info!("set ipv4 is: {}", ipv4);
                let _ = std::process::Command::new("ip")
                    .args(&["addr", "add", &format!("{}/{}", ipv4, ipv4_mask), "dev", &iface_name])
                    .output();
                tracing::debug!("start setting");
                landscape_ebpf::map_setting::add_ipv4_wan_ip(
                    iface.index,
                    ipv4.clone(),
                    default_router_ip.clone(),
                    ipv4_mask,
                    iface.mac.clone(),
                );

                let lan_info = LanRouteInfo {
                    ifindex: iface.index,
                    iface_name: iface_name.clone(),
                    iface_ip: IpAddr::V4(ipv4),
                    mac: iface.mac,
                    prefix: ipv4_mask,
                    mode: LanRouteMode::WanReachable,
                };
                route_service.insert_ipv4_lan_route(&iface_name, lan_info).await;

                if let Some(default_router_ip) = default_router_ip {
                    if !default_router_ip.is_broadcast()
                        && !default_router_ip.is_unspecified()
                        && !default_router_ip.is_loopback()
                    {
                        if default_router {
                            tracing::info!("setting default route: {:?}", default_router_ip);
                            LD_ALL_ROUTERS
                                .add_route(RouteInfo {
                                    iface_name: iface_name.clone(),
                                    weight: 1,
                                    route: RouteType::Ipv4(default_router_ip.clone()),
                                })
                                .await;
                        } else {
                            LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
                        }

                        let info = RouteTargetInfo {
                            ifindex: iface.index,
                            weight: 1,
                            mac: iface.mac.clone(),
                            is_docker: false,
                            iface_name: iface_name.clone(),
                            iface_ip: IpAddr::V4(ipv4),
                            default_route: default_router,
                            gateway_ip: IpAddr::V4(default_router_ip),
                        };
                        route_service.insert_ipv4_wan_route(&iface_name, info).await;
                    }
                }

                service_status.just_change_status(ServiceStatus::Running);
                service_status.wait_to_stopping().await;
                let _ = std::process::Command::new("ip")
                    .args(&["addr", "del", &format!("{}/{}", ipv4, ipv4_mask), "dev", &iface_name])
                    .output();

                if default_router {
                    LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
                }
                route_service.remove_ipv4_wan_route(&iface_name).await;
                route_service.remove_ipv4_lan_route(&iface_name).await;
                landscape_ebpf::map_setting::del_ipv4_wan_ip(iface.index);
                service_status.just_change_status(ServiceStatus::Stop);
            }
        }
        IfaceIpModelConfig::PPPoE { default_router, username, password, mtu } => {
            if let Some(mac_addr) = iface.mac {
                crate::wan_service::pppoe_client::run(
                    PPPoEClientConfig::new(
                        iface.index,
                        iface.name,
                        mac_addr,
                        username,
                        password,
                        default_router,
                        u16::try_from(mtu).unwrap_or(u16::MAX),
                    ),
                    service_status,
                    route_service,
                )
                .await;
            } else {
                service_status.just_change_status(ServiceStatus::Failed);
            }
        }
        IfaceIpModelConfig::DhcpClient { default_router, hostname, custome_opts: _ } => {
            if let Some(mac_addr) = iface.mac {
                let hostname =
                    hostname.filter(|h| !h.is_empty()).unwrap_or_else(|| LAND_HOSTNAME.clone());
                crate::wan_service::dhcpv4_client::v4::dhcp_v4_client(
                    iface.index,
                    iface.name,
                    mac_addr,
                    LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
                    service_status,
                    hostname,
                    default_router,
                    route_service,
                )
                .await;
            } else {
                service_status.just_change_status(ServiceStatus::Failed);
            }
        }
    };
}

#[derive(Clone)]
pub struct IfaceIpServiceManagerService {
    store: IfaceIpServiceRepository,
    service: ServiceManager<IPConfigService>,
}

impl ControllerService for IfaceIpServiceManagerService {
    type Id = String;
    type Config = IfaceIpServiceConfig;
    type DatabseAction = IfaceIpServiceRepository;
    type H = IPConfigService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl IfaceIpServiceManagerService {
    pub async fn new(
        route_service: IpRouteService,
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
    ) -> Self {
        let store = store_service.iface_ip_service_store();
        let iface_store = store_service.iface_store();
        let mut init_configs = Vec::new();
        for config in store.list().await.unwrap() {
            let iface_config = iface_store.find_by_id(config.iface_name.clone()).await.unwrap();
            if matches!(iface_config.map(|iface| iface.zone_type), Some(IfaceZoneType::Wan)) {
                init_configs.push(config);
            }
        }

        let server_starter = IPConfigService::new(route_service);
        let service = ServiceManager::init(init_configs, server_starter.clone()).await;

        let service_clone = service.clone();
        let iface_store = store_service.iface_store();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} IfaceIp service");
                        let iface_config =
                            iface_store.find_by_id(iface_name.clone()).await.unwrap();
                        if !matches!(
                            iface_config.map(|iface| iface.zone_type),
                            Some(IfaceZoneType::Wan)
                        ) {
                            continue;
                        }

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

        let store = store_service.iface_ip_service_store();
        Self { service, store }
    }
}

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT;
use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::sys_service::route_service::{LanRouteInfo, LanRouteMode, RouteTargetInfo};
use landscape_common::{
    args::LAND_HOSTNAME,
    config_service::iface::IfaceZoneType,
    event::hub::iface::IfaceObserverAction,
    global_const::default_router::{LD_ALL_ROUTERS, RouteInfo, RouteType},
    service::{
        ServiceHandle, ServiceStatus,
        controller::{ConfigStoreController, ConfigStoreServiceController},
        manager::{ServiceManager, ServiceStarterTrait},
    },
    wan_service::addr_binding::WanAddrBinding,
    wan_service::ip_config::{IfaceIpModelConfig, IfaceIpServiceConfig},
    wan_service::pppoe::PppoeDataplane,
};
use landscape_database::{
    iface_ip::repository::IfaceIpServiceRepository, provider::LandscapeDBServiceProvider,
};

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;
use crate::wan_service::pppoe_client::PPPoEClientConfig;
use landscape_common::dev::LandscapeInterface;

#[derive(Clone)]
#[allow(dead_code)]
pub struct IPConfigService {
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
}

impl IPConfigService {
    pub fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        pppoe_dataplane: Arc<dyn PppoeDataplane>,
    ) -> Self {
        IPConfigService { route_service, addr_binding, pppoe_dataplane }
    }
}
#[async_trait::async_trait]
impl ServiceStarterTrait for IPConfigService {
    type Config = IfaceIpServiceConfig;

    async fn start(&self, config: IfaceIpServiceConfig) -> ServiceHandle {
        let service_status = ServiceHandle::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                service_status.just_change_status(ServiceStatus::Staring);
                let route_service = self.route_service.clone();
                let addr_binding = self.addr_binding.clone();
                let pppoe_dataplane = self.pppoe_dataplane.clone();
                let spawn_status = service_status.clone();
                let task_status = service_status.clone();
                spawn_status.spawn_task(task_label::task::WAN_IPCONFIG_OBSERVER, async move {
                    init_service_from_config(
                        iface,
                        config.ip_model,
                        task_status,
                        route_service,
                        addr_binding,
                        pppoe_dataplane,
                    )
                    .await
                });
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
                // 契约:iface 缺失视为启动失败,拒绝持久化
                service_status.just_change_status(ServiceStatus::Staring);
                service_status.just_change_status(ServiceStatus::Failed);
            }
        } else {
            service_status.just_change_status(ServiceStatus::Disabled);
        }

        service_status
    }
}

/// 无 IP 模型时的占位运行:保持 `Running` 直到收到停止信号。
async fn run_idle_until_stopped(service_status: ServiceHandle) {
    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;
    service_status.just_change_status(ServiceStatus::Stop);
}

async fn init_service_from_config(
    iface: LandscapeInterface,
    service_config: IfaceIpModelConfig,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
) {
    match service_config {
        IfaceIpModelConfig::Nothing => {
            run_idle_until_stopped(service_status).await;
        }
        IfaceIpModelConfig::Static {
            default_router, default_router_ip, ipv4, ipv4_mask, ..
        } => {
            // TODO: IPV6 的设置
            if let Some(ipv4) = ipv4 {
                service_status.just_change_status(ServiceStatus::Staring);
                let iface_name = iface.name;
                tracing::info!("set ipv4 is: {}", ipv4);
                let _ = std::process::Command::new("ip")
                    .args(["addr", "add", &format!("{}/{}", ipv4, ipv4_mask), "dev", &iface_name])
                    .output();
                tracing::debug!("start setting");
                addr_binding.bind_ipv4(iface.index, ipv4, default_router_ip, ipv4_mask, iface.mac);

                let lan_info = LanRouteInfo {
                    ifindex: iface.index,
                    iface_name: iface_name.clone(),
                    iface_ip: IpAddr::V4(ipv4),
                    mac: iface.mac,
                    prefix: ipv4_mask,
                    mode: LanRouteMode::WanReachable,
                };
                route_service.insert_ipv4_lan_route(&iface_name, lan_info).await;

                if let Some(default_router_ip) = default_router_ip
                    && !default_router_ip.is_broadcast()
                    && !default_router_ip.is_unspecified()
                    && !default_router_ip.is_loopback()
                {
                    if default_router {
                        tracing::info!("setting default route: {:?}", default_router_ip);
                        LD_ALL_ROUTERS
                            .add_route(RouteInfo {
                                iface_name: iface_name.clone(),
                                weight: 1,
                                route: RouteType::Ipv4(default_router_ip),
                            })
                            .await;
                    } else {
                        LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
                    }

                    let info = RouteTargetInfo {
                        ifindex: iface.index,
                        weight: 1,
                        mac: iface.mac,
                        is_docker: false,
                        iface_name: iface_name.clone(),
                        iface_ip: IpAddr::V4(ipv4),
                        default_route: default_router,
                        gateway_ip: IpAddr::V4(default_router_ip),
                    };
                    route_service.insert_ipv4_wan_route(&iface_name, info).await;
                }

                service_status.just_change_status(ServiceStatus::Running);
                service_status.stop_token().cancelled().await;
                let _ = std::process::Command::new("ip")
                    .args(["addr", "del", &format!("{}/{}", ipv4, ipv4_mask), "dev", &iface_name])
                    .output();

                if default_router {
                    LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
                }
                route_service.remove_ipv4_wan_route(&iface_name).await;
                route_service.remove_ipv4_lan_route(&iface_name).await;
                addr_binding.unbind_ipv4(iface.index);
                service_status.just_change_status(ServiceStatus::Stop);
            } else {
                run_idle_until_stopped(service_status).await;
            }
        }
        IfaceIpModelConfig::PPPoE { default_router, username, password, mtu, ac_name } => {
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
                        ac_name,
                    ),
                    service_status,
                    route_service,
                    pppoe_dataplane,
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
                    addr_binding,
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

#[async_trait::async_trait]
impl ConfigStoreController for IfaceIpServiceManagerService {
    type Id = String;
    type Config = IfaceIpServiceConfig;
    type Store = IfaceIpServiceRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for IfaceIpServiceManagerService {
    type H = IPConfigService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    /// DHCP/PPPoE 客户端协商到 Running 可能超过默认窗口。
    fn start_confirm_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

impl IfaceIpServiceManagerService {
    pub async fn get_config_by_name(&self, iface_name: String) -> Option<IfaceIpServiceConfig> {
        self.find_by_id(iface_name).await.ok().flatten()
    }

    pub async fn delete_and_stop_iface_service(
        &self,
        iface_name: String,
    ) -> Result<Option<ServiceStatus>, DbError> {
        self.delete_and_stop_service(iface_name).await
    }
}

impl IfaceIpServiceManagerService {
    pub async fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        pppoe_dataplane: Arc<dyn PppoeDataplane>,
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

        let server_starter = IPConfigService::new(route_service, addr_binding, pppoe_dataplane);
        let service = ServiceManager::init(init_configs, server_starter.clone()).await;

        let service_clone = service.clone();
        let iface_store = store_service.iface_store();
        spawn_task(task_label::task::WAN_IPCONFIG_OBSERVER, async move {
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

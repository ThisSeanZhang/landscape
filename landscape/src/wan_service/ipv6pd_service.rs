use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::event::hub::{IAPrefixEventSender, IfaceEventReader};
use landscape_common::lan_service::lan_ipv6::{PdPrefixContext, PdPrefixContextMap, mark_wan_iid};
use landscape_common::service::manager::ServiceStarterTrait;
use landscape_common::sys_service::route_service::RouteTargetInfo;
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::ipv6_pd::IAPrefixMap;
use landscape_common::wan_service::ipv6_pd::IPV6PDPrefixStatus;
use landscape_common::wan_service::ipv6_pd::LDIAPrefix;

use landscape_common::database::LandscapeStore;
use landscape_common::database::error::DbError;
use landscape_common::{
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
    event::hub::iface::IfaceObserverAction,
    service::{
        WatchService,
        controller::{ConfigStoreController, ConfigStoreServiceController},
        manager::ServiceManager,
    },
    wan_service::ipv6_pd::IPV6PDServiceConfig,
};
use landscape_database::{
    dhcp_v6_client::repository::DHCPv6ClientRepository, provider::LandscapeDBServiceProvider,
};

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

pub fn generate_wan_iid() -> u64 {
    mark_wan_iid(rand::random::<u64>())
}

#[derive(Clone)]
pub struct IPV6PDService {
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    prefix_map: IAPrefixMap,
    shared_wan_iid: Arc<u64>,
    prefix_sender: IAPrefixEventSender,
}

impl IPV6PDService {
    pub fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        prefix_map: IAPrefixMap,
        shared_wan_iid: Arc<u64>,
        prefix_sender: IAPrefixEventSender,
    ) -> Self {
        Self {
            route_service,
            addr_binding,
            prefix_map,
            shared_wan_iid,
            prefix_sender,
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for IPV6PDService {
    type Config = IPV6PDServiceConfig;

    async fn start(&self, config: IPV6PDServiceConfig) -> WatchService {
        let service_status = WatchService::new();
        if config.enable {
            let route_service = self.route_service.clone();
            let addr_binding = self.addr_binding.clone();
            let prefix_map = self.prefix_map.clone();
            let shared_wan_iid = self.shared_wan_iid.clone();
            let prefix_sender = self.prefix_sender.clone();
            let expected_pd_len = config.config.expected_pd_len;
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let route_info = RouteTargetInfo {
                    ifindex: iface.index,
                    weight: 1,
                    mac: iface.mac,
                    is_docker: false,
                    iface_name: iface.name.clone(),
                    iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    default_route: true,
                    gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                };
                let status_clone = service_status.clone();
                spawn_task(task_label::task::WAN_IPV6PD_OBSERVER, async move {
                    crate::wan_service::ipv6pd_client::v6::dhcp_v6_pd_client(
                        config.iface_name,
                        iface.index,
                        iface.mac,
                        config.config.mac,
                        expected_pd_len,
                        LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
                        status_clone,
                        route_info,
                        route_service,
                        addr_binding,
                        prefix_map,
                        shared_wan_iid,
                        prefix_sender,
                    )
                    .await;
                });
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
                service_status.just_change_status(landscape_common::service::ServiceStatus::Failed);
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

#[async_trait::async_trait]
impl ConfigStoreController for DHCPv6ClientManagerService {
    type Id = String;
    type Config = IPV6PDServiceConfig;
    type Store = DHCPv6ClientRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for DHCPv6ClientManagerService {
    type H = IPV6PDService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }
}

impl DHCPv6ClientManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        prefix_map: IAPrefixMap,
        prefix_sender: IAPrefixEventSender,
        shared_wan_iid: Arc<u64>,
    ) -> Result<Self, DbError> {
        let store = store_service.dhcp_v6_client_store();
        let configs = store.list().await?;
        let server_starter = IPV6PDService::new(
            route_service,
            addr_binding,
            prefix_map.clone(),
            shared_wan_iid,
            prefix_sender,
        );
        let service = ServiceManager::init(configs, server_starter).await;

        let service_clone = service.clone();
        spawn_task(task_label::task::WAN_IPV6PD_OBSERVER, async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} IPv6PD service");
                        let service_config = match store.find_by_id(iface_name.clone()).await {
                            Ok(Some(service_config)) => service_config,
                            Ok(None) => continue,
                            Err(error) => {
                                tracing::error!(
                                    "failed to load IPv6PD config for {iface_name}: {error:?}"
                                );
                                continue;
                            }
                        };

                        let _ = service_clone.update_service(service_config).await;
                    }
                    IfaceObserverAction::Down(_) => {}
                }
            }
        });

        let store = store_service.dhcp_v6_client_store();
        Ok(Self { service, store, prefix_map })
    }

    pub fn get_ipv6_prefix_infos(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.prefix_map.get_info()
    }

    pub fn get_ipv6_prefix_statuses(&self) -> HashMap<String, IPV6PDPrefixStatus> {
        self.prefix_map.get_prefix_statuses()
    }

    pub async fn get_pd_prefix_contexts(&self) -> PdPrefixContextMap {
        self.store
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|config| {
                let iface_name = config.iface_name;
                let actual_prefix = self.prefix_map.load_actual(&iface_name);
                (
                    iface_name,
                    PdPrefixContext {
                        expected_pd_len: config.config.expected_pd_len,
                        actual_prefix,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::generate_wan_iid;
    use landscape_common::lan_service::lan_ipv6::is_wan_iid;

    #[test]
    fn generated_wan_iid_uses_the_wan_namespace() {
        assert!(is_wan_iid(generate_wan_iid()));
    }
}

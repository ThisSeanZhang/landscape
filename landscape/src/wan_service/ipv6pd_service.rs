use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use uuid::Uuid;

use landscape_common::event::hub::{IAPrefixEventSender, IfaceEventReader};
use landscape_common::lan_service::lan_ipv6::{mark_wan_iid, PdPrefixContext, PdPrefixContextMap};
use landscape_common::service::manager::ServiceStarterTrait;
use landscape_common::sys_service::route_service::RouteTargetInfo;
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::ipv6_pd::IAPrefixMap;
use landscape_common::wan_service::ipv6_pd::IPV6PDPrefixStatus;
use landscape_common::wan_service::ipv6_pd::LDIAPrefix;

use landscape_common::database::LandscapeStore;
use landscape_common::{
    event::hub::iface::IfaceObserverAction,
    service::{controller::ControllerService, manager::ServiceManager, WatchService},
    wan_service::ipv6_pd::IPV6PDServiceConfig,
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use landscape_database::{
    dhcp_v6_client::repository::DHCPv6ClientRepository, provider::LandscapeDBServiceProvider,
    wan_link::repository::WanLinkRepository,
};

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

pub fn generate_wan_iid() -> u64 {
    mark_wan_iid(rand::random::<u64>())
}

#[derive(Clone)]
pub struct IPV6PDService {
    route_service: IpRouteService,
    wan_link_repo: WanLinkRepository,
    addr_binding: Arc<dyn WanAddrBinding>,
    prefix_map: IAPrefixMap,
    shared_wan_iid: Arc<u64>,
    prefix_sender: IAPrefixEventSender,
}

impl IPV6PDService {
    pub fn new(
        route_service: IpRouteService,
        wan_link_repo: WanLinkRepository,
        addr_binding: Arc<dyn WanAddrBinding>,
        prefix_map: IAPrefixMap,
        shared_wan_iid: Arc<u64>,
        prefix_sender: IAPrefixEventSender,
    ) -> Self {
        Self {
            route_service,
            wan_link_repo,
            addr_binding,
            prefix_map,
            shared_wan_iid,
            prefix_sender,
        }
    }

    /// TODO(wan-link-cleanup): transitional seam. The legacy per-iface PD config
    /// only carries the net iface; resolve the owning link uuid through the
    /// `wan_links` store until the link runtime drives PD directly.
    async fn resolve_link_id(&self, iface_name: &str) -> Option<uuid::Uuid> {
        match self.wan_link_repo.find_links_touching_iface(iface_name).await {
            Ok(links) => links.first().map(|link| link.id),
            Err(error) => {
                tracing::warn!(iface_name, %error, "failed to resolve wan link for PD iface");
                None
            }
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
                let Some(link_id) = self.resolve_link_id(&config.iface_name).await else {
                    tracing::error!(
                        iface_name = %config.iface_name,
                        "IPv6PD: no link owns iface; refusing to start"
                    );
                    service_status
                        .just_change_status(landscape_common::service::ServiceStatus::Failed);
                    return service_status;
                };
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
                tokio::spawn(async move {
                    crate::wan_service::ipv6pd_client::v6::dhcp_v6_pd_client(
                        config.iface_name,
                        link_id,
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
    wan_link_repo: WanLinkRepository,
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
        mut dev_observer: IfaceEventReader,
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        prefix_map: IAPrefixMap,
        prefix_sender: IAPrefixEventSender,
        shared_wan_iid: Arc<u64>,
    ) -> Self {
        let store = store_service.dhcp_v6_client_store();
        let wan_link_repo = store_service.wan_link_store();
        let server_starter = IPV6PDService::new(
            route_service,
            wan_link_repo.clone(),
            addr_binding,
            prefix_map.clone(),
            shared_wan_iid,
            prefix_sender,
        );
        let service = ServiceManager::init(store.list().await.unwrap(), server_starter).await;

        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} IPv6PD service");
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

        let store = store_service.dhcp_v6_client_store();
        Self { service, store, prefix_map, wan_link_repo }
    }

    /// TODO(wan-link-cleanup): transitional seam for the legacy per-iface PD
    /// store; resolve the owning link uuid until PD is link-driven.
    async fn resolve_link_id(&self, iface_name: &str) -> Option<Uuid> {
        match self.wan_link_repo.find_links_touching_iface(iface_name).await {
            Ok(links) => links.first().map(|link| link.id),
            Err(error) => {
                tracing::warn!(iface_name, %error, "failed to resolve wan link for PD iface");
                None
            }
        }
    }

    pub fn get_ipv6_prefix_infos(&self) -> HashMap<Uuid, Option<LDIAPrefix>> {
        self.prefix_map.get_info()
    }

    pub fn get_ipv6_prefix_statuses(&self) -> HashMap<Uuid, IPV6PDPrefixStatus> {
        self.prefix_map.get_prefix_statuses()
    }

    pub async fn get_pd_prefix_contexts(&self) -> PdPrefixContextMap {
        let mut result = PdPrefixContextMap::new();
        for config in self.store.list().await.unwrap_or_default() {
            let Some(link_id) = self.resolve_link_id(&config.iface_name).await else {
                continue;
            };
            let actual_prefix = self.prefix_map.load_actual(link_id);
            result.insert(
                link_id,
                PdPrefixContext {
                    expected_pd_len: config.config.expected_pd_len,
                    actual_prefix,
                },
            );
        }
        result
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

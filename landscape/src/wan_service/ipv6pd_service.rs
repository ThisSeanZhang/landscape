use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use landscape_common::event::hub::{IAPrefixEventSender, IfaceEventReader};
use landscape_common::lan_service::lan_ipv6::{mark_wan_iid, PdPrefixContext, PdPrefixContextMap};
use landscape_common::service::manager::ServiceStarterTrait;
use landscape_common::sys_service::route_service::RouteTargetInfo;
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
};

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

pub fn generate_wan_iid() -> u64 {
    mark_wan_iid(rand::random::<u64>())
}

#[derive(Clone)]
pub struct IPV6PDService {
    route_service: IpRouteService,
    prefix_map: IAPrefixMap,
    shared_wan_iid: Arc<u64>,
    prefix_sender: IAPrefixEventSender,
}

impl IPV6PDService {
    pub fn new(
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        shared_wan_iid: Arc<u64>,
        prefix_sender: IAPrefixEventSender,
    ) -> Self {
        Self {
            route_service,
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
            let prefix_map = self.prefix_map.clone();
            let shared_wan_iid = self.shared_wan_iid.clone();
            let prefix_sender = self.prefix_sender.clone();
            let expected_pd_len = config.config.expected_pd_len;
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let route_info = RouteTargetInfo {
                    ifindex: iface.index,
                    weight: 1,
                    mac: iface.mac.clone(),
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
                        iface.index,
                        iface.mac,
                        config.config.mac,
                        expected_pd_len,
                        LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
                        status_clone,
                        route_info,
                        route_service,
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
        prefix_map: IAPrefixMap,
        prefix_sender: IAPrefixEventSender,
        shared_wan_iid: Arc<u64>,
    ) -> Self {
        let store = store_service.dhcp_v6_client_store();
        let server_starter =
            IPV6PDService::new(route_service, prefix_map.clone(), shared_wan_iid, prefix_sender);
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
        Self { service, store, prefix_map }
    }

    pub fn get_ipv6_prefix_infos(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.prefix_map.get_info()
    }

    pub async fn get_ipv6_prefix_statuses(&self) -> HashMap<String, IPV6PDPrefixStatus> {
        let runtime_statuses = self.prefix_map.get_prefix_statuses();
        let configs = match self.store.list().await {
            Ok(configs) => configs,
            Err(err) => {
                tracing::error!(?err, "failed to load IPv6 PD configs for prefix status");
                return runtime_statuses;
            }
        };

        merge_ipv6_prefix_statuses(configs, runtime_statuses)
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

fn merge_ipv6_prefix_statuses(
    configs: Vec<IPV6PDServiceConfig>,
    mut runtime_statuses: HashMap<String, IPV6PDPrefixStatus>,
) -> HashMap<String, IPV6PDPrefixStatus> {
    configs
        .into_iter()
        .filter(|config| config.enable)
        .map(|config| {
            let iface_name = config.iface_name;
            let actual_prefix =
                runtime_statuses.remove(&iface_name).and_then(|status| status.actual_prefix);
            (iface_name, IPV6PDPrefixStatus::new(config.config.expected_pd_len, actual_prefix))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::Ipv6Addr};

    use super::{generate_wan_iid, merge_ipv6_prefix_statuses};
    use landscape_common::lan_service::lan_ipv6::is_wan_iid;
    use landscape_common::net::MacAddr;
    use landscape_common::wan_service::ipv6_pd::{
        IPV6PDConfig, IPV6PDPrefixStatus, IPV6PDServiceConfig, LDIAPrefix,
    };

    fn config(iface_name: &str, enable: bool, expected_pd_len: u8) -> IPV6PDServiceConfig {
        IPV6PDServiceConfig {
            iface_name: iface_name.to_string(),
            enable,
            config: IPV6PDConfig {
                mac: MacAddr::from([0x02, 0, 0, 0, 0, 1]),
                expected_pd_len,
            },
            update_at: 0.0,
        }
    }

    fn prefix(prefix_len: u8) -> LDIAPrefix {
        LDIAPrefix {
            preferred_lifetime: 300,
            valid_lifetime: 600,
            prefix_len,
            prefix_ip: Ipv6Addr::LOCALHOST,
            last_update_time: 0.0,
        }
    }

    #[test]
    fn generated_wan_iid_uses_the_wan_namespace() {
        assert!(is_wan_iid(generate_wan_iid()));
    }

    #[test]
    fn prefix_statuses_include_enabled_waiting_configs_and_exclude_disabled_configs() {
        let statuses = merge_ipv6_prefix_statuses(
            vec![config("wan0", true, 60), config("wan1", false, 56)],
            HashMap::new(),
        );

        let waiting = statuses.get("wan0").unwrap();
        assert_eq!(waiting.expected_pd_len, 60);
        assert!(waiting.actual_prefix.is_none());
        assert_eq!(waiting.meets_expected_pd_len, None);
        assert!(!statuses.contains_key("wan1"));
    }

    #[test]
    fn prefix_statuses_use_current_config_expectation_with_runtime_prefix() {
        let runtime =
            HashMap::from([("wan0".to_string(), IPV6PDPrefixStatus::new(64, Some(prefix(62))))]);

        let statuses = merge_ipv6_prefix_statuses(vec![config("wan0", true, 60)], runtime);

        let status = statuses.get("wan0").unwrap();
        assert_eq!(status.expected_pd_len, 60);
        assert_eq!(status.actual_prefix.as_ref().unwrap().prefix_len, 62);
        assert_eq!(status.meets_expected_pd_len, Some(false));
    }
}

mod firewall;
mod mss;
mod nat;
mod pd;
mod v4;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::database::store::ConfigStore;
use landscape_common::dev::LandscapeInterface;
use landscape_common::event::hub::iface::IfaceObserverAction;
use landscape_common::event::hub::{IAPrefixEventSender, IfaceEventReader};
use landscape_common::lan_service::lan_ipv6::{PdPrefixContext, PdPrefixContextMap};
use landscape_common::service::{
    ServiceHandle, ServiceStatus,
    controller::{ConfigStoreController, ConfigStoreServiceController},
    manager::{ServiceManager, ServiceStarterTrait},
};
use landscape_common::wan_link::{RuntimeWanLinkConfig, WanLinkConfig};
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;
use landscape_common::wan_service::ipv6_pd::config::DEFAULT_EXPECTED_PD_LEN;
use landscape_common::wan_service::ipv6_pd::{IAPrefixMap, IPV6PDPrefixStatus, LDIAPrefix};
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::wan_service::pppoe::PppoeDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::wan_link::repository::WanLinkRepository;

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

/// One WAN link = one service instance owning the full uplink lifecycle.
///
/// `start` spawns the sections on a single [`ServiceHandle`], in a fixed
/// order: the v4 acquisition first (ethernet static/dhcp, pppd, native
/// PPPoE), then nat → mss → firewall → pd. Every section runs independently
/// and asynchronously; a section reporting a terminal state cancels the
/// link's stop token, which tears down all the other sections (v1 semantics:
/// the link is only healthy as a whole).
#[derive(Clone)]
pub struct WanLinkService {
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
    nat_dataplane: Arc<dyn NatDataplane>,
    mss_dataplane: Arc<dyn MssClampDataplane>,
    firewall_dataplane: Arc<dyn FirewallDataplane>,
    prefix_map: IAPrefixMap,
    prefix_sender: IAPrefixEventSender,
    shared_wan_iid: Arc<u64>,
}

impl WanLinkService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        pppoe_dataplane: Arc<dyn PppoeDataplane>,
        nat_dataplane: Arc<dyn NatDataplane>,
        mss_dataplane: Arc<dyn MssClampDataplane>,
        firewall_dataplane: Arc<dyn FirewallDataplane>,
        prefix_map: IAPrefixMap,
        prefix_sender: IAPrefixEventSender,
        shared_wan_iid: Arc<u64>,
    ) -> Self {
        Self {
            route_service,
            addr_binding,
            pppoe_dataplane,
            nat_dataplane,
            mss_dataplane,
            firewall_dataplane,
            prefix_map,
            prefix_sender,
            shared_wan_iid,
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for WanLinkService {
    type Config = WanLinkConfig;

    async fn start(&self, config: WanLinkConfig) -> ServiceHandle {
        let service_status = ServiceHandle::new();

        let Some(iface) = get_iface_by_name(&config.attach_iface_name).await else {
            tracing::error!("WAN link attach interface {} not found", config.attach_iface_name);
            // 契约:iface 缺失视为启动失败,拒绝持久化
            service_status.just_change_status(ServiceStatus::Staring);
            service_status.just_change_status(ServiceStatus::Failed);
            return service_status;
        };

        service_status.just_change_status(ServiceStatus::Staring);
        let runtime = RuntimeWanLinkConfig::from_config(&config);
        let resource = config.attach_iface_name.clone();

        {
            let status = service_status.clone();
            let route_service = self.route_service.clone();
            let addr_binding = self.addr_binding.clone();
            let pppoe_dataplane = self.pppoe_dataplane.clone();
            let runtime = runtime.clone();
            service_status.spawn_task_with_resource(
                task_label::task::WAN_IPCONFIG_OBSERVER,
                resource.clone(),
                async move {
                    v4::run(iface, runtime, status, route_service, addr_binding, pppoe_dataplane)
                        .await;
                },
            );
        }

        let section_iface_name = runtime.section_iface_name().to_string();

        if runtime.nat.enable {
            let config = runtime.nat;
            let status = service_status.clone();
            let stop = service_status.stop_token();
            let iface_name = section_iface_name.clone();
            let dataplane = self.nat_dataplane.clone();
            service_status.spawn_task_with_resource(
                task_label::task::NAT_RUN,
                iface_name.clone(),
                async move {
                    if let Some(iface) = wait_section_iface(&iface_name, &stop).await {
                        nat::run(iface, config, status, dataplane).await;
                    }
                },
            );
        }

        if runtime.mss.enable {
            let config = runtime.mss;
            let status = service_status.clone();
            let stop = service_status.stop_token();
            let iface_name = section_iface_name.clone();
            let dataplane = self.mss_dataplane.clone();
            service_status.spawn_task_with_resource(
                task_label::task::MSS_CLAMP_RUN,
                iface_name.clone(),
                async move {
                    if let Some(iface) = wait_section_iface(&iface_name, &stop).await {
                        mss::run(iface, config, status, dataplane).await;
                    }
                },
            );
        }

        if runtime.firewall.enable {
            let config = runtime.firewall;
            let status = service_status.clone();
            let stop = service_status.stop_token();
            let iface_name = section_iface_name.clone();
            let dataplane = self.firewall_dataplane.clone();
            service_status.spawn_task_with_resource(
                task_label::task::FIREWALL_RUN,
                iface_name.clone(),
                async move {
                    if let Some(iface) = wait_section_iface(&iface_name, &stop).await {
                        firewall::run(iface, config, status, dataplane).await;
                    }
                },
            );
        }

        if runtime.pd.enable {
            let config = runtime.pd;
            let status = service_status.clone();
            let stop = service_status.stop_token();
            let iface_name = section_iface_name.clone();
            let route_service = self.route_service.clone();
            let addr_binding = self.addr_binding.clone();
            let prefix_map = self.prefix_map.clone();
            let prefix_sender = self.prefix_sender.clone();
            let shared_wan_iid = self.shared_wan_iid.clone();
            service_status.spawn_task_with_resource(
                task_label::task::WAN_IPV6PD_OBSERVER,
                iface_name.clone(),
                async move {
                    if let Some(iface) = wait_section_iface(&iface_name, &stop).await {
                        pd::run(
                            iface,
                            config,
                            status,
                            route_service,
                            addr_binding,
                            prefix_map,
                            shared_wan_iid,
                            prefix_sender,
                        )
                        .await;
                    }
                },
            );
        }

        service_status
    }
}

/// Sections of pppd links live on the ppp device, which only exists once the
/// session is established: poll until it appears or the link stops. For
/// ethernet / native PPPoE links the attach iface already exists and the
/// first lookup returns immediately.
async fn wait_section_iface(
    iface_name: &str,
    stop: &CancellationToken,
) -> Option<LandscapeInterface> {
    loop {
        if let Some(iface) = get_iface_by_name(iface_name).await {
            return Some(iface);
        }
        tracing::info!(iface_name, "waiting for WAN link section iface to appear");
        tokio::select! {
            _ = stop.cancelled() => return None,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

#[derive(Clone)]
pub struct WanLinkServiceManagerService {
    store: WanLinkRepository,
    service: ServiceManager<WanLinkService>,
    prefix_map: IAPrefixMap,
}

#[async_trait::async_trait]
impl ConfigStoreController for WanLinkServiceManagerService {
    type Id = Uuid;
    type Config = WanLinkConfig;
    type Store = WanLinkRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for WanLinkServiceManagerService {
    type H = WanLinkService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }
}

impl WanLinkServiceManagerService {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        pppoe_dataplane: Arc<dyn PppoeDataplane>,
        nat_dataplane: Arc<dyn NatDataplane>,
        mss_dataplane: Arc<dyn MssClampDataplane>,
        firewall_dataplane: Arc<dyn FirewallDataplane>,
        prefix_map: IAPrefixMap,
        prefix_sender: IAPrefixEventSender,
        shared_wan_iid: Arc<u64>,
    ) -> Self {
        let store = store_service.wan_link_store();
        let starter = WanLinkService::new(
            route_service,
            addr_binding,
            pppoe_dataplane,
            nat_dataplane,
            mss_dataplane,
            firewall_dataplane,
            prefix_map.clone(),
            prefix_sender,
            shared_wan_iid,
        );
        let service = ServiceManager::init(store.list().await.unwrap(), starter).await;

        // Restart a link when its attach iface comes back (cable replug).
        // pppX devices of pppd links deliberately don't trigger a restart:
        // the sections wait for the device themselves and the pppd
        // supervisor redials on its own.
        let service_clone = service.clone();
        let obs_store = store_service.wan_link_store();
        spawn_task(task_label::task::WAN_LINK_OBSERVER, async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        let configs = match obs_store.list().await {
                            Ok(configs) => configs,
                            Err(error) => {
                                tracing::error!(%error, "failed to load WAN link configs");
                                continue;
                            }
                        };
                        for config in configs {
                            if config.attach_iface_name == iface_name {
                                tracing::info!(iface_name, "restart WAN link service");
                                let _ = service_clone.update_service(config).await;
                            }
                        }
                    }
                    IfaceObserverAction::Down(_) => {}
                }
            }
        });

        let store = store_service.wan_link_store();
        Self { service, store, prefix_map }
    }

    /// Obtained IA-PD prefixes per section iface (read-only status view).
    pub fn get_ipv6_prefix_infos(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.prefix_map.get_info()
    }

    /// IA-PD negotiation status per section iface (read-only status view).
    pub fn get_ipv6_prefix_statuses(&self) -> HashMap<String, IPV6PDPrefixStatus> {
        self.prefix_map.get_prefix_statuses()
    }

    /// PD context of every link with an enabled PD section, keyed by the
    /// iface the PD client runs on (the ppp device for pppd links). Used by
    /// LAN IPv6 config validation for prefix capacity planning.
    pub async fn get_pd_prefix_contexts(&self) -> PdPrefixContextMap {
        self.store
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|config| config.pd.enable)
            .map(|config| {
                let iface_name =
                    RuntimeWanLinkConfig::from_config(&config).section_iface_name().to_string();
                let actual_prefix = self.prefix_map.load_actual(&iface_name);
                (
                    iface_name,
                    PdPrefixContext {
                        expected_pd_len: config
                            .pd
                            .expected_pd_len
                            .unwrap_or(DEFAULT_EXPECTED_PD_LEN),
                        actual_prefix,
                    },
                )
            })
            .collect()
    }
}

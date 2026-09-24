//! WAN link runtime manager.
//!
//! One `WanLinkServiceManagerService` owns all links. Each active link runs one
//! instance task (see [`starter`]). Unlike the legacy per-feature managers,
//! instances receive config updates over a channel and reconcile in place, so a
//! section edit does not redial the session.

use std::collections::HashMap;
use std::sync::Arc;

use landscape_common::database::error::DbError;
use landscape_common::database::LandscapeStore;
use landscape_common::event::hub::iface::IfaceObserverAction;
use landscape_common::event::hub::{IAPrefixEventSender, IfaceEventReader};
use landscape_common::lan_service::lan_ipv6::{PdPrefixContext, PdPrefixContextMap};
use landscape_common::service::WatchService;
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;
use landscape_common::wan_service::ipv6_pd::{IAPrefixMap, IPV6PDPrefixStatus, LDIAPrefix};
use landscape_common::wan_service::link::{LinkStatus, WanLinkConfig, WanLinkKindConfig};
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::wan_service::pppoe::PppoeDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::wan_link::repository::WanLinkRepository;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

pub mod drivers;
pub mod ip_binder;
pub mod resolve;
pub mod starter;

#[cfg(test)]
mod tests;

pub use drivers::{
    IfaceLookup, NetlinkIfaceLookup, PdDeps, RealSectionRunner, RealSessionDriver, SectionRunner,
    SectionTask, SessionDriver, SessionSpec,
};
pub use ip_binder::{DefaultRouteOps, LdDefaultRouteOps, ShellSystemIfaceOps, SystemIfaceOps};
pub use starter::{LinkStatusStore, WanLinkDeps};

struct InstanceHandle {
    config_tx: mpsc::Sender<WanLinkConfig>,
    status: WatchService,
}

#[derive(Clone)]
pub struct WanLinkServiceManagerService {
    store: WanLinkRepository,
    deps: Arc<WanLinkDeps>,
    instances: Arc<RwLock<HashMap<Uuid, InstanceHandle>>>,
    status_store: LinkStatusStore,
    prefix_map: IAPrefixMap,
}

impl WanLinkServiceManagerService {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        pppoe_dataplane: Arc<dyn PppoeDataplane>,
        nat_dataplane: Arc<dyn NatDataplane>,
        firewall_dataplane: Arc<dyn FirewallDataplane>,
        mss_dataplane: Arc<dyn MssClampDataplane>,
        prefix_map: IAPrefixMap,
        shared_wan_iid: Arc<u64>,
        prefix_sender: IAPrefixEventSender,
        store_service: LandscapeDBServiceProvider,
        dev_observer: IfaceEventReader,
    ) -> Self {
        let session_driver = Arc::new(RealSessionDriver {
            route_service: route_service.clone(),
            addr_binding: addr_binding.clone(),
            pppoe_dataplane,
            system_ops: Arc::new(ShellSystemIfaceOps),
            default_routes: Arc::new(LdDefaultRouteOps),
        });
        let section_runner = Arc::new(RealSectionRunner {
            nat: nat_dataplane,
            firewall: firewall_dataplane,
            mss: mss_dataplane,
            pd: PdDeps {
                route_service,
                addr_binding,
                prefix_map: prefix_map.clone(),
                shared_wan_iid,
                prefix_sender,
            },
        });
        let deps = Arc::new(WanLinkDeps {
            iface_lookup: Arc::new(NetlinkIfaceLookup),
            session_driver,
            section_runner,
            status_store: Arc::default(),
            prefix_map,
        });
        Self::with_deps(deps, store_service, dev_observer).await
    }

    /// Testable constructor: injectable deps (drivers + iface lookup).
    pub async fn with_deps(
        deps: Arc<WanLinkDeps>,
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
    ) -> Self {
        let status_store = deps.status_store.clone();
        let prefix_map = deps.prefix_map.clone();
        let store = store_service.wan_link_store();
        let manager = Self {
            store: store.clone(),
            deps,
            instances: Arc::new(RwLock::new(HashMap::new())),
            status_store,
            prefix_map,
        };

        manager.reload().await;

        // Restart links when their attach iface (or the ppp net iface) appears.
        let observer_manager = manager.clone();
        landscape_common::concurrency::spawn_task(
            landscape_common::concurrency::task_label::task::WAN_LINK_IFACE_OBSERVER,
            async move {
                while let Ok(msg) = dev_observer.recv().await {
                    if let IfaceObserverAction::Up(iface_name) = msg {
                        let mut links =
                            store.find_by_attach_iface_name(&iface_name).await.unwrap_or_default();
                        links.extend(
                            store.find_links_touching_iface(&iface_name).await.unwrap_or_default(),
                        );
                        let mut seen = std::collections::HashSet::new();
                        for link in links {
                            if seen.insert(link.id) {
                                observer_manager.upsert_instance(link).await;
                            }
                        }
                    }
                }
            },
        );

        manager
    }

    async fn reload(&self) {
        let links = self.store.list().await.unwrap_or_default();
        for link in links {
            self.upsert_instance(link).await;
        }
    }

    /// Spawns the instance for a link or forwards the new config to the running
    /// one (in-place reconcile, no session restart unless its inputs changed).
    pub async fn upsert_instance(&self, config: WanLinkConfig) {
        let id = config.id;
        let mut instances = self.instances.write().await;
        if let Some(handle) = instances.get(&id) {
            match handle.config_tx.try_send(config.clone()) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(link_id = %id, "link config update dropped: channel full");
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    instances.remove(&id);
                }
            }
        }
        let (status, config_tx) = starter::spawn_instance(config, self.deps.clone());
        instances.insert(id, InstanceHandle { config_tx, status });
    }

    pub fn get_repository(&self) -> &WanLinkRepository {
        &self.store
    }

    pub async fn list_links(&self) -> Vec<WanLinkConfig> {
        self.store.list().await.unwrap_or_default()
    }

    pub async fn get_config_by_id(&self, id: Uuid) -> Option<WanLinkConfig> {
        self.store.find_by_id(id).await.ok().flatten()
    }

    pub async fn get_link_statuses(&self) -> HashMap<String, LinkStatus> {
        self.status_store.read().await.clone()
    }

    pub async fn get_all_status(&self) -> HashMap<String, WatchService> {
        self.instances
            .read()
            .await
            .iter()
            .map(|(id, handle)| (id.to_string(), handle.status.clone()))
            .collect()
    }

    /// Persist the config and hand it to the link instance.
    ///
    /// `link_chain_id` is backend-managed by the repository: an existing link
    /// keeps its stored value (client changes are ignored), a new link lets the
    /// insert path assign the smallest free id.
    pub async fn handle_service_config(&self, config: WanLinkConfig) -> Result<(), DbError> {
        let stored = self.store.upsert_preserving_chain_id(config).await?;
        self.upsert_instance(stored).await;
        Ok(())
    }

    /// Stop and delete one link.
    pub async fn delete_and_stop_iface_service(&self, id: Uuid) {
        if let Some(handle) = self.instances.write().await.remove(&id) {
            handle.status.wait_stop().await;
        }
        self.status_store.write().await.remove(&id.to_string());
        let _ = self.store.delete(id).await;
    }

    /// Delete every link attached to the given iface (zone change / removal).
    pub async fn delete_links_by_attach_iface(&self, attach_iface_name: &str) {
        if let Ok(links) = self.store.find_by_attach_iface_name(attach_iface_name).await {
            for link in links {
                self.delete_and_stop_iface_service(link.id).await;
            }
        }
    }

    /// pppd links whose net iface is the given ppp device.
    pub async fn get_pppd_links_touching_iface(&self, net_iface: &str) -> Vec<WanLinkConfig> {
        self.store
            .find_links_touching_iface(net_iface)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|link| matches!(link.kind, WanLinkKindConfig::Pppd { .. }))
            .collect()
    }

    pub async fn stop_all(&self) {
        let handles: Vec<InstanceHandle> =
            { self.instances.write().await.drain().map(|(_, handle)| handle).collect() };
        for handle in handles {
            handle.status.wait_stop().await;
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
        for link in self.store.list().await.unwrap_or_default() {
            if !link.pd.enable {
                continue;
            }
            let link_id = link.id;
            let actual_prefix = self.prefix_map.load_actual(link_id);
            result.insert(
                link_id,
                PdPrefixContext {
                    expected_pd_len: link.pd.expected_pd_len.unwrap_or(resolve::DEFAULT_PD_LEN),
                    actual_prefix,
                },
            );
        }
        result
    }
}

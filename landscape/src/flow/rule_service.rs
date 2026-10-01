use std::sync::Arc;

use landscape_common::{
    concurrency::{spawn_task, task_label},
    database::store::{Change, ConfigStore},
    event::dns::DnsEvent,
    event::hub::EnrolledDeviceEventReader,
    flow::{FlowEntryMatchMode, FlowRuleError, config::FlowConfig, dataplane::FlowRuleDataplane},
    service::controller::{ConfigStoreController, ConfigStoreFlowController},
};
use landscape_database::{
    flow_rule::repository::{FlowConfigRepository, find_duplicate_resolved_modes},
    provider::LandscapeDBServiceProvider,
};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

#[derive(Clone)]
pub struct FlowRuleService {
    store: FlowConfigRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    route_service: IpRouteService,
    dataplane: Arc<dyn FlowRuleDataplane>,
}

impl FlowRuleService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
        route_service: IpRouteService,
        device_reader: EnrolledDeviceEventReader,
        dataplane: Arc<dyn FlowRuleDataplane>,
    ) -> Self {
        let store = store_provider.flow_rule_store();
        let result = Self { store, dns_events_tx, route_service, dataplane };
        // Subscribe before the initial sync so no WanRouteEvent can slip in
        // between the sync and the subscription; events arriving during the
        // sync only trigger a redundant, idempotent resync.
        let wan_route_events = result.route_service.subscribe_wan_route_events();
        result.refresh_flow_matches().await;
        result.sync_all_flow_wan_targets().await;

        let this = result.clone();
        spawn_task(task_label::task::FLOW_RULE_OBSERVER, async move {
            let mut rx = device_reader;
            while rx.recv().await.is_ok() {
                this.refresh_flow_matches().await;
            }
        });

        // Recompute the per-flow WAN target slots whenever the route service
        // reports a WAN route change; the flow side owns the configs, so the
        // join lives here instead of inside the route service.
        let this = result.clone();
        spawn_task(task_label::task::FLOW_WAN_ROUTE_OBSERVER, async move {
            let mut events = wan_route_events;
            loop {
                match events.recv().await {
                    Ok(_) => this.sync_all_flow_wan_targets().await,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!("flow wan route observer missed {missed} events; resyncing");
                        this.sync_all_flow_wan_targets().await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        result
    }

    pub async fn refresh_flow_matches(&self) {
        let runtime_configs = match self.store.list_runtime_configs().await {
            Ok(runtime_configs) => runtime_configs,
            Err(error) => {
                tracing::error!("failed to load flow runtime configs: {error:?}");
                return;
            }
        };

        self.dataplane.sync_flow_matches(&runtime_configs);

        let _ = self.dns_events_tx.send(DnsEvent::FlowUpdated).await;
    }

    /// Recompute every flow's WAN target slots from the current store
    /// contents against the route service's WAN state.
    async fn sync_all_flow_wan_targets(&self) {
        let configs = self.store.list().await.unwrap_or_else(|error| {
            tracing::error!("failed to load flow configs for wan target sync: {error:?}");
            Vec::new()
        });
        self.route_service.sync_flow_wan_targets(&configs).await;
    }
}

impl FlowRuleService {
    pub async fn find_resolved_conflict_for_modes(
        &self,
        exclude_id: uuid::Uuid,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<(FlowEntryMatchMode, FlowConfig)>, FlowRuleError> {
        self.store.find_resolved_conflict_for_modes(exclude_id, modes).await
    }

    pub async fn find_duplicate_resolved_mode(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<FlowEntryMatchMode>, FlowRuleError> {
        let resolved_modes = self.store.resolve_modes(modes).await?;
        Ok(find_duplicate_resolved_modes(&resolved_modes))
    }

    pub async fn validate_modes_resolvable(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<(), FlowRuleError> {
        self.store.validate_modes_resolvable(modes).await
    }
}

impl ConfigStoreFlowController for FlowRuleService {}

#[async_trait::async_trait]
impl ConfigStoreController for FlowRuleService {
    type Id = Uuid;
    type Config = FlowConfig;
    type Store = FlowConfigRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        self.refresh_flow_matches().await;
        let configs: Vec<FlowConfig> = changes.into_iter().map(|change| change.new).collect();
        self.route_service.sync_flow_wan_targets(&configs).await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.refresh_flow_matches().await;
        self.route_service.clear_flow_wan_targets(old.flow_id);
    }
}

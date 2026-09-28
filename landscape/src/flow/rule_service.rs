use std::sync::Arc;

use landscape_common::{
    concurrency::{spawn_task, task_label},
    database::store::Change,
    event::hub::EnrolledDeviceEventReader,
    event::{dns::DnsEvent, route::RouteEvent},
    flow::{config::FlowConfig, dataplane::FlowRuleDataplane, FlowEntryMatchMode, FlowRuleError},
    service::controller::{ConfigStoreController, ConfigStoreFlowController},
};
use landscape_database::{
    flow_rule::repository::{find_duplicate_resolved_modes, FlowConfigRepository},
    provider::LandscapeDBServiceProvider,
};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct FlowRuleService {
    store: FlowConfigRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    route_events_tx: mpsc::Sender<RouteEvent>,
    dataplane: Arc<dyn FlowRuleDataplane>,
}

impl FlowRuleService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
        route_events_tx: mpsc::Sender<RouteEvent>,
        device_reader: EnrolledDeviceEventReader,
        dataplane: Arc<dyn FlowRuleDataplane>,
    ) -> Self {
        let store = store_provider.flow_rule_store();
        let result = Self { store, dns_events_tx, route_events_tx, dataplane };
        result.refresh_flow_matches().await;

        let this = result.clone();
        spawn_task(task_label::task::FLOW_RULE_OBSERVER, async move {
            let mut rx = device_reader;
            while rx.recv().await.is_ok() {
                this.refresh_flow_matches().await;
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
        let flow_id = (changes.len() == 1).then(|| changes[0].new.flow_id);
        let _ = self.route_events_tx.send(RouteEvent::FlowRuleUpdate { flow_id }).await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.refresh_flow_matches().await;
        let _ = self
            .route_events_tx
            .send(RouteEvent::FlowRuleUpdate { flow_id: Some(old.flow_id) })
            .await;
    }
}

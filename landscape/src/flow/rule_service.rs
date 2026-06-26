use landscape_common::{
    error::LdError,
    event::hub::EnrolledDeviceEventReader,
    event::{dns::DnsEvent, route::RouteEvent},
    flow::{config::FlowConfig, FlowEntryMatchMode},
    service::controller::{ConfigController, FlowConfigController},
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
}

impl FlowRuleService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
        route_events_tx: mpsc::Sender<RouteEvent>,
        device_reader: EnrolledDeviceEventReader,
    ) -> Self {
        let store = store_provider.flow_rule_store();
        let result = Self { store, dns_events_tx, route_events_tx };
        result.refresh_flow_matches().await;

        let this = result.clone();
        tokio::spawn(async move {
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

        if let Err(error) =
            landscape_ebpf::map_setting::flow::reconcile_flow_match_map(&runtime_configs)
        {
            tracing::error!("failed to reconcile flow match map: {error:?}");
            return;
        }

        let _ = self.dns_events_tx.send(DnsEvent::FlowUpdated).await;
    }
}

impl FlowRuleService {
    pub async fn find_conflict_by_entry_mode(
        &self,
        exclude_id: uuid::Uuid,
        mode: &FlowEntryMatchMode,
    ) -> Result<Option<FlowConfig>, LdError> {
        self.store.find_conflict_by_entry_mode(exclude_id, mode).await
    }

    pub async fn find_resolved_conflict_by_entry_mode(
        &self,
        exclude_id: uuid::Uuid,
        mode: &FlowEntryMatchMode,
    ) -> Result<Option<FlowConfig>, LdError> {
        self.store.find_resolved_conflict_by_entry_mode(exclude_id, mode).await
    }

    pub async fn find_resolved_conflict_for_modes(
        &self,
        exclude_id: uuid::Uuid,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<(FlowEntryMatchMode, FlowConfig)>, LdError> {
        self.store.find_resolved_conflict_for_modes(exclude_id, modes).await
    }

    pub async fn find_duplicate_resolved_mode(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<FlowEntryMatchMode>, LdError> {
        let resolved_modes = self.store.resolve_modes(modes).await?;
        Ok(find_duplicate_resolved_modes(&resolved_modes))
    }

    pub async fn validate_modes_resolvable(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<(), LdError> {
        self.store.validate_modes_resolvable(modes).await
    }
}

impl FlowConfigController for FlowRuleService {}

#[async_trait::async_trait]
impl ConfigController for FlowRuleService {
    type Id = Uuid;
    type Config = FlowConfig;
    type DatabseAction = FlowConfigRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn update_one_config(&self, config: Self::Config) {
        let _ = self
            .route_events_tx
            .send(RouteEvent::FlowRuleUpdate { flow_id: Some(config.flow_id) })
            .await;
    }

    async fn delete_one_config(&self, config: Self::Config) {
        let _ = self
            .route_events_tx
            .send(RouteEvent::FlowRuleUpdate { flow_id: Some(config.flow_id) })
            .await;
    }

    async fn update_many_config(&self, _configs: Vec<Self::Config>) {
        let _ = self.route_events_tx.send(RouteEvent::FlowRuleUpdate { flow_id: None }).await;
    }

    async fn after_update_config(
        &self,
        _new_configs: Vec<Self::Config>,
        _old_configs: Vec<Self::Config>,
    ) {
        self.refresh_flow_matches().await;
    }
}

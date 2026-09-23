use std::sync::Arc;

use landscape_common::{
    database::LandscapeStore,
    event::hub::EnrolledDeviceEventReader,
    event::{dns::DnsEvent, route::RouteEvent},
    flow::{
        config::FlowConfig, dataplane::FlowRuleDataplane, FlowEntryMatchMode, FlowRuleError,
        FlowTarget,
    },
    service::controller::{ConfigController, FlowConfigController},
};
use landscape_database::{
    flow_rule::repository::{find_duplicate_resolved_modes, FlowConfigRepository},
    provider::LandscapeDBServiceProvider,
    wan_link::repository::WanLinkRepository,
};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct FlowRuleService {
    store: FlowConfigRepository,
    wan_link_repo: WanLinkRepository,
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
        let wan_link_repo = store_provider.wan_link_store();
        let result = Self {
            store,
            wan_link_repo,
            dns_events_tx,
            route_events_tx,
            dataplane,
        };
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

    /// Resolve each interface target's link uuid and refresh the downgrade
    /// `name` mirror. Rejects missing or dangling link references.
    pub async fn materialize_target_mirrors(
        &self,
        config: &mut FlowConfig,
    ) -> Result<(), FlowRuleError> {
        for target in &mut config.flow_targets {
            let FlowTarget::Interface { name, link_id } = &mut target.target else {
                continue;
            };
            let Some(id) = *link_id else {
                return Err(FlowRuleError::LinkRequired);
            };
            let link = self
                .wan_link_repo
                .find_by_id(id)
                .await
                .map_err(FlowRuleError::Internal)?
                .ok_or(FlowRuleError::LinkNotFound(id))?;
            *name = link.net_iface_name();
        }
        Ok(())
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

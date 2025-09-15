use landscape_common::{
    event::{dns::DnsEvent, route::RouteEvent},
    flow::config::FlowConfig,
    service::controller_service::{ConfigController, FlowConfigController},
};
use landscape_database::{
    flow_rule::repository::FlowConfigRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::flow::update_flow_matchs;

#[derive(Clone)]
pub struct FlowRuleService {
    store: FlowConfigRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    route_events_tx: mpsc::Sender<RouteEvent>,
}

impl FlowRuleService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
        route_events_tx: mpsc::Sender<RouteEvent>,
    ) -> Self {
        let store = store.flow_rule_store();
        let result = Self { store, dns_events_tx, route_events_tx };
        result.after_update_config(result.list().await, vec![]).await;
        result
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
        new_configs: Vec<Self::Config>,
        old_configs: Vec<Self::Config>,
    ) {
        update_flow_matchs(new_configs, old_configs).await;
        let _ = self.dns_events_tx.send(DnsEvent::FlowUpdated).await;
    }
}

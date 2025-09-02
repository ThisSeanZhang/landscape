use std::collections::HashMap;

use landscape_common::{
    config::dns::DNSRuleConfig,
    event::dns::DnsEvent,
    service::controller_service_v2::{ConfigController, FlowConfigController},
};
use landscape_database::{
    dns_rule::repository::DNSRuleRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct DNSRuleService {
    store: DNSRuleRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
}

impl DNSRuleService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
    ) -> Self {
        let store = store.dns_rule_store();
        let dns_rule_service = Self { store, dns_events_tx };

        let rules = dns_rule_service.list().await;

        if rules.is_empty() {
            dns_rule_service.set(DNSRuleConfig::default()).await;
        }

        dns_rule_service
    }

    pub async fn get_flow_hashmap(&self) -> HashMap<u32, Vec<DNSRuleConfig>> {
        let rules = self.list().await;

        let mut groups: HashMap<u32, Vec<DNSRuleConfig>> = HashMap::new();
        for rule in rules.into_iter() {
            groups.entry(rule.flow_id).or_default().push(rule);
        }

        groups
    }
}

impl FlowConfigController for DNSRuleService {}

#[async_trait::async_trait]
impl ConfigController for DNSRuleService {
    type Id = Uuid;

    type Config = DNSRuleConfig;

    type DatabseAction = DNSRuleRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn update_one_config(&self, config: Self::Config) {
        let _ =
            self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: Some(config.flow_id) }).await;
    }
    async fn delete_one_config(&self, config: Self::Config) {
        let _ =
            self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: Some(config.flow_id) }).await;
    }
    async fn update_many_config(&self, _configs: Vec<Self::Config>) {
        let _ = self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: None }).await;
    }
}

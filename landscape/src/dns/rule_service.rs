use std::collections::HashMap;

use landscape_common::{
    database::error::DbError,
    database::store::{Change, ConfigStore},
    dns::rule::{DNSRuleConfig, DnsRuleError},
    event::dns::DnsEvent,
    service::controller::{ConfigStoreController, ConfigStoreFlowController},
};
use landscape_database::{
    dns_rule::repository::DNSRuleRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::dns::upstream_service::DnsUpstreamService;

#[derive(Clone)]
pub struct DNSRuleService {
    store: DNSRuleRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    dns_upstream_service: DnsUpstreamService,
}

impl DNSRuleService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
        dns_upstream_service: DnsUpstreamService,
    ) -> Result<Self, DbError> {
        let store = store.dns_rule_store();
        let dns_rule_service = Self { store, dns_events_tx, dns_upstream_service };

        let rules = dns_rule_service.list().await?;

        if rules.is_empty() {
            let (rule, upstream) = landscape_common::dns::gen_default_dns_rule_and_upstream();
            // Upstream first so a failure can never leave a rule referencing a
            // missing upstream; an orphan upstream (write succeeded, rule
            // failed) is harmless and converges on the next boot's re-seed.
            dns_rule_service.dns_upstream_service.upsert_seed(upstream).await?;
            dns_rule_service.store.upsert(rule).await?;
        }

        Ok(dns_rule_service)
    }

    pub async fn get_flow_hashmap(&self) -> Result<HashMap<u32, Vec<DNSRuleConfig>>, DbError> {
        let rules = self.list().await?;

        let mut groups: HashMap<u32, Vec<DNSRuleConfig>> = HashMap::new();
        for rule in rules.into_iter() {
            groups.entry(rule.flow_id).or_default().push(rule);
        }

        Ok(groups)
    }

    pub async fn find_required(&self, id: Uuid) -> Result<DNSRuleConfig, DnsRuleError> {
        self.find_by_id(id).await?.ok_or(DnsRuleError::NotFound(id))
    }

    pub async fn delete_required(&self, id: Uuid) -> Result<(), DnsRuleError> {
        self.delete(id).await?.ok_or(DnsRuleError::NotFound(id))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ConfigStoreFlowController for DNSRuleService {}

#[async_trait::async_trait]
impl ConfigStoreController for DNSRuleService {
    type Id = Uuid;

    type Config = DNSRuleConfig;

    type Store = DNSRuleRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        let flow_id = (changes.len() == 1).then(|| changes[0].new.flow_id);
        let _ = self.dns_events_tx.send(DnsEvent::RulesChanged { flow_id }).await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        let _ =
            self.dns_events_tx.send(DnsEvent::RulesChanged { flow_id: Some(old.flow_id) }).await;
    }
}

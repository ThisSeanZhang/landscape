use std::{collections::HashMap, sync::Arc};

use landscape_common::{
    dns::redirect::{DNSRedirectRule, DynamicDnsRedirectBatch, DynamicDnsRedirectScope},
    event::dns::DnsEvent,
    service::controller::{ConfigController, FlowConfigController},
};
use landscape_database::{
    dns_redirect::repository::DNSRedirectRuleRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

#[derive(Clone)]
pub struct DNSRedirectService {
    store: DNSRedirectRuleRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    dynamic_batches:
        Arc<RwLock<HashMap<DynamicDnsRedirectScope, HashMap<String, DynamicDnsRedirectBatch>>>>,
}

impl DNSRedirectService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
    ) -> Self {
        let store = store.dns_redirect_rule_store();

        Self {
            store,
            dns_events_tx,
            dynamic_batches: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_dynamic_batch(
        &self,
        batch: DynamicDnsRedirectBatch,
    ) -> DynamicDnsRedirectBatch {
        let scope = batch.scope.clone();
        let source_id = batch.source_id.clone();
        let mut dynamic_batches = self.dynamic_batches.write().await;

        let scope_batches = dynamic_batches.entry(scope.clone()).or_default();
        if batch.records.is_empty() {
            scope_batches.remove(&source_id);
            if scope_batches.is_empty() {
                dynamic_batches.remove(&scope);
            }
        } else {
            scope_batches.insert(source_id.clone(), batch.clone());
        }

        drop(dynamic_batches);
        self.notify_dynamic_batch_change(&scope, source_id).await;
        batch
    }

    pub async fn list_dynamic_batches(&self) -> Vec<DynamicDnsRedirectBatch> {
        let dynamic_batches = self.dynamic_batches.read().await;
        let mut result: Vec<_> = dynamic_batches
            .values()
            .flat_map(|scope_batches| scope_batches.values().cloned())
            .collect();
        sort_dynamic_batches(&mut result);
        result
    }

    pub async fn list_flow_dynamic_batches(&self, flow_id: u32) -> Vec<DynamicDnsRedirectBatch> {
        let dynamic_batches = self.dynamic_batches.read().await;
        let mut result: Vec<_> = dynamic_batches
            .iter()
            .filter(|(scope, _)| scope.applies_to_flow(flow_id))
            .flat_map(|(_, scope_batches)| scope_batches.values().cloned())
            .collect();
        sort_dynamic_batches(&mut result);
        result
    }

    async fn notify_dynamic_batch_change(
        &self,
        scope: &DynamicDnsRedirectScope,
        source_id: String,
    ) {
        let flow_id = match scope {
            DynamicDnsRedirectScope::Global => None,
            DynamicDnsRedirectScope::Flow(flow_id) => Some(*flow_id),
        };
        let _ =
            self.dns_events_tx.send(DnsEvent::DynamicRedirectsChanged { flow_id, source_id }).await;
    }
}

fn sort_dynamic_batches(batches: &mut [DynamicDnsRedirectBatch]) {
    batches.sort_by(|a, b| {
        scope_sort_rank(&a.scope)
            .cmp(&scope_sort_rank(&b.scope))
            .then_with(|| scope_flow_id(&a.scope).cmp(&scope_flow_id(&b.scope)))
            .then_with(|| a.source_id.cmp(&b.source_id))
    });
}

fn scope_sort_rank(scope: &DynamicDnsRedirectScope) -> u8 {
    match scope {
        DynamicDnsRedirectScope::Global => 0,
        DynamicDnsRedirectScope::Flow(_) => 1,
    }
}

fn scope_flow_id(scope: &DynamicDnsRedirectScope) -> u32 {
    match scope {
        DynamicDnsRedirectScope::Global => 0,
        DynamicDnsRedirectScope::Flow(flow_id) => *flow_id,
    }
}

impl FlowConfigController for DNSRedirectService {}

#[async_trait::async_trait]
impl ConfigController for DNSRedirectService {
    type Id = Uuid;

    type Config = DNSRedirectRule;

    type DatabseAction = DNSRedirectRuleRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn update_one_config(&self, _: Self::Config) {
        let _ = self.dns_events_tx.send(DnsEvent::RedirectsChanged { flow_id: None }).await;
    }

    async fn delete_one_config(&self, config: Self::Config) {
        if config.apply_flows.is_empty() {
            let _ = self.dns_events_tx.send(DnsEvent::RedirectsChanged { flow_id: None }).await;
        } else {
            for flow_id in config.apply_flows {
                let _ = self
                    .dns_events_tx
                    .send(DnsEvent::RedirectsChanged { flow_id: Some(flow_id) })
                    .await;
            }
        }
    }

    async fn update_many_config(&self, _configs: Vec<Self::Config>) {
        let _ = self.dns_events_tx.send(DnsEvent::RedirectsChanged { flow_id: None }).await;
    }
}

use landscape_common::{
    dns::redirect::DNSRedirectRule,
    event::dns::DnsEvent,
    service::controller_service_v2::{ConfigController, FlowConfigController},
};
use landscape_database::{
    dns_redirect::repository::DNSRedirectRuleRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct DNSRedirectService {
    store: DNSRedirectRuleRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
}

impl DNSRedirectService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
    ) -> Self {
        let store = store.dns_redirect_rule_store();
        let dns_rule_service = Self { store, dns_events_tx };

        dns_rule_service
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
        let _ = self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: None }).await;
    }

    async fn delete_one_config(&self, config: Self::Config) {
        if config.apply_flows.is_empty() {
            let _ = self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: None }).await;
        } else {
            for flow_id in config.apply_flows {
                let _ =
                    self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: Some(flow_id) }).await;
            }
        }
    }

    async fn update_many_config(&self, _configs: Vec<Self::Config>) {
        let _ = self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: None }).await;
    }
}

use landscape_common::{
    dns::redirect::DNSRedirectRule,
    service::controller_service_v2::{ConfigController, FlowConfigController},
};
use landscape_database::{
    dns_redirect::repository::DNSRedirectRuleRepository, provider::LandscapeDBServiceProvider,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct DNSRedirectService {
    store: DNSRedirectRuleRepository,
}

impl DNSRedirectService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        // dns_events_tx: mpsc::Sender<DnsEvent>,
    ) -> Self {
        let store = store.dns_redirect_rule_store();
        let dns_rule_service = Self { store };

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
}

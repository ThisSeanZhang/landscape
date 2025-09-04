use landscape_common::{
    dns::upstream::DnsUpstreamConfig, event::dns::DnsEvent,
    service::controller_service_v2::ConfigController,
};
use landscape_database::{
    dns_upstream::repository::DnsUpstreamRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct DnsUpstreamService {
    store: DnsUpstreamRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
}

impl DnsUpstreamService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
    ) -> Self {
        let store = store.dns_upstream_config_store();
        Self { store, dns_events_tx }
    }
}

#[async_trait::async_trait]
impl ConfigController for DnsUpstreamService {
    type Id = Uuid;
    type Config = DnsUpstreamConfig;
    type DatabseAction = DnsUpstreamRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn update_one_config(&self, _: Self::Config) {
        let _ = self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: None }).await;
    }

    async fn delete_one_config(&self, _: Self::Config) {
        let _ = self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: None }).await;
    }

    async fn update_many_config(&self, _configs: Vec<Self::Config>) {
        let _ = self.dns_events_tx.send(DnsEvent::RuleUpdated { flow_id: None }).await;
    }
}

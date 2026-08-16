use landscape_common::{
    database::error::DbError, database::store::ConfigStore, dns::config::DnsUpstreamConfig,
    event::dns::DnsEvent, service::controller::ConfigController,
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

    /// Blind server-authoritative write (startup seeding), no event dispatch.
    pub async fn upsert_seed(&self, config: DnsUpstreamConfig) -> Result<(), DbError> {
        self.store.upsert(config).await.map(|_| ())
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

    async fn update_one_config(&self, config: Self::Config) {
        let _ = self
            .dns_events_tx
            .send(DnsEvent::UpstreamsChanged { upstream_ids: vec![config.id] })
            .await;
    }

    async fn delete_one_config(&self, config: Self::Config) {
        let _ = self
            .dns_events_tx
            .send(DnsEvent::UpstreamsChanged { upstream_ids: vec![config.id] })
            .await;
    }

    async fn update_many_config(&self, configs: Vec<Self::Config>) {
        let upstream_ids = configs.into_iter().map(|config| config.id).collect();
        let _ = self.dns_events_tx.send(DnsEvent::UpstreamsChanged { upstream_ids }).await;
    }
}

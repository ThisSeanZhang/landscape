use landscape_common::{
    database::error::DbError,
    database::store::{Change, ConfigStore},
    dns::config::DnsUpstreamConfig,
    event::dns::DnsEvent,
    service::controller::ConfigStoreController,
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

    /// Batch reads by id used by the DNS runtime builder.
    pub async fn find_ids(&self, ids: Vec<Uuid>) -> Result<Vec<DnsUpstreamConfig>, DbError> {
        self.store.find_ids(ids).await
    }
}

#[async_trait::async_trait]
impl ConfigStoreController for DnsUpstreamService {
    type Id = Uuid;
    type Config = DnsUpstreamConfig;
    type Store = DnsUpstreamRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        let upstream_ids = changes.into_iter().map(|change| change.new.id).collect();
        let _ = self.dns_events_tx.send(DnsEvent::UpstreamsChanged { upstream_ids }).await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        let _ = self
            .dns_events_tx
            .send(DnsEvent::UpstreamsChanged { upstream_ids: vec![old.id] })
            .await;
    }
}

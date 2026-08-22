use std::path::PathBuf;

use landscape_common::{
    config::{MetricMode, MetricRuntimeConfig},
    database::error::DbError,
    event::{ConnectMessage, DnsMetricMessage},
    metric::connect::{
        ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
        ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat,
        IpRealtimeStat, MetricResolution,
    },
    metric::dns::{
        DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
        DnsSummaryQueryParams, DnsSummaryResponse,
    },
};
use tokio::sync::mpsc;

#[cfg(feature = "duckdb")]
pub(crate) mod cold;
pub(crate) mod ingest;
pub mod memory_store;

#[cfg(feature = "duckdb")]
pub mod duckdb;

pub use memory_store::MemoryMetricStore;

#[cfg(feature = "duckdb")]
pub use duckdb::DuckMetricStore;

#[cfg(feature = "metric-persistent")]
#[derive(Clone)]
#[allow(dead_code)]
struct PersistentMetricStore;

#[cfg(feature = "metric-persistent")]
#[allow(dead_code)]
impl PersistentMetricStore {
    fn new(_base_path: PathBuf, _config: MetricRuntimeConfig) -> Self {
        todo!("implement persistent metric store")
    }
}

#[derive(Clone)]
enum MetricBackend {
    Off,
    Memory(MemoryMetricStore),
    #[cfg(feature = "duckdb")]
    Duckdb(DuckMetricStore),
    #[cfg(feature = "metric-persistent")]
    #[allow(dead_code)]
    Persistent(PersistentMetricStore),
}

impl MetricBackend {
    async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        match resolved_metric_mode(config.mode.clone()) {
            MetricMode::Off => Self::Off,
            MetricMode::Memory => {
                #[cfg(feature = "duckdb")]
                tracing::info!("metric mode=memory, using in-memory realtime backend");

                #[cfg(not(feature = "duckdb"))]
                if matches!(config.mode, MetricMode::Duckdb) {
                    tracing::warn!(
                        "metric mode 'duckdb' requested without landscape-metric duckdb feature, falling back to memory"
                    );
                } else {
                    tracing::info!("metric mode=memory, using in-memory realtime backend");
                }

                Self::Memory(MemoryMetricStore::new(base_path, config).await)
            }
            MetricMode::Duckdb => {
                #[cfg(feature = "duckdb")]
                {
                    match DuckMetricStore::new(base_path.clone(), config.clone()).await {
                        Ok(store) => Self::Duckdb(store),
                        Err(error) => {
                            tracing::error!(
                                "failed to initialize duckdb metric backend, falling back to memory: {}",
                                error
                            );
                            Self::Memory(MemoryMetricStore::new(base_path, config).await)
                        }
                    }
                }

                #[cfg(not(feature = "duckdb"))]
                {
                    tracing::warn!(
                        "metric mode 'duckdb' requested without landscape-metric duckdb feature, falling back to memory"
                    );
                    Self::Memory(MemoryMetricStore::new(base_path, config).await)
                }
            }
        }
    }

    fn shutdown(&self) {
        match self {
            Self::Off => {}
            Self::Memory(store) => store.shutdown(),
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.shutdown(),
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => {}
        }
    }

    fn get_connect_msg_channel(&self) -> Option<mpsc::Sender<ConnectMessage>> {
        match self {
            Self::Off => None,
            Self::Memory(store) => Some(store.get_connect_msg_channel()),
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => Some(store.get_connect_msg_channel()),
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => None,
        }
    }

    fn get_dns_msg_channel(&self) -> Option<mpsc::Sender<DnsMetricMessage>> {
        match self {
            Self::Off => None,
            Self::Memory(store) => Some(store.get_dns_msg_channel()),
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => Some(store.get_dns_msg_channel()),
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => None,
        }
    }

    async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.connect_infos().await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.connect_infos().await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Vec::new(),
        }
    }

    async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.get_realtime_ip_stats(is_src).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.get_realtime_ip_stats(is_src).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Vec::new(),
        }
    }

    async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.get_realtime_iface_stats().await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.get_realtime_iface_stats().await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Vec::new(),
        }
    }

    async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.query_metric_by_key(key, resolution).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.query_metric_by_key(key, resolution).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Vec::new(),
        }
    }

    async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.history_summaries_complex(params).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.history_summaries_complex(params).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Vec::new(),
        }
    }

    async fn history_src_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.history_src_ip_stats(params).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.history_src_ip_stats(params).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Vec::new(),
        }
    }

    async fn history_dst_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.history_dst_ip_stats(params).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.history_dst_ip_stats(params).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Vec::new(),
        }
    }

    async fn get_global_stats(&self, force_refresh: bool) -> Result<ConnectGlobalStats, DbError> {
        match self {
            Self::Off => Ok(ConnectGlobalStats::default()),
            Self::Memory(store) => store.get_global_stats(force_refresh).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.get_global_stats(force_refresh).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => Ok(ConnectGlobalStats::default()),
        }
    }

    async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        match self {
            Self::Off => DnsHistoryResponse::default(),
            Self::Memory(store) => store.query_dns_history(params).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.query_dns_history(params).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => DnsHistoryResponse::default(),
        }
    }

    async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        match self {
            Self::Off => DnsSummaryResponse::default(),
            Self::Memory(store) => store.get_dns_summary(params).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.get_dns_summary(params).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => DnsSummaryResponse::default(),
        }
    }

    async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        match self {
            Self::Off => DnsLightweightSummaryResponse::default(),
            Self::Memory(store) => store.get_dns_lightweight_summary(params).await,
            #[cfg(feature = "duckdb")]
            Self::Duckdb(store) => store.get_dns_lightweight_summary(params).await,
            #[cfg(feature = "metric-persistent")]
            Self::Persistent(_) => DnsLightweightSummaryResponse::default(),
        }
    }
}

#[derive(Clone)]
pub struct MetricEngine {
    config: MetricRuntimeConfig,
    backend: MetricBackend,
}

impl MetricEngine {
    pub async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let backend = MetricBackend::new(base_path, config.clone()).await;
        Self { config, backend }
    }

    pub fn mode(&self) -> MetricMode {
        resolved_metric_mode(self.config.mode.clone())
    }

    pub fn get_connect_msg_channel(&self) -> Option<mpsc::Sender<ConnectMessage>> {
        self.backend.get_connect_msg_channel()
    }

    pub fn get_dns_msg_channel(&self) -> Option<mpsc::Sender<DnsMetricMessage>> {
        self.backend.get_dns_msg_channel()
    }

    pub fn shutdown(&self) {
        self.backend.shutdown();
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        self.backend.connect_infos().await
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        self.backend.get_realtime_ip_stats(is_src).await
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        self.backend.get_realtime_iface_stats().await
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        self.backend.query_metric_by_key(key, resolution).await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        self.backend.history_summaries_complex(params).await
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.backend.history_src_ip_stats(params).await
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.backend.history_dst_ip_stats(params).await
    }

    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        self.backend.get_global_stats(force_refresh).await
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        self.backend.query_dns_history(params).await
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        self.backend.get_dns_summary(params).await
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        self.backend.get_dns_lightweight_summary(params).await
    }
}

pub fn resolved_metric_mode(mode: MetricMode) -> MetricMode {
    #[cfg(feature = "duckdb")]
    {
        mode
    }

    #[cfg(not(feature = "duckdb"))]
    {
        if matches!(mode, MetricMode::Duckdb) {
            MetricMode::Memory
        } else {
            mode
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_mode_resolves_based_on_feature() {
        let mode = resolved_metric_mode(MetricMode::Duckdb);

        #[cfg(feature = "duckdb")]
        assert!(matches!(mode, MetricMode::Duckdb));

        #[cfg(not(feature = "duckdb"))]
        assert!(matches!(mode, MetricMode::Memory));
    }
}

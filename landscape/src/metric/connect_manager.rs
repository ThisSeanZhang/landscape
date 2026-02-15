use std::path::PathBuf;
use std::sync::Arc;

use landscape_common::config::MetricRuntimeConfig;
use tokio::sync::{mpsc, RwLock};

use landscape_common::event::ConnectMessage;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectMetricPoint, ConnectRealtimeStatus, IpRealtimeStat, MetricResolution,
};

use crate::metric::duckdb::DuckMetricStore;

#[derive(Clone)]
pub struct ConnectMetricManager {
    msg_channel: mpsc::Sender<ConnectMessage>,
    metric_store: DuckMetricStore,
    global_stats: Arc<RwLock<ConnectGlobalStats>>,
}

impl ConnectMetricManager {
    pub fn with_store(metric_store: DuckMetricStore) -> Self {
        let (msg_channel, mut message_rx) = mpsc::channel(1024);

        let metric_store_clone = metric_store.clone();

        tokio::spawn(async move {
            while let Some(msg) = message_rx.recv().await {
                let ConnectMessage::Metric(metric) = msg;
                metric_store_clone.insert_metric(metric).await;
            }
        });

        let global_stats = Arc::new(RwLock::new(ConnectGlobalStats::default()));

        // Regularly aggregate global statistics (every 24 hours)
        {
            let metric_store_clone = metric_store.clone();
            let global_stats_clone = global_stats.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400));
                loop {
                    interval.tick().await;
                    let stats = metric_store_clone.get_global_stats().await;
                    let mut lock = global_stats_clone.write().await;
                    *lock = stats;
                    tracing::info!("Global stats updated: {} connects", lock.total_connect_count);
                }
            });
        }

        ConnectMetricManager { msg_channel, metric_store, global_stats }
    }

    pub async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let metric_store = DuckMetricStore::new(base_path, config).await;
        Self::with_store(metric_store)
    }

    pub async fn get_global_stats(&self) -> ConnectGlobalStats {
        self.global_stats.read().await.clone()
    }

    pub async fn get_src_ip_stats(&self) -> Vec<IpRealtimeStat> {
        self.metric_store.get_realtime_ip_stats(true).await
    }

    pub async fn get_dst_ip_stats(&self) -> Vec<IpRealtimeStat> {
        self.metric_store.get_realtime_ip_stats(false).await
    }

    pub fn get_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        self.msg_channel.clone()
    }

    pub fn send_connect_msg(&self, msg: ConnectMessage) {
        if let Err(e) = self.msg_channel.try_send(msg) {
            tracing::error!("send firewall metric error: {e:?}");
        }
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        self.metric_store.connect_infos().await
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: Option<MetricResolution>,
    ) -> Vec<ConnectMetricPoint> {
        let resolution = resolution.unwrap_or(MetricResolution::Second);

        self.metric_store.query_metric_by_key(key, resolution).await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        self.metric_store.history_summaries_complex(params).await
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<landscape_common::metric::connect::IpHistoryStat> {
        self.metric_store.history_src_ip_stats(params).await
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<landscape_common::metric::connect::IpHistoryStat> {
        self.metric_store.history_dst_ip_stats(params).await
    }
}

use landscape_common::database::error::DbError;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
    ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat, IpRealtimeStat,
    MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use std::{path::PathBuf, sync::Arc};

use crate::{ConnectMetricEngine, DnsMetricEngine};
use landscape_common::metric::{connect::ConnectMetric, dns::DnsMetricEvent};
use landscape_common::sys_config::{
    ConnectMetricRuntimeConfig, DnsMetricConfig, RuntimeConfigSource,
};
use tokio::sync::mpsc;

/// Compatibility facade backed by the same in-memory engines as MetricService.
#[derive(Clone)]
pub struct MemoryMetricStore {
    connect: Arc<ConnectMetricEngine>,
    dns: Arc<DnsMetricEngine>,
}

impl MemoryMetricStore {
    pub async fn new(_base_path: PathBuf, config: ConnectMetricRuntimeConfig) -> Self {
        let dns = DnsMetricConfig::default().build_runtime();
        Self {
            connect: Arc::new(ConnectMetricEngine::off().start(config)),
            dns: Arc::new(DnsMetricEngine::off().start(dns)),
        }
    }

    pub fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMetric> {
        self.connect.get_connect_msg_channel().expect("active memory engine")
    }

    pub fn get_dns_msg_channel(&self) -> mpsc::Sender<DnsMetricEvent> {
        self.dns.get_dns_msg_channel().expect("active memory engine")
    }

    pub fn shutdown(&self) {
        self.connect.workers.stop.cancel();
        self.dns.workers.stop.cancel();
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        self.connect.connect_infos().await
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        self.connect.get_realtime_ip_stats(is_src).await
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        self.connect.get_realtime_iface_stats().await
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        self.connect.query_metric_by_key(key, resolution).await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> ConnectHistoryResponse {
        self.connect.history_summaries_complex(params).await
    }
    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.connect.history_src_ip_stats(params).await
    }
    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.connect.history_dst_ip_stats(params).await
    }
    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        self.connect.get_global_stats(force_refresh).await
    }
    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        self.dns.query_dns_history(params).await
    }
    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        self.dns.get_dns_summary(params).await
    }
    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        self.dns.get_dns_lightweight_summary(params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::connect::{ConnectKey, ConnectMetric, ConnectStatusType};
    use landscape_common::utils::time::now_ms;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn test_config() -> ConnectMetricRuntimeConfig {
        use landscape_common::sys_config::{ConnectMetricConfig, RuntimeConfigSource};
        let mut config = ConnectMetricConfig::default().build_runtime();
        config.second_window_minutes = 5;
        config.write_batch_size = 16;
        config.store.cleanup_interval_secs = 3600;
        config.store.write_flush_interval_secs = 1;
        config
    }

    fn test_metric(report_time: u64) -> (ConnectMetric, ConnectKey) {
        let create_time_ms = report_time.saturating_sub(1000);
        let metric = ConnectMetric::from_domain(
            create_time_ms,
            1,
            report_time,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1000,
            2000,
            1,
            1,
            2,
            100,
            10,
            200,
            20,
            ConnectStatusType::Active,
        );
        let key = ConnectKey { create_time: create_time_ms * 1_000_000, cpu_id: 1 };
        (metric, key)
    }

    #[tokio::test]
    async fn compatibility_facade_serves_realtime_api() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let tx = store.get_connect_msg_channel();
        let now = now_ms();
        let (metric, key) = test_metric(now - 1000);
        tx.send(metric).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let infos = store.connect_infos().await;
            if !infos.is_empty() {
                assert_eq!(infos[0].key.cpu_id, 1);
                assert!(infos[0].ingress_bps > 0);
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for metric");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let points = store.query_metric_by_key(key, MetricResolution::Second).await;
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].ingress_bytes, 100);
        store.shutdown();
    }

    /// Dropping the final facade releases both ingress channels even with live senders.
    #[tokio::test]
    async fn facade_worker_exits_when_both_channels_close() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let connect = store.get_connect_msg_channel();
        let dns = store.get_dns_msg_channel();
        drop(store);

        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connect.closed(), dns.closed());
        })
        .await
        .expect("facade worker must exit when both channels close");
    }
}

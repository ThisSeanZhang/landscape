use std::path::PathBuf;
use std::sync::Arc;

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::database::error::DbError;
use landscape_common::event::{ConnectMessage, DnsMetricMessage};
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat, IpRealtimeStat,
    MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_core::time::get_current_time_ms;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ingest::{
    cleanup_flow_cache, collect_connect_infos, collect_realtime_iface_stats,
    collect_realtime_ip_stats, drain_iface_buckets, process_connect_metric, second_points_by_key,
    second_ring_capacity, second_window_ms, FlowCache, IfaceBucketCache, IfaceRealtimeCache,
    CHANNEL_CAPACITY,
};

#[derive(Clone)]
pub struct MemoryMetricStore {
    connect_tx: mpsc::Sender<ConnectMessage>,
    dns_tx: mpsc::Sender<DnsMetricMessage>,
    shutdown: CancellationToken,
    flow_cache: FlowCache,
    second_window_ms: u64,
}

impl MemoryMetricStore {
    pub async fn new(_base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let (connect_tx, mut connect_rx) = mpsc::channel::<ConnectMessage>(CHANNEL_CAPACITY);
        let (dns_tx, mut dns_rx) = mpsc::channel::<DnsMetricMessage>(CHANNEL_CAPACITY);
        let shutdown = CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let flow_cache: FlowCache =
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let iface_realtime: IfaceRealtimeCache =
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let iface_buckets: IfaceBucketCache =
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let second_window_ms = second_window_ms(&config);
        let second_ring_cap = second_ring_capacity(&config);
        let cleanup_interval = std::time::Duration::from_secs(config.cleanup_interval_secs.max(1));
        let cleanup_flow_cache_ref = flow_cache.clone();
        let cleanup_iface_realtime_ref = iface_realtime.clone();
        let cleanup_iface_buckets_ref = iface_buckets.clone();

        tokio::spawn(async move {
            let mut cleanup_tick = tokio::time::interval(cleanup_interval);
            cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            cleanup_tick.tick().await;
            let mut connect_closed = false;
            let mut dns_closed = false;

            loop {
                tokio::select! {
                    _ = cleanup_tick.tick() => {
                        let now_ms = get_current_time_ms().unwrap_or_default();
                        let (_, batch) = cleanup_flow_cache(
                            &cleanup_flow_cache_ref,
                            &cleanup_iface_realtime_ref,
                            now_ms,
                            second_window_ms,
                        );
                        drop(batch);
                        let _ = drain_iface_buckets(&cleanup_iface_buckets_ref, &cleanup_iface_realtime_ref);
                    }
                    msg_opt = connect_rx.recv(), if !connect_closed => {
                        match msg_opt {
                            Some(ConnectMessage::Metric(metric)) => {
                                let batch = process_connect_metric(
                                    &cleanup_flow_cache_ref,
                                    &cleanup_iface_realtime_ref,
                                    &cleanup_iface_buckets_ref,
                                    metric,
                                    second_window_ms,
                                    second_ring_cap,
                                );
                                drop(batch);
                            }
                            None => connect_closed = true,
                        }
                    }
                    msg_opt = dns_rx.recv(), if !dns_closed => {
                        match msg_opt {
                            Some(DnsMetricMessage::Metric(_)) => {}
                            None => dns_closed = true,
                        }
                    }
                    _ = worker_shutdown.cancelled() => break,
                }

                if connect_closed && dns_closed {
                    break;
                }
            }
        });

        Self {
            connect_tx,
            dns_tx,
            shutdown,
            flow_cache,
            second_window_ms,
        }
    }

    pub fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        self.connect_tx.clone()
    }

    pub fn get_dns_msg_channel(&self) -> mpsc::Sender<DnsMetricMessage> {
        self.dns_tx.clone()
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        collect_connect_infos(&self.flow_cache, now_ms)
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        collect_realtime_ip_stats(&self.flow_cache, now_ms, is_src)
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        collect_realtime_iface_stats(&self.flow_cache, now_ms)
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        if resolution != MetricResolution::Second {
            return Vec::new();
        }

        let cutoff =
            get_current_time_ms().unwrap_or_default().saturating_sub(self.second_window_ms);
        second_points_by_key(&self.flow_cache, &key, cutoff)
    }

    pub async fn history_summaries_complex(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        Vec::new()
    }

    pub async fn history_src_ip_stats(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        Vec::new()
    }

    pub async fn history_dst_ip_stats(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        Vec::new()
    }

    pub async fn get_global_stats(
        &self,
        _force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        Ok(ConnectGlobalStats::default())
    }

    pub async fn query_dns_history(&self, _params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        DnsHistoryResponse::default()
    }

    pub async fn get_dns_summary(&self, _params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        DnsSummaryResponse::default()
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        _params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        DnsLightweightSummaryResponse::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::config::MetricMode;
    use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn test_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: MetricMode::Memory,
            connect_second_window_minutes: 5,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 7,
            connect_1d_retention_days: 30,
            dns_retention_days: 7,
            write_batch_size: 16,
            write_flush_interval_secs: 1,
            db_max_memory_mb: 128,
            db_max_threads: 1,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1_000,
            cleanup_slice_window_secs: 60,
        }
    }

    fn test_metric(cpu_id: u32, report_time: u64, ingress_bytes: u64) -> ConnectMetric {
        ConnectMetric {
            key: ConnectKey { create_time: 1_000, cpu_id },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            src_port: 10_000 + cpu_id as u16,
            dst_port: 20_000 + cpu_id as u16,
            l4_proto: 6,
            l3_proto: 4,
            flow_id: cpu_id as u8,
            trace_id: cpu_id as u8,
            gress: 0,
            ifindex: cpu_id + 10,
            report_time,
            create_time_ms: report_time.saturating_sub(1_000),
            ingress_bytes,
            ingress_packets: ingress_bytes / 10,
            egress_bytes: ingress_bytes * 2,
            egress_packets: ingress_bytes / 5,
            status: ConnectStatusType::Active,
        }
    }

    async fn wait_for_flows(
        store: &MemoryMetricStore,
        expected: usize,
    ) -> Vec<ConnectRealtimeStatus> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let infos = store.connect_infos().await;
            if infos.len() == expected {
                return infos;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {} active flows, got {}",
                expected,
                infos.len()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn connect_infos_returns_active_flows_sorted_by_recency() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let tx = store.get_connect_msg_channel();
        let now_ms = get_current_time_ms().unwrap();

        tx.send(ConnectMessage::Metric(test_metric(1, now_ms - 2_000, 100))).await.unwrap();
        tx.send(ConnectMessage::Metric(test_metric(2, now_ms - 1_000, 200))).await.unwrap();

        let infos = wait_for_flows(&store, 2).await;
        assert_eq!(infos[0].key.cpu_id, 2);
        assert_eq!(infos[1].key.cpu_id, 1);
        assert!(infos[0].ingress_bps > 0);
    }

    #[tokio::test]
    async fn disabled_flow_is_excluded_from_realtime_queries() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let tx = store.get_connect_msg_channel();
        let now_ms = get_current_time_ms().unwrap();

        tx.send(ConnectMessage::Metric(test_metric(1, now_ms - 1_000, 100))).await.unwrap();
        wait_for_flows(&store, 1).await;

        let mut closed = test_metric(1, now_ms - 500, 150);
        closed.status = ConnectStatusType::Disabled;
        tx.send(ConnectMessage::Metric(closed)).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if store.connect_infos().await.is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for disabled flow to drop out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn realtime_ip_and_iface_stats_aggregate_active_flows() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let tx = store.get_connect_msg_channel();
        let now_ms = get_current_time_ms().unwrap();

        tx.send(ConnectMessage::Metric(test_metric(1, now_ms - 1_000, 100))).await.unwrap();
        tx.send(ConnectMessage::Metric(test_metric(2, now_ms - 500, 300))).await.unwrap();
        wait_for_flows(&store, 2).await;

        let ip_stats = store.get_realtime_ip_stats(true).await;
        assert_eq!(ip_stats.len(), 1);
        assert_eq!(ip_stats[0].stats.active_conns, 2);

        let iface_stats = store.get_realtime_iface_stats().await;
        assert_eq!(iface_stats.len(), 2);
        assert!(iface_stats.iter().all(|s| s.stats.active_conns == 1));
    }

    #[tokio::test]
    async fn second_resolution_query_returns_points_for_key() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let tx = store.get_connect_msg_channel();
        let now_ms = get_current_time_ms().unwrap();
        let key = ConnectKey { create_time: 1_000, cpu_id: 1 };

        tx.send(ConnectMessage::Metric(test_metric(1, now_ms - 4_000, 100))).await.unwrap();
        tx.send(ConnectMessage::Metric(test_metric(1, now_ms - 3_000, 200))).await.unwrap();
        wait_for_flows(&store, 1).await;

        let cutoff = now_ms.saturating_sub(5 * 60 * 1_000);
        let points = store.query_metric_by_key(key.clone(), MetricResolution::Second).await;
        assert_eq!(points.len(), 2);
        assert!(points.iter().all(|p| p.report_time >= cutoff));
        assert_eq!(points.last().unwrap().ingress_bytes, 200);

        let minute_points = store.query_metric_by_key(key, MetricResolution::Minute).await;
        assert!(minute_points.is_empty());
    }

    #[tokio::test]
    async fn shutdown_stops_worker_after_store_is_dropped() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let flow_cache = Arc::downgrade(&store.flow_cache);

        store.shutdown();
        drop(store);

        tokio::time::timeout(Duration::from_secs(1), async {
            while flow_cache.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("memory metric worker did not stop after shutdown");
    }
}

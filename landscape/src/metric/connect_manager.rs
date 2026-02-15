use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use landscape_common::config::MetricRuntimeConfig;
use tokio::sync::{mpsc, RwLock};

use landscape_common::event::ConnectMessage;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey, ConnectMetric,
    ConnectRealtimeStatus, ConnectStatusType, IpAggregatedStats, IpRealtimeStat, MetricResolution,
};

use crate::metric::duckdb::DuckMetricStore;

const MAX_REPORT_INTERVAL_MS: u64 = 5000;
const HOUR_RESOLUTION_THRESHOLD_MS: u64 = 30 * 24 * 3600 * 1000;
const DAY_RESOLUTION_THRESHOLD_MS: u64 = 180 * 24 * 3600 * 1000;
const STALE_TIMEOUT_MS: u64 = 60000;

#[derive(Clone)]
pub struct ConnectMetricManager {
    realtime_metrics: Arc<RwLock<HashMap<ConnectKey, ConnectRealtimeStatus>>>,
    src_ip_stats: Arc<RwLock<HashMap<IpAddr, IpAggregatedStats>>>,
    dst_ip_stats: Arc<RwLock<HashMap<IpAddr, IpAggregatedStats>>>,
    msg_channel: mpsc::Sender<ConnectMessage>,
    metric_store: DuckMetricStore,
    global_stats: Arc<RwLock<ConnectGlobalStats>>,
}

impl ConnectMetricManager {
    pub fn with_store(metric_store: DuckMetricStore) -> Self {
        let realtime_metrics: Arc<RwLock<HashMap<ConnectKey, ConnectRealtimeStatus>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let src_ip_stats: Arc<RwLock<HashMap<IpAddr, IpAggregatedStats>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let dst_ip_stats: Arc<RwLock<HashMap<IpAddr, IpAggregatedStats>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (msg_channel, mut message_rx) = mpsc::channel(1024);

        let metric_store_clone = metric_store.clone();
        let realtime_metrics_clone = realtime_metrics.clone();
        let src_ip_stats_clone = src_ip_stats.clone();
        let dst_ip_stats_clone = dst_ip_stats.clone();

        tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                tokio::select! {
                    msg = message_rx.recv() => {
                        let msg = match msg {
                            Some(m) => m,
                            None => break,
                        };
                        let ConnectMessage::Metric(metric) = msg;
                        Self::handle_metric_message(
                            metric,
                            &metric_store_clone,
                            &realtime_metrics_clone,
                            &src_ip_stats_clone,
                            &dst_ip_stats_clone
                        ).await;
                    }
                    _ = cleanup_interval.tick() => {
                        Self::cleanup_stale_connections(
                            &realtime_metrics_clone,
                            &src_ip_stats_clone,
                            &dst_ip_stats_clone
                        ).await;
                    }
                }
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

        ConnectMetricManager {
            realtime_metrics,
            src_ip_stats,
            dst_ip_stats,
            msg_channel,
            metric_store,
            global_stats,
        }
    }

    pub async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let metric_store = DuckMetricStore::new(base_path, config).await;
        Self::with_store(metric_store)
    }

    pub async fn get_global_stats(&self) -> ConnectGlobalStats {
        self.global_stats.read().await.clone()
    }

    pub async fn get_src_ip_stats(&self) -> Vec<IpRealtimeStat> {
        let stats = self.src_ip_stats.read().await;
        stats.iter().map(|(ip, s)| IpRealtimeStat { ip: *ip, stats: s.clone() }).collect()
    }

    pub async fn get_dst_ip_stats(&self) -> Vec<IpRealtimeStat> {
        let stats = self.dst_ip_stats.read().await;
        stats.iter().map(|(ip, s)| IpRealtimeStat { ip: *ip, stats: s.clone() }).collect()
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
        let realtime_metrics = self.realtime_metrics.read().await;
        let mut result: Vec<ConnectRealtimeStatus> = realtime_metrics.values().cloned().collect();
        result.sort_by_key(|r| r.key.create_time);
        result
    }

    pub async fn query_metric_by_key(&self, key: ConnectKey) -> Vec<ConnectMetric> {
        let now = landscape_common::utils::time::get_current_time_ms().unwrap_or_default();
        let age_ms = now.saturating_sub(key.create_time);

        let resolution = if age_ms > DAY_RESOLUTION_THRESHOLD_MS {
            MetricResolution::Day
        } else if age_ms > HOUR_RESOLUTION_THRESHOLD_MS {
            MetricResolution::Hour
        } else {
            MetricResolution::Second
        };

        self.metric_store.query_metric_by_key(key, resolution).await
    }

    pub async fn query_metric_by_key_with_resolution(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetric> {
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

    async fn handle_metric_message(
        metric: ConnectMetric,
        metric_store: &DuckMetricStore,
        realtime_metrics: &RwLock<HashMap<ConnectKey, ConnectRealtimeStatus>>,
        src_ip_stats: &RwLock<HashMap<IpAddr, IpAggregatedStats>>,
        dst_ip_stats: &RwLock<HashMap<IpAddr, IpAggregatedStats>>,
    ) {
        metric_store.insert_metric(metric.clone()).await;

        let mut realtime_set = realtime_metrics.write().await;
        let mut src_agg = src_ip_stats.write().await;
        let mut dst_agg = dst_ip_stats.write().await;

        match metric.status {
            ConnectStatusType::Disabled => {
                if let Some(conn) = realtime_set.remove(&metric.key) {
                    let old_rates =
                        (conn.ingress_bps, conn.egress_bps, conn.ingress_pps, conn.egress_pps);
                    Self::apply_ip_diff(
                        &mut src_agg,
                        conn.src_ip,
                        Some(old_rates),
                        None,
                        false,
                        true,
                    );
                    Self::apply_ip_diff(
                        &mut dst_agg,
                        conn.dst_ip,
                        Some(old_rates),
                        None,
                        false,
                        true,
                    );
                }
            }
            ConnectStatusType::Active => {
                let key = metric.key.clone();
                let src_ip = metric.src_ip;
                let dst_ip = metric.dst_ip;

                // 1. Get (or create new connection)
                let mut is_new = false;
                let conn_status = realtime_set.entry(key.clone()).or_insert_with(|| {
                    is_new = true;
                    ConnectRealtimeStatus {
                        key,
                        src_ip,
                        dst_ip,
                        src_port: metric.src_port,
                        dst_port: metric.dst_port,
                        l4_proto: metric.l4_proto,
                        l3_proto: metric.l3_proto,
                        flow_id: metric.flow_id,
                        trace_id: metric.trace_id,
                        ingress_bps: 0,
                        egress_bps: 0,
                        ingress_pps: 0,
                        egress_pps: 0,
                        last_metric: None,
                    }
                });

                // 2. Prepare old rate snapshot for "subtract old"
                let old_rates = (
                    conn_status.ingress_bps,
                    conn_status.egress_bps,
                    conn_status.ingress_pps,
                    conn_status.egress_pps,
                );

                // 3. Calculate new rate (handle counter reset)
                if let Some(old_metric) = &conn_status.last_metric {
                    let delta_ms = metric.report_time.saturating_sub(old_metric.report_time);
                    if delta_ms > 0 {
                        let effective_delta_ms = delta_ms.min(MAX_REPORT_INTERVAL_MS);

                        let d_i_bytes = if metric.ingress_bytes >= old_metric.ingress_bytes {
                            metric.ingress_bytes - old_metric.ingress_bytes
                        } else {
                            metric.ingress_bytes
                        };
                        let d_e_bytes = if metric.egress_bytes >= old_metric.egress_bytes {
                            metric.egress_bytes - old_metric.egress_bytes
                        } else {
                            metric.egress_bytes
                        };
                        let d_i_pkts = if metric.ingress_packets >= old_metric.ingress_packets {
                            metric.ingress_packets - old_metric.ingress_packets
                        } else {
                            metric.ingress_packets
                        };
                        let d_e_pkts = if metric.egress_packets >= old_metric.egress_packets {
                            metric.egress_packets - old_metric.egress_packets
                        } else {
                            metric.egress_packets
                        };

                        conn_status.ingress_bps = (d_i_bytes * 8000) / effective_delta_ms;
                        conn_status.egress_bps = (d_e_bytes * 8000) / effective_delta_ms;
                        conn_status.ingress_pps = (d_i_pkts * 1000) / effective_delta_ms;
                        conn_status.egress_pps = (d_e_pkts * 1000) / effective_delta_ms;
                    }
                }
                conn_status.last_metric = Some(metric);

                // 4. Apply delta update (subtract old, add new)
                let old_rates_opt = if is_new { None } else { Some(old_rates) };
                Self::apply_ip_diff(
                    &mut src_agg,
                    conn_status.src_ip,
                    old_rates_opt,
                    Some(conn_status),
                    is_new,
                    false,
                );
                Self::apply_ip_diff(
                    &mut dst_agg,
                    conn_status.dst_ip,
                    old_rates_opt,
                    Some(conn_status),
                    is_new,
                    false,
                );
            }
            _ => {}
        }
    }

    /// Core helper method: Unified handling of IP aggregated statistics: add(+), subtract(-), or replace(Update)
    /// old_rates: (bps_i, bps_e, pps_i, pps_e)
    fn apply_ip_diff(
        agg_map: &mut HashMap<IpAddr, IpAggregatedStats>,
        ip: IpAddr,
        old_rates: Option<(u64, u64, u64, u64)>,
        new_status: Option<&ConnectRealtimeStatus>,
        is_add: bool,    // Whether it's a new connection joining
        is_remove: bool, // Whether the connection is completely removed
    ) {
        let entry = agg_map.entry(ip).or_default();

        // 1. Subtract old contribution (if any)
        if let Some((bps_i, bps_e, pps_i, pps_e)) = old_rates {
            entry.ingress_bps = entry.ingress_bps.saturating_sub(bps_i);
            entry.egress_bps = entry.egress_bps.saturating_sub(bps_e);
            entry.ingress_pps = entry.ingress_pps.saturating_sub(pps_i);
            entry.egress_pps = entry.egress_pps.saturating_sub(pps_e);
        }

        // 2. Add new contribution (if any)
        if let Some(new) = new_status {
            entry.ingress_bps = entry.ingress_bps.saturating_add(new.ingress_bps);
            entry.egress_bps = entry.egress_bps.saturating_add(new.egress_bps);
            entry.ingress_pps = entry.ingress_pps.saturating_add(new.ingress_pps);
            entry.egress_pps = entry.egress_pps.saturating_add(new.egress_pps);
        }

        // 3. Update connection counter
        if is_add {
            entry.active_conns += 1;
        }
        if is_remove {
            entry.active_conns = entry.active_conns.saturating_sub(1);
            if entry.active_conns == 0 {
                agg_map.remove(&ip);
            }
        }
    }

    async fn cleanup_stale_connections(
        realtime_metrics: &RwLock<HashMap<ConnectKey, ConnectRealtimeStatus>>,
        src_ip_stats: &RwLock<HashMap<IpAddr, IpAggregatedStats>>,
        dst_ip_stats: &RwLock<HashMap<IpAddr, IpAggregatedStats>>,
    ) {
        let now = landscape_common::utils::time::get_current_time_ms().unwrap_or_default();
        let mut realtime_set = realtime_metrics.write().await;
        let mut src_agg = src_ip_stats.write().await;
        let mut dst_agg = dst_ip_stats.write().await;

        realtime_set.retain(|key, conn| {
            let last_report =
                conn.last_metric.as_ref().map(|m| m.report_time).unwrap_or(key.create_time);
            if now.saturating_sub(last_report) > STALE_TIMEOUT_MS {
                let old_rates =
                    (conn.ingress_bps, conn.egress_bps, conn.ingress_pps, conn.egress_pps);
                Self::apply_ip_diff(&mut src_agg, conn.src_ip, Some(old_rates), None, false, true);
                Self::apply_ip_diff(&mut dst_agg, conn.dst_ip, Some(old_rates), None, false, true);
                tracing::debug!(
                    "Cleaned up stale connection: {:?} (last report: {})",
                    key,
                    last_report
                );
                false
            } else {
                true
            }
        });
    }
}

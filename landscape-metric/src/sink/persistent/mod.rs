pub(crate) mod sqlite;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::database::error::DbError;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectMetricPoint, IpHistoryStat, MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_core::time::get_current_time_ms;
use sqlx::SqlitePool;
use tokio::task::JoinHandle;

use super::MetricSink;
use crate::agg::{Batch, MS_PER_DAY};

/// 全局统计缓存每日漂移校正间隔:超过该时长未重建则后台重建一次。
const GLOBAL_STATS_REBUILD_INTERVAL_SECS: u64 = 24 * 3600;

/// 持久化 sink:聚合批次以单事务批量写入 sqlite,历史查询直接查库。
#[derive(Clone)]
pub(crate) struct PersistentMetricStore {
    connect_pool: SqlitePool,
    dns_pool: SqlitePool,
    rebuild_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl PersistentMetricStore {
    pub(crate) async fn new(base_path: PathBuf) -> Result<Self, String> {
        if !base_path.exists() {
            std::fs::create_dir_all(&base_path).map_err(|error| {
                format!(
                    "failed to create persistent metric directory {}: {}",
                    base_path.display(),
                    error
                )
            })?;
        }

        let version = landscape_common::LANDSCAPE_METRIC_DB_VERSION;
        let connect_db_path = base_path.join(format!("metrics_v{version}_connect.sqlite"));
        let dns_db_path = base_path.join(format!("metrics_v{version}_dns.sqlite"));

        let connect_pool = sqlite::open_connect_pool(&connect_db_path).await?;
        let dns_pool = sqlite::open_dns_pool(&dns_db_path).await?;

        tracing::info!(
            "persistent metric store ready: connect_db={} dns_db={}",
            connect_db_path.display(),
            dns_db_path.display()
        );

        Ok(Self {
            connect_pool,
            dns_pool,
            rebuild_handle: Arc::new(Mutex::new(None)),
        })
    }
}

#[async_trait::async_trait]
impl MetricSink for PersistentMetricStore {
    async fn apply_connect_batch(&self, batch: &Batch) -> bool {
        if batch.is_empty() {
            return true;
        }
        // 行为决策:写失败直接丢批次、不重试。metric 数据非关键路径,背压/重试会拖垮
        // 采集链路;代价是断电或磁盘异常时会丢少量聚合数据,因此必须保留 error 日志便于排查。
        if let Err(error) = sqlite::connect::apply_connect_batch(&self.connect_pool, batch).await {
            tracing::error!("failed to write persistent connect batch, dropping it: {}", error);
            return false;
        }
        true
    }

    async fn apply_dns_batch(&self, metrics: Vec<DnsMetric>) -> bool {
        if metrics.is_empty() {
            return true;
        }
        // 行为决策:同 connect 批次,写失败直接丢弃、不重试,保留 error 日志。
        if let Err(error) = sqlite::dns::insert_dns_batch(&self.dns_pool, &metrics).await {
            tracing::error!("failed to write persistent dns batch, dropping it: {}", error);
            return false;
        }
        true
    }

    async fn cleanup_connect(&self, config: &MetricRuntimeConfig) {
        let now_ms = get_current_time_ms().unwrap_or_default();

        let summary_cutoff =
            now_ms.saturating_sub(config.connect_summary_retention_days * MS_PER_DAY);
        if let Err(error) =
            sqlite::connect::cleanup_old_summaries(&self.connect_pool, summary_cutoff).await
        {
            tracing::error!("failed to cleanup persistent conn_summaries: {}", error);
        }

        if let Err(error) = sqlite::connect::enforce_summary_max_rows(
            &self.connect_pool,
            config.connect_summary_max_rows,
        )
        .await
        {
            tracing::error!("failed to enforce persistent conn_summaries max rows: {}", error);
        }

        let cutoffs = [
            (
                crate::agg::BucketKind::Minute,
                now_ms.saturating_sub(config.connect_1m_retention_days * MS_PER_DAY),
            ),
            (
                crate::agg::BucketKind::Hour,
                now_ms.saturating_sub(config.connect_1h_retention_days * MS_PER_DAY),
            ),
            (
                crate::agg::BucketKind::Day,
                now_ms.saturating_sub(config.connect_1d_retention_days * MS_PER_DAY),
            ),
        ];
        if let Err(error) = sqlite::connect::cleanup_old_buckets(
            &self.connect_pool,
            cutoffs,
            config.cleanup_time_budget_ms,
            config.cleanup_slice_window_secs,
        )
        .await
        {
            tracing::error!("failed to cleanup persistent connect buckets: {}", error);
        }

        // 回收已结束的后台任务。失败或 panic 后下一轮允许重试。
        let finished_handle = {
            let mut guard = self.rebuild_handle.lock().expect("persistent rebuild handle poisoned");
            if guard.as_ref().map(|handle| handle.is_finished()).unwrap_or(false) {
                guard.take()
            } else {
                None
            }
        };
        if let Some(handle) = finished_handle {
            let _ = handle.await;
        }

        // 每日漂移校正:缓存超过 24h 未重建时,后台异步全量重建;
        // 同一时刻至多一个重建任务。
        match sqlite::connect::global_stats_stale(
            &self.connect_pool,
            GLOBAL_STATS_REBUILD_INTERVAL_SECS,
        )
        .await
        {
            Ok(true) => {
                let mut guard =
                    self.rebuild_handle.lock().expect("persistent rebuild handle poisoned");
                if guard.is_none() {
                    tracing::info!(
                        "phase=persistent_connect.global_stats_rebuild starting daily drift correction rebuild"
                    );
                    let rebuild_pool = self.connect_pool.clone();
                    *guard = Some(tokio::spawn(async move {
                        if let Err(error) =
                            sqlite::connect::rebuild_global_stats_cache(&rebuild_pool).await
                        {
                            tracing::error!(
                                "failed to rebuild persistent connect global stats cache: {}",
                                error
                            );
                        }
                    }));
                }
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(
                    "failed to check persistent connect global stats cache staleness: {}",
                    error
                );
            }
        }
    }

    async fn cleanup_dns(&self, config: &MetricRuntimeConfig) {
        let cutoff = get_current_time_ms()
            .unwrap_or_default()
            .saturating_sub(config.dns_retention_days * MS_PER_DAY);
        match sqlite::dns::cleanup_old_dns(
            &self.dns_pool,
            cutoff,
            config.cleanup_time_budget_ms,
            config.cleanup_slice_window_secs,
        )
        .await
        {
            Ok(deleted) => {
                tracing::debug!("phase=persistent_dns.cleanup deleted_rows={}", deleted)
            }
            Err(error) => {
                tracing::error!("failed to cleanup persistent dns metrics: {}", error)
            }
        }
    }

    async fn close(&self) {
        let handle = self.rebuild_handle.lock().expect("persistent rebuild handle poisoned").take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        self.connect_pool.close().await;
        self.dns_pool.close().await;
    }

    async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        match sqlite::connect::query_metric_by_key(&self.connect_pool, &key, resolution).await {
            Ok(points) => points,
            Err(error) => {
                tracing::error!("failed to query persistent connect metrics by key: {}", error);
                Vec::new()
            }
        }
    }

    async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        match sqlite::connect::query_historical_summaries_complex(&self.connect_pool, params).await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect history summaries: {}", error);
                Vec::new()
            }
        }
    }

    async fn history_src_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match sqlite::connect::query_connection_ip_history(&self.connect_pool, params, true).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect src ip history: {}", error);
                Vec::new()
            }
        }
    }

    async fn history_dst_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match sqlite::connect::query_connection_ip_history(&self.connect_pool, params, false).await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect dst ip history: {}", error);
                Vec::new()
            }
        }
    }

    async fn get_global_stats(&self, force_refresh: bool) -> Result<ConnectGlobalStats, DbError> {
        if force_refresh {
            sqlite::connect::rebuild_global_stats_cache(&self.connect_pool).await.map_err(|error| {
                DbError::Internal(format!(
                    "failed to rebuild persistent connect global stats cache: {}",
                    error
                ))
            })
        } else {
            sqlite::connect::query_global_stats(&self.connect_pool).await.map_err(|error| {
                DbError::Internal(format!(
                    "failed to query persistent connect global stats cache: {}",
                    error
                ))
            })
        }
    }

    async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        match sqlite::dns::query_dns_history(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns history: {}", error);
                DnsHistoryResponse::default()
            }
        }
    }

    async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        match sqlite::dns::query_dns_summary(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns summary: {}", error);
                DnsSummaryResponse::default()
            }
        }
    }

    async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        match sqlite::dns::query_dns_lightweight_summary(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns lightweight summary: {}", error);
                DnsLightweightSummaryResponse::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::connect::{ConnectKey, ConnectMetric, ConnectStatusType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn test_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: landscape_common::config::MetricMode::Persistent,
            connect_second_window_minutes: 5,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 7,
            connect_1d_retention_days: 30,
            connect_summary_retention_days: 30,
            connect_summary_max_rows: 0,
            dns_retention_days: 7,
            write_batch_size: 16,
            write_flush_interval_secs: 1,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1_000,
            cleanup_slice_window_secs: 60,
        }
    }

    fn test_metric(
        create_time: u64,
        cpu_id: u32,
        report_time: u64,
        ingress_bytes: u64,
    ) -> ConnectMetric {
        ConnectMetric {
            key: ConnectKey { create_time, cpu_id },
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
            create_time_ms: create_time,
            ingress_bytes,
            ingress_packets: ingress_bytes / 10,
            egress_bytes: ingress_bytes * 2,
            egress_packets: ingress_bytes / 5,
            status: ConnectStatusType::Active,
        }
    }

    /// cleanup_connect 应检测到 global stats 缓存过期并后台重建,
    /// 重建结果必须与 conn_summaries 全表聚合一致(含绕过缓存的直接 SQL 写入)。
    #[tokio::test]
    async fn cleanup_connect_rebuilds_stale_global_stats_cache() {
        let temp = tempfile::tempdir().unwrap();
        let store = PersistentMetricStore::new(temp.path().to_path_buf()).await.unwrap();
        let pool = store.connect_pool.clone();
        let now_ms = get_current_time_ms().unwrap();

        // 1. 经 sink 写入一条 summary(缓存同步更新)。
        let mut batch = Batch::default();
        batch.push_summary(test_metric(1_000, 1, now_ms - 2_000, 100));
        assert!(store.apply_connect_batch(&batch).await);

        // 2. 直接 SQL 再插入一条 summary(绕过缓存,制造漂移)。
        sqlx::query(
            "INSERT INTO conn_summaries (
                create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto,
                flow_id, trace_id, ifindex, last_report_time,
                total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts,
                status, create_time_ms, gress
            ) VALUES (2_000, 2, '10.0.0.2', '10.0.1.2', 30_000, 40_000, 6, 4, 2, 2, 12,
                ?1, 300, 600, 30, 60, 2, 2_000, 0)",
        )
        .bind(now_ms as i64)
        .execute(&pool)
        .await
        .unwrap();

        // 3. 缓存标记为从未计算(0),强制 cleanup 判定过期。
        sqlx::query(
            "UPDATE conn_global_stats_cache
             SET last_calculate_time = 0, total_connect_count = 0, total_ingress_bytes = 0",
        )
        .execute(&pool)
        .await
        .unwrap();

        // 4. cleanup_connect 应触发后台重建。
        store.cleanup_connect(&test_config()).await;

        // 5. 轮询等待重建完成,断言缓存与全表聚合一致。
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let stats = loop {
            let stats = store.get_global_stats(false).await.unwrap();
            if stats.total_connect_count >= 2 {
                break stats;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for global stats rebuild"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(stats.total_connect_count, 2);
        assert_eq!(stats.total_ingress_bytes, 400);
        assert_eq!(stats.total_egress_bytes, 800);
        assert!(stats.last_calculate_time > 0, "rebuild must refresh last_calculate_time");

        // 6. 重建后的缓存不再判为过期,后续 cleanup 不重复触发(句柄回收路径无 panic)。
        store.cleanup_connect(&test_config()).await;
        let stats = store.get_global_stats(false).await.unwrap();
        assert_eq!(stats.total_connect_count, 2);
        assert_eq!(stats.total_ingress_bytes, 400);

        store.close().await;
    }
}

//! SQLite 存储与后台记录任务(整个文件由 `metric-persistent` feature 门禁,
//! 内部零 cfg)。

use std::path::{Path, PathBuf};
use std::time::Duration;

use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::memtrack;
use landscape_common::self_monitor::memory::{
    MemHistoryQueryParams, MemHistoryResponse, MemMinuteRecord,
};
use landscape_common::utils::time::now_ms;
use landscape_common::{LANDSCAPE_METRIC_DB_VERSION, LANDSCAPE_METRIC_DIR_NAME};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::aggregate::MinuteAggregator;

/// 采样周期:与 RAM 环形缓冲一致,1s 足够分钟聚合精度。
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// 记录任务内部的清理周期(与写入共用循环,清理本身按天删除,每天跑一次即可)。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(24 * 3600);

fn memory_db_path(base_path: &Path) -> PathBuf {
    base_path.join(format!("metrics_v{LANDSCAPE_METRIC_DB_VERSION}_memory.sqlite"))
}

/// 内存指标存储。行数小(每分钟每子系统 1 行),无容量控制,仅保留期清理。
#[derive(Clone)]
pub struct MemMetricStore {
    pool: SqlitePool,
}

impl MemMetricStore {
    pub async fn open(base_path: &Path) -> Result<Self, String> {
        let path = memory_db_path(base_path);
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool =
            SqlitePoolOptions::new().max_connections(2).connect_with(options).await.map_err(
                |error| format!("failed to open memory sqlite at {}: {}", path.display(), error),
            )?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mem_1m (
                minute_ts INTEGER NOT NULL,
                subsystem TEXT NOT NULL,
                live_avg INTEGER NOT NULL,
                live_max INTEGER NOT NULL,
                alloc_delta INTEGER NOT NULL,
                free_delta INTEGER NOT NULL,
                PRIMARY KEY (minute_ts, subsystem)
            ) WITHOUT ROWID",
        )
        .execute(&pool)
        .await
        .map_err(|error| format!("failed to initialize memory sqlite schema: {error}"))?;
        Ok(MemMetricStore { pool })
    }

    /// 写入已完成分钟的行;同键重复写入时保留已存行,避免覆盖完整数据。
    pub async fn record_minute(&self, rows: &[MemMinuteRecord]) -> bool {
        if rows.is_empty() {
            return true;
        }
        let mut tx = match self.pool.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                tracing::warn!("memory metric write failed to begin tx: {error}");
                return false;
            }
        };
        for row in rows {
            let result = sqlx::query(
                "INSERT INTO mem_1m
                    (minute_ts, subsystem, live_avg, live_max, alloc_delta, free_delta)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(minute_ts, subsystem) DO NOTHING",
            )
            .bind(row.minute_ts as i64)
            .bind(&row.subsystem)
            .bind(row.live_avg_bytes as i64)
            .bind(row.live_max_bytes as i64)
            .bind(row.alloc_delta_bytes as i64)
            .bind(row.free_delta_bytes as i64)
            .execute(&mut *tx)
            .await;
            if let Err(error) = result {
                tracing::warn!("memory metric insert failed: {error}");
                let _ = tx.rollback().await;
                return false;
            }
        }
        tx.commit().await.is_ok()
    }

    pub async fn query_history(&self, params: &MemHistoryQueryParams) -> MemHistoryResponse {
        let (start, end) = normalized_range(params, now_ms());
        // `limit` 语义 = 时间轴上的分钟数上限(取最近 N 分钟),避免把某个
        // 子系统序列从中间截断导致下标错位。
        let limit = params.limit.unwrap_or(0) as i64;

        let mut timeline_sql = String::from(
            "SELECT DISTINCT minute_ts FROM mem_1m WHERE minute_ts >= ? AND minute_ts < ?",
        );
        if params.subsystem.is_some() {
            timeline_sql.push_str(" AND subsystem = ?");
        }
        timeline_sql.push_str(if limit > 0 {
            " ORDER BY minute_ts DESC LIMIT ?"
        } else {
            " ORDER BY minute_ts ASC"
        });

        let mut timeline_query =
            sqlx::query_as::<_, (i64,)>(&timeline_sql).bind(start as i64).bind(end as i64);
        if let Some(subsystem) = &params.subsystem {
            timeline_query = timeline_query.bind(subsystem);
        }
        if limit > 0 {
            timeline_query = timeline_query.bind(limit);
        }

        let mut timeline: Vec<u64> = match timeline_query.fetch_all(&self.pool).await {
            Ok(rows) => rows.into_iter().map(|(minute_ts,)| minute_ts.max(0) as u64).collect(),
            Err(error) => {
                tracing::warn!("memory metric timeline query failed: {error}");
                return MemHistoryResponse::default();
            }
        };
        if limit > 0 {
            timeline.reverse();
        }
        let Some(&cutoff) = timeline.first() else {
            return MemHistoryResponse::default();
        };

        let mut rows_sql = String::from(
            "SELECT minute_ts, subsystem, live_avg, live_max, alloc_delta, free_delta
             FROM mem_1m WHERE minute_ts >= ? AND minute_ts < ?",
        );
        if params.subsystem.is_some() {
            rows_sql.push_str(" AND subsystem = ?");
        }
        rows_sql.push_str(" ORDER BY minute_ts ASC, subsystem ASC");

        let mut rows_query = sqlx::query_as::<_, (i64, String, i64, i64, i64, i64)>(&rows_sql)
            .bind(cutoff as i64)
            .bind(end as i64);
        if let Some(subsystem) = &params.subsystem {
            rows_query = rows_query.bind(subsystem);
        }

        let records: Vec<MemMinuteRecord> = match rows_query.fetch_all(&self.pool).await {
            Ok(rows) => rows
                .into_iter()
                .map(|(minute_ts, subsystem, live_avg, live_max, alloc_delta, free_delta)| {
                    MemMinuteRecord {
                        minute_ts: minute_ts.max(0) as u64,
                        subsystem,
                        live_avg_bytes: live_avg.max(0) as u64,
                        live_max_bytes: live_max.max(0) as u64,
                        alloc_delta_bytes: alloc_delta.max(0) as u64,
                        free_delta_bytes: free_delta.max(0) as u64,
                    }
                })
                .collect(),
            Err(error) => {
                tracing::warn!("memory metric query failed: {error}");
                return MemHistoryResponse::default();
            }
        };

        MemHistoryResponse::from_rows(records, timeline)
    }

    pub async fn cleanup(&self, retention_days: u64) {
        let cutoff = now_ms().saturating_sub(retention_days * 86_400_000);
        match sqlx::query("DELETE FROM mem_1m WHERE minute_ts < ?")
            .bind(cutoff as i64)
            .execute(&self.pool)
            .await
        {
            Ok(result) => {
                let rows = result.rows_affected();
                if rows > 0 {
                    tracing::info!("memory metric cleanup removed {rows} rows");
                }
            }
            Err(error) => tracing::warn!("memory metric cleanup failed: {error}"),
        }
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// 查询区间归一:0/0 → 最近 24h;end=0 → 当前时间;倒置区间钳制为空。
fn normalized_range(params: &MemHistoryQueryParams, now_ms: u64) -> (u64, u64) {
    const DEFAULT_WINDOW_MS: u64 = 24 * 3600 * 1000;
    let end = if params.end_time == 0 { now_ms } else { params.end_time };
    let start = if params.start_time == 0 {
        end.saturating_sub(DEFAULT_WINDOW_MS)
    } else {
        params.start_time
    };
    (start.min(end), end)
}

/// 已启动的内存指标记录:查询用的 store 与后台 recorder。
/// drop 不停止 recorder,需显式 [`MemRecording::stop_recorder`]。
/// API 契约见 `super::stub`(非 persistent 构建的同签名退化实现)。
pub struct MemRecording {
    store: MemMetricStore,
    recorder: Option<MemRecorder>,
}

impl MemRecording {
    /// 查询已持久化的分钟历史(失败/无数据返回空)。
    pub async fn query_history(&self, params: &MemHistoryQueryParams) -> MemHistoryResponse {
        self.store.query_history(params).await
    }

    /// 停止后台记录任务(丢弃未完成分钟)。store 保持可用(仅供查询)。
    pub async fn stop_recorder(&mut self) {
        if let Some(recorder) = self.recorder.take() {
            recorder.stop().await;
        }
    }

    /// 重新拉起后台记录任务(停止后可重启,如 metric 模式热切换)。
    pub fn spawn_recorder(&mut self, retention_days: u64) {
        if let Some(recorder) = self.recorder.take() {
            // 正常流程不会走到(recorder 已被 stop_recorder 取走),防御性取消。
            recorder.cancel.cancel();
        }
        self.recorder = Some(MemRecorder::spawn(self.store.clone(), retention_days));
    }
}

/// 后台记录任务句柄。
struct MemRecorder {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

impl MemRecorder {
    fn spawn(store: MemMetricStore, retention_days: u64) -> Self {
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = spawn_task(task_label::task::METRIC_MEM_RECORDER, async move {
            run_memory_recorder(store, retention_days, task_cancel).await;
        });
        MemRecorder { cancel, handle }
    }

    async fn stop(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

/// 打开 store 并启动内存指标记录任务:采样 → 分钟聚合 → 入库,顺带按天清理。
pub async fn start_memory_recording(
    base_path: PathBuf,
    retention_days: u64,
) -> Option<MemRecording> {
    let metric_dir = base_path.join(LANDSCAPE_METRIC_DIR_NAME);
    if let Err(error) = tokio::fs::create_dir_all(&metric_dir).await {
        tracing::warn!("failed to create metric directory for memory recording: {error}");
    }
    let store = match MemMetricStore::open(&metric_dir).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(
                "failed to open memory metric store, memory history will not persist: {error}"
            );
            return None;
        }
    };
    let mut recording = MemRecording { store, recorder: None };
    recording.spawn_recorder(retention_days);
    Some(recording)
}

async fn run_memory_recorder(
    store: MemMetricStore,
    retention_days: u64,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cleanup = tokio::time::interval(CLEANUP_INTERVAL);
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut aggregator = MinuteAggregator::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            // interval 首个 tick 立即触发,启动时的清理由此覆盖。
            _ = cleanup.tick() => store.cleanup(retention_days).await,
            _ = ticker.tick() => {
                let finished = aggregator.ingest(&memtrack::capture_compact());
                // 写失败不中断:分钟行已丢失,聚合器已翻转到新分钟。
                let _ = store.record_minute(&finished).await;
            }
        }
    }
    aggregator.discard_current();
    // 不在此处 close 共享池:store 仍被查询路径持有,随所有权释放自然关闭。
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::self_monitor::memory::MinutePoint;

    #[test]
    fn normalized_range_defaults_and_clamps() {
        let now = 10_000_000_000;
        assert_eq!(
            normalized_range(&MemHistoryQueryParams::default(), now),
            (now - 86_400_000, now)
        );
        assert_eq!(
            normalized_range(
                &MemHistoryQueryParams { start_time: 500, end_time: 0, ..Default::default() },
                now
            ),
            (500, now)
        );
        assert_eq!(
            normalized_range(
                &MemHistoryQueryParams {
                    start_time: 9_000,
                    end_time: 1_000,
                    ..Default::default()
                },
                now
            ),
            (1_000, 1_000)
        );
    }

    #[tokio::test]
    async fn memory_store_record_query_cleanup_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let store = MemMetricStore::open(temp.path()).await.unwrap();

        let rows = vec![
            MemMinuteRecord {
                minute_ts: 600_000,
                subsystem: "dns".to_string(),
                live_avg_bytes: 1_000,
                live_max_bytes: 1_200,
                alloc_delta_bytes: 500,
                free_delta_bytes: 400,
            },
            MemMinuteRecord {
                minute_ts: 600_000,
                subsystem: landscape_common::self_monitor::memory::PROCESS_SUBSYSTEM.to_string(),
                live_avg_bytes: 9_000,
                live_max_bytes: 9_500,
                alloc_delta_bytes: 0,
                free_delta_bytes: 0,
            },
        ];
        assert!(store.record_minute(&rows).await);
        let replacement = MemMinuteRecord {
            minute_ts: 600_000,
            subsystem: "dns".to_string(),
            live_avg_bytes: 9_000,
            live_max_bytes: 9_500,
            alloc_delta_bytes: 800,
            free_delta_bytes: 700,
        };
        assert!(store.record_minute(&[replacement]).await);

        let queried = store
            .query_history(&MemHistoryQueryParams {
                start_time: 0,
                end_time: 1_000_000,
                subsystem: Some("dns".to_string()),
                limit: None,
            })
            .await;
        assert_eq!(queried.timestamps, vec![600_000]);
        assert_eq!(queried.series.len(), 1);
        assert_eq!(queried.series[0].subsystem, "dns");
        assert_eq!(queried.series[0].points, vec![MinutePoint([1_000, 1_200, 500, 400])]);

        store.cleanup(0).await;
        let queried = store
            .query_history(&MemHistoryQueryParams {
                start_time: 0,
                end_time: 0,
                ..Default::default()
            })
            .await;
        assert!(queried.timestamps.is_empty());
        assert!(queried.series.is_empty());

        store.close().await;
    }

    #[tokio::test]
    async fn memory_store_series_gap_fill_and_timeline_limit() {
        let temp = tempfile::tempdir().unwrap();
        let store = MemMetricStore::open(temp.path()).await.unwrap();

        let row = |minute_ts: u64, subsystem: &str, live_avg: u64| MemMinuteRecord {
            minute_ts,
            subsystem: subsystem.to_string(),
            live_avg_bytes: live_avg,
            live_max_bytes: live_avg + 10,
            alloc_delta_bytes: 1,
            free_delta_bytes: 2,
        };
        // dns 连续两分钟;firewall 仅第一分钟(第二分钟缺行 → 补 0 对齐)。
        assert!(
            store
                .record_minute(&[
                    row(600_000, "dns", 100),
                    row(600_000, "firewall", 50),
                    row(660_000, "dns", 200),
                ])
                .await
        );

        let resp = store
            .query_history(&MemHistoryQueryParams {
                start_time: 0,
                end_time: 1_000_000,
                ..Default::default()
            })
            .await;
        assert_eq!(resp.timestamps, vec![600_000, 660_000]);
        assert_eq!(resp.series.len(), 2);
        let dns = resp.series.iter().find(|s| s.subsystem == "dns").unwrap();
        assert_eq!(dns.points, vec![MinutePoint([100, 110, 1, 2]), MinutePoint([200, 210, 1, 2])]);
        let fw = resp.series.iter().find(|s| s.subsystem == "firewall").unwrap();
        assert_eq!(fw.points, vec![MinutePoint([50, 60, 1, 2]), MinutePoint([0, 0, 0, 0])]);

        // limit = 时间轴分钟数上限:只保留最近 1 分钟,窗口内无数据的子系统不出现。
        let limited = store
            .query_history(&MemHistoryQueryParams {
                start_time: 0,
                end_time: 1_000_000,
                limit: Some(1),
                ..Default::default()
            })
            .await;
        assert_eq!(limited.timestamps, vec![660_000]);
        assert_eq!(limited.series.len(), 1);
        assert_eq!(limited.series[0].subsystem, "dns");
        assert_eq!(limited.series[0].points, vec![MinutePoint([200, 210, 1, 2])]);

        store.close().await;
    }
}

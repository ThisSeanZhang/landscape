//! 1 秒级 RAM 环形缓冲:最近 N 个快照,服务 `/api/v1/self-monitor/memory` 的
//! 实时/近期查询;分钟级历史走 MetricEngine 的持久化链路,两条链路相互独立。
//! 未开启 feature `mem-track` 时两条链路均不启动(见 [`start_sampler_with`])。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::registry::{
    CompactSnapshot, MemorySeriesResponse, SUBSYSTEMS, SlotCounters, SlotPoint, SnapshotMeta,
    SubsystemSeries, subsystem_label,
};
use crate::concurrency::{spawn_task, task_label};

/// 默认采样周期(1s)与缓冲容量(1 小时)。
pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_CAPACITY: usize = 3600;

/// 内存快照环形缓冲(克隆共享同一底层)。内部存紧凑快照(内联定长数组,
/// 采样路径零堆分配),查询时才转换为 API 快照。
#[derive(Clone)]
pub struct MemoryHistory {
    inner: Arc<Mutex<VecDeque<CompactSnapshot>>>,
    capacity: usize,
}

impl MemoryHistory {
    fn new(capacity: usize) -> Self {
        MemoryHistory {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    fn push(&self, snapshot: CompactSnapshot) {
        let mut guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.len() == self.capacity {
            guard.pop_front();
        }
        guard.push_back(snapshot);
    }

    /// 取最近 `limit` 个快照,投影为“共享时间轴 + 每子系统位置数组”的批量
    /// 响应(时间升序)。`limit = 0` 返回全部;`subsystem` 非空时只保留该
    /// 子系统一支(无数据则为空 series)。
    ///
    /// 锁内只 clone 紧凑快照,投影在锁外完成,避免持锁分配。
    pub fn recent_series(&self, limit: usize, subsystem: Option<&str>) -> MemorySeriesResponse {
        let samples: Vec<CompactSnapshot> = {
            let guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if limit == 0 || limit >= guard.len() {
                guard.iter().cloned().collect()
            } else {
                guard.iter().skip(guard.len() - limit).cloned().collect()
            }
        };
        build_series(&samples, subsystem)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn build_series(samples: &[CompactSnapshot], subsystem: Option<&str>) -> MemorySeriesResponse {
    let timestamps: Vec<u64> = samples.iter().map(|snapshot| snapshot.timestamp_ms).collect();
    let meta: Vec<SnapshotMeta> = samples.iter().map(|snapshot| snapshot.meta.clone()).collect();

    // 只输出窗口内曾经非零的槽位;从未使用的槽位整段为零,输出无信息。
    let mut used = [false; SUBSYSTEMS.len()];
    for sample in samples {
        for (slot, counters) in sample.iter_slots() {
            if counters != SlotCounters::default() {
                used[slot] = true;
            }
        }
    }

    let series = (0..SUBSYSTEMS.len())
        .filter(|&slot| {
            if !used[slot] {
                return false;
            }
            match subsystem {
                Some(name) => subsystem_label(slot) == name,
                None => true,
            }
        })
        .map(|slot| SubsystemSeries {
            subsystem: subsystem_label(slot).to_string(),
            points: samples.iter().map(|sample| SlotPoint::from(sample.counters(slot))).collect(),
        })
        .collect();

    MemorySeriesResponse { timestamps, meta: Some(meta), series }
}

/// 启动周期采样任务,返回共享环形缓冲。任务随运行时关闭而结束。
///
/// 未开启 feature `mem-track` 时返回不启动采样任务的空缓冲,实时历史
/// 恒为空(能力开关由 `Capability::MemTrack` 上报)。
pub fn start_sampler() -> MemoryHistory {
    start_sampler_with(DEFAULT_SAMPLE_INTERVAL, DEFAULT_CAPACITY)
}

/// 自定义周期与容量的变体(测试用)。
pub fn start_sampler_with(interval: Duration, capacity: usize) -> MemoryHistory {
    let history = MemoryHistory::new(capacity.max(1));
    if !cfg!(feature = "mem-track") {
        return history;
    }
    let task_history = history.clone();
    let _sampler_handle = spawn_task(task_label::task::MEM_SAMPLE, async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            task_history.push(super::capture_compact());
        }
    });
    history
}

#[cfg(test)]
mod tests {
    use super::super::registry::{CompactSnapshot, SlotCounters, SlotPoint};
    use super::*;

    #[tokio::test]
    #[cfg(feature = "mem-track")]
    async fn sampler_fills_ring_buffer() {
        let history = start_sampler_with(Duration::from_millis(5), 16);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while history.is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "sampler never produced a sample");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let series = history.recent_series(0, None);
        assert_eq!(series.timestamps.len(), history.len());
        assert_eq!(series.meta.as_ref().unwrap().len(), history.len());
    }

    #[tokio::test]
    #[cfg(not(feature = "mem-track"))]
    async fn sampler_is_inert_without_mem_track() {
        let history = start_sampler_with(Duration::from_millis(5), 16);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(history.is_empty());
        let series = history.recent_series(0, None);
        assert!(series.timestamps.is_empty());
        assert!(series.series.is_empty());
        assert!(series.meta.as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ring_respects_capacity_and_recent_limit() {
        let history = MemoryHistory::new(4);
        for i in 0..10 {
            let mut snap = super::super::capture_compact();
            snap.timestamp_ms = i;
            history.push(snap);
        }
        assert_eq!(history.len(), 4);
        let series = history.recent_series(2, None);
        assert_eq!(series.timestamps, vec![8, 9]);
    }

    #[test]
    fn series_projects_used_slots_and_filters_subsystem() {
        let dns = SUBSYSTEMS.iter().position(|s| *s == "dns").unwrap();
        let fw = SUBSYSTEMS.iter().position(|s| *s == "firewall").unwrap();

        let mut snap = CompactSnapshot::zeroed(1000);
        snap.set_slot(
            dns,
            SlotCounters {
                allocated_bytes: 10,
                freed_bytes: 4,
                live_bytes: 6,
                alloc_events: 1,
                free_events: 1,
            },
        );
        snap.set_slot(
            fw,
            SlotCounters {
                allocated_bytes: 3,
                freed_bytes: 1,
                live_bytes: 2,
                alloc_events: 1,
                free_events: 0,
            },
        );
        let mut snap2 = CompactSnapshot::zeroed(2000);
        snap2.set_slot(
            dns,
            SlotCounters {
                allocated_bytes: 20,
                freed_bytes: 5,
                live_bytes: 15,
                alloc_events: 2,
                free_events: 1,
            },
        );

        let all = build_series(&[snap.clone(), snap2.clone()], None);
        assert_eq!(all.timestamps, vec![1000, 2000]);
        // 只输出曾非零的槽位(dns/firewall),其余 24 个空槽被过滤。
        assert_eq!(all.series.len(), 2);
        let dns_series = all.series.iter().find(|s| s.subsystem == "dns").unwrap();
        assert_eq!(
            dns_series.points,
            vec![SlotPoint([10, 4, 6, 1, 1]), SlotPoint([20, 5, 15, 2, 1])]
        );
        let fw_series = all.series.iter().find(|s| s.subsystem == "firewall").unwrap();
        // 第二个快照未写 firewall,补零对齐。
        assert_eq!(fw_series.points, vec![SlotPoint([3, 1, 2, 1, 0]), SlotPoint([0; 5])]);

        let only_dns = build_series(&[snap, snap2], Some("dns"));
        assert_eq!(only_dns.series.len(), 1);
        assert_eq!(only_dns.series[0].subsystem, "dns");

        let none = build_series(&[], Some("dns"));
        assert!(none.series.is_empty());
        assert!(none.timestamps.is_empty());
    }
}

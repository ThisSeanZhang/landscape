//! 1 秒级 RAM 环形缓冲:最近 N 个快照,服务 `/api/v1/system/memory` 的
//! 实时/近期查询;分钟级历史走 MetricEngine 的持久化链路,互不串门。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::registry::{CompactSnapshot, MemorySnapshot};
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
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity.min(4096)))),
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

    /// 取最近 `limit` 个快照(时间升序)。`limit = 0` 返回全部。
    pub fn recent(&self, limit: usize) -> Vec<MemorySnapshot> {
        let guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if limit == 0 || limit >= guard.len() {
            guard.iter().map(|compact| compact.to_snapshot()).collect()
        } else {
            guard.iter().skip(guard.len() - limit).map(|compact| compact.to_snapshot()).collect()
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 启动周期采样任务,返回共享环形缓冲。任务随运行时关闭而结束。
pub fn start_sampler() -> MemoryHistory {
    start_sampler_with(DEFAULT_SAMPLE_INTERVAL, DEFAULT_CAPACITY)
}

/// 自定义周期与容量的变体(测试用)。
pub fn start_sampler_with(interval: Duration, capacity: usize) -> MemoryHistory {
    let history = MemoryHistory::new(capacity.max(1));
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
    use super::*;

    #[tokio::test]
    async fn sampler_fills_ring_buffer() {
        let history = start_sampler_with(Duration::from_millis(5), 16);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while history.is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "sampler never produced a sample");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let samples = history.recent(0);
        assert_eq!(samples.len(), history.len());
        assert!(!samples[0].modules.is_empty());
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
        let recent = history.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].timestamp_ms, 8);
        assert_eq!(recent[1].timestamp_ms, 9);
    }
}

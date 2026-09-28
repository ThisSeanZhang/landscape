//! 静态子系统注册表:固定槽位 + 无锁原子计数器,分配器热路径零加锁。

use std::sync::atomic::{AtomicU64, Ordering};

use crate::utils::time::now_ms;

/// 子系统标签。索引即槽位 ID,`UNATTRIBUTED` 为兜底槽位(未打标任务、启动
/// 早期分配)。入库与 API 按名称存储,追加新条目时保持已有顺序稳定。
pub const SUBSYSTEMS: &[&str] = &[
    "dns",
    "gateway",
    "firewall",
    "nat",
    "route",
    "metric",
    "geo",
    "docker",
    "wifi",
    "wan",
    "lan",
    "pppoe",
    "cert",
    "webserver",
    "event",
    "ebpf",
    "time",
    "dump",
    "pty",
    "service",
    "netlink",
    "flow",
    "arp",
    "sys",
    "unattributed",
];

pub const UNATTRIBUTED: usize = SUBSYSTEMS.len() - 1;

/// 单个子系统槽位的计数器组。
#[derive(Default)]
pub(crate) struct SubsystemCounters {
    pub(crate) allocated_bytes: AtomicU64,
    pub(crate) freed_bytes: AtomicU64,
    pub(crate) alloc_events: AtomicU64,
    pub(crate) free_events: AtomicU64,
}

#[derive(Default)]
pub(crate) struct Registry {
    slots: [SubsystemCounters; SUBSYSTEMS.len()],
}

static REGISTRY: Registry = Registry {
    slots: [const {
        SubsystemCounters {
            allocated_bytes: AtomicU64::new(0),
            freed_bytes: AtomicU64::new(0),
            alloc_events: AtomicU64::new(0),
            free_events: AtomicU64::new(0),
        }
    }; SUBSYSTEMS.len()],
};

impl Registry {
    pub(crate) fn get(&self, index: usize) -> &SubsystemCounters {
        &self.slots[index.min(UNATTRIBUTED)]
    }
}

impl SubsystemCounters {
    #[inline]
    pub(crate) fn record_alloc(&self, bytes: usize) {
        self.allocated_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.alloc_events.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn record_free(&self, bytes: usize) {
        self.freed_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.free_events.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn registry() -> &'static Registry {
    &REGISTRY
}

pub(crate) fn record_alloc(tag: usize, bytes: usize) {
    REGISTRY.get(tag).record_alloc(bytes);
}

pub(crate) fn record_free(tag: usize, bytes: usize) {
    REGISTRY.get(tag).record_free(bytes);
}

impl Registry {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &SubsystemCounters> {
        self.slots.iter()
    }
}

/// 按槽位 ID 取子系统名称;越界回落到 unattributed。
pub fn subsystem_label(index: usize) -> &'static str {
    SUBSYSTEMS.get(index.min(UNATTRIBUTED)).copied().unwrap_or("unattributed")
}

/// 子系统累计值(快照的单项)。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ModuleMemStat {
    pub subsystem: String,
    pub allocated_bytes: u64,
    pub freed_bytes: u64,
    /// allocated - freed。计数模式下为估算值(见模块文档);精确模式精确。
    pub live_bytes: u64,
    pub alloc_events: u64,
    pub free_events: u64,
}

/// 进程级校准信息。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SnapshotMeta {
    pub process_rss_bytes: Option<u64>,
    pub process_virtual_bytes: Option<u64>,
    pub total_live_bytes: u64,
    /// RSS − Σ(live):正值为分配器外开销(元数据/碎片/线程栈),负值为
    /// 尚未触碰或已归还操作系统的页。
    pub untracked_bytes: Option<i64>,
}

/// 一次全量快照。
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemorySnapshot {
    pub timestamp_ms: u64,
    /// 是否为精确模式(feature `mem-track-precise`)。
    pub precise: bool,
    pub meta: SnapshotMeta,
    pub modules: Vec<ModuleMemStat>,
}

impl MemorySnapshot {
    pub fn timestamp(&self) -> u64 {
        if self.timestamp_ms == 0 {
            now_ms()
        } else {
            self.timestamp_ms
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsystem_label_bounds() {
        assert_eq!(subsystem_label(0), "dns");
        assert_eq!(subsystem_label(UNATTRIBUTED), "unattributed");
        assert_eq!(subsystem_label(usize::MAX), "unattributed");
    }

    #[test]
    fn record_counters_by_tag() {
        // 用其它测试不占用的槽位(time)做差值精确断言:全局计数器被同二进制
        // 内并行运行的分配器测试共享,绝对值断言或重置操作都会互相干扰。
        let slot = SUBSYSTEMS.iter().position(|s| *s == "time").unwrap();
        let counters = registry().get(slot);
        let alloc_before = counters.allocated_bytes.load(Ordering::Relaxed);
        let freed_before = counters.freed_bytes.load(Ordering::Relaxed);
        let alloc_events_before = counters.alloc_events.load(Ordering::Relaxed);
        let free_events_before = counters.free_events.load(Ordering::Relaxed);

        record_alloc(slot, 100);
        record_alloc(slot, 28);
        record_free(slot, 50);

        assert_eq!(counters.allocated_bytes.load(Ordering::Relaxed) - alloc_before, 128);
        assert_eq!(counters.freed_bytes.load(Ordering::Relaxed) - freed_before, 50);
        assert_eq!(counters.alloc_events.load(Ordering::Relaxed) - alloc_events_before, 2);
        assert_eq!(counters.free_events.load(Ordering::Relaxed) - free_events_before, 1);
    }
}

//! 静态子系统注册表:固定槽位 + 无锁原子计数器,分配器热路径零加锁。

use std::sync::atomic::{AtomicU64, Ordering};

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
    "pppd",
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
    SUBSYSTEMS[index.min(UNATTRIBUTED)]
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

/// 单个槽位的计数器快照值。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotCounters {
    pub allocated_bytes: u64,
    pub freed_bytes: u64,
    pub live_bytes: u64,
    pub alloc_events: u64,
    pub free_events: u64,
}

impl From<SlotCounters> for SlotPoint {
    fn from(counters: SlotCounters) -> Self {
        SlotPoint([
            counters.allocated_bytes,
            counters.freed_bytes,
            counters.live_bytes,
            counters.alloc_events,
            counters.free_events,
        ])
    }
}

/// 位置数组形式的槽位快照点:JSON 为
/// `[allocated_bytes, freed_bytes, live_bytes, alloc_events, free_events]`。
///
/// 用位置数组而非命名字段对象是为了在批量历史里显著压缩 JSON 体积
/// (字段名不再逐点重复),字段顺序即契约,勿调整。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct SlotPoint(pub [u64; 5]);

/// 单个子系统的一段共享时间轴取值序列。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SubsystemSeries {
    pub subsystem: String,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<Vec<u64>>))]
    pub points: Vec<SlotPoint>,
}

/// RAM 环形缓冲历史的批量响应:所有 series 共享一条 `timestamps` 轴,
/// 缺失时刻按位置数组补零对齐。`precise`/`meta` 为进程级信息(内存历史
/// 恒有值;SQLite 分钟历史复用同一形状但置 `None`)。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemorySeriesResponse {
    pub timestamps: Vec<u64>,
    pub precise: Option<bool>,
    pub meta: Option<Vec<SnapshotMeta>>,
    pub series: Vec<SubsystemSeries>,
}

/// 紧凑快照:槽位定长计数器数组,无 String/Vec 堆分配,供采样热路径
/// (RAM 环形缓冲、分钟聚合)使用;仅在 API 查询边界才转换为响应类型。
#[derive(Clone, Debug)]
pub struct CompactSnapshot {
    pub timestamp_ms: u64,
    pub precise: bool,
    pub meta: SnapshotMeta,
    /// 顺序同 SUBSYSTEMS。
    pub(crate) stats: [SlotCounters; SUBSYSTEMS.len()],
}

impl CompactSnapshot {
    /// 全零快照(测试构造用)。
    pub fn zeroed(timestamp_ms: u64) -> Self {
        CompactSnapshot {
            timestamp_ms,
            precise: false,
            meta: SnapshotMeta::default(),
            stats: [SlotCounters::default(); SUBSYSTEMS.len()],
        }
    }

    pub fn set_slot(&mut self, slot: usize, counters: SlotCounters) {
        if let Some(dst) = self.stats.get_mut(slot) {
            *dst = counters;
        }
    }

    /// 越界回落到 unattributed 槽位。
    pub fn counters(&self, slot: usize) -> SlotCounters {
        self.stats[slot.min(UNATTRIBUTED)]
    }

    /// 遍历全部槽位,调用方自行过滤全零槽位。
    pub fn iter_slots(&self) -> impl Iterator<Item = (usize, SlotCounters)> + '_ {
        self.stats.iter().enumerate().map(|(slot, counters)| (slot, *counters))
    }

    pub fn to_snapshot(&self) -> MemorySnapshot {
        let modules = SUBSYSTEMS
            .iter()
            .zip(self.stats.iter())
            .map(|(name, c)| ModuleMemStat {
                subsystem: (*name).to_string(),
                allocated_bytes: c.allocated_bytes,
                freed_bytes: c.freed_bytes,
                live_bytes: c.live_bytes,
                alloc_events: c.alloc_events,
                free_events: c.free_events,
            })
            .collect();
        MemorySnapshot {
            timestamp_ms: self.timestamp_ms,
            precise: self.precise,
            meta: self.meta.clone(),
            modules,
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
    fn compact_snapshot_slots_and_conversion() {
        let mut compact = CompactSnapshot::zeroed(42);
        compact.set_slot(
            0,
            SlotCounters {
                allocated_bytes: 100,
                freed_bytes: 40,
                live_bytes: 60,
                alloc_events: 7,
                free_events: 5,
            },
        );
        assert_eq!(compact.counters(0).live_bytes, 60);
        assert_eq!(compact.counters(usize::MAX), SlotCounters::default());
        assert_eq!(compact.iter_slots().count(), SUBSYSTEMS.len());

        let snapshot = compact.to_snapshot();
        assert_eq!(snapshot.timestamp_ms, 42);
        assert_eq!(snapshot.modules.len(), SUBSYSTEMS.len());
        assert_eq!(snapshot.modules[0].subsystem, "dns");
        assert_eq!(snapshot.modules[0].live_bytes, 60);
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

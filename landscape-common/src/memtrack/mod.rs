//! 进程内按子系统的堆内存记账。
//!
//! `CountingAllocator`(全局分配器包装)在 alloc/dealloc 时读取当前线程的
//! 归属标签(见 [`tag`]),累加到 [`registry`] 对应子系统槽位;标签由
//! `spawn_task`/专用线程启动时设置,映射规则见 [`mapping`]。
//!
//! 仅在显式开启 feature `mem-track` 时统计:分配附加 32 字节头部记录
//! owner,dealloc 按真实归属扣减,各子系统 live 精确。未开启时分配器为
//! `System` 纯透传,零开销、不计数,各子系统计数恒为零。
//!
//! Σ(子系统 live) ≠ 进程 RSS(元数据/碎片/线程栈/C 库堆),差值在快照中
//! 以 `untracked_bytes` 明示,其构成拆解见 [`composition`]。

pub mod allocator;
pub mod composition;
pub mod mapping;
pub mod registry;
pub mod sampler;
pub mod tag;

pub use allocator::CountingAllocator;
pub use composition::MemoryComposition;
pub use mapping::{subsystem_from_task_label, subsystem_from_thread_name};
pub use registry::{
    CompactSnapshot, MemorySeriesResponse, MemorySnapshot, ModuleMemStat, SUBSYSTEMS, SlotCounters,
    SlotPoint, SnapshotMeta, SubsystemSeries, UNATTRIBUTED, subsystem_label,
};
pub use sampler::{MemoryHistory, start_sampler, start_sampler_with};
pub use tag::{TaggedFuture, with_tag};

use registry::registry;
use std::sync::atomic::Ordering;

/// 采集紧凑快照,供采样热路径(RAM 环形缓冲、分钟聚合)使用。注册表扫描
/// 无堆分配;Linux 上 statm 读取会经 read_to_string 产生一次小额分配。
/// 不计算 RSS 构成(见 [`composition`],由 API 查询边界按需补充)。
pub fn capture_compact() -> CompactSnapshot {
    let mut stats = [SlotCounters::default(); SUBSYSTEMS.len()];
    for (index, counters) in registry().iter().enumerate() {
        let allocated = counters.allocated_bytes.load(Ordering::Relaxed);
        let freed = counters.freed_bytes.load(Ordering::Relaxed);
        let live = allocated.saturating_sub(freed);
        stats[index] = SlotCounters {
            allocated_bytes: allocated,
            freed_bytes: freed,
            live_bytes: live,
            alloc_events: counters.alloc_events.load(Ordering::Relaxed),
            free_events: counters.free_events.load(Ordering::Relaxed),
        };
    }

    let total_live = global_live_bytes(&stats);
    let (virtual_bytes, rss_bytes) = read_proc_statm();
    let untracked_bytes = rss_bytes.map(|rss| {
        // RSS 与分配器视角的差值:RSS 更小(未触碰页/已归还)为负,更大为开销。
        rss as i64 - total_live as i64
    });

    CompactSnapshot {
        timestamp_ms: crate::utils::time::now_ms(),
        enabled: cfg!(feature = "mem-track"),
        meta: SnapshotMeta {
            process_rss_bytes: rss_bytes,
            process_virtual_bytes: virtual_bytes,
            total_live_bytes: total_live,
            untracked_bytes,
            composition: None,
        },
        stats,
    }
}

fn global_live_bytes(stats: &[SlotCounters]) -> u64 {
    let (allocated, freed) = stats.iter().fold((0u128, 0u128), |(allocated, freed), slot| {
        (allocated + slot.allocated_bytes as u128, freed + slot.freed_bytes as u128)
    });
    allocated.saturating_sub(freed).min(u64::MAX as u128) as u64
}

/// API 查询边界用的全量快照:在紧凑快照之上按需计算 RSS 构成分桶
/// (smaps 解析 + mallinfo2,仅 Linux;热路径采样不含构成);采样热路径
/// 走 [`capture_compact`]。
pub fn snapshot() -> MemorySnapshot {
    let mut compact = capture_compact();
    let live_alloc_events: u64 = compact
        .iter_slots()
        .map(|(_, counters)| counters.alloc_events.saturating_sub(counters.free_events))
        .sum();
    if let Some(composition) =
        composition::build_composition(compact.meta.total_live_bytes, live_alloc_events)
    {
        compact.meta.composition = Some(composition);
    }
    compact.to_snapshot()
}

/// 读取 `/proc/self/statm`(单位:页)返回 `(VmSize, VmRSS)` 字节。
#[cfg(target_os = "linux")]
fn read_proc_statm() -> (Option<u64>, Option<u64>) {
    use std::sync::OnceLock;
    static PAGE_SIZE: OnceLock<u64> = OnceLock::new();
    let page_size =
        *PAGE_SIZE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64);

    let Ok(content) = std::fs::read_to_string("/proc/self/statm") else {
        return (None, None);
    };
    let mut fields = content.split_whitespace();
    let virtual_pages = fields.next().and_then(|v| v.parse::<u64>().ok());
    let rss_pages = fields.next().and_then(|v| v.parse::<u64>().ok());
    (
        virtual_pages.map(|p| p.saturating_mul(page_size)),
        rss_pages.map(|p| p.saturating_mul(page_size)),
    )
}

#[cfg(not(target_os = "linux"))]
fn read_proc_statm() -> (Option<u64>, Option<u64>) {
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_live_subtracts_frees_after_summing_subsystems() {
        let stats = [
            SlotCounters {
                allocated_bytes: 100,
                live_bytes: 100,
                freed_bytes: 0,
                ..Default::default()
            },
            SlotCounters {
                allocated_bytes: 0,
                freed_bytes: 60,
                ..Default::default()
            },
        ];

        assert_eq!(global_live_bytes(&stats), 40);
        assert_eq!(stats.iter().map(|slot| slot.live_bytes).sum::<u64>(), 100);
    }

    #[test]
    fn snapshot_covers_all_subsystems_and_meta() {
        // 测试二进制未安装全局分配器,显式经过 CountingAllocator;仅在
        // mem-track 开启时计数非零,未开启时纯透传、不计数。全局计数被同
        // 二进制内并行测试共享,只能断言本测试独占槽位(0)的差值。
        use std::alloc::{GlobalAlloc, Layout};
        use std::sync::atomic::Ordering::Relaxed;
        let slot0_before = registry().get(0).allocated_bytes.load(Relaxed);
        let layout = Layout::from_size_align(128, 8).unwrap();
        let ptr = super::tag::with_tag(0, || unsafe {
            super::allocator::CountingAllocator.alloc(layout)
        });
        assert!(!ptr.is_null());

        let snap = snapshot();
        assert_eq!(snap.modules.len(), SUBSYSTEMS.len());
        assert_eq!(snap.modules[UNATTRIBUTED].subsystem, "unattributed");
        assert_eq!(snap.enabled, cfg!(feature = "mem-track"));
        let slot0_after = registry().get(0).allocated_bytes.load(Relaxed);
        if cfg!(feature = "mem-track") {
            assert!(slot0_after > slot0_before);
            assert!(snap.meta.total_live_bytes > 0);
        } else {
            assert_eq!(slot0_after, slot0_before);
        }
        // API 查询边界按需计算 RSS 构成(仅 Linux 有值)。
        if cfg!(target_os = "linux") {
            assert!(snap.meta.composition.is_some());
        }

        unsafe { super::allocator::CountingAllocator.dealloc(ptr, layout) };
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn statm_reports_nonzero_rss() {
        let (vsize, rss) = read_proc_statm();
        assert!(vsize.unwrap_or(0) > 0);
        assert!(rss.unwrap_or(0) > 0);
    }
}

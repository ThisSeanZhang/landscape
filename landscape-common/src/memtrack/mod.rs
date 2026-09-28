//! 进程内按子系统的堆内存记账。
//!
//! `CountingAllocator`(全局分配器包装)在 alloc/dealloc 时读取当前线程的
//! 归属标签(见 [`tag`]),累加到 [`registry`] 对应子系统槽位;标签由
//! `spawn_task`/专用线程启动时设置,映射规则见 [`mapping`]。
//!
//! - 默认计数模式:仅原子累加,开销约 1~3%;跨子系统传递后由他处 drop 的
//!   内存 live 估算可能漂移(流量准确,全局总 live 精确)。
//! - feature `mem-track-precise`:分配附加 32 字节头部记录 owner,dealloc
//!   按真实 owner 扣减,各子系统 live 精确。
//!
//! Σ(子系统 live) ≠ 进程 RSS(元数据/碎片/线程栈),差值在快照中以
//! `untracked_bytes` 明示。

pub mod allocator;
pub mod mapping;
pub mod registry;
pub mod sampler;
pub mod tag;

pub use allocator::CountingAllocator;
pub use mapping::{subsystem_from_task_label, subsystem_from_thread_name};
pub use registry::{
    subsystem_label, CompactSnapshot, MemorySeriesResponse, MemorySnapshot, ModuleMemStat,
    SlotCounters, SlotPoint, SnapshotMeta, SubsystemSeries, SUBSYSTEMS, UNATTRIBUTED,
};
pub use sampler::{start_sampler, start_sampler_with, MemoryHistory};
pub use tag::{with_tag, TaggedFuture};

use registry::registry;
use std::sync::atomic::Ordering;

/// 采集紧凑快照,供采样热路径(RAM 环形缓冲、分钟聚合)使用。注册表扫描
/// 无堆分配;Linux 上 statm 读取会经 read_to_string 产生一次小额分配。
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
        precise: cfg!(feature = "mem-track-precise"),
        meta: SnapshotMeta {
            process_rss_bytes: rss_bytes,
            process_virtual_bytes: virtual_bytes,
            total_live_bytes: total_live,
            untracked_bytes,
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

/// API 查询边界用的全量快照;采样热路径走 [`capture_compact`]。
pub fn snapshot() -> MemorySnapshot {
    capture_compact().to_snapshot()
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
        // 测试二进制未安装全局分配器,显式经过 CountingAllocator 保证计数非零。
        use std::alloc::{GlobalAlloc, Layout};
        let layout = Layout::from_size_align(128, 8).unwrap();
        let ptr = super::tag::with_tag(0, || unsafe {
            super::allocator::CountingAllocator.alloc(layout)
        });
        assert!(!ptr.is_null());

        let snap = snapshot();
        assert_eq!(snap.modules.len(), SUBSYSTEMS.len());
        assert_eq!(snap.modules[UNATTRIBUTED].subsystem, "unattributed");
        assert!(snap.meta.total_live_bytes > 0);

        unsafe { super::allocator::CountingAllocator.dealloc(ptr, layout) };
        assert!(snap.precise == cfg!(feature = "mem-track-precise"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn statm_reports_nonzero_rss() {
        let (vsize, rss) = read_proc_statm();
        assert!(vsize.unwrap_or(0) > 0);
        assert!(rss.unwrap_or(0) > 0);
    }
}

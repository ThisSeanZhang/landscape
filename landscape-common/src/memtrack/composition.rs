//! RSS 构成统计:把“未归属差额”(RSS − Σ 子系统 live)拆成可解释的分桶。
//!
//! 数据源(均为按需读取,不在采样热路径):
//! - `/proc/self/smaps`:按 VMA 归类 —— `[heap]`(brk 堆)、`[stack:tid]`
//!   (线程栈)、有路径名的映射(代码/动态库/数据文件)、其余匿名映射
//!   (malloc arena 的 mmap 区、libbpf mmap 的 map 等)。四桶之和 ≈ RSS。
//! - glibc `mallinfo2()`(仅 gnu 目标):`uordblks` 为 malloc in-use 总量
//!   (Rust 堆与 SQLite 等 C 堆同源),`fordblks` 为已释放但被 malloc 保留
//!   的量。由此估算 C 堆占用与碎片保留。musl 无此接口,对应字段为 None。
//!
//! 非 Linux 平台整体返回 None,调用方自然降级。

/// RSS 构成分桶 + malloc 视角拆分。全部为“尽力而为”的估算值,用于解释
/// `untracked_bytes` 的去向,不求精确到字节。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemoryComposition {
    /// `[heap]` VMA 的 RSS(glibc brk 堆)。
    pub heap_rss_bytes: u64,
    /// 全部 `[stack:tid]` VMA 的 RSS(线程栈已触碰页)。
    pub thread_stacks_rss_bytes: u64,
    /// 文件映射 RSS(二进制代码、动态库、mmap 的数据文件)。
    pub file_backed_rss_bytes: u64,
    /// 其余匿名映射 RSS(malloc arena 的 mmap 区、libbpf mmap 的 map 等)。
    pub other_anon_rss_bytes: u64,
    /// malloc in-use 总量(Rust 堆 + SQLite 等 C 堆同源;仅 glibc, musl 为 None)。
    pub malloc_in_use_bytes: Option<u64>,
    /// malloc 已保留的空闲量(已释放未归还 OS,即碎片/保留;仅 glibc)。
    pub malloc_free_held_bytes: Option<u64>,
    /// mem-track 头部开销估算(存活分配事件 × 32B;未启用跟踪为 0)。
    pub header_overhead_bytes: Option<u64>,
    /// C 库堆估算 = malloc in-use − Σ(live) − 头开销(SQLite 等;仅 glibc)。
    pub c_heap_estimated_bytes: Option<u64>,
}

impl MemoryComposition {
    /// smaps 四桶合计(≈ RSS,交叉校验用)。
    pub fn total_rss_bytes(&self) -> u64 {
        self.heap_rss_bytes
            .saturating_add(self.thread_stacks_rss_bytes)
            .saturating_add(self.file_backed_rss_bytes)
            .saturating_add(self.other_anon_rss_bytes)
    }
}

/// 解析 `/proc/self/smaps`,按 VMA 归类统计 RSS。
///
/// 测试通过 `parse_smaps` 传入样例文本,生产路径读取真实文件。
pub(crate) fn read_smaps_buckets() -> Option<MemoryComposition> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/self/smaps").ok()?;
        parse_smaps(&content).finish()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// smaps 解析的累加器:VMA header 行归类,`Rss:` 行累加到当前桶。
#[derive(Default)]
struct SmapsAccumulator {
    heap_rss: u64,
    thread_stacks_rss: u64,
    file_backed_rss: u64,
    other_anon_rss: u64,
    current: Option<&'static str>,
}

impl SmapsAccumulator {
    /// VMA header 行格式:`<start>-<end> <perms> <offset> <dev> <inode> [pathname]`,
    /// pathname 可能含空格(smaps 规定不转义),因此按空白切分后取第 6 个字段
    /// 起的剩余部分拼接。第 7 列及以后(kernel 5.11+ 新增的 `VmFlags` 前的
    /// 附加字段除外)不属于路径,这里只依据“第 6 字段是否存在”归类,足够。
    fn begin_vma(&mut self, header: &str) {
        let mut fields = header.split_whitespace();
        for _ in 0..5 {
            fields.next();
        }
        let pathname = fields.next().unwrap_or("");
        self.current = Some(match pathname {
            "" => "other_anon",
            "[heap]" => "heap",
            p if p.starts_with("[stack") => "thread_stacks",
            // [vvar]/[vdso]/[vsyscall] 等内核伪映射,量级 KB 内,并入匿名。
            p if p.starts_with('[') => "other_anon",
            _ => "file_backed",
        });
    }

    fn add_rss(&mut self, kb: u64) {
        let bucket = match self.current {
            Some("heap") => &mut self.heap_rss,
            Some("thread_stacks") => &mut self.thread_stacks_rss,
            Some("file_backed") => &mut self.file_backed_rss,
            _ => &mut self.other_anon_rss,
        };
        *bucket = bucket.saturating_add(kb.saturating_mul(1024));
    }

    fn finish(self) -> Option<MemoryComposition> {
        Some(MemoryComposition {
            heap_rss_bytes: self.heap_rss,
            thread_stacks_rss_bytes: self.thread_stacks_rss,
            file_backed_rss_bytes: self.file_backed_rss,
            other_anon_rss_bytes: self.other_anon_rss,
            ..MemoryComposition::default()
        })
    }
}

/// 解析 smaps 文本(模块内使用,测试直接调用)。
fn parse_smaps(content: &str) -> SmapsAccumulator {
    let mut acc = SmapsAccumulator::default();
    for line in content.lines() {
        // VMA header 行首字段形如 `7f00a000-7f00b000`(十六进制地址区间);
        // 字段行("Size:" 等)首字段含 ':' 或不含 '-'。
        let is_vma_header = line
            .split_whitespace()
            .next()
            .is_some_and(|first| first.contains('-') && !first.contains(':'));
        if is_vma_header {
            acc.begin_vma(line);
        } else if let Some(kb) = line
            .strip_prefix("Rss:")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
        {
            acc.add_rss(kb);
        }
    }
    acc
}

/// glibc `mallinfo2`:`uordblks`(in-use,含 Rust 堆与 C 堆)/ `fordblks`
/// (free 但被 malloc 保留)。musl 与非 Linux 无此接口。
pub(crate) fn read_mallinfo2() -> Option<(u64, u64)> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // mallinfo2 遍历全部 arena 需持锁,仅在 API 查询边界调用(3s 级频率),
        // 开销可接受。
        let info = unsafe { libc::mallinfo2() };
        Some((info.uordblks as u64, info.fordblks as u64))
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        None
    }
}

/// 组装完整构成:在 smaps 四桶之上叠加 mallinfo2 拆分与派生量。
///
/// - `header_overhead_bytes`:mem-track 开启时按“存活分配事件 × 32B 头”估算。
/// - `c_heap_estimated_bytes`:malloc in-use − Σ(live) − 头开销 ≈ SQLite 等
///   C 库堆(saturating,统计口径差异可能为负归零)。
pub(crate) fn build_composition(
    total_live_bytes: u64,
    live_alloc_events: u64,
) -> Option<MemoryComposition> {
    let mut composition = read_smaps_buckets()?;

    if let Some((in_use, free_held)) = read_mallinfo2() {
        let header_overhead =
            if cfg!(feature = "mem-track") { live_alloc_events.saturating_mul(32) } else { 0 };
        let rust_tracked = total_live_bytes.saturating_add(header_overhead);
        composition.malloc_in_use_bytes = Some(in_use);
        composition.malloc_free_held_bytes = Some(free_held);
        composition.header_overhead_bytes = Some(header_overhead);
        composition.c_heap_estimated_bytes = Some(in_use.saturating_sub(rust_tracked));
    }
    Some(composition)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
7f0000000000-7f0000001000 rw-p 00000000 00:01 1234 /usr/lib/libfoo.so
Size:                  4 kB
Rss:                   2 kB
7f0000001000-7f0000002000 rw-p 00000000 00:00 0
Size:                  4 kB
Rss:                   3 kB
7f0000002000-7f0000003000 rw-p 00000000 00:00 0 [heap]
Size:                  4 kB
Rss:                   5 kB
7f0000004000-7f0000005000 rw-p 00000000 00:00 0 [stack:4212]
Size:                  8 kB
Rss:                   7 kB
7f0000006000-7f0000007000 rw-p 00000000 00:00 0 [vdso]
Size:                  4 kB
Rss:                   1 kB
7f0000008000-7f0000009000 rw-p 00000000 00:01 5678 /path/with space/bin
Size:                  4 kB
Rss:                   4 kB
";

    #[test]
    fn smaps_sample_is_bucketed() {
        let composition = parse_smaps(SAMPLE).finish().unwrap();
        assert_eq!(composition.heap_rss_bytes, 5 * 1024);
        assert_eq!(composition.thread_stacks_rss_bytes, 7 * 1024);
        // 两个文件映射(含带空格路径):2 + 4 KiB。
        assert_eq!(composition.file_backed_rss_bytes, 6 * 1024);
        // 匿名 3 KiB + [vdso] 1 KiB。
        assert_eq!(composition.other_anon_rss_bytes, 4 * 1024);
    }

    #[test]
    fn composition_without_mallinfo_keeps_buckets() {
        // build_composition 在 mallinfo2 不可用(musl/非 gnu)时仍返回四桶;
        // gnu 环境下 mallinfo 字段有值,断言二选一。
        let composition = build_composition(1000, 10);
        assert!(composition.is_some());
        let composition = composition.unwrap();
        assert!(composition.heap_rss_bytes <= composition.total_rss_bytes());
        if cfg!(all(target_os = "linux", target_env = "gnu")) {
            assert!(composition.malloc_in_use_bytes.is_some());
            assert!(composition.malloc_free_held_bytes.is_some());
        } else {
            assert!(composition.malloc_in_use_bytes.is_none());
        }
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn mallinfo2_reports_nonnegative() {
        let (in_use, free_held) = read_mallinfo2().unwrap();
        // 测试进程已有堆分配,in-use 必为正;free-held可能为 0。
        assert!(in_use > 0);
        let _ = free_held;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_smaps_buckets_match_statm_within_noise() {
        let composition = read_smaps_buckets().unwrap();
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
        let content = std::fs::read_to_string("/proc/self/statm").unwrap();
        let rss: u64 = content
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok())
            .map(|pages| pages.saturating_mul(page_size))
            .unwrap_or(0);
        assert!(rss > 0);
        // 测试二进制内并行测试持续分配,两次 procfs 读取之间 RSS 可变;断言
        // 只保证分桶与 RSS 同数量级(健全性检查,非精确等式)。
        let total = composition.total_rss_bytes();
        let slack = rss / 2;
        assert!(total + slack >= rss && total <= rss + slack, "total={total} rss={rss}");
    }
}

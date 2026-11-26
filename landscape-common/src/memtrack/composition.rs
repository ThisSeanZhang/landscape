//! 按需读取 smaps 的 RSS/PSS 和 glibc 分配器统计。
//! RSS 分桶可以相加；malloc 是重叠的分配器视角，不能与 RSS 相加。
//! BPF ringbuf 的数据页双重映射会重复计入 RSS；PSS 按映射分摊共享页。

/// RSS 分桶、PSS 与独立的 malloc 视角。不是内核 BPF 总内存统计。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemoryComposition {
    /// `[heap]` VMA 的 RSS(glibc brk 堆)。
    pub heap_rss_bytes: u64,
    /// 可识别的 `[stack]` / `[stack:tid]` RSS；未命名线程栈归入匿名映射。
    pub thread_stacks_rss_bytes: u64,
    /// 文件映射 RSS(二进制代码、动态库、mmap 的数据文件)。
    pub file_backed_rss_bytes: u64,
    /// BPF map 映射 RSS，含 ringbuf 双重映射造成的重复计数。
    #[serde(default)]
    pub bpf_rss_bytes: u64,
    /// 全进程 PSS，共享物理页按映射数分摊，不等于独占内存。
    pub pss_bytes: Option<u64>,
    /// BPF map 映射 PSS，不包括未映射进程的内核 map 内存。
    pub bpf_pss_bytes: Option<u64>,
    /// 其余匿名映射 RSS(malloc arena、未命名线程栈等)。
    pub other_anon_rss_bytes: u64,
    /// malloc in-use 总量(Rust 堆 + SQLite 等 C 堆同源;仅 glibc, musl 为 None)。
    pub malloc_in_use_bytes: Option<u64>,
    /// malloc 已保留的空闲量(已释放未归还 OS,即碎片/保留;仅 glibc)。
    pub malloc_free_held_bytes: Option<u64>,
    /// mem-track 头部开销估算(存活分配事件 × 32B;未启用跟踪为 None)。
    pub header_overhead_bytes: Option<u64>,
    /// 分配器差额估算，含 C 分配、对齐和统计时差；不能精确归属 C 库。
    /// 保留字段名兼容 API；未启用 mem-track 时为 None。
    pub c_heap_estimated_bytes: Option<u64>,
}

impl MemoryComposition {
    /// smaps RSS 分桶合计(≈ RSS,交叉校验用)。
    pub fn total_rss_bytes(&self) -> u64 {
        self.heap_rss_bytes
            .saturating_add(self.thread_stacks_rss_bytes)
            .saturating_add(self.file_backed_rss_bytes)
            .saturating_add(self.other_anon_rss_bytes)
            .saturating_add(self.bpf_rss_bytes)
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
    bpf_rss: u64,
    pss: Option<u64>,
    bpf_pss: u64,
    current: Option<&'static str>,
}

impl SmapsAccumulator {
    /// 路径从第六个字段开始；分类只需路径前缀。
    fn begin_vma(&mut self, header: &str) {
        let mut fields = header.split_whitespace();
        for _ in 0..5 {
            fields.next();
        }
        let pathname = fields.next().unwrap_or("");
        self.current = Some(match pathname {
            "" => "other_anon",
            p if p.starts_with("anon_inode:bpf-map") => "bpf",
            p if p.starts_with("anon_inode:") => "other_anon",
            "[heap]" => "heap",
            p if p.starts_with("[stack") => "thread_stacks",
            // [vvar]/[vdso]/[vsyscall] 等内核伪映射,量级 KB 内,并入匿名。
            p if p.starts_with('[') => "other_anon",
            _ => "file_backed",
        });
    }

    fn add_rss(&mut self, kb: u64) {
        let bucket = match self.current {
            Some("bpf") => &mut self.bpf_rss,
            Some("heap") => &mut self.heap_rss,
            Some("thread_stacks") => &mut self.thread_stacks_rss,
            Some("file_backed") => &mut self.file_backed_rss,
            _ => &mut self.other_anon_rss,
        };
        *bucket = bucket.saturating_add(kb.saturating_mul(1024));
    }

    fn finish(self) -> Option<MemoryComposition> {
        Some(MemoryComposition {
            bpf_rss_bytes: self.bpf_rss,
            pss_bytes: self.pss,
            bpf_pss_bytes: self.pss.map(|_| self.bpf_pss),
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
        } else if let Some(kb) = line
            .strip_prefix("Pss:")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
        {
            let bytes = kb.saturating_mul(1024);
            acc.pss = Some(acc.pss.unwrap_or(0).saturating_add(bytes));
            if acc.current == Some("bpf") {
                acc.bpf_pss = acc.bpf_pss.saturating_add(bytes);
            }
        }
    }
    acc
}

/// glibc `mallinfo2`:`uordblks + hblkhd`(arena 在用和独立 mmap 分配)/ `fordblks`
/// (free 但被 malloc 保留)。musl 与非 Linux 无此接口。
pub(crate) fn read_mallinfo2() -> Option<(u64, u64)> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // mallinfo2 遍历全部 arena 需持锁,仅在 API 查询边界调用(3s 级频率),
        // 开销可接受。
        let info = unsafe { libc::mallinfo2() };
        Some(((info.uordblks as u64).saturating_add(info.hblkhd as u64), info.fordblks as u64))
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        None
    }
}

/// 组合两个独立视角；malloc 数字包含尚未驻留的分配，不能与 RSS 相加。
/// 差额含对齐、C 分配及采样时差，不代表某个 C 库的实际占用。
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
        if cfg!(feature = "mem-track") {
            composition.header_overhead_bytes = Some(header_overhead);
            composition.c_heap_estimated_bytes = Some(in_use.saturating_sub(rust_tracked));
        }
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
    fn bpf_double_mapping_is_separate_from_files_and_has_pss() {
        let sample = "1000-3000 rw-s 00000000 00:00 0 anon_inode:bpf-map
Rss: 8 kB
Pss: 4 kB
3000-4000 rw-p 00000000 00:00 0 [anon:worker stack]
Rss: 4 kB
Pss: 4 kB
4000-5000 r-xp 00000000 08:01 123 /bin/server
Rss: 4 kB
Pss: 2 kB
";
        let comp = parse_smaps(sample).finish().unwrap();
        assert_eq!(comp.bpf_rss_bytes, 8192);
        assert_eq!(comp.bpf_pss_bytes, Some(4096));
        assert_eq!(comp.file_backed_rss_bytes, 4096);
        assert_eq!(comp.other_anon_rss_bytes, 4096);
        assert_eq!(comp.total_rss_bytes(), 16384);
        assert_eq!(comp.pss_bytes, Some(10240));
        assert_eq!(parse_smaps(SAMPLE).finish().unwrap().pss_bytes, None);
    }

    #[test]
    fn older_snapshots_without_bpf_or_pss_fields_still_deserialize() {
        let comp: MemoryComposition = serde_json::from_str(
            r#"{"heap_rss_bytes":1024,"thread_stacks_rss_bytes":0,"file_backed_rss_bytes":4096,"other_anon_rss_bytes":0}"#,
        ).unwrap();
        assert_eq!(comp.bpf_rss_bytes, 0);
        assert_eq!(comp.pss_bytes, None);
        assert_eq!(comp.bpf_pss_bytes, None);
        assert_eq!(comp.total_rss_bytes(), 5120);
    }

    #[test]
    fn composition_without_mallinfo_keeps_buckets() {
        // build_composition 在 mallinfo2 不可用(musl/非 gnu)时仍返回 RSS 分桶;
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

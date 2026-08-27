use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use hdrhistogram::Histogram;
use landscape_common::metric::dns::{DnsMetric, DnsOutcome};

#[cfg(test)]
use landscape_common::metric::dns::DnsLightweightSummaryResponse;

#[cfg(test)]
use super::dns_bucket::minute_end;
use super::dns_bucket::{
    clean_ip_string, merge_slow_pairs, merge_top_pairs, minute_start, CountTopK, DnsCounters,
    DnsSummaryParts, SlowTopK, MINUTE_MS,
};

/// DNS 内存窗口时长(5 分钟)。仅服务首页 DnsStatusCard(其默认查询范围同为 5min);
/// 仪表盘状态卡 DNSDashboard(默认 10min)直接查 DB,不走窗口。
/// 窗口纯内存:只由采集方向 ingest 驱动,不落库、不与 DB 合并,重启后为空。
pub(crate) const DNS_RECENT_WINDOW_SECS: u64 = 5 * 60;

/// 每维度每分钟桶保留的 top-k 条数;读侧跨分钟 union 后重排。
const TOP_K: usize = 20;

#[derive(Debug)]
struct DnsMinuteBucket {
    flow_id: u32,
    minute_start: u64,
    counts: DnsCounters,
    /// 仅记录有效查询(Normal/NxDomain)的 duration_ms;block/filter/error/local/hit 不计入。
    latency: Histogram<u64>,
    top_domains: CountTopK<String>,
    top_clients: CountTopK<String>,
    top_blocked: CountTopK<String>,
    slowest: SlowTopK<String>,
}

impl DnsMinuteBucket {
    fn new(flow_id: u32, minute_start: u64) -> Self {
        Self {
            flow_id,
            minute_start,
            counts: DnsCounters::default(),
            latency: Histogram::<u64>::new(3).expect("create dns latency histogram"),
            top_domains: CountTopK::new(TOP_K),
            top_clients: CountTopK::new(TOP_K),
            top_blocked: CountTopK::new(TOP_K),
            slowest: SlowTopK::new(TOP_K),
        }
    }

    fn ingest(&mut self, metric: &DnsMetric) {
        self.counts.record(metric);

        self.top_domains.record(metric.domain.clone(), 1);
        self.top_clients.record(clean_ip_string(&metric.src_ip), 1);
        if metric.status == DnsOutcome::Block {
            self.top_blocked.record(metric.domain.clone(), 1);
        }

        // 仅 Normal/NxDomain 计入延迟。注意 NxDomain 中包含大量本地/缓存秒回的查询
        // (拦截 TLD、缓存命中的 NXDOMAIN、被类型过滤且缓存为 NXDOMAIN 的查询等),
        // 其耗时通常为 0~1ms,0ms 会被上方 max(1) 钳为 1ms;当这类查询在窗口内占多数时,
        // p50/p95/p99 可能显示 1ms,这是正常现象,并非 block/filter/error/local/hit 被计入。
        if matches!(metric.status, DnsOutcome::Normal | DnsOutcome::NxDomain) {
            self.slowest.record(metric.domain.clone(), metric.duration_ms as u64);
            let _ = self.latency.record(metric.duration_ms.max(1) as u64);
        }
    }

    fn trim(&mut self) {
        self.top_domains.trim();
        self.top_clients.trim();
        self.top_blocked.trim();
        self.slowest.trim();
    }
}

/// DNS 最近 5 分钟预聚合窗口(首页 DnsStatusCard 专用)。
///
/// 以 (flow_id × 分钟) 桶滚动维护计数、duration 分位数 sketch 与每维度 top-k 热点。
/// 数据流约定:窗口是纯内存实时结构,唯一数据源是采集方向(worker ingest);
/// 数据不落库(驱逐即丢弃,无 shutdown drain),查询也不与 DB 桶合并,重启后为空。
/// 查询区间必须落在窗口覆盖范围内 [minute_start(now-5min), minute_end(now)),
/// 由引擎侧(range 全覆盖判定)保证。
#[derive(Clone, Default)]
pub(crate) struct DnsRecentWindow {
    inner: Arc<RwLock<VecDeque<DnsMinuteBucket>>>,
}

impl DnsRecentWindow {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn cutoff(now_ms: u64) -> u64 {
        now_ms.saturating_sub(DNS_RECENT_WINDOW_SECS * 1000)
    }

    /// 窗口数据下界(分钟对齐):保留该值所在分钟及之后的所有分钟桶。
    fn window_start(now_ms: u64) -> u64 {
        minute_start(Self::cutoff(now_ms))
    }

    /// 将一条 DNS 指标归入对应 (flow_id, 分钟) 桶;其分钟桶完全落在窗口外时直接丢弃。
    pub(crate) fn ingest(&self, metric: &DnsMetric, now_ms: u64) {
        let bucket_start = minute_start(metric.report_time);
        let window_start = Self::window_start(now_ms);
        if bucket_start < window_start {
            return;
        }

        let mut buckets = self.inner.write().expect("dns recent window poisoned");
        let position = buckets.iter().position(|bucket| {
            bucket.minute_start > bucket_start
                || (bucket.minute_start == bucket_start && bucket.flow_id >= metric.flow_id)
        });
        let mut inserted_new = false;
        match position {
            Some(index)
                if buckets[index].minute_start == bucket_start
                    && buckets[index].flow_id == metric.flow_id =>
            {
                buckets[index].ingest(metric);
            }
            Some(index) => {
                let mut bucket = DnsMinuteBucket::new(metric.flow_id, bucket_start);
                bucket.ingest(metric);
                buckets.insert(index, bucket);
                inserted_new = true;
            }
            None => {
                let mut bucket = DnsMinuteBucket::new(metric.flow_id, bucket_start);
                bucket.ingest(metric);
                buckets.push_back(bucket);
                inserted_new = true;
            }
        }
        // 新分钟桶创建意味着更早的分钟已结束(除非时钟乱序),截断其 top-k 映射,
        // 控制持续异常基数下的内存上界。
        if inserted_new {
            for bucket in buckets.iter_mut() {
                if bucket.minute_start < bucket_start {
                    bucket.trim();
                }
            }
        }

        // 窗口纯内存:滚出窗口的整分钟桶直接丢弃,不落库。
        while let Some(front) = buckets.front() {
            if front.minute_start < window_start {
                buckets.pop_front();
            } else {
                break;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn bucket_count(&self) -> usize {
        self.inner.read().expect("dns recent window poisoned").len()
    }

    /// 按显式区间 `[start_ms, end_ms)` 聚合窗口内分钟桶(分钟粒度),支持 flow 过滤。
    ///
    /// 调用方必须传入分钟对齐的边界(`minute_start`/`minute_end` 对齐),
    /// 与 SQL 回退路径(`report_time >= start AND report_time < end`)语义一致。
    pub(crate) fn range_parts(
        &self,
        start_ms: u64,
        end_ms: u64,
        flow_id: Option<u32>,
    ) -> DnsSummaryParts {
        let buckets = self.inner.read().expect("dns recent window poisoned");
        let mut parts = DnsSummaryParts::default();
        for bucket in buckets.iter() {
            if let Some(flow) = flow_id {
                if bucket.flow_id != flow {
                    continue;
                }
            }
            if bucket.minute_start.saturating_add(MINUTE_MS) <= start_ms {
                continue;
            }
            if bucket.minute_start >= end_ms {
                continue;
            }
            parts.counts.merge(&bucket.counts);
            let _ = parts.latency.add(&bucket.latency);
            merge_top_pairs(&mut parts.top_domains, &bucket.top_domains.top());
            merge_top_pairs(&mut parts.top_clients, &bucket.top_clients.top());
            merge_top_pairs(&mut parts.top_blocked, &bucket.top_blocked.top());
            merge_slow_pairs(&mut parts.slowest, &bucket.slowest.top());
        }
        parts
    }

    #[cfg(test)]
    pub(crate) fn lightweight_summary(&self, now_ms: u64) -> DnsLightweightSummaryResponse {
        self.range_parts(minute_start(Self::cutoff(now_ms)), minute_end(now_ms), None)
            .into_lightweight_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn dns_metric(
        flow_id: u32,
        report_time: u64,
        query_type: &str,
        status: DnsOutcome,
        duration_ms: u32,
    ) -> DnsMetric {
        DnsMetric {
            flow_id,
            domain: "example.com".to_string(),
            query_type: query_type.to_string(),
            response_code: "NOERROR".to_string(),
            status,
            report_time,
            duration_ms,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            answers: Vec::new(),
        }
    }

    const NOW_MS: u64 = 100_000_000_000;

    #[test]
    fn counts_and_effective_semantics_match_sql() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(1, minute + 1, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(1, minute + 2, "A", DnsOutcome::Hit, 20), NOW_MS);
        window.ingest(&dns_metric(1, minute + 3, "AAAA", DnsOutcome::Normal, 30), NOW_MS);
        window.ingest(&dns_metric(1, minute + 4, "TXT", DnsOutcome::Block, 40), NOW_MS);
        window.ingest(&dns_metric(1, minute + 5, "A", DnsOutcome::NxDomain, 50), NOW_MS);
        window.ingest(&dns_metric(1, minute + 6, "AAAA", DnsOutcome::Local, 60), NOW_MS);
        window.ingest(&dns_metric(1, minute + 7, "A", DnsOutcome::Error, 70), NOW_MS);
        window.ingest(&dns_metric(1, minute + 8, "A", DnsOutcome::Filter, 80), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 8);
        assert_eq!(summary.cache_hit_count, 1);
        assert_eq!(summary.total_effective_queries, 5);
        assert_eq!(summary.total_v4, 3);
        assert_eq!(summary.hit_count_v4, 1);
        assert_eq!(summary.total_v6, 2);
        assert_eq!(summary.total_other, 0);
        assert_eq!(summary.block_count, 1);
        assert_eq!(summary.filter_count, 1);
        assert_eq!(summary.nxdomain_count, 1);
        assert_eq!(summary.error_count, 1);
    }

    #[test]
    fn latency_excludes_block_filter_error_local_hit() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(1, minute + 1, "A", DnsOutcome::Normal, 100), NOW_MS);
        window.ingest(&dns_metric(1, minute + 2, "A", DnsOutcome::Normal, 200), NOW_MS);
        window.ingest(&dns_metric(1, minute + 3, "A", DnsOutcome::NxDomain, 300), NOW_MS);
        window.ingest(&dns_metric(1, minute + 4, "A", DnsOutcome::Block, 1), NOW_MS);
        window.ingest(&dns_metric(1, minute + 5, "A", DnsOutcome::Filter, 1), NOW_MS);
        window.ingest(&dns_metric(1, minute + 6, "A", DnsOutcome::Error, 1), NOW_MS);
        window.ingest(&dns_metric(1, minute + 7, "A", DnsOutcome::Local, 1), NOW_MS);
        window.ingest(&dns_metric(1, minute + 8, "A", DnsOutcome::Hit, 1), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.avg_duration_ms, 200.0);
        assert_eq!(summary.p50_duration_ms, 200.0);
        assert_eq!(summary.max_duration_ms, 300.0);
        assert_eq!(summary.total_queries, 8);
    }

    #[test]
    fn expired_minutes_are_dropped() {
        let window = DnsRecentWindow::new();
        let window_start = minute_start(NOW_MS - DNS_RECENT_WINDOW_SECS * 1000);
        // 窗口下界前一整分钟的数据被丢弃(窗口纯内存,驱逐即丢弃)。
        window.ingest(
            &dns_metric(1, window_start - MINUTE_MS + 1, "A", DnsOutcome::Normal, 10),
            NOW_MS,
        );
        // 窗口下界所在分钟的数据保留
        window.ingest(&dns_metric(1, window_start + 1, "A", DnsOutcome::Normal, 20), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 1);
    }

    #[test]
    fn window_keeps_five_minutes_plus_boundary_minute() {
        let window = DnsRecentWindow::new();
        let current_minute = minute_start(NOW_MS);
        // 窗口覆盖 [minute_start(now-5min), now],下界所在分钟桶一并保留
        // (共 6 个整分钟桶),更早的数据在 ingest 时直接丢弃。
        for offset in 0..7 {
            let start = current_minute - offset * MINUTE_MS;
            window.ingest(&dns_metric(1, start + 1, "A", DnsOutcome::Normal, 10), NOW_MS);
        }

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 6);
    }

    #[test]
    fn empty_window_returns_zeroes() {
        let window = DnsRecentWindow::new();
        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 0);
        assert_eq!(summary.avg_duration_ms, 0.0);
        assert_eq!(summary.p99_duration_ms, 0.0);
        assert_eq!(summary.max_duration_ms, 0.0);
    }

    #[test]
    fn out_of_order_within_same_minute_lands_in_same_bucket() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(1, minute + 40, "A", DnsOutcome::Normal, 40), NOW_MS);
        window.ingest(&dns_metric(1, minute + 10, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(1, minute + 25, "A", DnsOutcome::Normal, 25), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 3);
        assert_eq!(summary.avg_duration_ms, 25.0);
    }

    #[test]
    fn out_of_order_previous_minute_creates_missing_bucket() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(1, minute + 30, "A", DnsOutcome::Normal, 30), NOW_MS);
        window.ingest(&dns_metric(1, minute - MINUTE_MS + 20, "A", DnsOutcome::Normal, 20), NOW_MS);
        window.ingest(&dns_metric(1, minute + 10, "A", DnsOutcome::Normal, 10), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 3);
        assert_eq!(summary.p50_duration_ms, 20.0);
    }

    #[test]
    fn out_of_order_older_bucket_stays_before_existing_buckets() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(1, minute, "A", DnsOutcome::Normal, 30), NOW_MS);
        window.ingest(&dns_metric(1, minute - 2 * MINUTE_MS, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(1, minute - MINUTE_MS, "A", DnsOutcome::Normal, 20), NOW_MS);
        window.ingest(
            &dns_metric(1, minute - 2 * MINUTE_MS + 1, "A", DnsOutcome::Normal, 10),
            NOW_MS,
        );

        let buckets = window.inner.read().expect("dns recent window poisoned");
        let starts: Vec<_> = buckets.iter().map(|bucket| bucket.minute_start).collect();
        assert_eq!(starts, vec![minute - 2 * MINUTE_MS, minute - MINUTE_MS, minute]);
        assert_eq!(buckets[0].counts.total_queries, 2);
    }

    #[test]
    fn range_summary_filters_by_start_and_end() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(1, minute - MINUTE_MS + 10, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(1, minute + 10, "A", DnsOutcome::Normal, 20), NOW_MS);
        window.ingest(&dns_metric(1, minute + MINUTE_MS + 10, "A", DnsOutcome::Normal, 30), NOW_MS);

        let summary =
            window.range_parts(minute, minute + MINUTE_MS, None).into_lightweight_response();
        assert_eq!(summary.total_queries, 1);
        assert_eq!(summary.avg_duration_ms, 20.0);

        let summary = window
            .range_parts(minute - MINUTE_MS, NOW_MS + MINUTE_MS, None)
            .into_lightweight_response();
        assert_eq!(summary.total_queries, 3);
    }

    #[test]
    fn metric_before_window_start_is_ignored() {
        let window = DnsRecentWindow::new();
        let window_start = minute_start(NOW_MS - DNS_RECENT_WINDOW_SECS * 1000);
        // 早于窗口下界 1ms 的记录(其分钟桶已整体过期)直接丢弃
        window.ingest(&dns_metric(1, window_start - 1, "A", DnsOutcome::Normal, 10), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 0);
    }

    #[test]
    fn different_flows_keep_separate_minute_buckets() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(1, minute + 10, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(2, minute + 20, "A", DnsOutcome::Normal, 20), NOW_MS);
        window.ingest(&dns_metric(1, minute + 30, "A", DnsOutcome::Normal, 30), NOW_MS);

        let buckets = window.inner.read().expect("dns recent window poisoned");
        assert_eq!(buckets.len(), 2, "two flows in the same minute produce two buckets");
        let flows: Vec<_> = buckets.iter().map(|bucket| bucket.flow_id).collect();
        assert_eq!(flows, vec![1, 2]);

        let flow_one = window.range_parts(minute, minute + MINUTE_MS, Some(1));
        let summary = flow_one.into_lightweight_response();
        assert_eq!(summary.total_queries, 2);
        assert_eq!(summary.avg_duration_ms, 20.0);

        let flow_two = window.range_parts(minute, minute + MINUTE_MS, Some(2));
        assert_eq!(flow_two.counts.total_queries, 1);

        let all = window.range_parts(minute, minute + MINUTE_MS, None);
        assert_eq!(all.counts.total_queries, 3);
    }

    #[test]
    fn new_minute_bucket_trims_completed_bucket_maps() {
        let window = DnsRecentWindow::new();
        let t0 = minute_start(NOW_MS);
        // t0 分钟灌入 25 个不同域名,全量保留。
        for index in 0..25 {
            let mut metric = dns_metric(1, t0 + index as u64, "A", DnsOutcome::Normal, 10);
            metric.domain = format!("d{}.com", index);
            window.ingest(&metric, NOW_MS);
        }
        // 下一分钟的新桶触发对 t0 桶的截断。
        window.ingest(
            &dns_metric(1, t0 + MINUTE_MS + 1, "A", DnsOutcome::Normal, 10),
            NOW_MS + MINUTE_MS,
        );

        let buckets = window.inner.read().expect("dns recent window poisoned");
        let first = &buckets[0];
        let tops = first.top_domains.top();
        assert_eq!(tops.len(), 20, "completed minute trimmed to top-k");
        assert_eq!(first.slowest.top().len(), 20);
    }
}

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use hdrhistogram::Histogram;
use landscape_common::metric::dns::{DnsLightweightSummaryResponse, DnsMetric, DnsOutcome};

/// DNS 最近状态窗口时长,硬编码为 5 分钟,与前端状态卡一致。
pub(crate) const DNS_RECENT_WINDOW_SECS: u64 = 5 * 60;
const MINUTE_MS: u64 = 60 * 1000;

pub(crate) fn minute_start(report_time: u64) -> u64 {
    report_time / MINUTE_MS * MINUTE_MS
}

pub(crate) fn minute_end(report_time: u64) -> u64 {
    report_time.div_ceil(MINUTE_MS) * MINUTE_MS
}

#[derive(Debug, Default, Clone, Copy)]
struct DnsCounters {
    total_queries: u64,
    total_effective_queries: u64,
    cache_hit_count: u64,
    total_v4: u64,
    hit_count_v4: u64,
    total_v6: u64,
    hit_count_v6: u64,
    total_other: u64,
    hit_count_other: u64,
    block_count: u64,
    filter_count: u64,
    nxdomain_count: u64,
    error_count: u64,
}

#[derive(Debug)]
struct DnsMinuteBucket {
    minute_start: u64,
    counts: DnsCounters,
    /// 仅记录有效查询(Normal/NxDomain)的 duration_ms;block/filter/error/local/hit 不计入。
    latency: Histogram<u64>,
}

impl DnsMinuteBucket {
    fn new(minute_start: u64) -> Self {
        Self {
            minute_start,
            counts: DnsCounters::default(),
            latency: Histogram::<u64>::new(3).expect("create dns latency histogram"),
        }
    }

    fn ingest(&mut self, metric: &DnsMetric) {
        self.counts.total_queries += 1;
        match metric.status {
            DnsOutcome::Hit => self.counts.cache_hit_count += 1,
            DnsOutcome::Block => self.counts.block_count += 1,
            DnsOutcome::Filter => self.counts.filter_count += 1,
            DnsOutcome::NxDomain => self.counts.nxdomain_count += 1,
            DnsOutcome::Error => self.counts.error_count += 1,
            DnsOutcome::Local | DnsOutcome::Normal => {}
        }

        let effective =
            !matches!(metric.status, DnsOutcome::Block | DnsOutcome::Filter | DnsOutcome::Error);
        if effective {
            self.counts.total_effective_queries += 1;
            match metric.query_type.as_str() {
                "A" => {
                    self.counts.total_v4 += 1;
                    if metric.status == DnsOutcome::Hit {
                        self.counts.hit_count_v4 += 1;
                    }
                }
                "AAAA" => {
                    self.counts.total_v6 += 1;
                    if metric.status == DnsOutcome::Hit {
                        self.counts.hit_count_v6 += 1;
                    }
                }
                _ => {
                    self.counts.total_other += 1;
                    if metric.status == DnsOutcome::Hit {
                        self.counts.hit_count_other += 1;
                    }
                }
            }
        }

        // 仅 Normal/NxDomain 计入延迟。注意 NxDomain 中包含大量本地/缓存秒回的查询
        // (拦截 TLD、缓存命中的 NXDOMAIN、被类型过滤且缓存为 NXDOMAIN 的查询等),
        // 其耗时通常为 0~1ms,0ms 会被上方 max(1) 钳为 1ms;当这类查询在窗口内占多数时,
        // p50/p95/p99 可能显示 1ms,这是正常现象,并非 block/filter/error/local/hit 被计入。
        if matches!(metric.status, DnsOutcome::Normal | DnsOutcome::NxDomain) {
            let _ = self.latency.record(metric.duration_ms.max(1) as u64);
        }
    }
}

/// DNS 最近 5 分钟预聚合窗口。
///
/// 以分钟桶滚动维护计数与 duration 分位数 sketch,实时状态卡直接读内存,
/// 不落库、不参与历史查询。窗口以分钟桶为保留粒度,覆盖
/// [minute_start(now-5min), minute_end(now)),与 SQL 回退路径
/// (report_time >= start AND report_time < end)对同一区间的聚合结果一致。
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

    /// 将一条 DNS 指标归入对应分钟桶;其分钟桶完全落在窗口外时直接丢弃。
    pub(crate) fn ingest(&self, metric: &DnsMetric, now_ms: u64) {
        let bucket_start = minute_start(metric.report_time);
        let window_start = Self::window_start(now_ms);
        if bucket_start < window_start {
            return;
        }

        let mut buckets = self.inner.write().expect("dns recent window poisoned");
        let position = buckets.iter().rposition(|bucket| bucket.minute_start <= bucket_start);
        match position {
            Some(index) if buckets[index].minute_start == bucket_start => {
                buckets[index].ingest(metric);
            }
            Some(index) => {
                let mut bucket = DnsMinuteBucket::new(bucket_start);
                bucket.ingest(metric);
                buckets.insert(index + 1, bucket);
            }
            None => {
                let mut bucket = DnsMinuteBucket::new(bucket_start);
                bucket.ingest(metric);
                buckets.push_front(bucket);
            }
        }

        while let Some(front) = buckets.front() {
            if front.minute_start < window_start {
                buckets.pop_front();
            } else {
                break;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn lightweight_summary(&self, now_ms: u64) -> DnsLightweightSummaryResponse {
        self.lightweight_summary_range(minute_start(Self::cutoff(now_ms)), minute_end(now_ms))
    }

    /// 按显式区间 `[start_ms, end_ms)` 聚合窗口内分钟桶(分钟粒度)。
    ///
    /// 调用方必须传入分钟对齐的边界(`minute_start`/`minute_end` 对齐),
    /// 与 SQL 回退路径(`report_time >= start AND report_time < end`)语义一致。
    pub(crate) fn lightweight_summary_range(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> DnsLightweightSummaryResponse {
        let buckets = self.inner.read().expect("dns recent window poisoned");

        let mut counts = DnsCounters::default();
        let mut latency = Histogram::<u64>::new(3).expect("create dns latency histogram");
        for bucket in buckets.iter() {
            if bucket.minute_start.saturating_add(MINUTE_MS) <= start_ms {
                continue;
            }
            if bucket.minute_start >= end_ms {
                continue;
            }
            counts.total_queries += bucket.counts.total_queries;
            counts.total_effective_queries += bucket.counts.total_effective_queries;
            counts.cache_hit_count += bucket.counts.cache_hit_count;
            counts.total_v4 += bucket.counts.total_v4;
            counts.hit_count_v4 += bucket.counts.hit_count_v4;
            counts.total_v6 += bucket.counts.total_v6;
            counts.hit_count_v6 += bucket.counts.hit_count_v6;
            counts.total_other += bucket.counts.total_other;
            counts.hit_count_other += bucket.counts.hit_count_other;
            counts.block_count += bucket.counts.block_count;
            counts.filter_count += bucket.counts.filter_count;
            counts.nxdomain_count += bucket.counts.nxdomain_count;
            counts.error_count += bucket.counts.error_count;
            let _ = latency.add(&bucket.latency);
        }

        let record_count = latency.len();
        DnsLightweightSummaryResponse {
            total_queries: counts.total_queries as usize,
            total_effective_queries: counts.total_effective_queries as usize,
            cache_hit_count: counts.cache_hit_count as usize,
            hit_count_v4: counts.hit_count_v4 as usize,
            hit_count_v6: counts.hit_count_v6 as usize,
            hit_count_other: counts.hit_count_other as usize,
            total_v4: counts.total_v4 as usize,
            total_v6: counts.total_v6 as usize,
            total_other: counts.total_other as usize,
            block_count: counts.block_count as usize,
            filter_count: counts.filter_count as usize,
            nxdomain_count: counts.nxdomain_count as usize,
            error_count: counts.error_count as usize,
            avg_duration_ms: if record_count == 0 { 0.0 } else { latency.mean() },
            p50_duration_ms: quantile_or_zero(&latency, 0.50),
            p95_duration_ms: quantile_or_zero(&latency, 0.95),
            p99_duration_ms: quantile_or_zero(&latency, 0.99),
            max_duration_ms: if record_count == 0 { 0.0 } else { latency.max() as f64 },
        }
    }
}

fn quantile_or_zero(latency: &Histogram<u64>, quantile: f64) -> f64 {
    if latency.is_empty() {
        0.0
    } else {
        latency.value_at_quantile(quantile) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn dns_metric(
        report_time: u64,
        query_type: &str,
        status: DnsOutcome,
        duration_ms: u32,
    ) -> DnsMetric {
        DnsMetric {
            flow_id: 1,
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

        window.ingest(&dns_metric(minute + 1, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(minute + 2, "A", DnsOutcome::Hit, 20), NOW_MS);
        window.ingest(&dns_metric(minute + 3, "AAAA", DnsOutcome::Normal, 30), NOW_MS);
        window.ingest(&dns_metric(minute + 4, "TXT", DnsOutcome::Block, 40), NOW_MS);
        window.ingest(&dns_metric(minute + 5, "A", DnsOutcome::NxDomain, 50), NOW_MS);
        window.ingest(&dns_metric(minute + 6, "AAAA", DnsOutcome::Local, 60), NOW_MS);
        window.ingest(&dns_metric(minute + 7, "A", DnsOutcome::Error, 70), NOW_MS);
        window.ingest(&dns_metric(minute + 8, "A", DnsOutcome::Filter, 80), NOW_MS);

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

        window.ingest(&dns_metric(minute + 1, "A", DnsOutcome::Normal, 100), NOW_MS);
        window.ingest(&dns_metric(minute + 2, "A", DnsOutcome::Normal, 200), NOW_MS);
        window.ingest(&dns_metric(minute + 3, "A", DnsOutcome::NxDomain, 300), NOW_MS);
        window.ingest(&dns_metric(minute + 4, "A", DnsOutcome::Block, 1), NOW_MS);
        window.ingest(&dns_metric(minute + 5, "A", DnsOutcome::Filter, 1), NOW_MS);
        window.ingest(&dns_metric(minute + 6, "A", DnsOutcome::Error, 1), NOW_MS);
        window.ingest(&dns_metric(minute + 7, "A", DnsOutcome::Local, 1), NOW_MS);
        window.ingest(&dns_metric(minute + 8, "A", DnsOutcome::Hit, 1), NOW_MS);

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
        // 窗口下界前一整分钟的数据被丢弃
        window
            .ingest(&dns_metric(window_start - MINUTE_MS + 1, "A", DnsOutcome::Normal, 10), NOW_MS);
        // 窗口下界所在分钟的数据保留
        window.ingest(&dns_metric(window_start + 1, "A", DnsOutcome::Normal, 20), NOW_MS);

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
            window.ingest(&dns_metric(start + 1, "A", DnsOutcome::Normal, 10), NOW_MS);
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

        window.ingest(&dns_metric(minute + 40, "A", DnsOutcome::Normal, 40), NOW_MS);
        window.ingest(&dns_metric(minute + 10, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(minute + 25, "A", DnsOutcome::Normal, 25), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 3);
        assert_eq!(summary.avg_duration_ms, 25.0);
    }

    #[test]
    fn out_of_order_previous_minute_creates_missing_bucket() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(minute + 30, "A", DnsOutcome::Normal, 30), NOW_MS);
        window.ingest(&dns_metric(minute - MINUTE_MS + 20, "A", DnsOutcome::Normal, 20), NOW_MS);
        window.ingest(&dns_metric(minute + 10, "A", DnsOutcome::Normal, 10), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 3);
        assert_eq!(summary.p50_duration_ms, 20.0);
    }

    #[test]
    fn out_of_order_older_bucket_stays_before_existing_buckets() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(minute, "A", DnsOutcome::Normal, 30), NOW_MS);
        window.ingest(&dns_metric(minute - 2 * MINUTE_MS, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(minute - MINUTE_MS, "A", DnsOutcome::Normal, 20), NOW_MS);
        window.ingest(&dns_metric(minute - 2 * MINUTE_MS + 1, "A", DnsOutcome::Normal, 10), NOW_MS);

        let buckets = window.inner.read().expect("dns recent window poisoned");
        let starts: Vec<_> = buckets.iter().map(|bucket| bucket.minute_start).collect();
        assert_eq!(starts, vec![minute - 2 * MINUTE_MS, minute - MINUTE_MS, minute]);
        assert_eq!(buckets[0].counts.total_queries, 2);
    }

    #[test]
    fn range_summary_filters_by_start_and_end() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);

        window.ingest(&dns_metric(minute - MINUTE_MS + 10, "A", DnsOutcome::Normal, 10), NOW_MS);
        window.ingest(&dns_metric(minute + 10, "A", DnsOutcome::Normal, 20), NOW_MS);
        window.ingest(&dns_metric(minute + MINUTE_MS + 10, "A", DnsOutcome::Normal, 30), NOW_MS);

        let summary = window.lightweight_summary_range(minute, minute + MINUTE_MS);
        assert_eq!(summary.total_queries, 1);
        assert_eq!(summary.avg_duration_ms, 20.0);

        let summary = window.lightweight_summary_range(minute - MINUTE_MS, NOW_MS + MINUTE_MS);
        assert_eq!(summary.total_queries, 3);
    }

    #[test]
    fn metric_before_window_start_is_ignored() {
        let window = DnsRecentWindow::new();
        let window_start = minute_start(NOW_MS - DNS_RECENT_WINDOW_SECS * 1000);
        // 早于窗口下界 1ms 的记录(其分钟桶已整体过期)直接丢弃
        window.ingest(&dns_metric(window_start - 1, "A", DnsOutcome::Normal, 10), NOW_MS);

        let summary = window.lightweight_summary(NOW_MS);
        assert_eq!(summary.total_queries, 0);
    }
}

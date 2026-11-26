use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use landscape_common::metric::dns::{
    DnsLatencyBand, DnsLiveDashboard, DnsMetric, DnsMetricEvent, DnsMinutePoint, DnsOutcome,
};

#[cfg(test)]
use landscape_common::metric::dns::DnsLightweightSummaryResponse;

#[cfg(test)]
use super::dns_bucket::minute_end;
use super::dns_bucket::{DnsSummaryParts, MINUTE_MS, clean_ip_string, minute_start};

/// Recent in-memory window shared by the homepage summary and the live dashboard.
pub(crate) const DNS_RECENT_WINDOW_SECS: u64 = 5 * 60;

fn read_or_recover<'a, T>(lock: &'a RwLock<T>) -> RwLockReadGuard<'a, T> {
    lock.read().unwrap_or_else(|poisoned| {
        tracing::error!("dns recent window lock poisoned; recovering the inner state");
        poisoned.into_inner()
    })
}

fn write_or_recover<'a, T>(lock: &'a RwLock<T>) -> RwLockWriteGuard<'a, T> {
    lock.write().unwrap_or_else(|poisoned| {
        tracing::error!("dns recent window lock poisoned; recovering the inner state");
        poisoned.into_inner()
    })
}

#[derive(Debug)]
struct DnsMinuteBucket {
    flow_id: u32,
    minute_start: u64,
    parts: DnsSummaryParts,
}

// Bound distinct ranking candidates per dimension, flow and minute. Compact in batches
// so a stream of unique names does not trigger an allocation and sort on every event.
const RANK_CANDIDATES: usize = 256;

fn compact_candidates<V: Copy, K: Ord>(entries: &mut HashMap<String, V>, score: impl Fn(V) -> K) {
    if entries.len() <= 2 * RANK_CANDIDATES {
        return;
    }
    let mut candidates: Vec<_> = entries.drain().collect();
    candidates.select_nth_unstable_by(RANK_CANDIDATES, |(a, av), (b, bv)| {
        score(*bv).cmp(&score(*av)).then_with(|| a.cmp(b))
    });
    entries.extend(candidates.into_iter().take(RANK_CANDIDATES));
}

fn count_key(map: &mut HashMap<String, u64>, key: &str) {
    if let Some(count) = map.get_mut(key) {
        *count += 1;
    } else {
        map.insert(key.to_owned(), 1);
        compact_candidates(map, |count| count);
    }
}

impl DnsMinuteBucket {
    fn new(flow_id: u32, minute_start: u64) -> Self {
        Self {
            flow_id,
            minute_start,
            parts: DnsSummaryParts::default(),
        }
    }

    fn ingest(&mut self, metric: &DnsMetric) {
        let parts = &mut self.parts;
        parts.counts.record(metric);
        count_key(&mut parts.top_domains, &metric.domain);
        count_key(&mut parts.top_clients, &clean_ip_string(&metric.src_ip));
        if metric.status == DnsOutcome::Block {
            count_key(&mut parts.top_blocked, &metric.domain);
        }
        if matches!(metric.status, DnsOutcome::Normal | DnsOutcome::NxDomain) {
            let _ = parts.latency.record(metric.duration_ms.max(1) as u64);
            let sample = parts.slowest.entry(metric.domain.clone()).or_default();
            sample.0 += 1;
            sample.1 += u64::from(metric.duration_ms);
            compact_candidates(&mut parts.slowest, |(count, sum)| (count >= 3, sum / count, count));
        }
    }
}

/// DNS 最近 5 分钟预聚合窗口。
///
/// 以 (flow_id × 分钟) 桶滚动维护计数与 duration 分位数 sketch。
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

    /// Update live state before handing the event to the optional history buffer.
    pub(crate) fn record_event(&self, event: DnsMetricEvent, now_ms: u64) -> DnsMetric {
        let metric = event.into_metric();
        self.ingest(&metric, now_ms);
        metric
    }

    /// 将一条 DNS 指标归入对应 (flow_id, 分钟) 桶;其分钟桶完全落在窗口外时直接丢弃。
    pub(crate) fn ingest(&self, metric: &DnsMetric, now_ms: u64) {
        let bucket_start = minute_start(metric.report_time);
        let window_start = Self::window_start(now_ms);
        if bucket_start < window_start {
            return;
        }

        let mut buckets = write_or_recover(&self.inner);
        let position = buckets.iter().position(|bucket| {
            bucket.minute_start > bucket_start
                || (bucket.minute_start == bucket_start && bucket.flow_id >= metric.flow_id)
        });
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
            }
            None => {
                let mut bucket = DnsMinuteBucket::new(metric.flow_id, bucket_start);
                bucket.ingest(metric);
                buckets.push_back(bucket);
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
        read_or_recover(&self.inner).len()
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
        let buckets = read_or_recover(&self.inner);
        let mut parts = DnsSummaryParts::default();
        for bucket in buckets.iter() {
            if let Some(flow) = flow_id
                && bucket.flow_id != flow
            {
                continue;
            }
            if bucket.minute_start.saturating_add(MINUTE_MS) <= start_ms {
                continue;
            }
            if bucket.minute_start >= end_ms {
                continue;
            }
            parts.counts.merge(&bucket.parts.counts);
            let _ = parts.latency.add(&bucket.parts.latency);
        }
        parts
    }

    pub(crate) fn dashboard(&self, now_ms: u64, flow: Option<u32>) -> DnsLiveDashboard {
        let start = Self::window_start(now_ms);
        let current = minute_start(now_ms);
        let mut minutes: Vec<_> = (start..=current)
            .step_by(MINUTE_MS as usize)
            .map(|start_ms| DnsMinutePoint {
                start_ms,
                queries: 0,
                hits: 0,
                blocks: 0,
                errors: 0,
            })
            .collect();
        let mut parts = DnsSummaryParts::default();
        {
            let buckets = read_or_recover(&self.inner);
            for bucket in buckets.iter().filter(|b| {
                (start..=current).contains(&b.minute_start) && flow.is_none_or(|id| id == b.flow_id)
            }) {
                let point = &mut minutes[((bucket.minute_start - start) / MINUTE_MS) as usize];
                let counts = &bucket.parts.counts;
                point.queries += counts.total_queries;
                point.hits += counts.cache_hit_count;
                point.blocks += counts.block_count;
                point.errors += counts.error_count;
                parts.merge(&bucket.parts);
            }
        }
        let limits = [10, 50, 100, 500, 1000];
        let mut latency: Vec<_> = limits
            .into_iter()
            .map(Some)
            .chain([None])
            .map(|upper_ms| DnsLatencyBand { upper_ms, count: 0 })
            .collect();
        for sample in parts.latency.iter_recorded() {
            let band = limits.partition_point(|&limit| limit < sample.value_iterated_to());
            latency[band].count += sample.count_since_last_iteration();
        }
        DnsLiveDashboard {
            summary: parts.into_summary_response(),
            minutes,
            latency,
        }
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
    fn dashboard_uses_one_window_for_rankings_latency_and_minute_counts() {
        let window = DnsRecentWindow::new();
        let minute = minute_start(NOW_MS);
        for duration in [10, 50, 1001] {
            window.ingest(
                &dns_metric(1, minute - MINUTE_MS, "A", DnsOutcome::Normal, duration),
                NOW_MS,
            );
        }
        window.ingest(&dns_metric(1, minute, "A", DnsOutcome::Block, 8), NOW_MS);
        window.ingest(&dns_metric(2, minute, "A", DnsOutcome::Hit, 8), NOW_MS);
        let live = window.dashboard(NOW_MS, Some(1));
        assert_eq!(live.summary.total_queries, 4);
        assert_eq!(live.summary.top_domains[0].count, 4);
        assert_eq!(live.summary.top_clients[0].name, "127.0.0.1");
        assert_eq!(live.summary.top_blocked[0].count, 1);
        assert_eq!(live.summary.slowest_domains[0].count, 3);
        assert_eq!(
            live.minutes.iter().map(|point| point.queries).collect::<Vec<_>>(),
            vec![0, 0, 0, 0, 3, 1]
        );
        assert_eq!(
            live.latency.iter().map(|band| band.count).collect::<Vec<_>>(),
            vec![1, 1, 0, 0, 0, 1]
        );
        assert_eq!(window.dashboard(NOW_MS, None).summary.total_queries, 5);
        assert!(window.dashboard(NOW_MS + 7 * MINUTE_MS, None).summary.top_domains.is_empty());
    }

    #[test]
    fn high_cardinality_compaction_keeps_hot_keys_and_exact_totals() {
        let window = DnsRecentWindow::new();
        let mut event = dns_metric(1, NOW_MS, "A", DnsOutcome::Block, 0);
        for _ in 0..10 {
            window.ingest(&event, NOW_MS);
        }
        for i in 0..2 * RANK_CANDIDATES {
            event.domain = format!("key-{i}");
            window.ingest(&event, NOW_MS);
        }
        let data = window.dashboard(NOW_MS, None);
        assert_eq!(data.summary.total_queries, 10 + 2 * RANK_CANDIDATES);
        assert_eq!(data.summary.top_blocked[0].count, 10);
        assert_eq!(read_or_recover(&window.inner)[0].parts.top_domains.len(), RANK_CANDIDATES);
    }

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
        assert_eq!(buckets[0].parts.counts.total_queries, 2);
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
}

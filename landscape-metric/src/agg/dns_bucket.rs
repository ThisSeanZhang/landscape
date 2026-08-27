use std::collections::HashMap;
use std::net::IpAddr;

use hdrhistogram::Histogram;
use landscape_common::metric::dns::{DnsLightweightSummaryResponse, DnsMetric, DnsOutcome};

pub(crate) const MINUTE_MS: u64 = 60 * 1000;

pub(crate) fn minute_start(report_time: u64) -> u64 {
    report_time / MINUTE_MS * MINUTE_MS
}

pub(crate) fn minute_end(report_time: u64) -> u64 {
    report_time.div_ceil(MINUTE_MS) * MINUTE_MS
}

/// 与 sqlite 存储一致的 IP 字符串化:IPv4 原样,IPv4-mapped IPv6 归一为 v4。
pub(crate) fn clean_ip_string(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                v6.to_string()
            }
        }
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// 单分钟桶的计数聚合,与 sqlite `query_dns_lightweight_summary` 的 COUNT 语义一致。
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DnsCounters {
    pub total_queries: u64,
    pub total_effective_queries: u64,
    pub cache_hit_count: u64,
    pub total_v4: u64,
    pub hit_count_v4: u64,
    pub total_v6: u64,
    pub hit_count_v6: u64,
    pub total_other: u64,
    pub hit_count_other: u64,
    pub block_count: u64,
    pub filter_count: u64,
    pub nxdomain_count: u64,
    pub error_count: u64,
}

impl DnsCounters {
    pub(crate) fn record(&mut self, metric: &DnsMetric) {
        self.total_queries += 1;
        match metric.status {
            DnsOutcome::Hit => self.cache_hit_count += 1,
            DnsOutcome::Block => self.block_count += 1,
            DnsOutcome::Filter => self.filter_count += 1,
            DnsOutcome::NxDomain => self.nxdomain_count += 1,
            DnsOutcome::Error => self.error_count += 1,
            DnsOutcome::Local | DnsOutcome::Normal => {}
        }

        let effective =
            !matches!(metric.status, DnsOutcome::Block | DnsOutcome::Filter | DnsOutcome::Error);
        if effective {
            self.total_effective_queries += 1;
            match metric.query_type.as_str() {
                "A" => {
                    self.total_v4 += 1;
                    if metric.status == DnsOutcome::Hit {
                        self.hit_count_v4 += 1;
                    }
                }
                "AAAA" => {
                    self.total_v6 += 1;
                    if metric.status == DnsOutcome::Hit {
                        self.hit_count_v6 += 1;
                    }
                }
                _ => {
                    self.total_other += 1;
                    if metric.status == DnsOutcome::Hit {
                        self.hit_count_other += 1;
                    }
                }
            }
        }
    }

    pub(crate) fn merge(&mut self, other: &DnsCounters) {
        self.total_queries += other.total_queries;
        self.total_effective_queries += other.total_effective_queries;
        self.cache_hit_count += other.cache_hit_count;
        self.total_v4 += other.total_v4;
        self.hit_count_v4 += other.hit_count_v4;
        self.total_v6 += other.total_v6;
        self.hit_count_v6 += other.hit_count_v6;
        self.total_other += other.total_other;
        self.hit_count_other += other.hit_count_other;
        self.block_count += other.block_count;
        self.filter_count += other.filter_count;
        self.nxdomain_count += other.nxdomain_count;
        self.error_count += other.error_count;
    }
}

/// top-k 计数累加器:分钟桶内全量计数,读取/驱逐时截断为 k。
/// 不做逐条淘汰——逐条增量到达的热点域名若在满桶时被淘汰将永远无法累积
/// (count=1 的新键恒为最小值)。内存由单分钟去重键数天然约束,
/// 窗口在创建新分钟桶时对旧桶截断,长时间异常基数下仍有界。
#[derive(Debug, Clone)]
pub(crate) struct CountTopK<V> {
    cap: usize,
    entries: HashMap<V, u64>,
}

impl<V> CountTopK<V>
where
    V: std::hash::Hash + Eq + Clone + Ord,
{
    pub(crate) fn new(cap: usize) -> Self {
        Self { cap: cap.max(1), entries: HashMap::new() }
    }

    pub(crate) fn record(&mut self, key: V, value: u64) {
        let entry = self.entries.entry(key).or_insert(0);
        *entry = entry.saturating_add(value);
    }

    /// 按计数降序返回 top-k(计数相同按 key 升序,保证确定性)。
    pub(crate) fn top(&self) -> Vec<(V, u64)> {
        let mut items: Vec<_> =
            self.entries.iter().map(|(key, count)| (key.clone(), *count)).collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        items.truncate(self.cap);
        items
    }

    /// 就地截断为 top-k(新分钟桶创建时对旧桶调用,控制内存上界)。
    pub(crate) fn trim(&mut self) {
        if self.entries.len() <= self.cap {
            return;
        }
        let keep: Vec<(V, u64)> = self.top();
        self.entries.clear();
        self.entries.extend(keep);
    }
}

/// 慢域名累加器:记录 count + 总耗时,读取/驱逐时按平均耗时截断 top-k。
#[derive(Debug, Clone)]
pub(crate) struct SlowTopK<V> {
    cap: usize,
    entries: HashMap<V, (u64, u64)>,
}

impl<V> SlowTopK<V>
where
    V: std::hash::Hash + Eq + Clone + Ord,
{
    pub(crate) fn new(cap: usize) -> Self {
        Self { cap: cap.max(1), entries: HashMap::new() }
    }

    pub(crate) fn record(&mut self, key: V, duration_ms: u64) {
        let entry = self.entries.entry(key).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(duration_ms);
    }

    /// 按平均耗时降序返回 top-k(返回 (key, count, sum_duration_ms))。
    pub(crate) fn top(&self) -> Vec<(V, u64, u64)> {
        let mut items: Vec<_> =
            self.entries.iter().map(|(key, stat)| (key.clone(), stat.0, stat.1)).collect();
        items.sort_by(|a, b| {
            avg_duration((b.1, b.2))
                .partial_cmp(&avg_duration((a.1, a.2)))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        items.truncate(self.cap);
        items
    }

    /// 就地截断为 top-k。
    pub(crate) fn trim(&mut self) {
        if self.entries.len() <= self.cap {
            return;
        }
        let keep: Vec<(V, u64, u64)> = self.top();
        self.entries.clear();
        self.entries.extend(keep.into_iter().map(|(key, count, sum)| (key, (count, sum))));
    }
}

fn avg_duration((count, sum): (u64, u64)) -> f64 {
    if count == 0 {
        0.0
    } else {
        sum as f64 / count as f64
    }
}

/// 一个 (flow_id, 分钟) 的预聚合行,由 DNS writer 从原始行批次构建后追加写入。
/// 同一 `bucket_time` 允许多行(不同批次各自成行),读侧逐行合并
/// (SUM 计数 + 直方图合并 + top union);`report_time` 为批内最后一条 metric 的
/// 完整时间,跨批次天然唯一,同键冲突直接忽略。
#[derive(Debug, Clone)]
pub(crate) struct DnsBucketRow {
    pub flow_id: u32,
    pub bucket_time: u64,
    pub report_time: u64,
    pub counts: DnsCounters,
    pub latency: Histogram<u64>,
    pub top_domains: Vec<(String, u64)>,
    pub top_clients: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
    pub slowest: Vec<(String, u64, u64)>,
}

/// 批内 (flow_id, 分钟) 聚合中间态:与内存窗口桶的计数语义一致,但不截断
/// (单批 ≤ 500 行,全量统计以保证桶是原始行的忠实聚合)。
#[derive(Debug)]
struct BatchAggregate {
    flow_id: u32,
    bucket_time: u64,
    counts: DnsCounters,
    latency: Histogram<u64>,
    top_domains: CountTopK<String>,
    top_clients: CountTopK<String>,
    top_blocked: CountTopK<String>,
    slowest: SlowTopK<String>,
    last_report_time: u64,
}

impl BatchAggregate {
    fn new(flow_id: u32, bucket_time: u64) -> Self {
        Self {
            flow_id,
            bucket_time,
            counts: DnsCounters::default(),
            latency: Histogram::<u64>::new(3).expect("create dns batch latency histogram"),
            top_domains: CountTopK::new(usize::MAX),
            top_clients: CountTopK::new(usize::MAX),
            top_blocked: CountTopK::new(usize::MAX),
            slowest: SlowTopK::new(usize::MAX),
            last_report_time: 0,
        }
    }

    /// 与 `DnsMinuteBucket::ingest` 完全一致的计数语义(状态分类/有效查询/延迟排除)。
    fn ingest(&mut self, metric: &DnsMetric) {
        self.counts.record(metric);
        self.last_report_time = self.last_report_time.max(metric.report_time);

        self.top_domains.record(metric.domain.clone(), 1);
        self.top_clients.record(clean_ip_string(&metric.src_ip), 1);
        if metric.status == DnsOutcome::Block {
            self.top_blocked.record(metric.domain.clone(), 1);
        }

        // 仅 Normal/NxDomain 计入延迟与慢域名。
        if matches!(metric.status, DnsOutcome::Normal | DnsOutcome::NxDomain) {
            self.slowest.record(metric.domain.clone(), metric.duration_ms as u64);
            let _ = self.latency.record(metric.duration_ms.max(1) as u64);
        }
    }

    fn into_row(self) -> DnsBucketRow {
        DnsBucketRow {
            flow_id: self.flow_id,
            bucket_time: self.bucket_time,
            report_time: self.last_report_time,
            counts: self.counts,
            latency: self.latency,
            top_domains: self.top_domains.top(),
            top_clients: self.top_clients.top(),
            top_blocked: self.top_blocked.top(),
            slowest: self.slowest.top(),
        }
    }
}

/// 从一批原始行构建 1m 桶行(DNS writer 同批落库,桶的唯一数据源)。
///
/// 按 (flow_id, 分钟) 分组,批次内全量统计(不截断);同一分钟由多个批次各自
/// 成行,读侧 `GROUP BY bucket_time` 逐行合并,与原始行 SQL 聚合语义一致。
pub(crate) fn dns_bucket_rows_from_batch(metrics: &[DnsMetric]) -> Vec<DnsBucketRow> {
    let mut aggregates: HashMap<(u32, u64), BatchAggregate> = HashMap::new();
    for metric in metrics {
        let bucket_time = minute_start(metric.report_time);
        let aggregate = aggregates
            .entry((metric.flow_id, bucket_time))
            .or_insert_with(|| BatchAggregate::new(metric.flow_id, bucket_time));
        aggregate.ingest(metric);
    }

    let mut rows: Vec<DnsBucketRow> =
        aggregates.into_values().map(BatchAggregate::into_row).collect();
    rows.sort_by(|a, b| a.flow_id.cmp(&b.flow_id).then_with(|| a.bucket_time.cmp(&b.bucket_time)));
    rows
}

/// 可合并的摘要片段:DB 桶行聚合出的摘要在此合并(读侧中间态)。
#[derive(Debug, Clone)]
pub(crate) struct DnsSummaryParts {
    pub counts: DnsCounters,
    pub latency: Histogram<u64>,
    pub top_domains: HashMap<String, u64>,
    pub top_clients: HashMap<String, u64>,
    pub top_blocked: HashMap<String, u64>,
    /// domain → (count, sum_duration_ms),仅 Normal/NxDomain。
    pub slowest: HashMap<String, (u64, u64)>,
}

impl Default for DnsSummaryParts {
    fn default() -> Self {
        Self {
            counts: DnsCounters::default(),
            latency: Histogram::<u64>::new(3).expect("create dns latency histogram"),
            top_domains: HashMap::new(),
            top_clients: HashMap::new(),
            top_blocked: HashMap::new(),
            slowest: HashMap::new(),
        }
    }
}

pub(crate) fn merge_top_pairs(map: &mut HashMap<String, u64>, pairs: &[(String, u64)]) {
    for (key, count) in pairs {
        *map.entry(key.clone()).or_insert(0) += count;
    }
}

pub(crate) fn merge_slow_pairs(
    map: &mut HashMap<String, (u64, u64)>,
    pairs: &[(String, u64, u64)],
) {
    for (key, count, sum) in pairs {
        let entry = map.entry(key.clone()).or_insert((0, 0));
        entry.0 += count;
        entry.1 += sum;
    }
}

impl DnsSummaryParts {
    /// 合并另一个摘要片段(仅测试使用)。
    #[cfg(test)]
    pub(crate) fn merge(&mut self, other: &DnsSummaryParts) {
        self.counts.merge(&other.counts);
        let _ = self.latency.add(&other.latency);
        for (key, count) in &other.top_domains {
            *self.top_domains.entry(key.clone()).or_insert(0) += count;
        }
        for (key, count) in &other.top_clients {
            *self.top_clients.entry(key.clone()).or_insert(0) += count;
        }
        for (key, count) in &other.top_blocked {
            *self.top_blocked.entry(key.clone()).or_insert(0) += count;
        }
        for (key, stat) in &other.slowest {
            let entry = self.slowest.entry(key.clone()).or_insert((0, 0));
            entry.0 += stat.0;
            entry.1 += stat.1;
        }
    }

    /// 合并持久化桶行(dns_metrics_1m 每行 + 对应 top 行;仅测试使用,
    /// 生产读侧由 sqlite 查询直接合并)。
    #[cfg(test)]
    pub(crate) fn merge_bucket_row(&mut self, row: &DnsBucketRow) {
        self.counts.merge(&row.counts);
        let _ = self.latency.add(&row.latency);
        merge_top_pairs(&mut self.top_domains, &row.top_domains);
        merge_top_pairs(&mut self.top_clients, &row.top_clients);
        merge_top_pairs(&mut self.top_blocked, &row.top_blocked);
        merge_slow_pairs(&mut self.slowest, &row.slowest);
    }

    /// 已记录延迟样本的均值(ms);无样本时为 0。
    #[cfg(test)]
    pub(crate) fn avg_duration_ms(&self) -> f64 {
        if self.latency.is_empty() {
            0.0
        } else {
            self.latency.mean()
        }
    }

    /// 组装轻量摘要(计数 + 延迟分位数,与 sqlite 回退路径同语义)。
    pub(crate) fn into_lightweight_response(self) -> DnsLightweightSummaryResponse {
        let record_count = self.latency.len();
        DnsLightweightSummaryResponse {
            total_queries: self.counts.total_queries as usize,
            total_effective_queries: self.counts.total_effective_queries as usize,
            cache_hit_count: self.counts.cache_hit_count as usize,
            hit_count_v4: self.counts.hit_count_v4 as usize,
            hit_count_v6: self.counts.hit_count_v6 as usize,
            hit_count_other: self.counts.hit_count_other as usize,
            total_v4: self.counts.total_v4 as usize,
            total_v6: self.counts.total_v6 as usize,
            total_other: self.counts.total_other as usize,
            block_count: self.counts.block_count as usize,
            filter_count: self.counts.filter_count as usize,
            nxdomain_count: self.counts.nxdomain_count as usize,
            error_count: self.counts.error_count as usize,
            avg_duration_ms: if record_count == 0 { 0.0 } else { self.latency.mean() },
            p50_duration_ms: quantile_or_zero(&self.latency, 0.50),
            p95_duration_ms: quantile_or_zero(&self.latency, 0.95),
            p99_duration_ms: quantile_or_zero(&self.latency, 0.99),
            max_duration_ms: if record_count == 0 { 0.0 } else { self.latency.max() as f64 },
        }
    }

    /// 组装完整摘要(计数 + 延迟分位数 + top 列表)。
    pub(crate) fn into_summary_response(self) -> landscape_common::metric::dns::DnsSummaryResponse {
        let record_count = self.latency.len();
        let entry = |items: Vec<(String, u64)>| {
            items
                .into_iter()
                .map(|(name, count)| landscape_common::metric::dns::DnsStatEntry {
                    name,
                    count: count as usize,
                    value: None,
                })
                .collect()
        };
        let slowest_entries = self
            .ranked_slowest(10)
            .into_iter()
            .map(|(name, count, sum)| landscape_common::metric::dns::DnsStatEntry {
                name,
                count: count as usize,
                value: Some(sum as f64 / count as f64),
            })
            .collect();
        landscape_common::metric::dns::DnsSummaryResponse {
            total_queries: self.counts.total_queries as usize,
            total_effective_queries: self.counts.total_effective_queries as usize,
            cache_hit_count: self.counts.cache_hit_count as usize,
            hit_count_v4: self.counts.hit_count_v4 as usize,
            hit_count_v6: self.counts.hit_count_v6 as usize,
            hit_count_other: self.counts.hit_count_other as usize,
            total_v4: self.counts.total_v4 as usize,
            total_v6: self.counts.total_v6 as usize,
            total_other: self.counts.total_other as usize,
            block_count: self.counts.block_count as usize,
            filter_count: self.counts.filter_count as usize,
            nxdomain_count: self.counts.nxdomain_count as usize,
            error_count: self.counts.error_count as usize,
            avg_duration_ms: if record_count == 0 { 0.0 } else { self.latency.mean() },
            p50_duration_ms: quantile_or_zero(&self.latency, 0.50),
            p95_duration_ms: quantile_or_zero(&self.latency, 0.95),
            p99_duration_ms: quantile_or_zero(&self.latency, 0.99),
            max_duration_ms: if record_count == 0 { 0.0 } else { self.latency.max() as f64 },
            top_clients: entry(self.ranked_top(&self.top_clients, 10)),
            top_domains: entry(self.ranked_top(&self.top_domains, 10)),
            top_blocked: entry(self.ranked_top(&self.top_blocked, 10)),
            slowest_domains: slowest_entries,
        }
    }

    /// 按计数降序返回 top-n 条目。
    pub(crate) fn ranked_top(
        &self,
        map: &HashMap<String, u64>,
        limit: usize,
    ) -> Vec<(String, u64)> {
        let mut items: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        items.truncate(limit);
        items
    }

    /// 按加权平均耗时降序返回 top-n 慢域名,总数 > 2 才入选(与 sqlite HAVING c > 2 一致)。
    pub(crate) fn ranked_slowest(&self, limit: usize) -> Vec<(String, u64, u64)> {
        let mut items: Vec<_> = self
            .slowest
            .iter()
            .filter(|(_, (count, _))| *count > 2)
            .map(|(k, (count, sum))| (k.clone(), *count, *sum))
            .collect();
        items.sort_by(|a, b| {
            avg_duration((b.1, b.2))
                .partial_cmp(&avg_duration((a.1, a.2)))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        items.truncate(limit);
        items
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
        flow_id: u32,
        domain: &str,
        query_type: &str,
        status: DnsOutcome,
        report_time: u64,
        duration_ms: u32,
    ) -> DnsMetric {
        DnsMetric {
            flow_id,
            domain: domain.to_string(),
            query_type: query_type.to_string(),
            response_code: "NOERROR".to_string(),
            status,
            report_time,
            duration_ms,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, flow_id as u8)),
            answers: Vec::new(),
        }
    }

    #[test]
    fn counters_record_matches_effective_semantics() {
        let mut counters = DnsCounters::default();
        for (domain, qtype, status, duration) in [
            ("a", "A", DnsOutcome::Normal, 10),
            ("b", "A", DnsOutcome::Hit, 20),
            ("c", "AAAA", DnsOutcome::Normal, 30),
            ("d", "TXT", DnsOutcome::Block, 40),
            ("e", "A", DnsOutcome::NxDomain, 50),
            ("f", "AAAA", DnsOutcome::Local, 60),
            ("g", "A", DnsOutcome::Error, 70),
            ("h", "A", DnsOutcome::Filter, 80),
        ] {
            counters.record(&dns_metric(1, domain, qtype, status, 100_000, duration));
        }
        assert_eq!(counters.total_queries, 8);
        assert_eq!(counters.cache_hit_count, 1);
        assert_eq!(counters.total_effective_queries, 5);
        assert_eq!(counters.total_v4, 3);
        assert_eq!(counters.hit_count_v4, 1);
        assert_eq!(counters.total_v6, 2);
        assert_eq!(counters.total_other, 0);
        assert_eq!(counters.block_count, 1);
        assert_eq!(counters.filter_count, 1);
        assert_eq!(counters.nxdomain_count, 1);
        assert_eq!(counters.error_count, 1);
    }

    #[test]
    fn counters_merge_sums_each_field() {
        let mut left = DnsCounters::default();
        left.record(&dns_metric(1, "a", "A", DnsOutcome::Normal, 1, 10));
        left.record(&dns_metric(1, "b", "A", DnsOutcome::Block, 2, 10));
        let mut right = DnsCounters::default();
        right.record(&dns_metric(1, "c", "AAAA", DnsOutcome::Hit, 3, 10));
        left.merge(&right);
        assert_eq!(left.total_queries, 3);
        assert_eq!(left.total_effective_queries, 2);
        assert_eq!(left.block_count, 1);
        assert_eq!(left.cache_hit_count, 1);
    }

    #[test]
    fn count_top_k_returns_sorted_top_capped_at_k() {
        let mut top = CountTopK::new(3);
        for (domain, count) in [("a", 1u64), ("b", 5), ("c", 3), ("d", 2), ("e", 4)] {
            for _ in 0..count {
                top.record(domain.to_string(), 1);
            }
        }
        let items = top.top();
        assert_eq!(items, vec![("b".to_string(), 5), ("e".to_string(), 4), ("c".to_string(), 3)]);
    }

    #[test]
    fn count_top_k_incremental_hot_keys_accumulate() {
        // 回归:逐条到达的热点键不得在满桶时被逐条淘汰。
        let mut top = CountTopK::new(2);
        for _ in 0..10 {
            top.record("hot".to_string(), 1);
        }
        for _ in 0..3 {
            top.record("warm".to_string(), 1);
        }
        for _ in 0..2 {
            top.record("cold".to_string(), 1);
        }
        let items = top.top();
        assert_eq!(items, vec![("hot".to_string(), 10), ("warm".to_string(), 3)]);
    }

    #[test]
    fn count_top_k_trim_keeps_exact_top_k() {
        let mut top = CountTopK::new(2);
        for (domain, count) in [("a", 1u64), ("b", 5), ("c", 3), ("d", 2), ("e", 4)] {
            for _ in 0..count {
                top.record(domain.to_string(), 1);
            }
        }
        top.trim();
        assert_eq!(top.entries.len(), 2);
        let items = top.top();
        assert_eq!(items, vec![("b".to_string(), 5), ("e".to_string(), 4)]);
    }

    #[test]
    fn slow_top_k_ranks_by_avg_duration() {
        let mut top = SlowTopK::new(10);
        top.record("slow".to_string(), 900);
        top.record("fast".to_string(), 10);
        top.record("fast".to_string(), 10);
        let items = top.top();
        assert_eq!(items[0], ("slow".to_string(), 1, 900));
        assert_eq!(items[1], ("fast".to_string(), 2, 20));
    }

    #[test]
    fn parts_merge_combines_counts_latency_and_tops() {
        let mut left = DnsSummaryParts::default();
        let mut right = DnsSummaryParts::default();
        left.counts.record(&dns_metric(1, "a", "A", DnsOutcome::Normal, 1, 100));
        right.counts.record(&dns_metric(1, "b", "A", DnsOutcome::Normal, 2, 200));
        let _ = left.latency.record(100);
        let _ = right.latency.record(200);
        left.top_domains.insert("a".to_string(), 1);
        right.top_domains.insert("a".to_string(), 1);
        right.top_domains.insert("b".to_string(), 1);
        left.merge(&right);
        assert_eq!(left.counts.total_queries, 2);
        assert_eq!(left.top_domains.get("a"), Some(&2));
        assert_eq!(left.top_domains.get("b"), Some(&1));
        let response = left.into_lightweight_response();
        assert_eq!(response.total_queries, 2);
        assert_eq!(response.avg_duration_ms, 150.0);
        assert_eq!(response.max_duration_ms, 200.0);
    }

    #[test]
    fn parts_ranked_slowest_filters_total_count_le_two() {
        let mut parts = DnsSummaryParts::default();
        parts.slowest.insert("one-shot".to_string(), (1, 900));
        parts.slowest.insert("repeated".to_string(), (3, 600));
        let ranked = parts.ranked_slowest(10);
        assert_eq!(ranked, vec![("repeated".to_string(), 3, 600)]);
    }

    #[test]
    fn bucket_row_merges_into_parts() {
        let mut row = DnsBucketRow {
            flow_id: 1,
            bucket_time: 100_000,
            report_time: 100_059,
            counts: DnsCounters::default(),
            latency: Histogram::<u64>::new(3).expect("create dns latency histogram"),
            top_domains: Vec::new(),
            top_clients: Vec::new(),
            top_blocked: Vec::new(),
            slowest: Vec::new(),
        };
        row.counts.record(&dns_metric(1, "a", "A", DnsOutcome::Normal, 100_010, 10));
        let _ = row.latency.record(10);
        row.top_domains.push(("a".to_string(), 1));
        row.slowest.push(("a".to_string(), 1, 10));

        let mut parts = DnsSummaryParts::default();
        parts.merge_bucket_row(&row);
        assert_eq!(parts.counts.total_queries, 1);
        assert_eq!(parts.top_domains.get("a"), Some(&1));
        let response = parts.into_lightweight_response();
        assert_eq!(response.avg_duration_ms, 10.0);
    }

    #[test]
    fn batch_rows_aggregate_per_flow_and_minute() {
        let metrics = vec![
            dns_metric(1, "a.com", "A", DnsOutcome::Normal, 60_000, 10),
            dns_metric(1, "a.com", "A", DnsOutcome::Block, 60_030, 5),
            dns_metric(1, "a.com", "AAAA", DnsOutcome::Normal, 120_000, 20),
            dns_metric(2, "b.com", "A", DnsOutcome::Normal, 60_010, 30),
        ];
        let rows = dns_bucket_rows_from_batch(&metrics);
        // 按 (flow_id, bucket_time) 排序:flow1 的两个分钟 + flow2 的一个分钟。
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows.iter().map(|row| (row.flow_id, row.bucket_time)).collect::<Vec<_>>(),
            vec![(1, 60_000), (1, 120_000), (2, 60_000)]
        );

        let flow1_min0 = &rows[0];
        assert_eq!(flow1_min0.counts.total_queries, 2, "same-minute metrics merged");
        assert_eq!(flow1_min0.counts.block_count, 1);
        assert_eq!(flow1_min0.report_time, 60_030, "row carries the batch's last metric time");
        assert_eq!(flow1_min0.top_domains, vec![("a.com".to_string(), 2)]);
        assert_eq!(flow1_min0.top_blocked, vec![("a.com".to_string(), 1)]);
        assert_eq!(flow1_min0.slowest, vec![("a.com".to_string(), 1, 10)]);

        let flow1_min1 = &rows[1];
        assert_eq!(flow1_min1.counts.total_queries, 1);
        assert_eq!(flow1_min1.counts.total_v6, 1);
        assert_eq!(flow1_min1.report_time, 120_000);

        let flow2 = &rows[2];
        assert_eq!(flow2.counts.total_queries, 1);
        assert_eq!(flow2.top_clients, vec![("10.0.0.2".to_string(), 1)]);
    }

    #[test]
    fn clean_ip_string_normalizes_mapped_ipv6() {
        assert_eq!(clean_ip_string(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), "10.0.0.1");
        let mapped = Ipv4Addr::new(192, 0, 2, 128).to_ipv6_mapped();
        assert_eq!(clean_ip_string(&IpAddr::V6(mapped)), "192.0.2.128");
        assert_eq!(clean_ip_string(&IpAddr::V6("2001:db8::1".parse().unwrap())), "2001:db8::1");
    }
}

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::metric::connect::{
    ConnectKey, ConnectMetric, ConnectMetricPoint, ConnectRealtimeStatus, ConnectStatusType,
    IfaceRealtimeStat, IpAggregatedStats, IpRealtimeStat,
};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::batch::{Batch, BucketKind};

pub(crate) const CHANNEL_CAPACITY: usize = 1024;
pub(crate) const MS_PER_MINUTE: u64 = 60 * 1000;
pub(crate) const MS_PER_HOUR: u64 = 60 * MS_PER_MINUTE;
pub(crate) const MS_PER_DAY: u64 = 24 * MS_PER_HOUR;
const MS_PER_TEN_MINUTES: u64 = 10 * MS_PER_MINUTE;
const STALE_TIMEOUT_MS: u64 = 5 * MS_PER_MINUTE;
const DEFAULT_CONNECT_SAMPLE_INTERVAL_MS: u64 = 5 * 1000;

fn read_or_recover<'a, T>(lock: &'a RwLock<T>, name: &str) -> RwLockReadGuard<'a, T> {
    lock.read().unwrap_or_else(|poisoned| {
        tracing::error!("{name} lock poisoned; recovering the inner state");
        poisoned.into_inner()
    })
}

fn write_or_recover<'a, T>(lock: &'a RwLock<T>, name: &str) -> RwLockWriteGuard<'a, T> {
    lock.write().unwrap_or_else(|poisoned| {
        tracing::error!("{name} lock poisoned; recovering the inner state");
        poisoned.into_inner()
    })
}

pub(crate) fn bucket_start(report_time: u64, bucket_ms: u64) -> u64 {
    report_time / bucket_ms * bucket_ms
}

pub(crate) fn minute_slot(report_time: u64) -> u64 {
    bucket_start(report_time, MS_PER_MINUTE)
}

pub(crate) fn hour_refresh_slot(report_time: u64) -> u64 {
    bucket_start(report_time, MS_PER_TEN_MINUTES)
}

pub(crate) fn day_refresh_slot(report_time: u64) -> u64 {
    bucket_start(report_time, MS_PER_HOUR)
}

pub(crate) fn second_window_ms(config: &MetricRuntimeConfig) -> u64 {
    config.connect_second_window_minutes.max(1).saturating_mul(MS_PER_MINUTE)
}

pub(crate) fn second_ring_capacity(config: &MetricRuntimeConfig) -> usize {
    let target_points = second_window_ms(config) / DEFAULT_CONNECT_SAMPLE_INTERVAL_MS;
    target_points.saturating_add(8).clamp(32, 4096) as usize
}

fn metric_to_point(metric: &ConnectMetric) -> ConnectMetricPoint {
    ConnectMetricPoint {
        report_time: metric.report_time,
        ingress_bytes: metric.ingress_bytes,
        ingress_packets: metric.ingress_packets,
        egress_bytes: metric.egress_bytes,
        egress_packets: metric.egress_packets,
        status: metric.status_type(),
    }
}

fn metric_to_realtime(metric: &ConnectMetric) -> ConnectRealtimeStatus {
    ConnectRealtimeStatus {
        key: metric.key(),
        src_ip: metric.src_ip(),
        dst_ip: metric.dst_ip(),
        src_port: metric.src_port,
        dst_port: metric.dst_port,
        l4_proto: metric.l4_proto,
        l3_proto: metric.l3_proto,
        flow_id: metric.flow_id,
        trace_id: metric.trace_id,
        gress: metric.gress,
        ifindex: metric.ifindex,
        create_time_ms: metric.create_time_ms(),
        ingress_bps: 0,
        egress_bps: 0,
        ingress_pps: 0,
        egress_pps: 0,
        last_report_time: metric.report_time,
        status: metric.status_type(),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FlowRateContribution {
    pub ifindex: u32,
    pub ingress_bps: u64,
    pub egress_bps: u64,
    pub ingress_pps: u64,
    pub egress_pps: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IfaceRealtimeAcc {
    pub ingress_bps: u64,
    pub egress_bps: u64,
    pub ingress_pps: u64,
    pub egress_pps: u64,
    pub active_conns: u32,
    pub last_report_time: u64,
}

impl IfaceRealtimeAcc {
    fn add_contribution(&mut self, contribution: FlowRateContribution, report_time: u64) {
        self.ingress_bps = self.ingress_bps.saturating_add(contribution.ingress_bps);
        self.egress_bps = self.egress_bps.saturating_add(contribution.egress_bps);
        self.ingress_pps = self.ingress_pps.saturating_add(contribution.ingress_pps);
        self.egress_pps = self.egress_pps.saturating_add(contribution.egress_pps);
        self.active_conns = self.active_conns.saturating_add(1);
        self.last_report_time = self.last_report_time.max(report_time);
    }

    fn remove_contribution(&mut self, contribution: FlowRateContribution) {
        self.ingress_bps = self.ingress_bps.saturating_sub(contribution.ingress_bps);
        self.egress_bps = self.egress_bps.saturating_sub(contribution.egress_bps);
        self.ingress_pps = self.ingress_pps.saturating_sub(contribution.ingress_pps);
        self.egress_pps = self.egress_pps.saturating_sub(contribution.egress_pps);
        self.active_conns = self.active_conns.saturating_sub(1);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MetricDelta {
    ingress_bytes: u64,
    ingress_packets: u64,
    egress_bytes: u64,
    egress_packets: u64,
}

impl MetricDelta {
    fn from_metrics(previous: &ConnectMetric, current: &ConnectMetric) -> Self {
        Self {
            ingress_bytes: current.ingress_bytes.saturating_sub(previous.ingress_bytes),
            ingress_packets: current.ingress_packets.saturating_sub(previous.ingress_packets),
            egress_bytes: current.egress_bytes.saturating_sub(previous.egress_bytes),
            egress_packets: current.egress_packets.saturating_sub(previous.egress_packets),
        }
    }

    fn from_initial(metric: &ConnectMetric) -> Self {
        Self {
            ingress_bytes: metric.ingress_bytes,
            ingress_packets: metric.ingress_packets,
            egress_bytes: metric.egress_bytes,
            egress_packets: metric.egress_packets,
        }
    }
}

pub(crate) type IfaceRealtimeCache = Arc<RwLock<HashMap<u32, IfaceRealtimeAcc>>>;

#[derive(Clone)]
pub(crate) struct FlowState {
    last_metric: ConnectMetric,
    realtime: ConnectRealtimeStatus,
    rate: FlowRateContribution,
    counted_in_iface_realtime: bool,
    second_ring: VecDeque<ConnectMetricPoint>,
    last_minute_slot: u64,
    last_hour_refresh_slot: u64,
    last_day_refresh_slot: u64,
    finalized: bool,
}

impl FlowState {
    fn new(metric: ConnectMetric, window_ms: u64, ring_cap: usize) -> Self {
        let report_time = metric.report_time;
        let mut second_ring = VecDeque::with_capacity(ring_cap.max(1));
        second_ring.push_back(metric_to_point(&metric));

        let rate = initial_rate_contribution(&metric);
        let mut realtime = metric_to_realtime(&metric);
        apply_rate_to_realtime(&mut realtime, rate);

        let mut state = Self {
            realtime,
            last_metric: metric,
            rate,
            counted_in_iface_realtime: false,
            second_ring,
            last_minute_slot: minute_slot(report_time),
            last_hour_refresh_slot: hour_refresh_slot(report_time),
            last_day_refresh_slot: day_refresh_slot(report_time),
            finalized: false,
        };
        state.trim_second_ring(window_ms, ring_cap);
        state
    }

    fn update_from_metric(&mut self, metric: ConnectMetric, window_ms: u64, ring_cap: usize) {
        let next_rate = if metric.report_time > self.last_metric.report_time {
            let delta_t = metric.report_time.saturating_sub(self.last_metric.report_time);
            rate_from_delta(
                metric.ifindex,
                MetricDelta::from_metrics(&self.last_metric, &metric),
                delta_t,
            )
        } else {
            FlowRateContribution { ifindex: metric.ifindex, ..self.rate }
        };

        self.realtime.last_report_time = metric.report_time;
        self.realtime.src_ip = metric.src_ip();
        self.realtime.dst_ip = metric.dst_ip();
        self.realtime.src_port = metric.src_port;
        self.realtime.dst_port = metric.dst_port;
        self.realtime.l4_proto = metric.l4_proto;
        self.realtime.l3_proto = metric.l3_proto;
        self.realtime.flow_id = metric.flow_id;
        self.realtime.trace_id = metric.trace_id;
        self.realtime.gress = metric.gress;
        self.realtime.ifindex = metric.ifindex;
        self.realtime.create_time_ms = metric.create_time_ms();
        apply_rate_to_realtime(&mut self.realtime, next_rate);
        if metric.status_type() != ConnectStatusType::Unknow {
            self.realtime.status = metric.status_type();
        }

        self.last_metric = metric.clone();
        self.rate = next_rate;
        self.second_ring.push_back(metric_to_point(&metric));
        self.finalized = false;
        self.trim_second_ring(window_ms, ring_cap);
    }

    fn should_count_iface_realtime(&self) -> bool {
        !self.finalized && self.realtime.status != ConnectStatusType::Disabled
    }

    fn trim_second_ring(&mut self, window_ms: u64, ring_cap: usize) {
        let cutoff = self.realtime.last_report_time.saturating_sub(window_ms);
        self.trim_second_ring_before(cutoff);
        while self.second_ring.len() > ring_cap.max(1) {
            self.second_ring.pop_front();
        }
    }

    fn trim_second_ring_before(&mut self, cutoff: u64) {
        while let Some(point) = self.second_ring.front() {
            if point.report_time >= cutoff {
                break;
            }
            self.second_ring.pop_front();
        }
    }

    fn second_points_since(&self, cutoff: u64) -> Vec<ConnectMetricPoint> {
        self.second_ring.iter().filter(|point| point.report_time >= cutoff).cloned().collect()
    }

    fn is_active(&self, now_ms: u64) -> bool {
        !self.finalized
            && self.realtime.status != ConnectStatusType::Disabled
            && self.realtime.last_report_time >= now_ms.saturating_sub(STALE_TIMEOUT_MS)
    }
}

fn rate_from_delta(ifindex: u32, delta: MetricDelta, delta_t_ms: u64) -> FlowRateContribution {
    if delta_t_ms == 0 {
        return FlowRateContribution { ifindex, ..Default::default() };
    }

    FlowRateContribution {
        ifindex,
        ingress_bps: delta.ingress_bytes.saturating_mul(8000) / delta_t_ms,
        egress_bps: delta.egress_bytes.saturating_mul(8000) / delta_t_ms,
        ingress_pps: delta.ingress_packets.saturating_mul(1000) / delta_t_ms,
        egress_pps: delta.egress_packets.saturating_mul(1000) / delta_t_ms,
    }
}

fn initial_rate_contribution(metric: &ConnectMetric) -> FlowRateContribution {
    let start_time = metric.create_time_ms().min(metric.report_time);
    let delta_t = metric.report_time.saturating_sub(start_time);
    rate_from_delta(metric.ifindex, MetricDelta::from_initial(metric), delta_t)
}

fn apply_rate_to_realtime(realtime: &mut ConnectRealtimeStatus, rate: FlowRateContribution) {
    realtime.ingress_bps = rate.ingress_bps;
    realtime.egress_bps = rate.egress_bps;
    realtime.ingress_pps = rate.ingress_pps;
    realtime.egress_pps = rate.egress_pps;
}

pub(crate) type FlowCache = Arc<RwLock<HashMap<ConnectKey, FlowState>>>;

fn add_iface_realtime_contribution(
    iface_realtime: &IfaceRealtimeCache,
    contribution: FlowRateContribution,
    report_time: u64,
) {
    let mut cache = write_or_recover(iface_realtime, "metric iface realtime cache");
    cache.entry(contribution.ifindex).or_default().add_contribution(contribution, report_time);
}

fn remove_iface_realtime_contribution(
    iface_realtime: &IfaceRealtimeCache,
    contribution: FlowRateContribution,
) {
    let mut cache = write_or_recover(iface_realtime, "metric iface realtime cache");
    if let Some(acc) = cache.get_mut(&contribution.ifindex) {
        acc.remove_contribution(contribution);
        if acc.active_conns == 0 {
            cache.remove(&contribution.ifindex);
        }
    }
}

fn remove_state_iface_realtime(iface_realtime: &IfaceRealtimeCache, state: &mut FlowState) {
    if !state.counted_in_iface_realtime {
        return;
    }

    remove_iface_realtime_contribution(iface_realtime, state.rate);
    state.counted_in_iface_realtime = false;
}

fn add_state_iface_realtime(iface_realtime: &IfaceRealtimeCache, state: &mut FlowState) {
    if state.counted_in_iface_realtime || !state.should_count_iface_realtime() {
        return;
    }

    add_iface_realtime_contribution(iface_realtime, state.rate, state.realtime.last_report_time);
    state.counted_in_iface_realtime = true;
}

fn finalize_state_batch(
    state: &mut FlowState,
    mark_disabled: bool,
    batch: &mut Batch,
    iface_realtime: &IfaceRealtimeCache,
) {
    if state.finalized {
        return;
    }

    remove_state_iface_realtime(iface_realtime, state);

    let mut metric = state.last_metric.clone();
    if mark_disabled {
        metric.status = ConnectStatusType::Disabled.into();
        state.last_metric.status = ConnectStatusType::Disabled.into();
        state.realtime.status = ConnectStatusType::Disabled;
    }

    batch.push_bucket(BucketKind::Minute, metric.clone(), minute_slot(metric.report_time));
    batch.push_bucket(
        BucketKind::Hour,
        metric.clone(),
        bucket_start(metric.report_time, MS_PER_HOUR),
    );
    batch.push_bucket(
        BucketKind::Day,
        metric.clone(),
        bucket_start(metric.report_time, MS_PER_DAY),
    );
    batch.push_summary(metric);
    state.finalized = true;
}

/// 聚合一条连接指标:维护 flow 状态机,产出跨分钟/小时/日边界及终结时的批次片段。
pub(crate) fn process_connect_metric(
    flow_cache: &FlowCache,
    iface_realtime: &IfaceRealtimeCache,
    metric: ConnectMetric,
    second_window_ms: u64,
    second_ring_cap: usize,
) -> Batch {
    let curr_minute_slot = minute_slot(metric.report_time);
    let curr_hour_refresh_slot = hour_refresh_slot(metric.report_time);
    let curr_day_refresh_slot = day_refresh_slot(metric.report_time);

    let mut batch = Batch::default();
    let mut cache = write_or_recover(flow_cache, "metric flow cache");
    match cache.entry(metric.key()) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let state = entry.get_mut();
            if metric.report_time < state.last_metric.report_time {
                return batch;
            }

            remove_state_iface_realtime(iface_realtime, state);

            let previous_minute_bucket = minute_slot(state.last_metric.report_time);
            let previous_hour_bucket = bucket_start(state.last_metric.report_time, MS_PER_HOUR);
            let previous_day_bucket = bucket_start(state.last_metric.report_time, MS_PER_DAY);

            if curr_minute_slot > state.last_minute_slot {
                batch.push_bucket(BucketKind::Minute, metric.clone(), previous_minute_bucket);
                batch.push_summary(metric.clone());
                state.last_minute_slot = curr_minute_slot;
            }
            if curr_hour_refresh_slot > state.last_hour_refresh_slot {
                batch.push_bucket(BucketKind::Hour, metric.clone(), previous_hour_bucket);
                state.last_hour_refresh_slot = curr_hour_refresh_slot;
            }
            if curr_day_refresh_slot > state.last_day_refresh_slot {
                batch.push_bucket(BucketKind::Day, metric.clone(), previous_day_bucket);
                state.last_day_refresh_slot = curr_day_refresh_slot;
            }

            let should_finalize = metric.status_type() == ConnectStatusType::Disabled;
            state.update_from_metric(metric, second_window_ms, second_ring_cap);
            if should_finalize {
                finalize_state_batch(state, true, &mut batch, iface_realtime);
            } else {
                add_state_iface_realtime(iface_realtime, state);
            }
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            let should_finalize = metric.status_type() == ConnectStatusType::Disabled;
            let mut state = FlowState::new(metric, second_window_ms, second_ring_cap);
            if should_finalize {
                finalize_state_batch(&mut state, true, &mut batch, iface_realtime);
            } else {
                add_state_iface_realtime(iface_realtime, &mut state);
            }
            entry.insert(state);
        }
    }

    batch
}

#[derive(Default)]
pub(crate) struct FlowCacheStats {
    pub active_flows: usize,
    pub finalized_flows: usize,
    pub finalized_in_run: usize,
    pub second_ring_points: usize,
}

pub(crate) fn cleanup_flow_cache(
    flow_cache: &FlowCache,
    iface_realtime: &IfaceRealtimeCache,
    now_ms: u64,
    second_window_ms: u64,
) -> (FlowCacheStats, Batch) {
    let stale_cutoff = now_ms.saturating_sub(STALE_TIMEOUT_MS);
    let window_cutoff = now_ms.saturating_sub(second_window_ms);

    let mut cache = write_or_recover(flow_cache, "metric flow cache");
    let mut expired_keys = Vec::new();
    let mut stats = FlowCacheStats::default();
    let mut batch = Batch::default();

    for (key, state) in cache.iter_mut() {
        if !state.finalized && state.realtime.last_report_time < stale_cutoff {
            finalize_state_batch(state, true, &mut batch, iface_realtime);
            stats.finalized_in_run += 1;
        }

        state.trim_second_ring_before(window_cutoff);
        stats.second_ring_points += state.second_ring.len();

        if state.finalized {
            stats.finalized_flows += 1;
        } else if state.is_active(now_ms) {
            stats.active_flows += 1;
        }

        if state.finalized && state.realtime.last_report_time < window_cutoff {
            expired_keys.push(key.clone());
        }
    }

    for key in expired_keys {
        cache.remove(&key);
    }

    (stats, batch)
}

#[cfg(feature = "metric-persistent")]
pub(crate) fn finalize_all_flows(
    flow_cache: &FlowCache,
    iface_realtime: &IfaceRealtimeCache,
) -> Batch {
    let mut cache = write_or_recover(flow_cache, "metric flow cache");
    let mut batch = Batch::default();
    for state in cache.values_mut() {
        finalize_state_batch(state, true, &mut batch, iface_realtime);
    }
    batch
}

pub(crate) fn collect_connect_infos(
    flow_cache: &FlowCache,
    now_ms: u64,
) -> Vec<ConnectRealtimeStatus> {
    let cache = read_or_recover(flow_cache, "metric flow cache");
    let mut infos: Vec<_> = cache
        .values()
        .filter(|state| state.is_active(now_ms))
        .map(|state| state.realtime.clone())
        .collect();
    infos.sort_by_key(|i| std::cmp::Reverse(i.last_report_time));
    infos
}

pub(crate) fn collect_realtime_ip_stats(
    flow_cache: &FlowCache,
    now_ms: u64,
    is_src: bool,
) -> Vec<IpRealtimeStat> {
    let cache = read_or_recover(flow_cache, "metric flow cache");
    let mut stats_map: HashMap<IpAddr, IpAggregatedStats> = HashMap::new();

    for state in cache.values().filter(|state| state.is_active(now_ms)) {
        let ip = if is_src { state.realtime.src_ip } else { state.realtime.dst_ip };
        let stats = stats_map.entry(ip).or_default();
        stats.ingress_bps += state.realtime.ingress_bps;
        stats.egress_bps += state.realtime.egress_bps;
        stats.ingress_pps += state.realtime.ingress_pps;
        stats.egress_pps += state.realtime.egress_pps;
        stats.active_conns += 1;
    }

    stats_map.into_iter().map(|(ip, stats)| IpRealtimeStat { ip, stats }).collect()
}

/// 实时接口统计直接读写路径上增量维护的 iface_realtime 缓存(单一数据源),
/// 与 flow_cache 全扫结果一致,但查询开销与活跃接口数成正比而非连接数。
pub(crate) fn collect_realtime_iface_stats(
    iface_realtime: &IfaceRealtimeCache,
    now_ms: u64,
) -> Vec<IfaceRealtimeStat> {
    let stale_cutoff = now_ms.saturating_sub(STALE_TIMEOUT_MS);
    let cache = read_or_recover(iface_realtime, "metric iface realtime cache");
    let mut stats: Vec<_> = cache
        .iter()
        .filter(|(_, acc)| acc.last_report_time >= stale_cutoff)
        .map(|(ifindex, acc)| IfaceRealtimeStat {
            ifindex: *ifindex,
            stats: IpAggregatedStats {
                ingress_bps: acc.ingress_bps,
                egress_bps: acc.egress_bps,
                ingress_pps: acc.ingress_pps,
                egress_pps: acc.egress_pps,
                active_conns: acc.active_conns,
            },
            last_report_time: acc.last_report_time,
        })
        .collect();
    stats.sort_by_key(|s| std::cmp::Reverse(s.stats.ingress_bps));
    stats
}

pub(crate) fn second_points_by_key(
    flow_cache: &FlowCache,
    key: &ConnectKey,
    cutoff: u64,
) -> Vec<ConnectMetricPoint> {
    let cache = read_or_recover(flow_cache, "metric flow cache");
    cache.get(key).map(|state| state.second_points_since(cutoff)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_metric(
        create_time: u64,
        cpu_id: u32,
        report_time: u64,
        ingress_bytes: u64,
        egress_bytes: u64,
    ) -> ConnectMetric {
        ConnectMetric::from_domain(
            create_time,
            cpu_id,
            report_time,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            10_000 + cpu_id as u16,
            20_000 + cpu_id as u16,
            cpu_id as u8,
            cpu_id as u8,
            cpu_id + 10,
            ingress_bytes,
            ingress_bytes / 10,
            egress_bytes,
            egress_bytes / 10,
            ConnectStatusType::Active,
        )
    }

    fn test_caches() -> (FlowCache, IfaceRealtimeCache) {
        (Arc::new(RwLock::new(HashMap::new())), Arc::new(RwLock::new(HashMap::new())))
    }

    const WINDOW_MS: u64 = 5 * 60 * 1000;
    const RING_CAP: usize = 64;

    #[test]
    fn process_connect_metric_creates_active_flow_without_batch() {
        let (flow, iface_realtime) = test_caches();
        let batch = process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        assert!(batch.is_empty());

        let infos = collect_connect_infos(&flow, 70_000);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].key.cpu_id, 0);
        assert!(infos[0].ingress_bps > 0);
        assert!(infos[0].egress_bps > 0);
    }

    #[test]
    fn process_connect_metric_disabled_flow_emits_buckets_and_summary() {
        let (flow, iface_realtime) = test_caches();
        let mut metric = test_metric(1_000, 0, 60_000, 100, 200);
        metric.status = ConnectStatusType::Disabled.into();
        let batch = process_connect_metric(&flow, &iface_realtime, metric, WINDOW_MS, RING_CAP);

        assert_eq!(batch.summary_metrics.len(), 1);
        assert_eq!(batch.bucket_writes.len(), 3);
        let kinds: Vec<_> = batch.bucket_writes.iter().map(|w| w.kind).collect();
        assert!(kinds.contains(&BucketKind::Minute));
        assert!(kinds.contains(&BucketKind::Hour));
        assert!(kinds.contains(&BucketKind::Day));
        assert_eq!(batch.bucket_writes[0].bucket_report_time, 60_000);

        assert!(collect_connect_infos(&flow, 70_000).is_empty());
    }

    #[test]
    fn minute_slot_transition_emits_minute_bucket_and_summary() {
        let (flow, iface_realtime) = test_caches();
        let first = process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        assert!(first.is_empty());

        let second = process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 120_000, 300, 600),
            WINDOW_MS,
            RING_CAP,
        );
        assert_eq!(second.summary_metrics.len(), 1);
        assert_eq!(second.bucket_writes.len(), 1);
        assert_eq!(second.bucket_writes[0].kind, BucketKind::Minute);
        assert_eq!(second.bucket_writes[0].bucket_report_time, 60_000);
        assert_eq!(second.summary_metrics[0].ingress_bytes, 300);
    }

    #[test]
    fn stale_flow_is_finalized_and_removed_by_cleanup() {
        let (flow, iface_realtime) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );

        let now_ms = 60_000 + STALE_TIMEOUT_MS + 40_000;
        let (stats, batch) = cleanup_flow_cache(&flow, &iface_realtime, now_ms, WINDOW_MS);
        assert_eq!(stats.finalized_in_run, 1);
        assert_eq!(stats.finalized_flows, 1);
        assert_eq!(batch.bucket_writes.len(), 3);
        assert!(collect_connect_infos(&flow, now_ms).is_empty());
    }

    #[test]
    fn active_flow_survives_cleanup_within_window() {
        let (flow, iface_realtime) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );

        let now_ms = 60_000 + 60_000;
        let (stats, batch) = cleanup_flow_cache(&flow, &iface_realtime, now_ms, WINDOW_MS);
        assert_eq!(stats.finalized_in_run, 0);
        assert_eq!(stats.active_flows, 1);
        assert!(batch.is_empty());
        assert_eq!(collect_connect_infos(&flow, now_ms).len(), 1);
    }

    #[test]
    fn second_ring_points_respect_window_cutoff() {
        let (flow, iface_realtime) = test_caches();
        let key = ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 0 };
        for t in [60_000u64, 61_000, 62_000, 63_000] {
            process_connect_metric(
                &flow,
                &iface_realtime,
                test_metric(1_000, 0, t, 100, 200),
                WINDOW_MS,
                RING_CAP,
            );
        }

        let points = second_points_by_key(&flow, &key, 62_000);
        let times: Vec<_> = points.iter().map(|p| p.report_time).collect();
        assert_eq!(times, vec![62_000, 63_000]);
    }

    #[test]
    fn realtime_ip_stats_aggregate_by_source_ip() {
        let (flow, iface_realtime) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(2_000, 1, 61_000, 300, 400),
            WINDOW_MS,
            RING_CAP,
        );

        let stats = collect_realtime_ip_stats(&flow, 70_000, true);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].stats.active_conns, 2);
        assert!(stats[0].stats.ingress_bps > 0);
    }

    #[test]
    fn iface_realtime_stats_read_incremental_cache() {
        let (flow, iface_realtime) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(2_000, 1, 61_000, 300, 400),
            WINDOW_MS,
            RING_CAP,
        );

        let stats = collect_realtime_iface_stats(&iface_realtime, 70_000);
        assert_eq!(stats.len(), 2);
        assert!(stats.iter().all(|s| s.stats.active_conns == 1));
        let total_conns: u32 = stats.iter().map(|s| s.stats.active_conns).sum();
        assert_eq!(total_conns, 2);
    }

    #[test]
    fn finalized_flows_leave_iface_realtime_cache() {
        let (flow, iface_realtime) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        assert_eq!(collect_realtime_iface_stats(&iface_realtime, 70_000).len(), 1);

        let mut closed = test_metric(1_000, 0, 61_000, 200, 400);
        closed.status = ConnectStatusType::Disabled.into();
        process_connect_metric(&flow, &iface_realtime, closed, WINDOW_MS, RING_CAP);

        assert!(collect_realtime_iface_stats(&iface_realtime, 70_000).is_empty());
    }

    fn test_config(window_minutes: u64) -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: landscape_common::config::MetricMode::Memory,
            connect_second_window_minutes: window_minutes,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 7,
            connect_1d_retention_days: 30,
            connect_summary_retention_days: 30,
            connect_summary_max_rows: 0,
            connect_db_max_bytes: landscape_common::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES,
            dns_retention_days: 7,
            dns_1m_retention_days: 30,
            dns_db_max_bytes: landscape_common::DEFAULT_DNS_METRIC_DB_MAX_BYTES,
            write_batch_size: 2,
            write_flush_interval_secs: 3600,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1_000,
            cleanup_slice_window_secs: 60,
        }
    }

    #[test]
    fn bucket_start_aligns_down_to_bucket_boundary() {
        assert_eq!(bucket_start(60_000, MS_PER_MINUTE), 60_000);
        assert_eq!(bucket_start(65_000, MS_PER_MINUTE), 60_000);
        assert_eq!(bucket_start(59_999, MS_PER_MINUTE), 0);
        assert_eq!(bucket_start(3_700_000, MS_PER_HOUR), 3_600_000);
        assert_eq!(bucket_start(86_400_000, MS_PER_DAY), 86_400_000);
        assert_eq!(bucket_start(86_400_001, MS_PER_DAY), 86_400_000);
    }

    #[test]
    fn slot_helpers_use_expected_granularity() {
        assert_eq!(minute_slot(61_000), 60_000);
        assert_eq!(hour_refresh_slot(605_000), 600_000);
        assert_eq!(hour_refresh_slot(599_999), 0);
        assert_eq!(day_refresh_slot(3_700_000), 3_600_000);
        assert_eq!(day_refresh_slot(7_199_999), 7_200_000 - MS_PER_HOUR);
    }

    #[test]
    fn second_window_ms_clamps_to_one_minute() {
        assert_eq!(second_window_ms(&test_config(0)), 60_000);
        assert_eq!(second_window_ms(&test_config(5)), 5 * 60 * 1000);
    }

    #[test]
    fn second_ring_capacity_respects_clamp_bounds() {
        assert_eq!(second_ring_capacity(&test_config(1)), 32);
        assert_eq!(second_ring_capacity(&test_config(5)), 68);
        assert_eq!(second_ring_capacity(&test_config(340)), 4088);
        assert_eq!(second_ring_capacity(&test_config(100_000)), 4096);
    }

    #[cfg(feature = "metric-persistent")]
    #[test]
    fn finalize_all_flows_emits_disabled_batches_and_clears_realtime() {
        let (flow, iface_realtime) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        process_connect_metric(
            &flow,
            &iface_realtime,
            test_metric(2_000, 1, 61_000, 300, 400),
            WINDOW_MS,
            RING_CAP,
        );
        assert_eq!(collect_realtime_iface_stats(&iface_realtime, 70_000).len(), 2);

        let batch = finalize_all_flows(&flow, &iface_realtime);
        assert_eq!(batch.summary_metrics.len(), 2);
        assert_eq!(batch.bucket_writes.len(), 6);
        assert!(batch
            .summary_metrics
            .iter()
            .all(|m| m.status_type() == ConnectStatusType::Disabled));
        assert!(collect_connect_infos(&flow, 70_000).is_empty());
        assert!(collect_realtime_iface_stats(&iface_realtime, 70_000).is_empty());

        let second = finalize_all_flows(&flow, &iface_realtime);
        assert!(second.is_empty());
    }
}

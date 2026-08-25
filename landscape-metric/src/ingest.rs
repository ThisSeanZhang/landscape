use landscape_common::config::MetricRuntimeConfig;
use landscape_common::metric::connect::{
    ConnectKey, ConnectMetric, ConnectMetricPoint, ConnectRealtimeStatus, ConnectStatusType,
    IfaceRealtimeStat, IpAggregatedStats, IpRealtimeStat,
};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

pub(crate) const CHANNEL_CAPACITY: usize = 1024;
pub(crate) const MS_PER_MINUTE: u64 = 60 * 1000;
pub(crate) const MS_PER_HOUR: u64 = 60 * MS_PER_MINUTE;
pub(crate) const MS_PER_DAY: u64 = 24 * MS_PER_HOUR;
pub(crate) const IFACE_BUCKET_MS: u64 = 5 * 1000;
const MS_PER_TEN_MINUTES: u64 = 10 * MS_PER_MINUTE;
const STALE_TIMEOUT_MS: u64 = 5 * MS_PER_MINUTE;
const DEFAULT_CONNECT_SAMPLE_INTERVAL_MS: u64 = 5 * 1000;

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

#[cfg(feature = "metric-persistent")]
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

fn metric_to_point(metric: &ConnectMetric) -> ConnectMetricPoint {
    ConnectMetricPoint {
        report_time: metric.report_time,
        ingress_bytes: metric.ingress_bytes,
        ingress_packets: metric.ingress_packets,
        egress_bytes: metric.egress_bytes,
        egress_packets: metric.egress_packets,
        status: metric.status.clone(),
    }
}

fn metric_to_realtime(metric: &ConnectMetric) -> ConnectRealtimeStatus {
    ConnectRealtimeStatus {
        key: metric.key.clone(),
        src_ip: metric.src_ip,
        dst_ip: metric.dst_ip,
        src_port: metric.src_port,
        dst_port: metric.dst_port,
        l4_proto: metric.l4_proto,
        l3_proto: metric.l3_proto,
        flow_id: metric.flow_id,
        trace_id: metric.trace_id,
        gress: metric.gress,
        ifindex: metric.ifindex,
        create_time_ms: metric.create_time_ms,
        ingress_bps: 0,
        egress_bps: 0,
        ingress_pps: 0,
        egress_pps: 0,
        last_report_time: metric.report_time,
        status: metric.status.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "metric-persistent"), allow(dead_code))]
pub(crate) enum BucketKind {
    Minute,
    Hour,
    Day,
}

#[cfg_attr(not(feature = "metric-persistent"), allow(dead_code))]
impl BucketKind {
    pub(crate) fn table_name(self) -> &'static str {
        match self {
            Self::Minute => "conn_metrics_1m",
            Self::Hour => "conn_metrics_1h",
            Self::Day => "conn_metrics_1d",
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "metric-persistent"), allow(dead_code))]
pub(crate) struct BucketWrite {
    pub kind: BucketKind,
    pub metric: ConnectMetric,
    pub bucket_report_time: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IfaceBucketKey {
    pub ifindex: u32,
    pub bucket_start: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IfaceBucketAcc {
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
    pub active_conns: u32,
    pub last_report_time: u64,
}

impl IfaceBucketAcc {
    fn add_delta(&mut self, delta: MetricDelta, report_time: u64) {
        self.ingress_bytes = self.ingress_bytes.saturating_add(delta.ingress_bytes);
        self.ingress_packets = self.ingress_packets.saturating_add(delta.ingress_packets);
        self.egress_bytes = self.egress_bytes.saturating_add(delta.egress_bytes);
        self.egress_packets = self.egress_packets.saturating_add(delta.egress_packets);
        self.last_report_time = self.last_report_time.max(report_time);
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

    fn is_zero(self) -> bool {
        self.ingress_bytes == 0
            && self.ingress_packets == 0
            && self.egress_bytes == 0
            && self.egress_packets == 0
    }

    fn scale(self, numerator: u64, denominator: u64) -> Self {
        if denominator == 0 {
            return Self::default();
        }
        Self {
            ingress_bytes: scale_u64(self.ingress_bytes, numerator, denominator),
            ingress_packets: scale_u64(self.ingress_packets, numerator, denominator),
            egress_bytes: scale_u64(self.egress_bytes, numerator, denominator),
            egress_packets: scale_u64(self.egress_packets, numerator, denominator),
        }
    }

    fn saturating_sub(self, other: Self) -> Self {
        Self {
            ingress_bytes: self.ingress_bytes.saturating_sub(other.ingress_bytes),
            ingress_packets: self.ingress_packets.saturating_sub(other.ingress_packets),
            egress_bytes: self.egress_bytes.saturating_sub(other.egress_bytes),
            egress_packets: self.egress_packets.saturating_sub(other.egress_packets),
        }
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            ingress_bytes: self.ingress_bytes.saturating_add(other.ingress_bytes),
            ingress_packets: self.ingress_packets.saturating_add(other.ingress_packets),
            egress_bytes: self.egress_bytes.saturating_add(other.egress_bytes),
            egress_packets: self.egress_packets.saturating_add(other.egress_packets),
        }
    }
}

fn scale_u64(value: u64, numerator: u64, denominator: u64) -> u64 {
    ((value as u128).saturating_mul(numerator as u128) / denominator as u128) as u64
}

pub(crate) type IfaceRealtimeCache = Arc<RwLock<HashMap<u32, IfaceRealtimeAcc>>>;
pub(crate) type IfaceBucketCache = Arc<RwLock<HashMap<IfaceBucketKey, IfaceBucketAcc>>>;

#[derive(Debug, Clone, Default)]
#[cfg_attr(not(feature = "metric-persistent"), allow(dead_code))]
pub(crate) struct PersistenceBatch {
    pub summary_metrics: Vec<ConnectMetric>,
    pub bucket_writes: Vec<BucketWrite>,
    pub iface_bucket_writes: Vec<IfaceBucketWrite>,
}

#[cfg_attr(not(feature = "metric-persistent"), allow(dead_code))]
impl PersistenceBatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.summary_metrics.is_empty()
            && self.bucket_writes.is_empty()
            && self.iface_bucket_writes.is_empty()
    }

    pub(crate) fn op_count(&self) -> usize {
        self.summary_metrics.len() + self.bucket_writes.len() + self.iface_bucket_writes.len()
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.summary_metrics.extend(other.summary_metrics);
        self.bucket_writes.extend(other.bucket_writes);
        self.iface_bucket_writes.extend(other.iface_bucket_writes);
    }

    fn push_summary(&mut self, metric: ConnectMetric) {
        self.summary_metrics.push(metric);
    }

    fn push_bucket(&mut self, kind: BucketKind, metric: ConnectMetric, bucket_report_time: u64) {
        self.bucket_writes.push(BucketWrite { kind, metric, bucket_report_time });
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct IfaceBucketWrite {
    pub ifindex: u32,
    pub report_time: u64,
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
    pub active_conns: u32,
}

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
        self.realtime.src_ip = metric.src_ip;
        self.realtime.dst_ip = metric.dst_ip;
        self.realtime.src_port = metric.src_port;
        self.realtime.dst_port = metric.dst_port;
        self.realtime.l4_proto = metric.l4_proto;
        self.realtime.l3_proto = metric.l3_proto;
        self.realtime.flow_id = metric.flow_id;
        self.realtime.trace_id = metric.trace_id;
        self.realtime.gress = metric.gress;
        self.realtime.ifindex = metric.ifindex;
        self.realtime.create_time_ms = metric.create_time_ms;
        apply_rate_to_realtime(&mut self.realtime, next_rate);
        if metric.status != ConnectStatusType::Unknow {
            self.realtime.status = metric.status.clone();
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
    let start_time = metric.create_time_ms.min(metric.report_time);
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
    let mut cache = iface_realtime.write().expect("metric iface realtime cache poisoned");
    cache.entry(contribution.ifindex).or_default().add_contribution(contribution, report_time);
}

fn remove_iface_realtime_contribution(
    iface_realtime: &IfaceRealtimeCache,
    contribution: FlowRateContribution,
) {
    let mut cache = iface_realtime.write().expect("metric iface realtime cache poisoned");
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
    batch: &mut PersistenceBatch,
    iface_realtime: &IfaceRealtimeCache,
) {
    if state.finalized {
        return;
    }

    remove_state_iface_realtime(iface_realtime, state);

    let mut metric = state.last_metric.clone();
    if mark_disabled {
        metric.status = ConnectStatusType::Disabled;
        state.last_metric.status = ConnectStatusType::Disabled;
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

fn record_iface_delta(
    iface_buckets: &IfaceBucketCache,
    ifindex: u32,
    start_time: u64,
    end_time: u64,
    delta: MetricDelta,
) {
    if delta.is_zero() {
        return;
    }

    let mut cache = iface_buckets.write().expect("metric iface bucket cache poisoned");
    if end_time <= start_time {
        let bucket_start = bucket_start(end_time, IFACE_BUCKET_MS);
        cache
            .entry(IfaceBucketKey { ifindex, bucket_start })
            .or_default()
            .add_delta(delta, end_time);
        return;
    }

    let total_duration = end_time - start_time;
    let mut cursor = start_time;
    let mut assigned = MetricDelta::default();
    while cursor < end_time {
        let bucket = bucket_start(cursor, IFACE_BUCKET_MS);
        let bucket_end = bucket.saturating_add(IFACE_BUCKET_MS).min(end_time);
        let segment_duration = bucket_end.saturating_sub(cursor);
        let mut segment_delta = delta.scale(segment_duration, total_duration);
        let is_last = bucket_end >= end_time;
        if is_last {
            segment_delta = delta.saturating_sub(assigned);
        } else {
            assigned = assigned.saturating_add(segment_delta);
        }

        cache
            .entry(IfaceBucketKey { ifindex, bucket_start: bucket })
            .or_default()
            .add_delta(segment_delta, bucket_end);
        cursor = bucket_end;
    }
}

fn record_metric_iface_delta(
    iface_buckets: &IfaceBucketCache,
    previous: Option<&ConnectMetric>,
    metric: &ConnectMetric,
) {
    let (start_time, delta) = match previous {
        Some(previous) => (previous.report_time, MetricDelta::from_metrics(previous, metric)),
        None => return,
    };
    record_iface_delta(iface_buckets, metric.ifindex, start_time, metric.report_time, delta);
}

pub(crate) fn drain_iface_buckets(
    iface_buckets: &IfaceBucketCache,
    iface_realtime: &IfaceRealtimeCache,
) -> Vec<IfaceBucketWrite> {
    let realtime = iface_realtime.read().expect("metric iface realtime cache poisoned");
    let mut buckets = iface_buckets.write().expect("metric iface bucket cache poisoned");
    let mut writes: Vec<_> = buckets
        .drain()
        .map(|(key, acc)| {
            let active_conns = realtime.get(&key.ifindex).map(|acc| acc.active_conns).unwrap_or(0);
            IfaceBucketWrite {
                ifindex: key.ifindex,
                report_time: key.bucket_start,
                ingress_bytes: acc.ingress_bytes,
                ingress_packets: acc.ingress_packets,
                egress_bytes: acc.egress_bytes,
                egress_packets: acc.egress_packets,
                active_conns,
            }
        })
        .collect();
    writes.sort_by_key(|w| (w.report_time, w.ifindex));
    writes
}

pub(crate) fn process_connect_metric(
    flow_cache: &FlowCache,
    iface_realtime: &IfaceRealtimeCache,
    iface_buckets: &IfaceBucketCache,
    metric: ConnectMetric,
    second_window_ms: u64,
    second_ring_cap: usize,
) -> PersistenceBatch {
    let curr_minute_slot = minute_slot(metric.report_time);
    let curr_hour_refresh_slot = hour_refresh_slot(metric.report_time);
    let curr_day_refresh_slot = day_refresh_slot(metric.report_time);

    let mut batch = PersistenceBatch::default();
    let mut cache = flow_cache.write().expect("metric flow cache poisoned");
    match cache.entry(metric.key.clone()) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let state = entry.get_mut();
            if metric.report_time < state.last_metric.report_time {
                return batch;
            }

            record_metric_iface_delta(iface_buckets, Some(&state.last_metric), &metric);
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

            let should_finalize = metric.status == ConnectStatusType::Disabled;
            state.update_from_metric(metric, second_window_ms, second_ring_cap);
            if should_finalize {
                finalize_state_batch(state, true, &mut batch, iface_realtime);
            } else {
                add_state_iface_realtime(iface_realtime, state);
            }
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            record_metric_iface_delta(iface_buckets, None, &metric);
            let should_finalize = metric.status == ConnectStatusType::Disabled;
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
#[cfg_attr(not(feature = "metric-persistent"), allow(dead_code))]
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
) -> (FlowCacheStats, PersistenceBatch) {
    let stale_cutoff = now_ms.saturating_sub(STALE_TIMEOUT_MS);
    let window_cutoff = now_ms.saturating_sub(second_window_ms);

    let mut cache = flow_cache.write().expect("metric flow cache poisoned");
    let mut expired_keys = Vec::new();
    let mut stats = FlowCacheStats::default();
    let mut batch = PersistenceBatch::default();

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
) -> PersistenceBatch {
    let mut cache = flow_cache.write().expect("metric flow cache poisoned");
    let mut batch = PersistenceBatch::default();
    for state in cache.values_mut() {
        finalize_state_batch(state, true, &mut batch, iface_realtime);
    }
    batch
}

pub(crate) fn collect_connect_infos(
    flow_cache: &FlowCache,
    now_ms: u64,
) -> Vec<ConnectRealtimeStatus> {
    let cache = flow_cache.read().expect("metric flow cache poisoned");
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
    let cache = flow_cache.read().expect("metric flow cache poisoned");
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

pub(crate) fn collect_realtime_iface_stats(
    flow_cache: &FlowCache,
    now_ms: u64,
) -> Vec<IfaceRealtimeStat> {
    let cache = flow_cache.read().expect("metric flow cache poisoned");
    let mut stats_map: HashMap<u32, IfaceRealtimeAcc> = HashMap::new();

    for state in cache.values().filter(|state| state.is_active(now_ms)) {
        let stats = stats_map.entry(state.realtime.ifindex).or_default();
        stats.ingress_bps = stats.ingress_bps.saturating_add(state.realtime.ingress_bps);
        stats.egress_bps = stats.egress_bps.saturating_add(state.realtime.egress_bps);
        stats.ingress_pps = stats.ingress_pps.saturating_add(state.realtime.ingress_pps);
        stats.egress_pps = stats.egress_pps.saturating_add(state.realtime.egress_pps);
        stats.active_conns = stats.active_conns.saturating_add(1);
        stats.last_report_time = stats.last_report_time.max(state.realtime.last_report_time);
    }

    let mut stats: Vec<_> = stats_map
        .into_iter()
        .map(|(ifindex, acc)| IfaceRealtimeStat {
            ifindex,
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
    let cache = flow_cache.read().expect("metric flow cache poisoned");
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
        ConnectMetric {
            key: ConnectKey { create_time, cpu_id },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            src_port: 10_000 + cpu_id as u16,
            dst_port: 20_000 + cpu_id as u16,
            l4_proto: 6,
            l3_proto: 4,
            flow_id: cpu_id as u8,
            trace_id: cpu_id as u8,
            gress: 0,
            ifindex: cpu_id + 10,
            report_time,
            create_time_ms: create_time,
            ingress_bytes,
            ingress_packets: ingress_bytes / 10,
            egress_bytes,
            egress_packets: egress_bytes / 10,
            status: ConnectStatusType::Active,
        }
    }

    fn test_caches() -> (FlowCache, IfaceRealtimeCache, IfaceBucketCache) {
        (
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(RwLock::new(HashMap::new())),
        )
    }

    const WINDOW_MS: u64 = 5 * 60 * 1000;
    const RING_CAP: usize = 64;

    #[test]
    fn process_connect_metric_creates_active_flow_without_batch() {
        let (flow, iface_realtime, iface_buckets) = test_caches();
        let batch = process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        assert!(batch.is_empty());

        let infos = collect_connect_infos(&flow, 70_000);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].key.cpu_id, 0);
        assert!(infos[0].ingress_bps > 0);
        assert_eq!(infos[0].egress_bps > 0, true);
    }

    #[test]
    fn process_connect_metric_disabled_flow_emits_buckets_and_summary() {
        let (flow, iface_realtime, iface_buckets) = test_caches();
        let mut metric = test_metric(1_000, 0, 60_000, 100, 200);
        metric.status = ConnectStatusType::Disabled;
        let batch = process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
            metric,
            WINDOW_MS,
            RING_CAP,
        );

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
        let (flow, iface_realtime, iface_buckets) = test_caches();
        let first = process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        assert!(first.is_empty());

        let second = process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
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
        let (flow, iface_realtime, iface_buckets) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
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
        let (flow, iface_realtime, iface_buckets) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
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
    fn iface_delta_is_split_across_five_second_buckets() {
        let (flow, iface_realtime, iface_buckets) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
            test_metric(1_000, 0, 67_000, 200, 400),
            WINDOW_MS,
            RING_CAP,
        );

        let writes = drain_iface_buckets(&iface_buckets, &iface_realtime);
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].report_time, 60_000);
        assert_eq!(writes[1].report_time, 65_000);
        assert_eq!(writes[0].ingress_bytes + writes[1].ingress_bytes, 100);
        assert!(writes[0].ingress_bytes > 0 && writes[1].ingress_bytes > 0);
    }

    #[test]
    fn second_ring_points_respect_window_cutoff() {
        let (flow, iface_realtime, iface_buckets) = test_caches();
        let key = ConnectKey { create_time: 1_000, cpu_id: 0 };
        for t in [60_000u64, 61_000, 62_000, 63_000] {
            process_connect_metric(
                &flow,
                &iface_realtime,
                &iface_buckets,
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
        let (flow, iface_realtime, iface_buckets) = test_caches();
        process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
            test_metric(1_000, 0, 60_000, 100, 200),
            WINDOW_MS,
            RING_CAP,
        );
        process_connect_metric(
            &flow,
            &iface_realtime,
            &iface_buckets,
            test_metric(2_000, 1, 61_000, 300, 400),
            WINDOW_MS,
            RING_CAP,
        );

        let stats = collect_realtime_ip_stats(&flow, 70_000, true);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].stats.active_conns, 2);
        assert_eq!(stats[0].stats.ingress_bps > 0, true);
    }
}

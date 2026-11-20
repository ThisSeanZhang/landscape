use landscape_common::metric::connect::ConnectMetric;

use super::flow::{MS_PER_DAY, MS_PER_HOUR, MS_PER_MINUTE};

const MS_PER_TEN_MINUTES: u64 = 10 * MS_PER_MINUTE;

fn bucket_start(report_time: u64, bucket_ms: u64) -> u64 {
    report_time / bucket_ms * bucket_ms
}

fn minute_slot(report_time: u64) -> u64 {
    bucket_start(report_time, MS_PER_MINUTE)
}

fn hour_refresh_slot(report_time: u64) -> u64 {
    bucket_start(report_time, MS_PER_TEN_MINUTES)
}

fn day_refresh_slot(report_time: u64) -> u64 {
    bucket_start(report_time, MS_PER_HOUR)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BucketKind {
    Minute,
    Hour,
    Day,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "metric-persistent"), allow(dead_code))]
pub(crate) struct BucketWrite {
    pub kind: BucketKind,
    pub metric: ConnectMetric,
    pub bucket_report_time: u64,
}

/// 聚合层产出的待持久化批次:连接汇总 + 1m/1h/1d 时间桶。
/// 仅在启用持久化时填充，由 writer 异步写入存储。
#[derive(Debug, Clone, Default)]
pub(crate) struct Batch {
    pub summary_metrics: Vec<ConnectMetric>,
    pub bucket_writes: Vec<BucketWrite>,
}

impl Batch {
    pub(crate) fn is_empty(&self) -> bool {
        self.summary_metrics.is_empty() && self.bucket_writes.is_empty()
    }

    pub(crate) fn op_count(&self) -> usize {
        self.summary_metrics.len() + self.bucket_writes.len()
    }

    /// Seal elapsed buckets with their last observation; refresh open buckets with the new one.
    pub(crate) fn record_progress(&mut self, previous: &ConnectMetric, metric: &ConnectMetric) {
        let time = metric.report_time;
        let minute = minute_slot(previous.report_time);
        if minute_slot(time) == minute {
            return;
        }
        self.push_bucket(BucketKind::Minute, previous.clone(), minute);
        self.push_summary(metric.clone());
        if hour_refresh_slot(time) > hour_refresh_slot(previous.report_time) {
            let bucket = bucket_start(previous.report_time, MS_PER_HOUR);
            let sample = if bucket == bucket_start(time, MS_PER_HOUR) { metric } else { previous };
            self.push_bucket(BucketKind::Hour, sample.clone(), bucket);
        }
        if day_refresh_slot(time) > day_refresh_slot(previous.report_time) {
            let bucket = bucket_start(previous.report_time, MS_PER_DAY);
            let sample = if bucket == bucket_start(time, MS_PER_DAY) { metric } else { previous };
            self.push_bucket(BucketKind::Day, sample.clone(), bucket);
        }
    }

    pub(crate) fn record_final(&mut self, metric: &ConnectMetric) {
        let time = metric.report_time;
        self.push_bucket(BucketKind::Minute, metric.clone(), minute_slot(time));
        self.push_bucket(BucketKind::Hour, metric.clone(), bucket_start(time, MS_PER_HOUR));
        self.push_bucket(BucketKind::Day, metric.clone(), bucket_start(time, MS_PER_DAY));
        self.push_summary(metric.clone());
    }

    pub(crate) fn push_summary(&mut self, metric: ConnectMetric) {
        self.summary_metrics.push(metric);
    }

    pub(crate) fn push_bucket(
        &mut self,
        kind: BucketKind,
        metric: ConnectMetric,
        bucket_report_time: u64,
    ) {
        self.bucket_writes.push(BucketWrite { kind, metric, bucket_report_time });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::connect::ConnectStatusType;
    use std::net::{IpAddr, Ipv4Addr};

    fn metric(cpu_id: u32) -> ConnectMetric {
        ConnectMetric::from_domain(
            1_000,
            cpu_id,
            60_000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            10_000,
            20_000,
            1,
            1,
            2,
            100,
            10,
            200,
            20,
            ConnectStatusType::Active,
        )
    }

    #[test]
    fn default_batch_is_empty_with_zero_ops() {
        let batch = Batch::default();
        assert!(batch.is_empty());
        assert_eq!(batch.op_count(), 0);
    }

    #[test]
    fn push_summary_and_bucket_are_counted() {
        let mut batch = Batch::default();
        batch.push_summary(metric(0));
        batch.push_bucket(BucketKind::Minute, metric(1), 60_000);
        batch.push_bucket(BucketKind::Hour, metric(1), 3_600_000);

        assert!(!batch.is_empty());
        assert_eq!(batch.op_count(), 3);
        assert_eq!(batch.summary_metrics.len(), 1);
        assert_eq!(batch.bucket_writes.len(), 2);
        assert_eq!(batch.bucket_writes[0].kind, BucketKind::Minute);
        assert_eq!(batch.bucket_writes[0].bucket_report_time, 60_000);
        assert_eq!(batch.bucket_writes[1].kind, BucketKind::Hour);
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
    fn crossing_midnight_emits_all_previous_buckets_once() {
        let mut batch = Batch::default();
        let mut current = metric(0);
        current.report_time = MS_PER_DAY;
        let mut previous = current.clone();
        previous.report_time -= 1;
        batch.record_progress(&previous, &current);
        batch.record_progress(&current, &current);
        assert_eq!(batch.summary_metrics.len(), 1);
        let buckets: Vec<_> =
            batch.bucket_writes.iter().map(|row| (row.kind, row.bucket_report_time)).collect();
        assert_eq!(
            buckets,
            [
                (BucketKind::Minute, MS_PER_DAY - MS_PER_MINUTE),
                (BucketKind::Hour, MS_PER_DAY - MS_PER_HOUR),
                (BucketKind::Day, 0)
            ]
        );
    }
}

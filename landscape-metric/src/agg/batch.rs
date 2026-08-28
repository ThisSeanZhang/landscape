use landscape_common::metric::connect::ConnectMetric;

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
/// sink 层负责将批次写入具体存储;内存 sink 直接丢弃。
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

    pub(crate) fn extend(&mut self, other: Self) {
        self.summary_metrics.extend(other.summary_metrics);
        self.bucket_writes.extend(other.bucket_writes);
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
    fn extend_merges_summaries_and_buckets() {
        let mut left = Batch::default();
        left.push_summary(metric(0));
        left.push_bucket(BucketKind::Day, metric(0), 0);

        let mut right = Batch::default();
        right.push_summary(metric(1));
        right.push_bucket(BucketKind::Minute, metric(1), 60_000);
        right.push_bucket(BucketKind::Hour, metric(1), 3_600_000);

        left.extend(right);
        assert_eq!(left.summary_metrics.len(), 2);
        assert_eq!(left.bucket_writes.len(), 3);
        assert_eq!(left.op_count(), 5);
    }

    #[test]
    fn extending_with_empty_batch_is_noop() {
        let mut batch = Batch::default();
        batch.push_summary(metric(0));
        batch.extend(Batch::default());
        assert_eq!(batch.op_count(), 1);
        assert_eq!(batch.summary_metrics[0].key().cpu_id, 0);
    }
}

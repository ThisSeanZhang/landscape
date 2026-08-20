use landscape_common::config::MetricRuntimeConfig;
use landscape_common::metric::dns::DnsMetric;

use crate::metric::ingest::{BucketWrite, IfaceBucketWrite};

/// Stats for one batch of bucket writes persisted to the cold store.
#[derive(Debug, Clone, Default)]
pub(crate) struct BucketPersistStats {
    pub rows: usize,
    pub iface_rows: usize,
    pub elapsed_ms: u128,
}

/// Stats for one batch of DNS metrics persisted to the cold store.
#[derive(Debug, Clone, Default)]
pub(crate) struct DnsPersistStats {
    pub rows: usize,
    pub elapsed_ms: u128,
}

/// Stats for one cold-store cleanup run.
#[derive(Debug, Clone, Default)]
pub(crate) struct ColdCleanupStats {
    pub deleted_rows: usize,
    pub elapsed_ms: u128,
}

/// Cold history store abstraction.
///
/// Implementations must persist metrics in batches (one transaction per
/// batch) and must never emit per-row writes: the ingest pipeline always
/// flushes batches on size or time thresholds.
pub(crate) trait ColdStore: Send + Sync {
    /// Persist a batch of connection bucket upserts.
    fn persist_buckets(
        &self,
        bucket_writes: &[BucketWrite],
        iface_bucket_writes: &[IfaceBucketWrite],
    ) -> Result<BucketPersistStats, String>;

    /// Persist a batch of DNS metrics.
    fn persist_dns(&self, metrics: &[DnsMetric]) -> Result<DnsPersistStats, String>;

    /// Run retention cleanup.
    fn cleanup(&self, config: &MetricRuntimeConfig) -> Result<ColdCleanupStats, String>;
}

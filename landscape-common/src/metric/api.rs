use serde::{Deserialize, Serialize};

use super::connect::{ConnectHistoryStatus, ConnectKey, MetricResolution};
use super::dns::{DnsMetric, DnsStatEntry};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MetricChartRequest {
    pub key: ConnectKey,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub resolution: Option<MetricResolution>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectHistoryResponse {
    pub items: Vec<ConnectHistoryStatus>,
    pub total: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsHistoryResponse {
    pub items: Vec<DnsMetric>,
    pub total: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsSummaryResponse {
    pub total_queries: usize,
    pub total_effective_queries: usize,
    pub cache_hit_count: usize,
    pub hit_count_v4: usize,
    pub hit_count_v6: usize,
    pub hit_count_other: usize,
    pub total_v4: usize,
    pub total_v6: usize,
    pub total_other: usize,
    pub block_count: usize,
    pub filter_count: usize,
    pub nxdomain_count: usize,
    pub error_count: usize,
    pub avg_duration_ms: f64,
    pub p50_duration_ms: f64,
    pub p95_duration_ms: f64,
    pub p99_duration_ms: f64,
    pub max_duration_ms: f64,
    pub top_clients: Vec<DnsStatEntry>,
    pub top_domains: Vec<DnsStatEntry>,
    pub top_blocked: Vec<DnsStatEntry>,
    pub slowest_domains: Vec<DnsStatEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsLightweightSummaryResponse {
    pub total_queries: usize,
    pub total_effective_queries: usize,
    pub cache_hit_count: usize,
    pub hit_count_v4: usize,
    pub hit_count_v6: usize,
    pub hit_count_other: usize,
    pub total_v4: usize,
    pub total_v6: usize,
    pub total_other: usize,
    pub block_count: usize,
    pub filter_count: usize,
    pub nxdomain_count: usize,
    pub error_count: usize,
    pub avg_duration_ms: f64,
    pub p50_duration_ms: f64,
    pub p95_duration_ms: f64,
    pub p99_duration_ms: f64,
    pub max_duration_ms: f64,
}

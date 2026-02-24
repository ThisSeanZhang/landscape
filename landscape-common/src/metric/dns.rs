use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DnsResultStatus {
    Local,    // 重定向有值
    Block,    // 重定向空值
    Hit,      // 命中缓存
    NxDomain, // 域名不存在
    Filter,   // 被过滤 (OnlyIPv4/OnlyIPv6)
    #[default]
    Normal, // 正常透传
    Error,    // 异常
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsMetric {
    pub flow_id: u32,
    pub domain: String,
    pub query_type: String,
    pub response_code: String,
    pub status: DnsResultStatus,
    pub report_time: u64,
    pub duration_ms: u32,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub src_ip: IpAddr,
    pub answers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DnsSortKey {
    #[default]
    Time,
    Domain,
    Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct DnsHistoryQueryParams {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub start_time: Option<u64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub end_time: Option<u64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub limit: Option<usize>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub offset: Option<usize>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub domain: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub src_ip: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub query_type: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub status: Option<DnsResultStatus>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub min_duration_ms: Option<u32>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub max_duration_ms: Option<u32>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_key: Option<DnsSortKey>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_order: Option<crate::metric::connect::SortOrder>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub flow_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct DnsSummaryQueryParams {
    pub start_time: u64,
    pub end_time: u64,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub flow_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsStatEntry {
    pub name: String,
    pub count: usize,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub value: Option<f64>,
}

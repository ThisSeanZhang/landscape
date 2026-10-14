use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Record, RecordType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

pub use super::api::{DnsHistoryResponse, DnsLightweightSummaryResponse, DnsSummaryResponse};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DnsOutcome {
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
    pub status: DnsOutcome,
    pub report_time: u64,
    pub duration_ms: u32,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub src_ip: IpAddr,
    pub answers: Vec<String>,
}

#[derive(Debug)]
pub struct DnsMetricEvent {
    pub flow_id: u32,
    pub domain: Arc<str>,
    pub query_type: RecordType,
    pub response_code: ResponseCode,
    pub status: DnsOutcome,
    pub report_time: u64,
    pub duration_ms: u32,
    pub src_ip: IpAddr,
    pub answers: Vec<Record>,
}

impl DnsMetricEvent {
    pub fn into_metric(self) -> DnsMetric {
        DnsMetric {
            flow_id: self.flow_id,
            domain: self.domain.to_string(),
            query_type: self.query_type.to_string(),
            response_code: self.response_code.to_string(),
            status: self.status,
            report_time: self.report_time,
            duration_ms: self.duration_ms,
            src_ip: self.src_ip,
            answers: self.answers.iter().map(|r| r.to_string()).collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
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
    pub status: Option<DnsOutcome>,
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
pub struct DnsStatEntry {
    pub name: String,
    pub count: usize,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub value: Option<f64>,
}

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

///
#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectKey {
    #[serde(with = "crate::utils::serde_helper")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub create_time: u64,
    pub cpu_id: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ConnectStatusType {
    #[default]
    Unknow,
    Active,
    Disabled,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum MetricResolution {
    #[serde(rename = "second")]
    Second,
    #[serde(rename = "minute")]
    Minute,
    #[serde(rename = "hour")]
    Hour,
    #[serde(rename = "day")]
    Day,
}

impl Default for MetricResolution {
    fn default() -> Self {
        MetricResolution::Second
    }
}

impl From<u8> for ConnectStatusType {
    fn from(value: u8) -> Self {
        match value {
            1 => ConnectStatusType::Active,
            2 => ConnectStatusType::Disabled,
            _ => ConnectStatusType::Unknow,
        }
    }
}

impl Into<u8> for ConnectStatusType {
    fn into(self) -> u8 {
        match self {
            ConnectStatusType::Unknow => 0,
            ConnectStatusType::Active => 1,
            ConnectStatusType::Disabled => 2,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone)]
pub struct ConnectMetric {
    pub key: ConnectKey,

    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    pub l4_proto: u8,
    pub l3_proto: u8,

    pub flow_id: u8,
    pub trace_id: u8,
    pub gress: u8,

    pub report_time: u64,

    pub create_time_ms: u64,

    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,

    pub status: ConnectStatusType,
}

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectMetricPoint {
    pub report_time: u64,

    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,

    pub status: ConnectStatusType,
}

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone)]
pub struct ConnectAgg {
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectRealtimeStatus {
    pub key: ConnectKey,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub src_ip: IpAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    pub l4_proto: u8,
    pub l3_proto: u8,

    pub flow_id: u8,
    pub trace_id: u8,
    pub gress: u8,

    pub create_time_ms: u64,

    pub ingress_bps: u64,
    pub egress_bps: u64,
    pub ingress_pps: u64,
    pub egress_pps: u64,
    pub last_report_time: u64,
    pub status: ConnectStatusType,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectGlobalStats {
    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub total_ingress_pkts: u64,
    pub total_egress_pkts: u64,
    pub total_connect_count: u64,
    pub last_calculate_time: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ConnectSortKey {
    #[default]
    Time,
    Port,
    Ingress,
    Egress,
    Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct ConnectHistoryQueryParams {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub start_time: Option<u64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub end_time: Option<u64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub limit: Option<usize>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub src_ip: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub dst_ip: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub port_start: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub port_end: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub l3_proto: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub l4_proto: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub flow_id: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_key: Option<ConnectSortKey>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_order: Option<SortOrder>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub status: Option<u8>, // 0: Active, 1: Closed
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub gress: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectHistoryStatus {
    pub key: ConnectKey,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub src_ip: IpAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    pub l4_proto: u8,
    pub l3_proto: u8,

    pub flow_id: u8,
    pub trace_id: u8,
    pub gress: u8,

    pub create_time_ms: u64,

    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub total_ingress_pkts: u64,
    pub total_egress_pkts: u64,
    pub last_report_time: u64,

    pub status: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IpAggregatedStats {
    pub ingress_bps: u64,
    pub egress_bps: u64,
    pub ingress_pps: u64,
    pub egress_pps: u64,
    pub active_conns: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IpRealtimeStat {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
    pub stats: IpAggregatedStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IpHistoryStat {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
    pub flow_id: u8,
    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub total_ingress_pkts: u64,
    pub total_egress_pkts: u64,
    pub connect_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MetricChartRequest {
    pub key: ConnectKey,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub resolution: Option<MetricResolution>,
}

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

///
#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct ConnectKey {
    #[ts(type = "number")]
    pub create_time: u64,
    pub cpu_id: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, Eq, Hash, PartialEq, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
#[serde(rename_all = "snake_case")]
pub enum ConnectStatusType {
    #[default]
    Unknow,
    Active,
    Disabled,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
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

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
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

    #[ts(type = "number")]
    pub report_time: u64,

    #[ts(type = "number")]
    pub ingress_bytes: u64,
    #[ts(type = "number")]
    pub ingress_packets: u64,
    #[ts(type = "number")]
    pub egress_bytes: u64,
    #[ts(type = "number")]
    pub egress_packets: u64,

    pub status: ConnectStatusType,
}

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct ConnectAgg {
    #[ts(type = "number")]
    pub ingress_bytes: u64,
    #[ts(type = "number")]
    pub ingress_packets: u64,
    #[ts(type = "number")]
    pub egress_bytes: u64,
    #[ts(type = "number")]
    pub egress_packets: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct ConnectRealtimeStatus {
    pub key: ConnectKey,

    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    pub l4_proto: u8,
    pub l3_proto: u8,

    pub flow_id: u8,
    pub trace_id: u8,

    #[ts(type = "number")]
    pub ingress_bps: u64,
    #[ts(type = "number")]
    pub egress_bps: u64,
    #[ts(type = "number")]
    pub ingress_pps: u64,
    #[ts(type = "number")]
    pub egress_pps: u64,

    pub last_metric: Option<ConnectMetric>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct ConnectGlobalStats {
    #[ts(type = "number")]
    pub total_ingress_bytes: u64,
    #[ts(type = "number")]
    pub total_egress_bytes: u64,
    #[ts(type = "number")]
    pub total_ingress_pkts: u64,
    #[ts(type = "number")]
    pub total_egress_pkts: u64,
    #[ts(type = "number")]
    pub total_connect_count: u64,
    #[ts(type = "number")]
    pub last_calculate_time: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
#[serde(rename_all = "lowercase")]
pub enum ConnectSortKey {
    #[default]
    Time,
    Port,
    Ingress,
    Egress,
    Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct ConnectHistoryQueryParams {
    #[ts(optional)]
    #[ts(type = "number")]
    pub start_time: Option<u64>,
    #[ts(optional)]
    #[ts(type = "number")]
    pub end_time: Option<u64>,
    #[ts(optional)]
    pub limit: Option<usize>,
    #[ts(optional)]
    pub src_ip: Option<String>,
    #[ts(optional)]
    pub dst_ip: Option<String>,
    #[ts(optional)]
    pub port_start: Option<u16>,
    #[ts(optional)]
    pub port_end: Option<u16>,
    #[ts(optional)]
    pub l3_proto: Option<u8>,
    #[ts(optional)]
    pub l4_proto: Option<u8>,
    #[ts(optional)]
    pub flow_id: Option<u8>,
    #[ts(optional)]
    pub sort_key: Option<ConnectSortKey>,
    #[ts(optional)]
    pub sort_order: Option<SortOrder>,
    #[ts(optional)]
    pub status: Option<u8>, // 0: Active, 1: Closed
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct ConnectHistoryStatus {
    pub key: ConnectKey,

    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    pub l4_proto: u8,
    pub l3_proto: u8,

    pub flow_id: u8,
    pub trace_id: u8,

    #[ts(type = "number")]
    pub total_ingress_bytes: u64,
    #[ts(type = "number")]
    pub total_egress_bytes: u64,
    #[ts(type = "number")]
    pub total_ingress_pkts: u64,
    #[ts(type = "number")]
    pub total_egress_pkts: u64,
    #[ts(type = "number")]
    pub last_report_time: u64,

    pub status: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct IpAggregatedStats {
    #[ts(type = "number")]
    pub ingress_bps: u64,
    #[ts(type = "number")]
    pub egress_bps: u64,
    #[ts(type = "number")]
    pub ingress_pps: u64,
    #[ts(type = "number")]
    pub egress_pps: u64,
    pub active_conns: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct IpRealtimeStat {
    pub ip: IpAddr,
    pub stats: IpAggregatedStats,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct IpHistoryStat {
    pub ip: IpAddr,
    pub flow_id: u8,
    #[ts(type = "number")]
    pub total_ingress_bytes: u64,
    #[ts(type = "number")]
    pub total_egress_bytes: u64,
    #[ts(type = "number")]
    pub total_ingress_pkts: u64,
    #[ts(type = "number")]
    pub total_egress_pkts: u64,
    pub connect_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "common/metric/connect.d.ts")]
pub struct MetricChartRequest {
    pub key: ConnectKey,
    #[ts(optional)]
    pub resolution: Option<MetricResolution>,
}

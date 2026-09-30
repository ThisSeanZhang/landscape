use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::flow::mark::FlowMark;

pub use super::api::{FlowMatchRequest, FlowVerdictRequest};

// ===== Step 1: Flow Match =====

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FlowMatchSource {
    #[default]
    Default,
    Mac,
    Ipv4,
    Ipv6,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowMatchResult {
    /// Flow matched by exact MAC.
    pub flow_id_by_mac: Option<u32>,
    /// Legacy aggregate IP match result. When both IPv4 and IPv6 are provided,
    /// IPv4 is preferred over IPv6.
    pub flow_id_by_ip: Option<u32>,
    /// Flow matched by source IPv4.
    pub flow_id_by_ipv4: Option<u32>,
    /// Flow matched by source IPv6.
    pub flow_id_by_ipv6: Option<u32>,
    /// Legacy aggregate effective flow. When both IPv4 and IPv6 are provided,
    /// IPv4 is preferred over IPv6, then MAC, then default flow.
    pub effective_flow_id: u32,
    /// Effective flow for IPv4 traffic: IPv4 match first, then MAC, then default flow.
    pub effective_flow_id_v4: u32,
    /// Effective flow for IPv6 traffic: IPv6 match first, then MAC, then default flow.
    pub effective_flow_id_v6: u32,
    /// Legacy aggregate winner for `effective_flow_id`.
    #[serde(default)]
    pub effective_flow_source: FlowMatchSource,
    /// Winner for IPv4 traffic.
    #[serde(default)]
    pub effective_flow_source_v4: FlowMatchSource,
    /// Winner for IPv6 traffic.
    #[serde(default)]
    pub effective_flow_source_v6: FlowMatchSource,
}

// ===== Step 2: Flow Verdict =====

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FlowVerdictSource {
    #[default]
    Default,
    IpRule,
    DnsRule,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowVerdictResult {
    pub verdicts: Vec<SingleVerdictResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SingleVerdictResult {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub dst_ip: IpAddr,
    pub ip_rule_match: Option<FlowRuleMatchResult>,
    pub dns_rule_match: Option<FlowRuleMatchResult>,
    #[serde(default)]
    pub effective_rule_source: FlowVerdictSource,
    pub effective_mark: FlowMark,
    /// Mark value expected in route cache after runtime flow-id expansion.
    pub expected_cache_mark: u32,
    pub has_cache: bool,
    pub cached_mark: Option<u32>,
    pub cache_consistent: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowRuleMatchResult {
    pub mark: FlowMark,
    pub priority: u16,
}

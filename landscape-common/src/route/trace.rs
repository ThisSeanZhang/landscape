use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::{flow::mark::FlowMark, net::MacAddr};

// ===== Step 1: Flow Match =====

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowMatchRequest {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv6: Option<Ipv6Addr>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub src_mac: Option<MacAddr>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowMatchResult {
    pub flow_id_by_mac: Option<u32>,
    pub flow_id_by_ip: Option<u32>,
    pub effective_flow_id: u32,
}

// ===== Step 2: Flow Verdict =====

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowVerdictRequest {
    pub flow_id: u32,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub src_ipv6: Option<Ipv6Addr>,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub dst_ips: Vec<IpAddr>,
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
    pub effective_mark: FlowMark,
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

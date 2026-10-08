use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::net::MacAddr;

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

use uuid::Uuid;

use super::config::{FlowConfig, FlowTarget, WeightedFlowTarget};
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

fn default_flow_target_weight() -> u32 {
    1
}

/// API view of [`FlowTarget`]: the iface-name mirror is server-internal
/// (DB write-back for downgraded binaries) and never crosses the API.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ApiFlowTarget {
    Interface {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        link_id: Uuid,
    },
    Netns {
        container_name: String,
    },
}

impl From<FlowTarget> for ApiFlowTarget {
    fn from(value: FlowTarget) -> Self {
        match value {
            FlowTarget::Interface { link_id, .. } => ApiFlowTarget::Interface { link_id },
            FlowTarget::Netns { container_name } => ApiFlowTarget::Netns { container_name },
        }
    }
}

impl From<ApiFlowTarget> for FlowTarget {
    fn from(value: ApiFlowTarget) -> Self {
        match value {
            ApiFlowTarget::Interface { link_id } => {
                FlowTarget::Interface { link_id, name: String::new() }
            }
            ApiFlowTarget::Netns { container_name } => FlowTarget::Netns { container_name },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiWeightedFlowTarget {
    pub target: ApiFlowTarget,
    #[serde(default = "default_flow_target_weight")]
    pub weight: u32,
}

impl From<WeightedFlowTarget> for ApiWeightedFlowTarget {
    fn from(value: WeightedFlowTarget) -> Self {
        Self { target: value.target.into(), weight: value.weight }
    }
}

impl From<ApiWeightedFlowTarget> for WeightedFlowTarget {
    fn from(value: ApiWeightedFlowTarget) -> Self {
        Self { target: value.target.into(), weight: value.weight }
    }
}

/// API view of [`FlowConfig`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiFlowConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub enable: bool,
    pub flow_id: u32,
    pub flow_match_rules: Vec<super::config::FlowEntryRule>,
    pub flow_targets: Vec<ApiWeightedFlowTarget>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub name: String,
    pub remark: String,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl From<FlowConfig> for ApiFlowConfig {
    fn from(value: FlowConfig) -> Self {
        Self {
            id: value.id,
            enable: value.enable,
            flow_id: value.flow_id,
            flow_match_rules: value.flow_match_rules,
            flow_targets: value.flow_targets.into_iter().map(Into::into).collect(),
            name: value.name,
            remark: value.remark,
            update_at: value.update_at,
        }
    }
}

impl From<ApiFlowConfig> for FlowConfig {
    fn from(value: ApiFlowConfig) -> Self {
        Self {
            id: value.id,
            enable: value.enable,
            flow_id: value.flow_id,
            flow_match_rules: value.flow_match_rules,
            flow_targets: value.flow_targets.into_iter().map(Into::into).collect(),
            name: value.name,
            remark: value.remark,
            update_at: value.update_at,
        }
    }
}

use std::{fmt, net::IpAddr};

use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};

use crate::config::ConfigId;
use crate::{flow::mark::FlowMark, net::MacAddr};

pub mod config;
pub mod mark;
pub mod target;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum FlowRuleError {
    #[error("Flow rule '{0}' not found")]
    #[api_error(id = "flow_rule.not_found", status = 404)]
    NotFound(ConfigId),

    #[error("Duplicate entry match rule: {0}")]
    #[api_error(id = "flow_rule.duplicate_entry", status = 400)]
    DuplicateEntryRule(String),

    #[error("Entry rule '{rule}' conflicts with flow '{flow_remark}' (ID: {flow_id})")]
    #[api_error(id = "flow_rule.conflict_entry", status = 400)]
    ConflictEntryRule { rule: String, flow_remark: String, flow_id: u32 },
}

/// Flow 入口匹配规则
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowEntryRule {
    // pub vlan_id: Option<u32>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub qos: Option<u32>,
    pub mode: FlowEntryMatchMode,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum FlowEntryMatchMode {
    Mac {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        mac_addr: MacAddr,
    },
    Ip {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ip: IpAddr,
        #[serde(default = "default_prefix_len")]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        prefix_len: u8,
    },
}

impl fmt::Display for FlowEntryMatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowEntryMatchMode::Mac { mac_addr } => write!(f, "MAC {}", mac_addr),
            FlowEntryMatchMode::Ip { ip, prefix_len } => write!(f, "IP {}/{}", ip, prefix_len),
        }
    }
}

/// 用于 Flow ebpf 匹配记录操作
pub struct FlowEbpfMatchPair {
    pub entry_rule: FlowEntryRule,
    pub flow_id: u32,
}

impl FlowEbpfMatchPair {
    pub fn new(entry_rule: FlowEntryRule, flow_id: u32) -> Self {
        Self { entry_rule, flow_id }
    }
}

fn default_prefix_len() -> u8 {
    32
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum FlowTarget {
    Interface { name: String },
    Netns { container_name: String },
}

/// 用于 Flow ebpf DNS Map 记录操作
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowMarkInfo {
    pub ip: IpAddr,
    pub mark: u32,
    pub priority: u16,
}

#[derive(Debug, Clone)]
pub struct DnsRuntimeMarkInfo {
    pub mark: FlowMark,
    pub priority: u16,
}

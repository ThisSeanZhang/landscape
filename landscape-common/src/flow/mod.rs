use std::{fmt, net::IpAddr};

use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};

use crate::config::ConfigId;
use crate::database::error::DbError;
use crate::service::ServiceConfigError;
use crate::{flow::mark::FlowMark, net::MacAddr};
use uuid::Uuid;

pub mod config;
pub mod ip_mark;
pub mod mark;
pub mod service;
pub mod target;
pub mod trace;

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

    #[error("At least one configured flow target must have a positive weight")]
    #[api_error(id = "flow_rule.invalid_target_weight", status = 400)]
    InvalidTargetWeight,

    #[error("Flow rule cannot have more than 16 targets (load balancing uses 16 slots)")]
    #[api_error(id = "flow_rule.too_many_targets", status = 400)]
    TooManyTargets,

    #[error("Flow device target '{0}' not found")]
    #[api_error(id = "flow_rule.device_not_found", status = 404)]
    DeviceNotFound(ConfigId),

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
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
    Device {
        device_id: Uuid,
    },
}

impl FlowEntryMatchMode {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if let FlowEntryMatchMode::Ip { ip, prefix_len } = self {
            let max_prefix_len = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };

            if *prefix_len > max_prefix_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "flow entry rule prefix_len ({prefix_len}) must be <= {max_prefix_len} for {ip}",
                    ),
                });
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedFlowEntryRule {
    pub qos: Option<u32>,
    pub mode: ResolvedFlowEntryMatchMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedFlowEntryMatchMode {
    Mac { mac_addr: MacAddr },
    Ip { ip: IpAddr, prefix_len: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFlowConfig {
    pub flow_id: u32,
    pub flow_match_rules: Vec<ResolvedFlowEntryRule>,
}

impl FlowEntryRule {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        self.mode.validate()
    }
}

impl fmt::Display for FlowEntryMatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowEntryMatchMode::Mac { mac_addr } => write!(f, "MAC {}", mac_addr),
            FlowEntryMatchMode::Ip { ip, prefix_len } => write!(f, "IP {}/{}", ip, prefix_len),
            FlowEntryMatchMode::Device { device_id } => write!(f, "Device {}", device_id),
        }
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

fn default_flow_target_weight() -> u32 {
    1
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WeightedFlowTarget {
    pub target: FlowTarget,
    #[serde(default = "default_flow_target_weight")]
    pub weight: u32,
}

impl WeightedFlowTarget {
    pub fn new(target: FlowTarget, weight: u32) -> Self {
        Self { target, weight }
    }
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

#[cfg(test)]
mod tests {
    use super::FlowEntryMatchMode;

    #[test]
    fn rejects_ipv4_prefixes_longer_than_32() {
        let result =
            FlowEntryMatchMode::Ip { ip: "192.0.2.1".parse().unwrap(), prefix_len: 33 }.validate();

        assert!(result.is_err());
    }

    #[test]
    fn rejects_ipv6_prefixes_longer_than_128() {
        let result = FlowEntryMatchMode::Ip {
            ip: "2001:db8::1".parse().unwrap(),
            prefix_len: 129,
        }
        .validate();

        assert!(result.is_err());
    }

    #[test]
    fn accepts_ipv6_host_prefix() {
        let result = FlowEntryMatchMode::Ip {
            ip: "2001:db8::1".parse().unwrap(),
            prefix_len: 128,
        }
        .validate();

        assert!(result.is_ok());
    }
}

use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config_service::geo::GeoConfigKey;
use crate::database::repository::LandscapeDBStore;
use crate::flow::mark::FlowMark;
use crate::net::MacAddr;
use crate::service::ServiceConfigError;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

/// 流控配置结构体
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    /// 是否启用
    pub enable: bool,
    /// 流 ID
    pub flow_id: u32,
    /// 匹配规则
    pub flow_match_rules: Vec<FlowEntryRule>,
    /// 处理流量目标网卡, 目前只取第一个
    /// 暂定, 可能会移动到具体的网卡上进行设置
    pub flow_targets: Vec<WeightedFlowTarget>,
    /// 名称 (用于展示的简短标识, 为空时回退到 remark)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub name: String,
    /// 备注
    pub remark: String,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for FlowConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

/// Maximum number of targets a flow rule may reference.
pub const MAX_FLOW_TARGETS: usize = 16;

impl crate::database::validator::ValidatableConfig for FlowConfig {
    fn validate(&self) -> Result<(), ServiceConfigError> {
        for rule in &self.flow_match_rules {
            rule.validate()?;
        }

        if !self.flow_targets.is_empty() && self.flow_targets.iter().all(|t| t.weight == 0) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "flow targets must not all have zero weight".to_string(),
            });
        }
        if self.flow_targets.len() > MAX_FLOW_TARGETS {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("too many flow targets (max {MAX_FLOW_TARGETS})"),
            });
        }

        let mut seen = std::collections::HashSet::new();
        for rule in &self.flow_match_rules {
            if !seen.insert(&rule.mode) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("duplicate entry rule mode '{}'", rule.mode),
                });
            }
        }

        Ok(())
    }
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
/// 对于外部 IP 规则
pub struct WanIpRuleConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: Option<String>,
    // 优先级 用作存储主键
    pub index: u32,
    // 是否启用
    pub enable: bool,
    /// 流量标记
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mark: FlowMark,
    /// 匹配规则列表
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub source: Vec<WanIPRuleSource>,
    // 备注
    pub remark: String,

    #[serde(default = "default_flow_id")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub flow_id: u32,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub override_dns: bool,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

fn default_flow_id() -> u32 {
    0_u32
}

impl LandscapeDBStore<Uuid> for WanIpRuleConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum WanIPRuleSource {
    GeoKey(GeoConfigKey),
    Config(IpConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IpConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
    pub prefix: u32,
    // pub reverse_match: String,
}

crate::impl_trivial_validatable!(WanIpRuleConfig);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_weighted_flow_targets_preserves_weight() {
        let json = serde_json::json!({
            "id": Uuid::nil(),
            "enable": true,
            "flow_id": 1,
            "flow_match_rules": [],
            "flow_targets": [
                {
                    "target": { "t": "interface", "name": "wan0" },
                    "weight": 3
                }
            ],
            "remark": "weighted",
            "update_at": 0.0
        });

        let config: FlowConfig =
            serde_json::from_value(json).expect("deserialize weighted flow config");

        assert_eq!(config.flow_targets.len(), 1);
        assert_eq!(
            serde_json::to_value(&config.flow_targets[0]).unwrap(),
            serde_json::json!({
                "target": { "t": "interface", "name": "wan0" },
                "weight": 3
            })
        );
    }

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

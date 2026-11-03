use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::DEFAULT_FLOW_ID;
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
    /// Weighted exits, or primary/backup order when failover is enabled.
    pub flow_targets: Vec<WeightedFlowTarget>,
    #[serde(default)]
    pub failover: FlowFailoverConfig,
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

/// Opt-in ordered WAN failover. Legacy flows remain in weighted mode.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowFailoverConfig {
    /// Probe verdicts or acquired link routes decide automatic eligibility.
    #[serde(default)]
    pub trigger: FlowFailoverTrigger,
    /// Ordered mode remains selected when automatic switching is turned off.
    #[serde(default)]
    pub mode: FlowTargetMode,
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_auto_failback")]
    pub auto_failback: bool,
    /// Keep a route during startup/reconfiguration while probes have no verdict.
    #[serde(default = "default_unknown_grace_secs")]
    pub unknown_grace_secs: u16,
    /// After grace, allow an unknown (never a known failed) configured WAN.
    #[serde(default)]
    pub fail_open_on_unknown: bool,
    /// Higher-priority WAN must remain healthy this long before failback.
    #[serde(default = "default_failback_delay_secs")]
    pub failback_delay_secs: u16,
    /// Minimum time between non-emergency switches; failures bypass this hold.
    #[serde(default = "default_switch_hold_secs")]
    pub switch_hold_secs: u16,
    #[serde(default = "default_failure_connection_policy")]
    pub failure_connection_policy: FlowConnectionPolicy,
    #[serde(default)]
    pub recovery_connection_policy: FlowConnectionPolicy,
    /// Apply this ordered policy to packets using the reserved default flow.
    #[serde(default)]
    pub bind_default_flow: bool,
    /// Also choose the kernel source/route for unmarked router-originated traffic.
    #[serde(default)]
    pub bind_router_traffic: bool,
}

fn default_unknown_grace_secs() -> u16 {
    30
}
fn default_failback_delay_secs() -> u16 {
    30
}
fn default_switch_hold_secs() -> u16 {
    5
}
fn default_failure_connection_policy() -> FlowConnectionPolicy {
    FlowConnectionPolicy::ResetExisting
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FlowConnectionPolicy {
    #[default]
    NewConnectionsOnly,
    ResetExisting,
}

fn default_auto_failback() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FlowFailoverTrigger {
    #[default]
    HealthCheck,
    LinkState,
}

impl Default for FlowFailoverConfig {
    fn default() -> Self {
        Self {
            trigger: FlowFailoverTrigger::HealthCheck,
            mode: FlowTargetMode::Weighted,
            enable: false,
            auto_failback: true,
            unknown_grace_secs: default_unknown_grace_secs(),
            fail_open_on_unknown: false,
            failback_delay_secs: default_failback_delay_secs(),
            switch_hold_secs: default_switch_hold_secs(),
            failure_connection_policy: default_failure_connection_policy(),
            recovery_connection_policy: FlowConnectionPolicy::NewConnectionsOnly,
            bind_default_flow: false,
            bind_router_traffic: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FlowTargetMode {
    #[default]
    Weighted,
    PrimaryBackup,
}

impl FlowFailoverConfig {
    pub fn requires_health_checks(&self) -> bool {
        self.enable && self.trigger == FlowFailoverTrigger::HealthCheck
    }

    pub fn ordered_targets(&self) -> bool {
        self.enable || self.mode == FlowTargetMode::PrimaryBackup
    }
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
        if self.flow_id == DEFAULT_FLOW_ID {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "flow_id {DEFAULT_FLOW_ID} is reserved for the default flow and cannot be used by a flow config"
                ),
            });
        }
        if self.flow_id > u32::from(u8::MAX) {
            return Err(ServiceConfigError::FlowIdOutOfRange { flow_id: self.flow_id });
        }
        if (self.failover.bind_default_flow && !self.failover.ordered_targets())
            || (self.failover.bind_router_traffic && !self.failover.bind_default_flow)
        {
            return Err(ServiceConfigError::InvalidConfig { reason: "default/router WAN binding requires an ordered flow; router binding also requires default flow binding".into() });
        }
        for rule in &self.flow_match_rules {
            rule.validate()?;
        }

        if !self.failover.ordered_targets()
            && !self.flow_targets.is_empty()
            && self.flow_targets.iter().all(|t| t.weight == 0)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "flow targets must not all have zero weight".to_string(),
            });
        }
        if self.flow_targets.len() > MAX_FLOW_TARGETS {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("too many flow targets (max {MAX_FLOW_TARGETS})"),
            });
        }

        if self.failover.ordered_targets() {
            if self.failover.unknown_grace_secs > 600
                || self.failover.failback_delay_secs > 3600
                || self.failover.switch_hold_secs > 3600
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "WAN grace must be <= 600s and failback/hold must be <= 3600s".into(),
                });
            }
            let mut links = std::collections::HashSet::new();
            let min_targets = if self.failover.enable { 2 } else { 1 };
            if self.flow_targets.len() < min_targets
                || self.flow_targets.iter().any(|target| match &target.target {
                    FlowTarget::Interface { link_id, .. } => !links.insert(*link_id),
                    FlowTarget::Netns { .. } => true,
                })
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "WAN primary/backup mode requires at least {min_targets} distinct WAN links, ordered primary first"
                    ),
                });
            }
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
    Interface {
        /// Reference key into `wan_links`.
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        link_id: Uuid,
        /// Net-iface name mirror, re-derived from `link_id` on every save.
        /// CLEAN when 1.0.0 (dropped with the legacy name-keyed format).
        name: String,
    },
    Netns {
        container_name: String,
    },
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
                    "target": { "t": "interface", "link_id": Uuid::nil(), "name": "wan0" },
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
                "target": { "t": "interface", "link_id": Uuid::nil(), "name": "wan0" },
                "weight": 3
            })
        );
    }

    #[test]
    fn rejects_reserved_default_flow_id() {
        let config = FlowConfig {
            id: Uuid::nil(),
            enable: true,
            flow_id: DEFAULT_FLOW_ID,
            failover: Default::default(),
            flow_match_rules: vec![],
            flow_targets: vec![],
            name: String::new(),
            remark: String::new(),
            update_at: 0.0,
        };

        let result = crate::database::validator::ValidatableConfig::validate(&config);

        assert!(result.is_err(), "flow_id 0 is reserved for the default flow");
    }

    #[test]
    fn rejects_flow_ids_that_alias_another_dataplane_flow() {
        use crate::database::validator::ValidatableConfig;
        let mut config: FlowConfig = serde_json::from_value(serde_json::json!({
            "enable": true, "flow_id": 255, "flow_match_rules": [],
            "flow_targets": [], "remark": "last supported flow"
        }))
        .unwrap();
        assert!(config.validate().is_ok());
        for id in [256, 300, u32::MAX] {
            config.flow_id = id;
            assert!(
                matches!(config.validate(), Err(ServiceConfigError::FlowIdOutOfRange { flow_id }) if flow_id == id)
            );
        }
    }

    #[test]
    fn failover_defaults_and_validation() {
        use crate::database::validator::ValidatableConfig;
        let mut config: FlowConfig = serde_json::from_value(serde_json::json!({
            "enable": true, "flow_id": 1, "flow_match_rules": [],
            "flow_targets": [], "remark": "legacy"
        }))
        .unwrap();
        assert!(!config.failover.enable);
        assert_eq!(config.failover.trigger, FlowFailoverTrigger::HealthCheck);
        assert!(config.failover.auto_failback);
        config.failover.enable = true;
        assert!(config.validate().is_err());
        let target = |id| {
            WeightedFlowTarget::new(
                FlowTarget::Interface { link_id: Uuid::from_u128(id), name: String::new() },
                0,
            )
        };
        config.flow_targets = vec![target(1), target(1)];
        assert!(config.validate().is_err());
        config.flow_targets = vec![target(1), target(2)];
        assert!(config.validate().is_ok(), "weights are ignored for ordered failover");
        config.flow_targets[1] =
            WeightedFlowTarget::new(FlowTarget::Netns { container_name: "proxy".into() }, 1);
        assert!(config.validate().is_err());
    }

    #[test]
    fn interface_target_requires_link_id() {
        let json = serde_json::json!({
            "t": "interface",
            "name": "wan0"
        });

        let result: Result<FlowTarget, _> = serde_json::from_value(json);
        assert!(result.is_err(), "link_id is mandatory on interface targets");
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

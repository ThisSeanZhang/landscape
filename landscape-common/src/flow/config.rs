use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::flow::{FlowEntryRule, WeightedFlowTarget};
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
}

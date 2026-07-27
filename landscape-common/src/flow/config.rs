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

impl FlowConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        for rule in &self.flow_match_rules {
            rule.validate()?;
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

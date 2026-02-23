use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::flow::{FlowEntryRule, FlowTarget};
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

/// 流控配置结构体
#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/flow.d.ts")]
pub struct FlowConfig {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
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
    pub flow_targets: Vec<FlowTarget>,
    /// 备注
    pub remark: String,

    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for FlowConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

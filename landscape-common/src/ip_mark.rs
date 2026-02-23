use std::net::IpAddr;

use landscape_macro::LdApiError;

use crate::config::geo::GeoConfigKey;
use crate::config::ConfigId;
use crate::utils::time::get_f64_timestamp;
use crate::{database::repository::LandscapeDBStore, flow::mark::FlowMark};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DstIpRuleError {
    #[error("Destination IP rule '{0}' not found")]
    #[api_error(id = "dst_ip_rule.not_found", status = 404)]
    NotFound(ConfigId),
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/flow.d.ts")]
/// 对于外部 IP 规则
pub struct WanIpRuleConfig {
    pub id: Option<Uuid>,
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
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

fn default_flow_id() -> u32 {
    0_u32
}

impl LandscapeDBStore<Uuid> for WanIpRuleConfig {
    fn get_id(&self) -> Uuid {
        self.id.unwrap_or(Uuid::new_v4())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/flow.d.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum WanIPRuleSource {
    GeoKey(GeoConfigKey),
    Config(IpConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/flow.d.ts")]
pub struct IpConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
    pub prefix: u32,
    // pub reverse_match: String,
}

/// IP 标记最小单元
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpMarkInfo {
    pub mark: FlowMark,
    pub cidr: IpConfig,
    // pub override_dns: bool,
    pub priority: u16,
}

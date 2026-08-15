use std::net::IpAddr;

use landscape_macro::LdApiError;

use crate::config::ConfigId;
use crate::config_service::geo::GeoConfigKey;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::{database::repository::LandscapeDBStore, flow::mark::FlowMark};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DstIpRuleError {
    #[error("Destination IP rule '{0}' not found")]
    #[api_error(id = "dst_ip_rule.not_found", status = 404)]
    NotFound(ConfigId),
    #[error("Destination IP rule '{0}' cannot be moved to another flow; delete it and create a new rule in the target flow instead")]
    #[api_error(id = "dst_ip_rule.cannot_change_flow", status = 400)]
    CannotChangeFlow(ConfigId),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
/// 对于外部 IP 规则
pub struct WanIpRuleConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
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

/// IP 标记最小单元
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpMarkInfo {
    pub mark: FlowMark,
    pub cidr: IpConfig,
    // pub override_dns: bool,
    pub priority: u16,
}

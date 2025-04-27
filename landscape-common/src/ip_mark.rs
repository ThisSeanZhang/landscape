use std::net::IpAddr;

use crate::{flow::mark::FlowDnsMark, mark::PacketMark, store::storev2::LandScapeStore};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "flow.ts")]
/// 对于外部 IP 规则
pub struct WanIPRuleConfig {
    pub id: String,
    // 优先级 用作存储主键
    pub index: u32,
    // 是否启用
    pub enable: bool,
    /// 流量标记
    #[serde(default)]
    pub mark: FlowDnsMark,
    /// 匹配规则列表
    #[serde(default)]
    pub source: Vec<WanIPRuleSource>,
    // 备注
    pub remark: String,

    #[serde(default = "default_flow_id")]
    pub flow_id: u32,

    #[serde(default)]
    pub override_dns: bool,
}

fn default_flow_id() -> u32 {
    0_u32
}

impl LandScapeStore for WanIPRuleConfig {
    fn get_store_key(&self) -> String {
        self.id.clone()
    }
}

#[deprecated]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// 对于外部 IP 规则
pub struct LanIPRuleConfig {
    // 优先级 用作存储主键
    pub index: u32,
    // 是否启用
    pub enable: bool,
    /// 流量标记
    #[serde(default)]
    pub mark: PacketMark,
    /// 匹配规则列表
    #[serde(default)]
    pub source: Vec<IpConfig>,
    // 备注
    pub remark: String,
}

impl LandScapeStore for LanIPRuleConfig {
    fn get_store_key(&self) -> String {
        self.index.to_string()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "flow.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum WanIPRuleSource {
    GeoKey { country_code: String },
    Config(IpConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, TS)]
#[ts(export, export_to = "flow.ts")]
pub struct IpConfig {
    pub ip: IpAddr,
    pub prefix: u32,
    // pub reverse_match: String,
}

/// IP 标记最小单元
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpMarkInfo {
    pub mark: FlowDnsMark,
    pub cidr: IpConfig,
    pub override_dns: bool,
}

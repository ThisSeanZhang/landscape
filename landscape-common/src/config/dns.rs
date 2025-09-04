use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::dns::config::DnsUpstreamConfig;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::{flow::mark::FlowMark, store::storev2::LandscapeStore};

use super::geo::GeoConfigKey;

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct DNSRedirectRuleConfig {
    pub id: Uuid,
    pub remark: String,
    pub enable: bool,

    /// DNS Query Result
    pub result: Vec<IpAddr>,

    /// Match Domains
    #[serde(default)]
    pub source: Vec<DomainConfig>,

    #[serde(default = "get_f64_timestamp")]
    pub update_at: f64,
}

/// DNS 配置
#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct DNSRuleConfig {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    pub id: Uuid,

    pub name: String,
    /// 优先级
    pub index: u32,
    /// 是否启用
    pub enable: bool,
    /// 过滤模式
    #[serde(default)]
    pub filter: FilterResult,

    pub upstream_id: Uuid,
    /// 流量标记
    #[serde(default)]
    pub mark: FlowMark,
    /// 匹配规则列表
    #[serde(default)]
    pub source: Vec<RuleSource>,

    #[serde(default = "default_flow_id")]
    pub flow_id: u32,

    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    pub update_at: f64,
}

pub fn default_flow_id() -> u32 {
    0_u32
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DNSRuntimeRule {
    pub id: Uuid,
    pub name: String,
    /// 优先级
    pub index: u32,
    /// 是否启用
    pub enable: bool,
    /// 过滤模式
    pub filter: FilterResult,
    /// 解析模式
    pub resolve_mode: DnsUpstreamConfig,
    /// 流量标记
    pub mark: FlowMark,
    /// 匹配规则列表
    pub source: Vec<DomainConfig>,

    pub flow_id: u32,
}

impl LandscapeStore for DNSRuleConfig {
    fn get_store_key(&self) -> String {
        self.index.to_string()
    }
}

impl LandscapeDBStore<Uuid> for DNSRuleConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    GeoKey(GeoConfigKey),
    Config(DomainConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct DomainConfig {
    pub match_type: DomainMatchType,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
#[serde(rename_all = "snake_case")]
pub enum DomainMatchType {
    /// The value is used as is.
    Plain = 0,
    /// The value is used as a regular expression.
    Regex = 1,
    /// 域名匹配， 前缀匹配
    Domain = 2,
    /// The value is a domain.
    Full = 3,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
#[serde(rename_all = "snake_case")]
pub enum FilterResult {
    #[default]
    Unfilter,
    #[serde(rename = "only_ipv4")]
    OnlyIPv4,
    #[serde(rename = "only_ipv6")]
    OnlyIPv6,
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns_record_type.d.ts")]
#[serde(rename_all = "UPPERCASE")]
pub enum LandscapeDnsRecordType {
    A,
    AAAA,
}

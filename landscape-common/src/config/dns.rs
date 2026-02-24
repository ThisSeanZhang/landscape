use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ConfigId;
use crate::database::repository::LandscapeDBStore;
use crate::dns::config::{DnsBindConfig, DnsUpstreamConfig};
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::{flow::mark::FlowMark, store::storev2::LandscapeStore};

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsRuleError {
    #[error("DNS rule '{0}' not found")]
    #[api_error(id = "dns_rule.not_found", status = 404)]
    NotFound(ConfigId),
}

use super::geo::GeoConfigKey;

/// DNS 配置
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DNSRuleConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    /// 名称
    pub name: String,
    /// 优先级
    pub index: u32,
    /// 是否启用
    pub enable: bool,
    /// 过滤模式
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub filter: FilterResult,
    /// 上游配置 ID
    pub upstream_id: Uuid,
    /// 源 IP 绑定配置
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub bind_config: DnsBindConfig,
    /// 流量标记
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mark: FlowMark,
    /// 匹配规则列表
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub source: Vec<RuleSource>,
    /// 关联 Flow ID
    #[serde(default = "default_flow_id")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub flow_id: u32,
    /// 最近一次更新时间
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
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
    /// 源 IP 绑定配置
    pub bind_config: DnsBindConfig,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    GeoKey(GeoConfigKey),
    Config(DomainConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DomainConfig {
    pub match_type: DomainMatchType,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FilterResult {
    #[default]
    Unfilter,
    #[serde(rename = "only_ipv4")]
    OnlyIPv4,
    #[serde(rename = "only_ipv6")]
    OnlyIPv6,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "UPPERCASE")]
pub enum LandscapeDnsRecordType {
    A,
    AAAA,
}

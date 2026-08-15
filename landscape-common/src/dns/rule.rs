use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ConfigId;
use crate::database::repository::LandscapeDBStore;
use crate::dns::config::DnsUpstreamConfig;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::{flow::mark::FlowMark, store::storev2::LandscapeStore};

use crate::config_service::geo::GeoConfigKey;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsRuleError {
    #[error("DNS rule '{0}' not found")]
    #[api_error(id = "dns_rule.not_found", status = 404)]
    NotFound(ConfigId),
    #[error("DNS rule '{0}' cannot be moved to another flow; delete it and create a new rule in the target flow instead")]
    #[api_error(id = "dns_rule.cannot_change_flow", status = 400)]
    CannotChangeFlow(ConfigId),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DNSRuleConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: String,
    pub index: u32,
    pub enable: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub filter: FilterResult,
    pub upstream_id: Uuid,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mark: FlowMark,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub source: Vec<RuleSource>,
    #[serde(default = "default_flow_id")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub flow_id: u32,
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
    pub index: u32,
    pub enable: bool,
    pub filter: FilterResult,
    pub resolve_mode: DnsUpstreamConfig,
    pub mark: FlowMark,
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
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
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
    HTTPS,
}

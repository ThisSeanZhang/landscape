use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use uuid::Uuid;

use crate::config::FlowId;
use crate::config_service::geo::GeoFileCacheKey;
use crate::dns::rule::{DomainConfig, DomainMatchType, FilterResult};
use crate::flow::mark::FlowMark;

use super::config::DnsUpstreamConfig;
use super::redirect::{
    DEFAULT_BLOCK_METADATA_QUERIES, DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS, DnsRedirectAnswerMode,
    default_block_metadata_queries,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CacheRuntimeConfig {
    pub cache_capacity: u32,
    pub cache_ttl: u32,
    pub negative_cache_ttl: u32,
}

impl Default for CacheRuntimeConfig {
    fn default() -> Self {
        Self {
            cache_capacity: crate::DEFAULT_DNS_CACHE_CAPACITY,
            cache_ttl: crate::DEFAULT_DNS_CACHE_TTL,
            negative_cache_ttl: crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DohRuntimeConfig {
    pub listen_port: u16,
    pub http_endpoint: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowDnsDependencies {
    pub geo_keys: HashSet<GeoFileCacheKey>,
    pub upstream_ids: HashSet<Uuid>,
    pub dynamic_redirect_sources: HashSet<String>,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DynamicDnsRedirectScope {
    Global,
    Flow(FlowId),
}

impl DynamicDnsRedirectScope {
    pub fn applies_to_flow(&self, flow_id: FlowId) -> bool {
        match self {
            Self::Global => true,
            Self::Flow(scope_flow_id) => *scope_flow_id == flow_id,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum DynamicDnsMatch {
    Full(String),
    Domain(String),
}

impl From<DynamicDnsMatch> for DomainConfig {
    fn from(value: DynamicDnsMatch) -> Self {
        match value {
            DynamicDnsMatch::Full(value) => {
                DomainConfig { match_type: DomainMatchType::Full, value }
            }
            DynamicDnsMatch::Domain(value) => {
                DomainConfig { match_type: DomainMatchType::Domain, value }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DynamicDnsRedirectRecord {
    pub match_rule: DynamicDnsMatch,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub answer_mode: DnsRedirectAnswerMode,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub result_info: Vec<IpAddr>,
    pub ttl_secs: u32,
    /// Whether metadata queries (NS/SOA/TXT/MX/CAA) matching this record are
    /// intercepted (default true) or passed through to upstream.
    #[serde(default = "default_block_metadata_queries")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub block_metadata_queries: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DynamicDnsRedirectBatch {
    pub source_id: String,
    pub scope: DynamicDnsRedirectScope,
    pub records: Vec<DynamicDnsRedirectRecord>,
}

#[derive(Debug)]
pub struct DNSRedirectRuntimeRule {
    pub redirect_id: Option<Uuid>,
    pub dynamic_redirect_source: Option<String>,
    pub answer_mode: DnsRedirectAnswerMode,
    pub match_rules: Vec<DomainConfig>,
    pub result_info: Vec<IpAddr>,
    pub ttl_secs: u32,
    pub block_metadata_queries: bool,
}

impl Default for DNSRedirectRuntimeRule {
    fn default() -> Self {
        Self {
            redirect_id: None,
            dynamic_redirect_source: None,
            answer_mode: DnsRedirectAnswerMode::default(),
            match_rules: vec![],
            result_info: vec![],
            ttl_secs: DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
            block_metadata_queries: DEFAULT_BLOCK_METADATA_QUERIES,
        }
    }
}

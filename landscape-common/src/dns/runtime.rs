use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dns::config::{DnsBindConfig, DnsUpstreamConfig};
use crate::dns::redirect::DNSRedirectRuntimeRule;
use crate::dns::redirect::DnsRedirectAnswerMode;
use crate::dns::rule::{DNSRuntimeRule, DomainConfig, FilterResult};
use crate::dns::upstream::DnsUpstreamMode;
use crate::flow::mark::FlowMark;
use crate::geo::GeoFileCacheKey;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CacheRuntimeConfig {
    pub cache_capacity: u32,
    pub cache_ttl: u32,
    pub negative_cache_ttl: u32,
    pub lan_suffix: String,
}

impl Default for CacheRuntimeConfig {
    fn default() -> Self {
        Self {
            cache_capacity: crate::DEFAULT_DNS_CACHE_CAPACITY,
            cache_ttl: crate::DEFAULT_DNS_CACHE_TTL,
            negative_cache_ttl: crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL,
            lan_suffix: crate::DEFAULT_DNS_LAN_SUFFIX.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DohRuntimeConfig {
    pub listen_port: u16,
    pub http_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuntimeUpstreamTarget {
    pub mode: DnsUpstreamMode,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ips: Vec<IpAddr>,
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub port: Option<u16>,
    pub enable_ip_validation: bool,
}

impl From<&DnsUpstreamConfig> for RuntimeUpstreamTarget {
    fn from(value: &DnsUpstreamConfig) -> Self {
        Self {
            mode: value.mode.clone(),
            ips: value.ips.clone(),
            port: value.port,
            enable_ip_validation: value.enable_ip_validation.unwrap_or(false),
        }
    }
}

impl From<RuntimeUpstreamTarget> for DnsUpstreamConfig {
    fn from(value: RuntimeUpstreamTarget) -> Self {
        Self {
            id: Uuid::nil(),
            remark: String::new(),
            mode: value.mode,
            ips: value.ips,
            port: value.port,
            enable_ip_validation: Some(value.enable_ip_validation),
            update_at: 0.0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuntimeDnsRule {
    pub rule_id: Uuid,
    pub order: u32,
    pub filter: FilterResult,
    pub upstream: RuntimeUpstreamTarget,
    pub bind_config: DnsBindConfig,
    pub mark: FlowMark,
    pub sources: Vec<DomainConfig>,
}

impl From<DNSRuntimeRule> for RuntimeDnsRule {
    fn from(value: DNSRuntimeRule) -> Self {
        Self {
            rule_id: value.id,
            order: value.index,
            filter: value.filter,
            upstream: RuntimeUpstreamTarget::from(&value.resolve_mode),
            bind_config: value.bind_config,
            mark: value.mark,
            sources: value.source,
        }
    }
}

impl From<RuntimeDnsRule> for DNSRuntimeRule {
    fn from(value: RuntimeDnsRule) -> Self {
        Self {
            id: value.rule_id,
            name: String::new(),
            index: value.order,
            enable: true,
            filter: value.filter,
            resolve_mode: value.upstream.into(),
            bind_config: value.bind_config,
            mark: value.mark,
            source: value.sources,
            flow_id: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuntimeRedirectRule {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub redirect_id: Option<Uuid>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub dynamic_source_id: Option<String>,
    pub order: u32,
    pub answer_mode: DnsRedirectAnswerMode,
    pub match_rules: Vec<DomainConfig>,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub result_ips: Vec<IpAddr>,
    pub ttl_secs: u32,
}

impl From<DNSRedirectRuntimeRule> for RuntimeRedirectRule {
    fn from(value: DNSRedirectRuntimeRule) -> Self {
        Self {
            redirect_id: value.redirect_id,
            dynamic_source_id: value.dynamic_redirect_source,
            order: 0,
            answer_mode: value.answer_mode,
            match_rules: value.match_rules,
            result_ips: value.result_info,
            ttl_secs: value.ttl_secs,
        }
    }
}

impl From<RuntimeRedirectRule> for DNSRedirectRuntimeRule {
    fn from(value: RuntimeRedirectRule) -> Self {
        Self {
            redirect_id: value.redirect_id,
            dynamic_redirect_source: value.dynamic_source_id,
            answer_mode: value.answer_mode,
            match_rules: value.match_rules,
            result_info: value.result_ips,
            ttl_secs: value.ttl_secs,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowDnsDesiredState {
    pub flow_id: u32,
    pub dns_rules: Vec<RuntimeDnsRule>,
    pub redirect_rules: Vec<RuntimeRedirectRule>,
    pub cache_runtime: CacheRuntimeConfig,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub doh_runtime: Option<DohRuntimeConfig>,
}

impl Default for FlowDnsDesiredState {
    fn default() -> Self {
        Self {
            flow_id: 0,
            dns_rules: vec![],
            redirect_rules: vec![],
            cache_runtime: CacheRuntimeConfig::default(),
            doh_runtime: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowDnsDependencies {
    pub geo_keys: HashSet<GeoFileCacheKey>,
    pub upstream_ids: HashSet<Uuid>,
    pub dynamic_redirect_sources: HashSet<String>,
}

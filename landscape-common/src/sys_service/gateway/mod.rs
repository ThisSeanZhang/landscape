pub mod settings;

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::config::ConfigId;
use crate::database::repository::LandscapeDBStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum GatewayError {
    #[error("Gateway rule '{0}' not found")]
    #[api_error(id = "gateway.rule_not_found", status = 404)]
    NotFound(ConfigId),
    #[error(
        "Gateway rule type 'legacy_path_prefix' is read-only and cannot be created or updated"
    )]
    #[api_error(id = "gateway.legacy_path_prefix_unsupported", status = 400)]
    LegacyPathPrefixUnsupported,
    #[error("Gateway rule '{rule_name}' requires at least one domain")]
    #[api_error(id = "gateway.domains_required", status = 400)]
    DomainsRequired { rule_name: String },
    #[error("Host domain conflict: domain '{domain}' already used by rule '{rule_name}'")]
    #[api_error(id = "gateway.host_conflict", status = 409)]
    HostConflict { domain: String, rule_name: String },
    #[error(
        "Wildcard domain '{wildcard}' covers specific domain '{domain}' in rule '{rule_name}'"
    )]
    #[api_error(id = "gateway.wildcard_covers_domain", status = 409)]
    WildcardCoversDomain { wildcard: String, domain: String, rule_name: String },
    #[error("Domain pattern '{domain}' overlaps with '{other_domain}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.domain_pattern_overlap", status = 409)]
    DomainPatternOverlap { domain: String, other_domain: String, rule_name: String },
    #[error("Path prefix '{new_prefix}' overlaps with '{existing_prefix}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.path_prefix_overlap", status = 409)]
    PathPrefixOverlap { new_prefix: String, existing_prefix: String, rule_name: String },
    #[error("Path prefix '{prefix}' is invalid")]
    #[api_error(id = "gateway.invalid_path_prefix", status = 400)]
    InvalidPathPrefix { prefix: String },
    #[error("Duplicate path prefix '{prefix}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.duplicate_path_group_prefix", status = 409)]
    DuplicatePathGroupPrefix { prefix: String, rule_name: String },
    #[error("SNI passthrough rules do not support request header injection or client IP headers")]
    #[api_error(id = "gateway.sni_proxy_header_unsupported", status = 400)]
    SniProxyHeaderUnsupported,
    #[error("Invalid request header name '{name}'")]
    #[api_error(id = "gateway.invalid_header_name", status = 400)]
    InvalidHeaderName { name: String },
    #[error("Invalid request header value for '{name}'")]
    #[api_error(id = "gateway.invalid_header_value", status = 400)]
    InvalidHeaderValue { name: String },
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HttpUpstreamRuleConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub enable: bool,
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    pub match_rule: HttpUpstreamMatchRule,
    pub upstream: HttpUpstreamConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

#[derive(Debug, Deserialize)]
struct HttpUpstreamRuleConfigCompat {
    #[serde(default = "gen_database_uuid")]
    pub id: Uuid,
    pub enable: bool,
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    pub match_rule: HttpUpstreamMatchRuleCompat,
    pub upstream: HttpUpstreamConfig,
    #[serde(default = "get_f64_timestamp")]
    pub update_at: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HttpUpstreamMatchRule {
    Host {
        #[serde(default)]
        path_groups: Vec<HttpPathGroup>,
    },
    SniProxy,
    LegacyPathPrefix {
        prefix: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum HttpUpstreamMatchRuleCompat {
    Host {
        #[serde(default)]
        domains: Vec<String>,
        #[serde(default)]
        path_groups: Vec<HttpPathGroup>,
    },
    PathPrefix {
        #[serde(default)]
        domains: Vec<String>,
        prefix: String,
    },
    SniProxy {
        #[serde(default)]
        domains: Vec<String>,
    },
    LegacyPathPrefix {
        prefix: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HttpPathGroup {
    pub prefix: String,
    #[serde(default)]
    pub rewrite_mode: PathRewriteMode,
    pub upstream: HttpUpstreamConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PathRewriteMode {
    #[default]
    Preserve,
    StripPrefix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HttpUpstreamConfig {
    pub targets: Vec<HttpUpstreamTarget>,
    #[serde(default)]
    pub load_balance: LoadBalanceMethod,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub request_headers: Vec<ProxyRequestHeader>,
    #[serde(default)]
    pub header_conflict_mode: ProxyHeaderConflictMode,
    #[serde(default)]
    pub client_ip_headers: ClientIpHeaderPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HttpUpstreamTarget {
    pub address: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub skip_cert_verify: bool,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceMethod {
    #[default]
    RoundRobin,
    Random,
    Consistent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProxyRequestHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProxyHeaderConflictMode {
    #[default]
    Set,
    Append,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClientIpHeaderPolicy {
    #[default]
    Standard,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HealthCheckConfig {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

impl LandscapeDBStore<Uuid> for HttpUpstreamRuleConfig {
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

impl<'de> Deserialize<'de> for HttpUpstreamRuleConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compat = HttpUpstreamRuleConfigCompat::deserialize(deserializer)?;

        let (match_rule, nested_domains) = match compat.match_rule {
            HttpUpstreamMatchRuleCompat::Host { domains, path_groups } => {
                (HttpUpstreamMatchRule::Host { path_groups }, domains)
            }
            HttpUpstreamMatchRuleCompat::SniProxy { domains } => {
                (HttpUpstreamMatchRule::SniProxy, domains)
            }
            HttpUpstreamMatchRuleCompat::PathPrefix { domains, prefix } => {
                (HttpUpstreamMatchRule::LegacyPathPrefix { prefix }, domains)
            }
            HttpUpstreamMatchRuleCompat::LegacyPathPrefix { prefix } => {
                (HttpUpstreamMatchRule::LegacyPathPrefix { prefix }, Vec::new())
            }
        };

        let domains = if compat.domains.is_empty() { nested_domains } else { compat.domains };

        Ok(Self {
            id: compat.id,
            enable: compat.enable,
            name: compat.name,
            domains,
            match_rule,
            upstream: compat.upstream,
            update_at: compat.update_at,
        })
    }
}

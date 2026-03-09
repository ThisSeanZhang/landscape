pub mod config;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::store::storev2::LandscapeStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::LdApiError;

use super::ConfigId;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum GatewayError {
    #[error("Gateway rule '{0}' not found")]
    #[api_error(id = "gateway.rule_not_found", status = 404)]
    NotFound(ConfigId),

    #[error("Host domain conflict: domain '{domain}' already used by rule '{rule_name}'")]
    #[api_error(id = "gateway.host_conflict", status = 409)]
    HostConflict { domain: String, rule_name: String },

    #[error(
        "Wildcard domain '{wildcard}' covers specific domain '{domain}' in rule '{rule_name}'"
    )]
    #[api_error(id = "gateway.wildcard_covers_domain", status = 409)]
    WildcardCoversDomain { wildcard: String, domain: String, rule_name: String },

    #[error("Path prefix '{new_prefix}' overlaps with '{existing_prefix}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.path_prefix_overlap", status = 409)]
    PathPrefixOverlap { new_prefix: String, existing_prefix: String, rule_name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HttpUpstreamRuleConfig {
    #[serde(default = "gen_database_uuid")]
    pub id: Uuid,
    pub enable: bool,
    pub name: String,
    pub match_rule: HttpUpstreamMatchRule,
    pub upstream: HttpUpstreamConfig,
    #[serde(default = "get_f64_timestamp")]
    pub update_at: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HttpUpstreamMatchRule {
    Host { domains: Vec<String> },
    PathPrefix { prefix: String },
    SniProxy { domains: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HttpUpstreamConfig {
    pub targets: Vec<HttpUpstreamTarget>,
    #[serde(default)]
    pub load_balance: LoadBalanceMethod,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
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
pub struct HealthCheckConfig {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

impl LandscapeStore for HttpUpstreamRuleConfig {
    fn get_store_key(&self) -> String {
        self.id.to_string()
    }
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

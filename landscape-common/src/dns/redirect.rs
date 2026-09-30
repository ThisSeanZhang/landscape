use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

pub use super::error::DnsRedirectError;
pub use super::runtime::{
    DNSRedirectRuntimeRule, DynamicDnsMatch, DynamicDnsRedirectBatch, DynamicDnsRedirectRecord,
    DynamicDnsRedirectScope,
};

use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::{config::FlowId, database::repository::LandscapeDBStore, dns::rule::RuleSource};

pub const DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS: u32 = 10;

/// Default for `block_metadata_queries`: strict interception is the legacy
/// behavior, so configs created before the field existed keep intercepting
/// metadata queries (NS/SOA/TXT/MX/CAA) unless explicitly opted out.
pub const DEFAULT_BLOCK_METADATA_QUERIES: bool = true;

pub(crate) fn default_block_metadata_queries() -> bool {
    DEFAULT_BLOCK_METADATA_QUERIES
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DnsRedirectAnswerMode {
    #[default]
    StaticIps,
    AllLocalIps,
}

impl DnsRedirectAnswerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticIps => "static_ips",
            Self::AllLocalIps => "all_local_ips",
        }
    }

    pub fn from_db_value(value: &str) -> Self {
        match value {
            "all_local_ips" => Self::AllLocalIps,
            _ => Self::StaticIps,
        }
    }
}

/// 用于定义 DNS 重定向的单元配置
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DNSRedirectRule {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,

    pub name: Option<String>,

    pub remark: String,

    pub enable: bool,

    pub match_rules: Vec<RuleSource>,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub answer_mode: DnsRedirectAnswerMode,

    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub result_info: Vec<IpAddr>,

    pub apply_flows: Vec<FlowId>,

    /// When true (default), metadata queries (NS/SOA/TXT/MX/CAA) matching this
    /// rule are intercepted too. Set to false to pass them through to the
    /// upstream resolver, e.g. when certificate issuance (ACME dns-01
    /// validation) runs on the LAN and needs NS records. The router's own
    /// certificate issuance is not affected.
    #[serde(default = "default_block_metadata_queries")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub block_metadata_queries: bool,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for DNSRedirectRule {
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

crate::impl_trivial_validatable!(DNSRedirectRule);

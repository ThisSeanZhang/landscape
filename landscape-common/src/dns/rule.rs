use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::flow::mark::FlowMark;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

use crate::config_service::geo::GeoConfigKey;

pub use super::error::DnsRuleError;
pub use super::runtime::DNSRuntimeRule;

/// An independently managed upstream selected when this WAN carries DNS traffic.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsWanUpstream {
    pub link_id: Uuid,
    pub upstream_id: Uuid,
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
    /// Empty keeps the single-upstream behavior. Otherwise the owning flow's
    /// selected WAN chooses one independent upstream; no static fallback.
    #[serde(default)]
    pub wan_upstreams: Vec<DnsWanUpstream>,
    #[serde(skip)]
    #[cfg_attr(feature = "openapi", schema(ignore))]
    pub resolved_wan: Option<super::bind::DnsWanBinding>,
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

impl crate::database::validator::ValidatableConfig for DNSRuleConfig {
    fn validate(&self) -> Result<(), crate::service::ServiceConfigError> {
        let mut links = std::collections::HashSet::new();
        for mapping in &self.wan_upstreams {
            if mapping.link_id.is_nil()
                || mapping.upstream_id.is_nil()
                || !links.insert(mapping.link_id)
            {
                return Err(crate::service::ServiceConfigError::InvalidConfig {
                    reason: "WAN DNS groups require unique WAN IDs and nonempty upstream IDs"
                        .into(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod wan_group_tests {
    use super::*;
    use crate::database::validator::ValidatableConfig;

    #[test]
    fn legacy_rules_default_empty_and_runtime_binding_cannot_be_injected() {
        let value = serde_json::json!({"name":"legacy","index":10,"enable":true,"upstream_id":Uuid::new_v4(),"resolved_wan":{"ipv4":["evil","192.0.2.1"]}});
        let mut rule: DNSRuleConfig = serde_json::from_value(value).unwrap();
        assert!(rule.wan_upstreams.is_empty());
        assert!(rule.resolved_wan.is_none());
        assert!(serde_json::to_value(&rule).unwrap().get("resolved_wan").is_none());
        rule.wan_upstreams = vec![DnsWanUpstream {
            link_id: Uuid::new_v4(),
            upstream_id: Uuid::new_v4(),
        }];
        assert!(rule.validate().is_ok());
        rule.wan_upstreams.push(rule.wan_upstreams[0].clone());
        assert!(rule.validate().is_err());
    }
}

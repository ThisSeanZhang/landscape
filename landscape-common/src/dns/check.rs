use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::FlowId;
use crate::dns::rule::{DNSRuntimeRule, FilterResult, LandscapeDnsRecordType};

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsCheckError {
    #[error("DNS flow '{0}' not found")]
    #[api_error(id = "dns_check.flow_not_found", status = 404)]
    FlowNotFound(FlowId),

    #[error("DNS cache refresh requires a matched upstream rule for '{0}'")]
    #[api_error(id = "dns_check.refresh_requires_rule", status = 409)]
    RefreshRequiresRule(String),

    #[error("DNS cache refresh is not available for redirected domain '{0}'")]
    #[api_error(id = "dns_check.refresh_redirected", status = 409)]
    RefreshRedirected(String),

    #[error("DNS cache refresh failed for '{0}'")]
    #[api_error(id = "dns_check.refresh_failed", status = 502)]
    RefreshFailed(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeRecord {
    pub name: String,
    pub rr_type: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CheckDnsResult {
    pub config: Option<DNSRuntimeRule>,
    pub records: Option<Vec<LandscapeRecord>>,
    pub cache_records: Option<Vec<LandscapeRecord>>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CheckChainDnsResult {
    /// Matched redirect rule id, if this query was answered by redirect logic.
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub redirect_id: Option<Uuid>,
    /// Dynamic redirect source description, when present.
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub dynamic_redirect_source: Option<String>,
    /// Matched DNS rule id, if any.
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub rule_id: Option<Uuid>,
    /// Filter configured on the matched DNS rule or cache entry.
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub rule_filter: Option<FilterResult>,
    /// Indicates whether the current query type would be filtered by the matched rule.
    /// This flag is reported even when `apply_filter` is false.
    #[serde(default)]
    pub query_filtered: bool,
    /// Upstream or redirect records returned for this query. These are filtered only
    /// when `apply_filter` is true.
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub records: Option<Vec<LandscapeRecord>>,
    /// Cached records for this query. These are filtered only when `apply_filter` is true.
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub cache_records: Option<Vec<LandscapeRecord>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct CheckDnsReq {
    /// Flow used to evaluate DNS rules.
    #[cfg_attr(feature = "openapi", param(value_type = u32))]
    pub flow_id: FlowId,
    /// Domain to query. IDN input is normalized to ASCII before lookup.
    pub domain: String,
    /// DNS record type to query.
    pub record_type: LandscapeDnsRecordType,
    /// Apply the matched DNS rule filter to returned records.
    ///
    /// Set this to `false` when you want full upstream/cache visibility together with
    /// `query_filtered`. Set it to `true` when you want the returned records to match
    /// runtime filtering behavior.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", param(required = false))]
    pub apply_filter: bool,
}

impl CheckDnsReq {
    pub fn get_domain(&self) -> String {
        let domain = self.domain.trim().trim_end_matches('.');
        match idna::domain_to_ascii(domain) {
            Ok(ascii) => format!("{}.", ascii),
            Err(_) => format!("{}.", domain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::rule::LandscapeDnsRecordType;

    #[test]
    fn check_dns_req_normalizes_trailing_dot_once() {
        let req = CheckDnsReq {
            flow_id: 1,
            domain: "example.com.".to_string(),
            record_type: LandscapeDnsRecordType::A,
            apply_filter: false,
        };

        assert_eq!(req.get_domain(), "example.com.");
    }

    #[test]
    fn check_dns_req_adds_missing_trailing_dot() {
        let req = CheckDnsReq {
            flow_id: 1,
            domain: "example.com".to_string(),
            record_type: LandscapeDnsRecordType::A,
            apply_filter: false,
        };

        assert_eq!(req.get_domain(), "example.com.");
    }
}

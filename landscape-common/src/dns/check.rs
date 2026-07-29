use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::FlowId;
use crate::dns::domain::normalize_domain_name;
use crate::dns::error::DnsError;
use crate::dns::rule::{DNSRuntimeRule, FilterResult, LandscapeDnsRecordType};

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
    pub fn get_domain(&self) -> Result<String, DnsError> {
        Ok(format!("{}.", normalize_domain_name(&self.domain)?))
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

        assert_eq!(req.get_domain().unwrap(), "example.com.");
    }

    #[test]
    fn check_dns_req_adds_missing_trailing_dot() {
        let req = CheckDnsReq {
            flow_id: 1,
            domain: "example.com".to_string(),
            record_type: LandscapeDnsRecordType::A,
            apply_filter: false,
        };

        assert_eq!(req.get_domain().unwrap(), "example.com.");
    }
}

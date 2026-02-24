use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{dns::DNSRuntimeRule, dns::LandscapeDnsRecordType, FlowId};

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
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub redirect_id: Option<Uuid>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub rule_id: Option<Uuid>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub records: Option<Vec<LandscapeRecord>>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub cache_records: Option<Vec<LandscapeRecord>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct CheckDnsReq {
    #[cfg_attr(feature = "openapi", param(value_type = u32))]
    pub flow_id: FlowId,
    pub domain: String,
    pub record_type: LandscapeDnsRecordType,
}

impl CheckDnsReq {
    pub fn get_domain(&self) -> String {
        match idna::domain_to_ascii(&self.domain) {
            Ok(ascii) => format!("{}.", ascii),
            Err(_) => format!("{}.", self.domain),
        }
    }
}

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::config::{dns::DNSRuntimeRule, dns::LandscapeDnsRecordType, FlowId};

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct LandscapeRecord {
    pub name: String,
    pub rr_type: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Default, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct CheckDnsResult {
    #[ts(type = "any | null")]
    pub config: Option<DNSRuntimeRule>,
    pub records: Option<Vec<LandscapeRecord>>,
    pub cache_records: Option<Vec<LandscapeRecord>>,
}

#[derive(Serialize, Deserialize, Debug, Default, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct CheckChainDnsResult {
    pub redirect_id: Option<Uuid>,
    pub rule_id: Option<Uuid>,
    pub records: Option<Vec<LandscapeRecord>>,
    pub cache_records: Option<Vec<LandscapeRecord>>,
}

#[derive(Serialize, Deserialize, Debug, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct CheckDnsReq {
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

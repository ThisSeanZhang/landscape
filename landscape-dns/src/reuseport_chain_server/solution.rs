use std::{net::IpAddr, str::FromStr as _};

use hickory_proto::rr::{
    rdata::{A, AAAA},
    RData, Record, RecordType,
};
use landscape_common::dns::redirect::DNSRedirectRuntimeRule;
use uuid::Uuid;

use crate::rule::matcher::DomainMatcher;

#[derive(Debug)]
pub struct RedirectSolution {
    pub id: Uuid,
    matcher: DomainMatcher,
    result_info: Vec<IpAddr>,
}

impl RedirectSolution {
    pub fn new(rule: DNSRedirectRuntimeRule) -> Self {
        let matcher = DomainMatcher::new(rule.match_rules);
        Self {
            matcher,
            id: rule.id,
            result_info: rule.result_info,
        }
    }

    pub fn is_match(&self, domain: &str) -> bool {
        let domain = if let Some(stripped) = domain.strip_suffix('.') { stripped } else { domain };
        self.matcher.is_match(domain)
    }

    pub fn lookup(&self, domain: &str, query_type: RecordType) -> Vec<Record> {
        let mut result = vec![];
        for ip in &self.result_info {
            let rdata_ip = match (ip, &query_type) {
                (IpAddr::V4(ip), RecordType::A) => Some(RData::A(A(*ip))),
                (IpAddr::V6(ip), RecordType::AAAA) => Some(RData::AAAA(AAAA(*ip))),
                _ => None,
            };

            if let Some(rdata) = rdata_ip {
                result.push(Record::from_rdata(
                    hickory_resolver::Name::from_str(domain).unwrap(),
                    10,
                    rdata,
                ));
            }
        }

        result
    }
}

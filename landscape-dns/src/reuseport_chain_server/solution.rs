use std::{net::IpAddr, str::FromStr as _};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{
    rdata::{A, AAAA},
    RData, Record, RecordType,
};
use uuid::Uuid;

use landscape_common::dns::redirect::DNSRedirectRuntimeRule;
use landscape_common::{
    config::dns::{DNSRuntimeRule, FilterResult},
    flow::DnsRuntimeMarkInfo,
};

use crate::connection::LandscapeMarkDNSResolver;
use crate::reuseport_chain_server::matcher::DomainMatcher;

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

#[derive(Debug)]
pub struct ResolutionRule {
    matcher: DomainMatcher,
    config: DNSRuntimeRule,
    mark: DnsRuntimeMarkInfo,
    resolver: LandscapeMarkDNSResolver,
}

impl ResolutionRule {
    pub fn new(config: DNSRuntimeRule, flow_id: u32) -> Self {
        let span = tracing::info_span!("dns_rule", flow_id = flow_id);
        let _ = span.enter();

        let matcher = DomainMatcher::new(config.source.clone());

        let resolver =
            crate::connection::create_resolver(flow_id, config.mark, config.resolve_mode.clone());

        let mark = DnsRuntimeMarkInfo {
            mark: config.mark.clone(),
            priority: config.index as u16,
        };
        ResolutionRule { matcher, config, resolver, mark }
    }

    pub fn mark(&self) -> &DnsRuntimeMarkInfo {
        &self.mark
    }

    pub fn filter_mode(&self) -> FilterResult {
        self.config.filter.clone()
    }

    pub fn get_config_id(&self) -> Uuid {
        self.config.id
    }

    /// 确定是不是当前规则进行处理
    pub fn is_match(&self, domain: &str) -> bool {
        let match_result = if self.config.source.is_empty() {
            true
        } else {
            let domain =
                if let Some(stripped) = domain.strip_suffix('.') { stripped } else { domain };
            self.matcher.is_match(domain)
        };
        match_result
    }

    pub async fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<Vec<Record>, ResponseCode> {
        match self.resolver.lookup(domain, query_type).await {
            Ok(lookup) => Ok(lookup.records().to_vec()),
            Err(e) => {
                let result = if e.is_no_records_found() {
                    ResponseCode::NoError
                } else {
                    tracing::error!(
                        "[flow_id: {:?}, config: {}] DNS resolution failed for {}: {}",
                        self.config.flow_id,
                        self.config.resolve_mode.id,
                        domain,
                        e
                    );
                    ResponseCode::ServFail
                };
                Err(result)
            }
        }
    }
}

use std::{net::IpAddr, str::FromStr};

use hickory_proto::rr::{
    rdata::{A, AAAA},
    RData, Record, RecordType,
};
use uuid::Uuid;

use landscape_common::dns::redirect::DnsRedirectAnswerMode;
use landscape_common::{
    dns::rule::FilterResult,
    dns::{RuntimeDnsRule, RuntimeRedirectRule},
    flow::DnsRuntimeMarkInfo,
};

use crate::connection::LandscapeMarkDNSResolver;
use crate::server::matcher::DomainMatcher;

#[derive(Debug)]
pub struct RedirectSolution {
    pub redirect_id: Option<Uuid>,
    pub dynamic_redirect_source: Option<String>,
    pub answer_mode: DnsRedirectAnswerMode,
    matcher: DomainMatcher,
    result_info: Vec<IpAddr>,
    ttl_secs: u32,
}

impl RedirectSolution {
    pub fn new(rule: RuntimeRedirectRule) -> Self {
        let RuntimeRedirectRule {
            redirect_id,
            dynamic_source_id,
            order: _,
            answer_mode,
            match_rules,
            result_ips,
            ttl_secs,
        } = rule;
        let matcher = DomainMatcher::new(match_rules);
        Self {
            matcher,
            redirect_id,
            dynamic_redirect_source: dynamic_source_id,
            answer_mode,
            result_info: result_ips,
            ttl_secs,
        }
    }

    pub fn is_match(&self, domain: &str) -> bool {
        let domain = if let Some(stripped) = domain.strip_suffix('.') { stripped } else { domain };
        self.matcher.is_match(domain)
    }

    pub fn lookup(&self, domain: &str, query_type: RecordType) -> Vec<Record> {
        self.lookup_with_addrs(domain, query_type, &self.result_info)
    }

    pub fn lookup_with_addrs(
        &self,
        domain: &str,
        query_type: RecordType,
        addrs: &[IpAddr],
    ) -> Vec<Record> {
        let mut result = vec![];
        for ip in addrs {
            let rdata_ip = match (ip, &query_type) {
                (IpAddr::V4(ip), RecordType::A) => Some(RData::A(A(*ip))),
                (IpAddr::V6(ip), RecordType::AAAA) => Some(RData::AAAA(AAAA(*ip))),
                _ => None,
            };

            if let Some(rdata) = rdata_ip {
                result.push(Record::from_rdata(
                    hickory_proto::rr::Name::from_str(domain).unwrap(),
                    self.ttl_secs,
                    rdata,
                ));
            }
        }

        result
    }

    pub fn is_block(&self) -> bool {
        matches!(self.answer_mode, DnsRedirectAnswerMode::StaticIps) && self.result_info.is_empty()
    }

    pub fn uses_local_answer_provider(&self) -> bool {
        matches!(self.answer_mode, DnsRedirectAnswerMode::AllLocalIps)
    }
}

#[derive(Debug)]
pub struct ResolutionRule {
    matcher: DomainMatcher,
    config: RuntimeDnsRule,
    flow_id: u32,
    mark: DnsRuntimeMarkInfo,
    resolver: LandscapeMarkDNSResolver,

    enable_ip_validation: bool,
}

impl ResolutionRule {
    pub fn new(config: RuntimeDnsRule, flow_id: u32) -> Self {
        let span = tracing::info_span!("dns_rule", flow_id = flow_id);
        let _ = span.enter();

        let matcher = DomainMatcher::new(config.sources.clone());

        let enable_ip_validation = config.upstream.enable_ip_validation;
        let resolver = crate::connection::create_resolver(
            flow_id,
            config.mark,
            config.bind_config.clone(),
            config.upstream.clone(),
        );

        let mark = DnsRuntimeMarkInfo {
            mark: config.mark.clone(),
            priority: config.order as u16,
        };
        ResolutionRule {
            matcher,
            config,
            flow_id,
            resolver,
            mark,
            enable_ip_validation,
        }
    }

    pub fn mark(&self) -> &DnsRuntimeMarkInfo {
        &self.mark
    }

    pub fn filter_mode(&self) -> FilterResult {
        self.config.filter.clone()
    }

    pub fn get_config_id(&self) -> Uuid {
        self.config.rule_id
    }

    pub fn order(&self) -> u32 {
        self.config.order
    }

    /// 确定是不是当前规则进行处理
    pub fn is_match(&self, domain: &str) -> bool {
        let match_result = if self.config.sources.is_empty() {
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
    ) -> crate::error::DnsResult<Vec<Record>> {
        match self.resolver.lookup(domain, query_type).await {
            Ok(lookup) => {
                let result = if self.enable_ip_validation {
                    lookup
                        .answers()
                        .iter()
                        .filter(|ietm| match &ietm.data {
                            RData::A(A(ipv4)) => is_global_ipv4(ipv4),
                            RData::AAAA(AAAA(ipv6)) => is_global_ipv6(ipv6),
                            _ => true,
                        })
                        .cloned()
                        .collect()
                } else {
                    lookup.answers().to_vec()
                };
                Ok(result)
            }
            Err(e) => {
                use crate::error::DnsError;
                match &e {
                    hickory_resolver::net::NetError::Dns(
                        hickory_resolver::net::DnsError::NoRecordsFound(no_records),
                    ) => {
                        return Err(DnsError::Protocol(no_records.response_code));
                    }
                    hickory_resolver::net::NetError::Timeout => {
                        return Err(DnsError::Timeout);
                    }
                    _ => {}
                }
                tracing::error!(
                    "[flow_id: {}, rule: {}] DNS resolution failed for {}: {}",
                    self.flow_id,
                    self.config.rule_id,
                    domain,
                    e
                );
                Err(DnsError::Internal(e.to_string()))
            }
        }
    }
}

// Copy from unstable feature
fn is_global_ipv4(addr: &std::net::Ipv4Addr) -> bool {
    !(addr.octets()[0] == 0
        || addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || (addr.octets()[0] == 192
            && addr.octets()[1] == 0
            && addr.octets()[2] == 0
            && addr.octets()[3] != 9
            && addr.octets()[3] != 10)
        || addr.is_documentation()
        || addr.is_broadcast())
}

// Copy from unstable feature
fn is_global_ipv6(addr: &std::net::Ipv6Addr) -> bool {
    !(addr.is_unspecified()
            || addr.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                    || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x3F)
                ))
            // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
            // IANA says N/A.
            || matches!(addr.segments(), [0x2002, _, _, _, _, _, _, _])
            // Segment Routing (SRv6) SIDs (`5f00::/16`)
            || matches!(addr.segments(), [0x5f00, ..])
            || addr.is_unique_local()
            || addr.is_unicast_link_local())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use landscape_common::dns::{
        redirect::{DNSRedirectRuntimeRule, DnsRedirectAnswerMode},
        rule::{DomainConfig, DomainMatchType},
    };

    use super::*;

    #[test]
    fn dynamic_redirect_solution_preserves_source_and_ttl() {
        let solution = RedirectSolution::new(
            DNSRedirectRuntimeRule {
                redirect_id: None,
                dynamic_redirect_source: Some("docker:test".to_string()),
                answer_mode: DnsRedirectAnswerMode::StaticIps,
                match_rules: vec![DomainConfig {
                    match_type: DomainMatchType::Full,
                    value: "example.com".to_string(),
                }],
                result_info: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
                ttl_secs: 42,
            }
            .into(),
        );

        assert!(solution.is_match("example.com."));
        assert!(solution.redirect_id.is_none());
        assert_eq!(solution.dynamic_redirect_source.as_deref(), Some("docker:test"));

        let records = solution.lookup("example.com.", RecordType::A);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, 42);
    }
}

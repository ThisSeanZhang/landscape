use std::net::IpAddr;

use hickory_proto::rr::{
    rdata::{A, AAAA},
    RData, Record, RecordType,
};
use uuid::Uuid;

use landscape_common::dns::redirect::DnsRedirectAnswerMode;
use landscape_common::flow::mark::FlowMark;
use landscape_common::{
    dns::{
        config::{DnsBindConfig, DnsUpstreamConfig},
        rule::FilterResult,
    },
    flow::DnsRuntimeMarkInfo,
};

use crate::connection::LandscapeMarkDNSResolver;
use crate::domain::ParsedDomain;
use crate::server::matcher::RuntimeRuleMatcher;

/// Pure-data input for [`DNSRedirectRuntime::new`]: mirrors its fields so
/// construction sites stay self-documenting.
#[derive(Debug)]
pub struct RedirectRuleParams {
    pub redirect_id: Option<Uuid>,
    pub dynamic_redirect_source: Option<String>,
    pub answer_mode: DnsRedirectAnswerMode,
    pub matcher: RuntimeRuleMatcher,
    pub result_info: Vec<IpAddr>,
    pub ttl_secs: u32,
    /// When true, metadata queries (NS/SOA/TXT/MX/CAA) matching this rule are
    /// intercepted too; when false they pass through to the upstream resolver.
    pub block_metadata_queries: bool,
}

#[derive(Debug)]
pub struct DNSRedirectRuntime {
    pub redirect_id: Option<Uuid>,
    pub dynamic_redirect_source: Option<String>,
    pub answer_mode: DnsRedirectAnswerMode,
    matcher: RuntimeRuleMatcher,
    result_info: Vec<IpAddr>,
    ttl_secs: u32,
    block_metadata_queries: bool,
}

impl DNSRedirectRuntime {
    pub fn new(params: RedirectRuleParams) -> Self {
        let RedirectRuleParams {
            redirect_id,
            dynamic_redirect_source,
            answer_mode,
            matcher,
            result_info,
            ttl_secs,
            block_metadata_queries,
        } = params;
        Self {
            matcher,
            redirect_id,
            dynamic_redirect_source,
            answer_mode,
            result_info,
            ttl_secs,
            block_metadata_queries,
        }
    }

    pub fn is_match(&self, domain: &ParsedDomain) -> bool {
        self.matcher.is_match(domain)
    }

    pub fn blocks_metadata_queries(&self) -> bool {
        self.block_metadata_queries
    }

    pub fn lookup(&self, domain: &ParsedDomain, query_type: RecordType) -> Vec<Record> {
        self.lookup_with_addrs(domain, query_type, &self.result_info)
    }

    pub fn lookup_with_addrs(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        addrs: &[IpAddr],
    ) -> Vec<Record> {
        let owner = domain.as_dns_name().clone();
        let mut result = vec![];
        for ip in addrs {
            let rdata_ip = match (ip, &query_type) {
                (IpAddr::V4(ip), RecordType::A) => Some(RData::A(A(*ip))),
                (IpAddr::V6(ip), RecordType::AAAA) => Some(RData::AAAA(AAAA(*ip))),
                _ => None,
            };

            if let Some(rdata) = rdata_ip {
                result.push(Record::from_rdata(owner.clone(), self.ttl_secs, rdata));
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

/// Pure-data input for [`DNSResolveRuntime::new`]: mirrors its fields so
/// construction sites stay self-documenting and stay in sync at compile time.
#[derive(Debug)]
pub struct ResolveRuleParams {
    pub rule_id: Uuid,
    pub order: u32,
    pub filter: FilterResult,
    pub bind_config: DnsBindConfig,
    pub mark: FlowMark,
    pub upstream: DnsUpstreamConfig,
    pub matcher: RuntimeRuleMatcher,
    pub flow_id: u32,
}

#[derive(Debug)]
pub struct DNSResolveRuntime {
    matcher: RuntimeRuleMatcher,
    rule_id: Uuid,
    order: u32,
    filter: FilterResult,
    flow_id: u32,
    mark: DnsRuntimeMarkInfo,
    resolver: LandscapeMarkDNSResolver,

    enable_ip_validation: bool,
}

impl DNSResolveRuntime {
    pub fn new(params: ResolveRuleParams) -> Option<Self> {
        let ResolveRuleParams {
            rule_id,
            order,
            filter,
            bind_config,
            mark: mark_config,
            upstream,
            matcher,
            flow_id,
        } = params;
        let span = tracing::info_span!("dns_rule", flow_id = flow_id);
        let _ = span.enter();

        let enable_ip_validation = upstream.enable_ip_validation.unwrap_or(false);
        let Some(resolver) =
            crate::connection::create_resolver(flow_id, mark_config, bind_config, upstream)
        else {
            tracing::warn!(rule_id = %rule_id, flow_id = flow_id, "skip DNS rule: failed to build resolver");
            return None;
        };

        let mark = DnsRuntimeMarkInfo { mark: mark_config, priority: order as u16 };
        Some(DNSResolveRuntime {
            matcher,
            rule_id,
            order,
            filter,
            flow_id,
            resolver,
            mark,
            enable_ip_validation,
        })
    }

    pub fn mark(&self) -> &DnsRuntimeMarkInfo {
        &self.mark
    }

    pub fn filter_mode(&self) -> FilterResult {
        self.filter.clone()
    }

    pub fn get_config_id(&self) -> Uuid {
        self.rule_id
    }

    pub fn order(&self) -> u32 {
        self.order
    }

    /// checks whether this rule should handle the query
    pub fn is_match(&self, domain: &ParsedDomain) -> bool {
        self.matcher.is_match(domain)
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
                        tracing::warn!(
                            flow_id = self.flow_id,
                            rule_id = %self.rule_id,
                            domain = %domain,
                            response_code = ?no_records.response_code,
                            "upstream answered an error code"
                        );
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
                    self.rule_id,
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
                    || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
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
        redirect::DnsRedirectAnswerMode,
        rule::{DomainConfig, DomainMatchType},
    };

    use super::*;

    #[test]
    fn dynamic_redirect_solution_preserves_source_and_ttl() {
        let solution = DNSRedirectRuntime::new(RedirectRuleParams {
            redirect_id: None,
            dynamic_redirect_source: Some("docker:test".to_string()),
            answer_mode: DnsRedirectAnswerMode::StaticIps,
            matcher: RuntimeRuleMatcher::new(
                vec![DomainConfig {
                    match_type: DomainMatchType::Full,
                    value: "example.com".to_string(),
                }],
                vec![],
                vec![],
                false,
            ),
            result_info: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            ttl_secs: 42,
            block_metadata_queries: true,
        });

        assert!(solution.is_match(&ParsedDomain::new("example.com.").unwrap()));
        assert!(solution.redirect_id.is_none());
        assert_eq!(solution.dynamic_redirect_source.as_deref(), Some("docker:test"));

        let records = solution.lookup(&ParsedDomain::new("example.com.").unwrap(), RecordType::A);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, 42);
    }
}

use std::{net::IpAddr, str::FromStr as _};

use hickory_proto::rr::{
    rdata::{A, AAAA},
    RData, Record, RecordType,
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    Resolver,
};
use landscape_common::{
    dns::{
        redirect::DNSRedirectRuntimeRule,
        upstream::{DnsUpstreamConfig, DnsUpstreamMode},
    },
    flow::mark::FlowMark,
};
use uuid::Uuid;

use crate::{
    connection::{MarkConnectionProvider, MarkRuntimeProvider},
    rule::matcher::DomainMatcher,
};

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
pub struct UpstreamSolution {
    resolver_id: Uuid,

    pub resolver: Resolver<MarkConnectionProvider>,
}

impl UpstreamSolution {
    pub fn new(
        flow_id: u32,
        mark: FlowMark,
        DnsUpstreamConfig { id, mode, ips, port, .. }: DnsUpstreamConfig,
    ) -> Self {
        let name_server = match mode {
            DnsUpstreamMode::Plaintext => {
                NameServerConfigGroup::from_ips_clear(&ips, port.unwrap_or(53), true)
            }
            DnsUpstreamMode::Tls { domain } => NameServerConfigGroup::from_ips_tls(
                &ips,
                port.unwrap_or(843),
                domain.to_string(),
                true,
            ),
            DnsUpstreamMode::Https { domain } => NameServerConfigGroup::from_ips_https(
                &ips,
                port.unwrap_or(443),
                domain.to_string(),
                true,
            ),
            DnsUpstreamMode::Quic { domain } => NameServerConfigGroup::from_ips_quic(
                &ips,
                port.unwrap_or(443),
                domain.to_string(),
                true,
            ),
        };

        let resolve = ResolverConfig::from_parts(None, vec![], name_server);

        let mark_value = mark.get_dns_mark(flow_id);

        let mut options = ResolverOpts::default();
        options.cache_size = 0;
        options.num_concurrent_reqs = 1;
        options.preserve_intermediates = true;
        // options.use_hosts_file = ResolveHosts::Never;
        let resolver = Resolver::builder_with_config(
            resolve,
            MarkConnectionProvider::new(MarkRuntimeProvider::new(mark_value)),
        )
        .with_options(options)
        .build();

        Self { resolver_id: id, resolver }
    }
}

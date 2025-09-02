use hickory_proto::{
    op::ResponseCode,
    rr::{
        rdata::{A, AAAA},
        RData, Record, RecordType,
    },
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    Resolver,
};
use landscape_common::{
    config::dns::{
        DNSResolveMode, DNSRuntimeRule, DnsUpstreamType, DomainConfig, DomainMatchType,
        FilterResult,
    },
    flow::{mark::FlowMark, DnsRuntimeMarkInfo},
};
use matcher::DomainMatcher;
use std::net::IpAddr;
use std::str::FromStr;
use uuid::Uuid;

use crate::connection::{MarkConnectionProvider, MarkRuntimeProvider};

pub mod matcher;

#[derive(Debug)]
pub struct CacheResolver {
    pub flow_id: u32,
    pub resolver: Resolver<MarkConnectionProvider>,
}

impl CacheResolver {
    pub fn new(resolve: ResolverConfig, mark: &FlowMark, flow_id: u32) -> Self {
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
        CacheResolver { resolver, flow_id: flow_id }
    }
}

#[derive(Debug)]
pub enum ResolverType {
    RedirectResolver(Vec<IpAddr>),
    CacheResolver(CacheResolver),
}
impl ResolverType {
    pub fn new(config: &DNSRuntimeRule, flow_id: u32) -> Self {
        match &config.resolve_mode {
            DNSResolveMode::Redirect { ips } => ResolverType::RedirectResolver(ips.clone()),
            DNSResolveMode::Upstream { upstream, ips, port } => {
                let name_server = match upstream {
                    DnsUpstreamType::Plaintext => {
                        NameServerConfigGroup::from_ips_clear(ips, port.unwrap_or(53), true)
                    }
                    DnsUpstreamType::Tls { domain } => NameServerConfigGroup::from_ips_tls(
                        ips,
                        port.unwrap_or(843),
                        domain.to_string(),
                        true,
                    ),
                    DnsUpstreamType::Https { domain } => NameServerConfigGroup::from_ips_https(
                        ips,
                        port.unwrap_or(443),
                        domain.to_string(),
                        true,
                    ),
                };

                let resolve = ResolverConfig::from_parts(None, vec![], name_server);

                ResolverType::CacheResolver(CacheResolver::new(resolve, &config.mark, flow_id))
            }
            DNSResolveMode::Cloudflare { mode } => {
                let server = match mode {
                    landscape_common::config::dns::CloudflareMode::Plaintext => {
                        NameServerConfigGroup::cloudflare()
                    }
                    landscape_common::config::dns::CloudflareMode::Tls => {
                        NameServerConfigGroup::cloudflare_tls()
                    }
                    landscape_common::config::dns::CloudflareMode::Https => {
                        NameServerConfigGroup::cloudflare_https()
                    }
                };
                let resolve = ResolverConfig::from_parts(None, vec![], server);
                ResolverType::CacheResolver(CacheResolver::new(resolve, &config.mark, flow_id))
            }
        }
    }

    pub async fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<Vec<Record>, ResponseCode> {
        match self {
            ResolverType::RedirectResolver(result_ip) => {
                let mut result = vec![];
                for ip in result_ip {
                    let rdata_ip = match (ip, &query_type) {
                        (IpAddr::V4(ip), RecordType::A) => Some(RData::A(A(*ip))),
                        (IpAddr::V6(ip), RecordType::AAAA) => Some(RData::AAAA(AAAA(*ip))),
                        _ => None,
                    };

                    if let Some(rdata) = rdata_ip {
                        result.push(Record::from_rdata(
                            hickory_resolver::Name::from_str(domain).unwrap(),
                            300,
                            rdata,
                        ));
                    }
                }

                Ok(result)
            }
            ResolverType::CacheResolver(resolver) => {
                match resolver.resolver.lookup(domain, query_type).await {
                    Ok(lookup) => Ok(lookup.records().to_vec()),
                    Err(e) => {
                        let result = if e.is_no_records_found() {
                            ResponseCode::NoError
                        } else {
                            tracing::error!(
                                "[flow_id: {:?}] DNS resolution failed for {}: {}",
                                resolver.flow_id,
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
    }
}

#[derive(Debug)]
/// 与规则是 1:1 创建的
pub struct ResolutionRule {
    // 启动之后配置的 matcher
    matcher: DomainMatcher,
    //
    config: DNSRuntimeRule,

    mark: DnsRuntimeMarkInfo,

    resolver: ResolverType,
}

impl ResolutionRule {
    pub fn new(config: DNSRuntimeRule, flow_id: u32) -> Self {
        let span = tracing::info_span!("dns_rule", flow_id = flow_id);
        let _ = span.enter();

        let matcher = DomainMatcher::new(config.source.clone());

        let resolver = ResolverType::new(&config, flow_id);

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

    pub fn get_runtime_config(&self) -> DNSRuntimeRule {
        self.config.clone()
    }

    pub fn get_config_id(&self) -> Option<Uuid> {
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
        // TODO: do fiter in here
        self.resolver.lookup(domain, query_type).await
    }
}

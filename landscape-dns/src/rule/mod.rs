use hickory_proto::{
    op::ResponseCode,
    rr::{
        rdata::{A, AAAA},
        RData, Record, RecordType,
    },
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig},
    Resolver,
};
use landscape_common::{
    dns::{
        DNSResolveMode, DNSRuleConfig, DnsUpstreamType, DomainConfig, DomainMatchType, RuleSource,
    },
    mark::PacketMark,
};
use matcher::DomainMatcher;
use std::str::FromStr;
use std::{collections::HashMap, net::IpAddr};

use crate::{
    connection::{MarkConnectionProvider, MarkRuntimeProvider},
    protos::geo::{mod_Domain::Type, Domain},
};

mod matcher;

pub struct CacheResolver {
    pub resolver: Resolver<MarkConnectionProvider>,
}

impl CacheResolver {
    pub fn new(resolve: ResolverConfig, mark: &PacketMark) -> Self {
        let mark_value = match mark.clone() {
            PacketMark::Redirect { index } => PacketMark::Redirect { index }.into(),
            _ => PacketMark::Direct.into(),
        };

        let resolver = Resolver::builder_with_config(
            resolve,
            MarkConnectionProvider::new(MarkRuntimeProvider::new(mark_value)),
        )
        .build();
        CacheResolver { resolver }
    }
}

pub enum ResolverType {
    RedirectResolver(Vec<IpAddr>),
    CacheResolver(CacheResolver),
}
impl ResolverType {
    pub fn new(config: &DNSRuleConfig) -> Self {
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

                ResolverType::CacheResolver(CacheResolver::new(resolve, &config.mark))
            }
            DNSResolveMode::CloudFlare { mode } => {
                let server = match mode {
                    landscape_common::dns::CloudFlareMode::Plaintext => {
                        NameServerConfigGroup::cloudflare()
                    }
                    landscape_common::dns::CloudFlareMode::Tls => {
                        NameServerConfigGroup::cloudflare_tls()
                    }
                    landscape_common::dns::CloudFlareMode::Https => {
                        NameServerConfigGroup::cloudflare_https()
                    }
                };
                let resolve = ResolverConfig::from_parts(None, vec![], server);
                ResolverType::CacheResolver(CacheResolver::new(resolve, &config.mark))
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
                    let rdata_ip = match ip {
                        IpAddr::V4(ip) => RData::A(A(ip.clone())),
                        IpAddr::V6(ip) => RData::AAAA(AAAA(ip.clone())),
                    };
                    result.push(Record::from_rdata(
                        hickory_resolver::Name::from_str(domain).unwrap(),
                        300,
                        rdata_ip,
                    ));
                }
                Ok(vec![])
            }
            ResolverType::CacheResolver(resolver) => {
                match resolver.resolver.lookup(domain, query_type).await {
                    Ok(lookup) => Ok(lookup.records().to_vec()),
                    Err(e) => {
                        tracing::error!("DNS resolution failed for {}: {}", domain, e);
                        let result = if e.is_no_records_found() {
                            ResponseCode::NoError
                        } else {
                            ResponseCode::ServFail
                        };
                        Err(result)
                    }
                }
            }
        }
    }
}

/// 与规则是 1:1 创建的
pub struct ResolutionRule {
    // 启动之后配置的 matcher
    matcher: DomainMatcher,
    //
    config: DNSRuleConfig,

    resolver: ResolverType,
}

impl ResolutionRule {
    pub fn new(config: DNSRuleConfig, geo_file: &HashMap<String, Vec<DomainConfig>>) -> Self {
        let matcher = DomainMatcher::new(convert_config_to_runtime_rule(&config, geo_file));

        let resolver = ResolverType::new(&config);

        ResolutionRule { matcher, config, resolver }
    }

    pub fn mark(&self) -> &PacketMark {
        &self.config.mark
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

pub fn convert_config_to_runtime_rule(
    config: &DNSRuleConfig,
    geo_file: &HashMap<String, Vec<DomainConfig>>,
) -> Vec<DomainConfig> {
    let mut all_domain_rules = vec![];
    for each in config.source.iter() {
        match each {
            RuleSource::GeoKey { key } => {
                if let Some(domains) = geo_file.get(&key.to_uppercase()) {
                    // for each_d in domains.iter() {
                    //     all_domain_rules.push(DomainConfig::from(each_d));
                    // }
                    all_domain_rules.extend(domains.iter().cloned());
                }
            }
            RuleSource::Config(c) => {
                // all_domain_rules.extend(vec.iter().cloned());
                all_domain_rules.push(c.clone());
            }
        }
    }
    all_domain_rules
}

pub fn convert_match_type_from_proto(value: Type) -> DomainMatchType {
    match value {
        Type::Plain => DomainMatchType::Plain,
        Type::Regex => DomainMatchType::Regex,
        Type::Domain => DomainMatchType::Domain,
        Type::Full => DomainMatchType::Full,
    }
}

pub fn convert_domain_from_proto(value: &Domain) -> DomainConfig {
    DomainConfig {
        match_type: convert_match_type_from_proto(value.type_pb),
        value: value.value.to_lowercase(),
    }
}

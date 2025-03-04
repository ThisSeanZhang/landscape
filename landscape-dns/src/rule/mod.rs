use hickory_proto::{
    op::ResponseCode,
    rr::{rdata::A, RData, Record, RecordType},
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    AsyncResolver,
};
use landscape_common::{
    dns::{DNSRuleConfig, DomainConfig, DomainMatchType, RuleSource},
    mark::PacketMark,
};
use matcher::DomainMatcher;
use std::str::FromStr;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use crate::{
    connection::{MarkConnectionProvider, MarkRuntimeProvider},
    protos::geo::{mod_Domain::Type, Domain},
};

mod matcher;

pub struct CacheResolver {
    pub resolver: AsyncResolver<MarkConnectionProvider>,
}

impl CacheResolver {
    pub fn new(config: &DNSRuleConfig) -> Self {
        let mark_value = match config.mark.clone() {
            PacketMark::Redirect { index } => PacketMark::Redirect { index }.into(),
            _ => PacketMark::Direct.into(),
        };
        let resolve = if let Ok(ip) = config.dns_resolve_ip.parse::<Ipv4Addr>() {
            ResolverConfig::from_parts(
                None,
                vec![],
                NameServerConfigGroup::from_ips_clear(&[IpAddr::V4(ip)], 53, true),
            )
        } else {
            ResolverConfig::cloudflare()
        };

        let resolver = AsyncResolver::new_with_conn(
            resolve,
            ResolverOpts::default(),
            MarkConnectionProvider::new(MarkRuntimeProvider::new(mark_value)),
        );
        CacheResolver { resolver }
    }
}

pub enum ResolverType {
    RedirectResolver(String),
    CacheResolver(CacheResolver),
}
impl ResolverType {
    pub fn new(config: &DNSRuleConfig) -> Self {
        if config.redirection {
            ResolverType::RedirectResolver(config.dns_resolve_ip.clone())
        } else {
            ResolverType::CacheResolver(CacheResolver::new(config))
        }
    }

    pub async fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<Vec<Record>, ResponseCode> {
        match self {
            ResolverType::RedirectResolver(result_ip) => Ok(vec![Record::from_rdata(
                hickory_resolver::Name::from_str(domain).unwrap(),
                300,
                RData::A(A::from_str(result_ip).unwrap()),
            )]),
            ResolverType::CacheResolver(resolver) => {
                match resolver.resolver.lookup(domain, query_type).await {
                    Ok(lookup) => Ok(lookup.records().to_vec()),
                    Err(e) => {
                        tracing::error!("DNS resolution failed for {}: {}", domain, e);
                        let result = match e.kind() {
                            hickory_resolver::error::ResolveErrorKind::NoRecordsFound {
                                ..
                            } => ResponseCode::NoError,
                            _ => ResponseCode::ServFail,
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
        self.resolver.lookup(domain, query_type).await
    }

    // // 检查缓存并根据 TTL 判断是否过期
    // // 不同的记录可能的过期时间不同
    // pub async fn lookup(&self, domain: &str, query_type: RecordType) -> Option<Vec<Record>> {
    //     let mut cache = self.cache.lock().await;
    //     if let Some(records) = cache.get(&(domain.to_string(), query_type)) {
    //         let mut is_expire = false;
    //         let mut valid_records: Vec<Record> = vec![];
    //         for (rdata, insert_time) in records.iter() {
    //             if insert_time.elapsed().as_secs() > rdata.ttl() as u64 {
    //                 is_expire = true;
    //                 break;
    //             }
    //             valid_records.push(rdata.clone());
    //         }

    //         if is_expire {
    //             return None;
    //         }

    //         // 如果有有效的记录，返回它们
    //         if !valid_records.is_empty() {
    //             return Some(valid_records);
    //         }
    //     }
    //     None
    // }

    // // 将解析结果插入缓存，为每个 (domain, RecordType) 设置单独的 TTL
    // pub async fn insert(&self, domain: String, query_type: RecordType, rdata_ttl_vec: Vec<Record>) {
    //     let mut cache = self.cache.lock().await;
    //     let now = Instant::now();

    //     // 将记录和插入时间存储到缓存中
    //     let mut records_with_expiration: Vec<(Record, Instant)> = vec![];
    //     let mut ipv4s = vec![];
    //     for rdata in rdata_ttl_vec.into_iter() {
    //         if let Some(data) = rdata.data() {
    //             match data {
    //                 hickory_proto::rr::RData::A(a) => {
    //                     ipv4s.push((a.0, 32_u32));
    //                 }
    //                 _ => {}
    //             }
    //         }
    //         records_with_expiration.push((rdata, now));
    //     }
    //     // let records_with_expiration: Vec<(Record, Instant)> =
    //     //     rdata_ttl_vec.into_iter().map(|rdata| (rdata, now)).collect();

    //     cache.put((domain, query_type), records_with_expiration);
    //     // 将 mark 写入 mark ebpf map
    //     if self.config.mark.need_add_mark_config() {
    //         println!("setting ips: {:?}, Mark: {:?}", ipv4s, self.config.mark);
    //         // TODO: 如果写入错误 返回错误后 向客户端返回查询错误
    //         landscape_ebpf::map_setting::add_ips_mark(ipv4s, self.config.mark.clone().into());
    //     }
    // }

    // // 根据请求的类型解析域名，返回 RData
    // pub async fn resolve_domain(
    //     &self,
    //     domain: &str,
    //     query_type: RecordType,
    // ) -> Result<Vec<Record>, ResponseCode> {
    //     match self.resolver.lookup(domain, query_type).await {
    //         Ok(lookup) => {
    //             let records: Vec<Record> = lookup
    //                 .record_iter()
    //                 .map(|record| record.clone())
    //                 // .into()
    //                 // .filter_map(|record| {
    //                 //     // 过滤匹配的记录类型
    //                 //     if record.record_type() == query_type {
    //                 //         Some(record.clone())
    //                 //     } else {
    //                 //         None
    //                 //     }
    //                 // })
    //                 .collect();

    //             if !records.is_empty() {
    //                 Ok(records)
    //             } else {
    //                 Err(ResponseCode::ServFail)
    //             }
    //         }
    //         Err(e) => {
    //             eprintln!("DNS resolution failed for {}: {}", domain, e);
    //             let result = match e.kind() {
    //                 hickory_resolver::error::ResolveErrorKind::NoRecordsFound {
    //                     response_code,
    //                     ..
    //                 } => response_code.clone(),
    //                 _ => ResponseCode::ServFail,
    //             };
    //             Err(result)
    //         }
    //     }
    // }
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

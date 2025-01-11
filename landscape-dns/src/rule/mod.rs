use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    sync::Arc,
};

use hickory_proto::{
    op::ResponseCode,
    rr::{Record, RecordType},
};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    AsyncResolver,
};
use landscape_common::{mark::PacketMark, store::storev2::LandScapeStore};
use matcher::DomainMatcher;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::sync::Mutex;

use lru::LruCache;

use crate::{
    connection::{MarkConnectionProvider, MarkRuntimeProvider},
    protos::geo::{mod_Domain::Type, Domain},
};

mod matcher;

pub struct ResolutionRule {
    // 需要有对应的 DNS 缓存
    cache: Arc<Mutex<LruCache<(String, RecordType), Vec<(Record, Instant)>>>>,
    // 启动之后配置的 matcher
    matcher: DomainMatcher,
    //
    config: DNSRuleConfig,

    resolver: AsyncResolver<MarkConnectionProvider>,
}

impl ResolutionRule {
    pub fn new(config: DNSRuleConfig, geo_file: &HashMap<String, Vec<DomainConfig>>) -> Self {
        let matcher = DomainMatcher::new(config.get_all_domain_configs(geo_file));

        let mark_value = match config.mark.clone() {
            PacketMark::Redirect { index } => PacketMark::Redirect { index }.into(),
            _ => PacketMark::Direct.into(),
        };
        println!("dns rule name: {:?}, {:?} {:?}", config.name, config.mark, mark_value);
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

        ResolutionRule {
            cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(512).unwrap()))),
            matcher,
            config,
            resolver,
        }
    }
    pub async fn is_match(&self, domain: &str) -> bool {
        let match_result = if self.config.source.is_empty() {
            true
        } else {
            let domain =
                if let Some(stripped) = domain.strip_suffix('.') { stripped } else { domain };
            self.matcher.is_match(domain)
        };
        match_result
    }
    // 检查缓存并根据 TTL 判断是否过期
    pub async fn lookup(&self, domain: &str, query_type: RecordType) -> Option<Vec<Record>> {
        let mut cache = self.cache.lock().await;
        if let Some(records) = cache.get(&(domain.to_string(), query_type)) {
            let valid_records: Vec<Record> = records
                .iter()
                .filter_map(|(rdata, insert_time)| {
                    // 检查插入时间加上 TTL 是否超过当前时间，如果没过期，返回记录
                    if insert_time.elapsed().as_secs() > rdata.ttl() as u64 {
                        Some(rdata.clone())
                    } else {
                        None
                    }
                })
                .collect();

            // 如果有有效的记录，返回它们
            if !valid_records.is_empty() {
                return Some(valid_records);
            }
        }
        None
    }

    // 将解析结果插入缓存，为每个 (domain, RecordType) 设置单独的 TTL
    pub async fn insert(&self, domain: String, query_type: RecordType, rdata_ttl_vec: Vec<Record>) {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();

        // 将记录和插入时间存储到缓存中
        let mut records_with_expiration: Vec<(Record, Instant)> = vec![];
        let mut ipv4s = vec![];
        for rdata in rdata_ttl_vec.into_iter() {
            if let Some(data) = rdata.data() {
                match data {
                    hickory_proto::rr::RData::A(a) => {
                        ipv4s.push((a.0, 32_u32));
                    }
                    _ => {}
                }
            }
            records_with_expiration.push((rdata, now));
        }
        // let records_with_expiration: Vec<(Record, Instant)> =
        //     rdata_ttl_vec.into_iter().map(|rdata| (rdata, now)).collect();

        cache.put((domain, query_type), records_with_expiration);
        // 将 mark 写入 mark ebpf map
        if self.config.mark.need_add_mark_config() {
            println!("setting ips: {:?}, Mark: {:?}", ipv4s, self.config.mark);
            // TODO: 如果写入错误 返回错误后 向客户端返回查询错误
            landscape_ebpf::map_setting::add_ips_mark(ipv4s, self.config.mark.clone().into());
        }
    }

    // 根据请求的类型解析域名，返回 RData
    pub async fn resolve_domain(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<Vec<Record>, ResponseCode> {
        match self.resolver.lookup(domain, query_type).await {
            Ok(lookup) => {
                let records: Vec<Record> = lookup
                    .record_iter()
                    .map(|record| record.clone())
                    // .into()
                    // .filter_map(|record| {
                    //     // 过滤匹配的记录类型
                    //     if record.record_type() == query_type {
                    //         Some(record.clone())
                    //     } else {
                    //         None
                    //     }
                    // })
                    .collect();

                if !records.is_empty() {
                    Ok(records)
                } else {
                    Err(ResponseCode::NXDomain)
                }
            }
            Err(e) => {
                eprintln!("DNS resolution failed for {}: {}", domain, e);
                let result = match e.kind() {
                    hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
                        ResponseCode::NoError
                    }
                    _ => ResponseCode::ServFail,
                };
                Err(result)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// 用于保存和还原的之持久化配置
pub struct DNSRuleConfig {
    pub name: String,
    // 优先级
    pub index: u32,
    // 是否启用
    pub enable: bool,
    // 配置使用的 DNS 解析服务器
    pub dns_resolve_ip: String,
    /// 流量标记
    pub mark: PacketMark,
    pub source: Vec<RuleSource>,
    // 还需增加一个字段, 用于配置解析的类型是 静态的 还是 递归的, 静态的就是 域名劫持 递归的就是向上游请求 DNS 信息
}

impl LandScapeStore for DNSRuleConfig {
    fn get_store_key(&self) -> String {
        self.index.to_string()
    }
}

impl Default for DNSRuleConfig {
    fn default() -> Self {
        Self {
            name: "default rule".into(),
            index: 10000,
            enable: true,
            dns_resolve_ip: Default::default(),
            mark: Default::default(),
            source: vec![],
        }
    }
}

impl DNSRuleConfig {
    pub fn get_all_domain_configs(
        &self,
        geo_file: &HashMap<String, Vec<DomainConfig>>,
    ) -> Vec<DomainConfig> {
        // println!("geo geo_file: {:?}", geo_file.keys().collect::<Vec<&String>>());
        let mut all_domain_rules = vec![];
        for each in self.source.iter() {
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    GeoKey { key: String },
    Config(DomainConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DomainConfig {
    pub match_type: DomainMatchType,
    pub value: String,
}

impl From<&Domain<'_>> for DomainConfig {
    fn from(value: &Domain) -> Self {
        DomainConfig {
            match_type: DomainMatchType::from(value.type_pb),
            value: value.value.to_lowercase(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainMatchType {
    /// The value is used as is.
    Plain = 0,
    /// The value is used as a regular expression.
    Regex = 1,
    /// 域名匹配， 前缀匹配
    Domain = 2,
    /// The value is a domain.
    Full = 3,
}

impl From<Type> for DomainMatchType {
    fn from(value: Type) -> Self {
        match value {
            Type::Plain => DomainMatchType::Plain,
            Type::Regex => DomainMatchType::Regex,
            Type::Domain => DomainMatchType::Domain,
            Type::Full => DomainMatchType::Full,
        }
    }
}

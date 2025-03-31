use core::panic;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use hickory_proto::{
    op::{Header, ResponseCode},
    rr::{Record, RecordType},
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use lru::LruCache;
use tokio::sync::Mutex;

use crate::{rule::ResolutionRule, CacheDNSItem, DNSCache};
use landscape_common::{
    dns::{DNSRuleConfig, DomainConfig},
    ip_mark::{IpConfig, IpMarkInfo},
    mark::PacketMark,
};

static RESOLVER_CONF: &'static str = "/etc/resolv.conf";
static RESOLVER_CONF_LD_BACK: &'static str = "/etc/resolv.conf.ld_back";

fn check_resolver_conf() {
    let resolver_file = PathBuf::from(RESOLVER_CONF);
    let resolver_file_back = PathBuf::from(RESOLVER_CONF_LD_BACK);
    let new_content = "nameserver 127.0.0.1\n";

    if resolver_file.is_symlink() {
        // 如果是符号链接，直接删除
        fs::remove_file(&resolver_file).unwrap();
    } else if resolver_file.exists() {
        if resolver_file.is_file() {
            // 如果是普通文件，检查备份文件
            if resolver_file_back.exists() {
                fs::remove_file(&resolver_file).unwrap();
            } else {
                let Ok(()) = fs::rename(&resolver_file, &resolver_file_back) else {
                    tracing::error!("move {resolver_file:?} error, Skip it");
                    return;
                };
            }
        } else {
            panic!("other kind file");
        }
    }

    // 写入新内容到 /etc/resolv.conf
    fs::write(&resolver_file, new_content).unwrap();
}

/// 整个 DNS 规则匹配树
#[derive(Clone)]
pub struct DnsServer {
    /// 所有的域名处理对象
    /// 遍历的顺序是小到大
    resolves: BTreeMap<u32, Arc<ResolutionRule>>,
    cache: Arc<Mutex<DNSCache>>,
}

impl DnsServer {
    pub fn new(
        dns_rules: Vec<DNSRuleConfig>,
        geo_map: HashMap<String, Vec<DomainConfig>>,
        old_cache: Option<Arc<Mutex<DNSCache>>>,
    ) -> DnsServer {
        check_resolver_conf();

        let mut resolves = BTreeMap::new();

        for rule in dns_rules.into_iter() {
            // println!("dns_rules: {:?}", rule);
            resolves.insert(rule.index, Arc::new(ResolutionRule::new(rule, &geo_map)));
        }

        let mut cache = LruCache::new(NonZeroUsize::new(2048).unwrap());
        if let Some(old_cache) = old_cache {
            if let Ok(old_cache) = old_cache.try_lock() {
                let mut update_dns_mark_list = HashSet::new();
                let mut del_dns_mark_list = HashSet::new();

                for ((domain, req_type), value) in old_cache.iter() {
                    'resolver: for (_index, resolver) in resolves.iter() {
                        // println!("old domain: {domain:?}");
                        if resolver.is_match(&domain) {
                            let new_mark = resolver.mark().clone();
                            // println!("old domain match resolver: {domain:?}");
                            let mut cache_items = vec![];
                            for CacheDNSItem { rdatas, insert_time, mark } in value.iter() {
                                if matches!(new_mark, PacketMark::NoMark)
                                    && matches!(mark, PacketMark::NoMark)
                                {
                                    continue;
                                }

                                // println!("old mark: {mark:?}, new_mark: {new_mark:?}");
                                if new_mark != *mark {
                                    for rdata in rdatas.iter() {
                                        match rdata.data() {
                                            hickory_proto::rr::RData::A(a) => {
                                                if matches!(new_mark, PacketMark::NoMark) {
                                                    del_dns_mark_list.insert(IpConfig {
                                                        ip: std::net::IpAddr::V4(a.0),
                                                        prefix: 32_u32,
                                                    });
                                                } else {
                                                    update_dns_mark_list.insert(IpMarkInfo {
                                                        mark: new_mark,
                                                        cidr: IpConfig {
                                                            ip: std::net::IpAddr::V4(a.0),
                                                            prefix: 32_u32,
                                                        },
                                                    });
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    cache_items.push(CacheDNSItem {
                                        rdatas: rdatas.clone(),
                                        insert_time: insert_time.clone(),
                                        mark: new_mark.clone(),
                                    });
                                } else {
                                    cache_items.push(CacheDNSItem {
                                        rdatas: rdatas.clone(),
                                        insert_time: insert_time.clone(),
                                        mark: new_mark.clone(),
                                    });
                                }
                            }
                            if !cache_items.is_empty() {
                                cache.push((domain.clone(), req_type.clone()), cache_items);
                            }
                            break 'resolver;
                        }
                    }
                }
                tracing::info!("add_dns_marks: {:?}", update_dns_mark_list);
                tracing::info!("del_dns_marks: {:?}", del_dns_mark_list);
                landscape_ebpf::map_setting::add_dns_marks(
                    update_dns_mark_list.into_iter().collect(),
                );
                landscape_ebpf::map_setting::del_dns_marks(del_dns_mark_list.into_iter().collect());
            }
        }

        drop(geo_map);

        // println!("cache: {:?}", cache);
        let cache = Arc::new(Mutex::new(cache));

        DnsServer { resolves, cache }
    }

    pub fn clone_cache(&self) -> Arc<Mutex<DNSCache>> {
        self.cache.clone()
    }

    // 检查缓存并根据 TTL 判断是否过期
    // 不同的记录可能的过期时间不同
    pub async fn lookup_cache(&self, domain: &str, query_type: RecordType) -> Option<Vec<Record>> {
        let mut cache = self.cache.lock().await;
        if let Some(records) = cache.get(&(domain.to_string(), query_type)) {
            let mut is_expire = false;
            let mut valid_records: Vec<Record> = vec![];
            'a_record: for CacheDNSItem { rdatas, insert_time, .. } in records.iter() {
                for rdata in rdatas.iter() {
                    if insert_time.elapsed().as_secs() > rdata.ttl() as u64 {
                        is_expire = true;
                        break 'a_record;
                    }
                }
                valid_records.extend_from_slice(rdatas);
            }

            if is_expire {
                return None;
            }

            // 如果有有效的记录，返回它们
            if !valid_records.is_empty() {
                return Some(valid_records);
            }
        }
        None
    }

    pub async fn insert(
        &self,
        domain: &str,
        query_type: RecordType,
        rdata_ttl_vec: Vec<Record>,
        mark: &PacketMark,
    ) {
        let insert_time = Instant::now();

        // 将记录和插入时间存储到缓存中
        let mut records_with_expiration: Vec<CacheDNSItem> = vec![];
        // TODO: 目前仅记录 IPV4 缓存
        let mut update_dns_mark_list = HashSet::new();
        let mut rdatas = vec![];
        for rdata in rdata_ttl_vec.into_iter() {
            match rdata.data() {
                hickory_proto::rr::RData::A(a) => {
                    update_dns_mark_list.insert(IpMarkInfo {
                        mark: mark.clone(),
                        cidr: IpConfig { ip: std::net::IpAddr::V4(a.0), prefix: 32_u32 },
                    });
                }
                _ => {}
            }
            rdatas.push(rdata);
        }
        records_with_expiration.push(CacheDNSItem { rdatas, insert_time, mark: mark.clone() });
        // let records_with_expiration: Vec<(Record, Instant)> =
        //     rdata_ttl_vec.into_iter().map(|rdata| (rdata, now)).collect();

        let mut cache = self.cache.lock().await;
        cache.put((domain.to_string(), query_type), records_with_expiration);
        drop(cache);
        // 将 mark 写入 mark ebpf map
        if mark.need_add_mark_config() {
            tracing::info!("setting ips: {:?}, Mark: {:?}", update_dns_mark_list, mark);
            // TODO: 如果写入错误 返回错误后 向客户端返回查询错误
            landscape_ebpf::map_setting::add_dns_marks(update_dns_mark_list.into_iter().collect());
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let queries = request.queries();
        if queries.is_empty() {
            let mut header = Header::response_from_request(request.header());
            header.set_response_code(ResponseCode::FormErr);
            let response =
                MessageResponseBuilder::from_message_request(request).build_no_records(header);
            let result = response_handle.send_response(response).await;
            return match result {
                Err(e) => {
                    tracing::error!("Request failed: {}", e);
                    serve_failed()
                }
                Ok(info) => info,
            };
        }

        // 先只处理第一个查询
        let req = &queries[0];
        let domain = req.name().to_string();
        let query_type = req.query_type();

        let response_builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NoError);
        header.set_authoritative(true);
        header.set_recursion_available(true);

        let mut records = vec![];

        // TODO: 修改逻辑
        if let Some(result) = self.lookup_cache(&domain, query_type).await {
            records = result;
        } else {
            for (_index, resolver) in self.resolves.iter() {
                if resolver.is_match(&domain) {
                    records = match resolver.lookup(&domain, query_type).await {
                        Ok(rdata_vec) => {
                            if rdata_vec.len() > 0 {
                                self.insert(
                                    &domain,
                                    query_type,
                                    rdata_vec.clone(),
                                    resolver.mark(),
                                )
                                .await;
                            }
                            rdata_vec
                        }
                        Err(error_code) => {
                            // 构建并返回错误响应
                            header.set_response_code(error_code);
                            let response = MessageResponseBuilder::from_message_request(request)
                                .build_no_records(header);
                            let result = response_handle.send_response(response).await;
                            return match result {
                                Err(e) => {
                                    tracing::error!("Request failed: {}", e);
                                    serve_failed()
                                }
                                Ok(info) => info,
                            };
                        }
                    };
                    break;
                }
            }
        }

        // 如果没有找到记录，返回 NXDomain 响应
        if records.is_empty() {
            // header.set_response_code(ResponseCode::NXDomain);
            let response = response_builder.build_no_records(header);
            let result = response_handle.send_response(response).await;
            return match result {
                Err(e) => {
                    tracing::error!("Request failed: {}", e);
                    serve_failed()
                }
                Ok(info) => info,
            };
        }

        let response = response_builder.build(
            header,
            records.iter(),
            vec![].into_iter(),
            vec![].into_iter(),
            vec![].into_iter(),
        );

        let result = response_handle.send_response(response).await;
        match result {
            Err(e) => {
                tracing::error!("Request failed: {}", e);
                serve_failed()
            }
            Ok(info) => info,
        }
    }
}

fn serve_failed() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::ServFail);
    header.into()
}

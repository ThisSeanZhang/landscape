use std::{
    collections::{BTreeMap, HashSet},
    num::NonZeroUsize,
    sync::Arc,
    time::Instant,
    vec,
};

use arc_swap::ArcSwap;
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

use crate::{
    reuseport_chain_server::solution::{RedirectSolution, ResolutionRule},
    CacheDNSItem, CheckChainDnsResult, DNSCache,
};
use landscape_common::{
    config::dns::FilterResult,
    dns::ChainDnsServerInitInfo,
    flow::{DnsRuntimeMarkInfo, FlowMarkInfo},
};

#[derive(Clone, Debug)]
pub struct ChainDnsRequestHandle {
    redirect_solution: Arc<ArcSwap<Vec<RedirectSolution>>>,
    resolves: BTreeMap<u32, Arc<ResolutionRule>>,
    pub cache: Arc<Mutex<DNSCache>>,
    pub flow_id: u32,
}

impl ChainDnsRequestHandle {
    pub fn new(info: ChainDnsServerInitInfo, flow_id: u32) -> ChainDnsRequestHandle {
        let mut resolves = BTreeMap::new();
        for rule in info.dns_rules.into_iter() {
            resolves.insert(rule.index, Arc::new(ResolutionRule::new(rule, flow_id)));
        }
        let cache = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(2048).unwrap())));

        let redirect_solution =
            info.redirect_rules.into_iter().map(RedirectSolution::new).collect();

        ChainDnsRequestHandle {
            resolves,
            cache,
            flow_id,
            redirect_solution: Arc::new(ArcSwap::from_pointee(redirect_solution)),
        }
    }

    pub async fn renew_rules(&mut self, info: ChainDnsServerInitInfo) {
        let mut resolves = BTreeMap::new();
        for rule in info.dns_rules.into_iter() {
            // println!("dns_rules: {:?}", rule);
            resolves.insert(rule.index, Arc::new(ResolutionRule::new(rule, self.flow_id)));
        }

        let mut cache = LruCache::new(NonZeroUsize::new(2048).unwrap());

        if let Ok(old_cache) = self.cache.try_lock() {
            let mut update_dns_mark_list: HashSet<FlowMarkInfo> = HashSet::new();
            let mut del_dns_mark_list: HashSet<FlowMarkInfo> = HashSet::new();

            for ((domain, req_type), value) in old_cache.iter() {
                'resolver: for (_index, resolver) in resolves.iter() {
                    if resolver.is_match(&domain) {
                        let new_mark = resolver.mark().clone();
                        // println!("old domain match resolver: {domain:?}");
                        let mut cache_items = vec![];
                        // println!(
                        //     "resolves: {:?}: match: {domain:?}, new_mark: {new_mark:?}",
                        //     resolver.config
                        // );
                        for cache_item in value.iter() {
                            // 新配置是 NoMark 的排除
                            match (
                                cache_item.mark.mark.need_insert_in_ebpf_map(),
                                new_mark.mark.need_insert_in_ebpf_map(),
                            ) {
                                (true, true) => {
                                    // 规则更新前后都需要写入 ebpf map
                                    // 因为现在是创建新的 map 所以即使一样也需要更新
                                    update_dns_mark_list
                                        .extend(cache_item.get_update_rules_with_mark(&new_mark));
                                }
                                (true, false) => {
                                    // 原先已经写入了
                                    // 现在不需要了
                                    del_dns_mark_list.extend(cache_item.get_update_rules());
                                }
                                (false, true) => {
                                    // 原先没写入
                                    // 目前需要缓存了
                                    update_dns_mark_list
                                        .extend(cache_item.get_update_rules_with_mark(&new_mark));
                                }
                                (false, false) => {
                                    // 原先没缓存，现在也不需要存储的
                                }
                            }

                            let mut new_record = cache_item.clone();
                            new_record.mark = new_mark.clone();
                            new_record.filter = resolver.filter_mode();
                            cache_items.push(new_record);
                        }
                        if !cache_items.is_empty() {
                            cache.push((domain.clone(), req_type.clone()), cache_items);
                        }
                        break 'resolver;
                    }
                }
            }
            tracing::info!("add_dns_marks: {:?}", update_dns_mark_list);

            landscape_ebpf::map_setting::flow_dns::create_flow_dns_inner_map(
                self.flow_id,
                update_dns_mark_list.into_iter().collect(),
            );
            // landscape_ebpf::map_setting::flow_dns::del_flow_dns_mark_rules(
            //     self.flow_id,
            //     del_dns_mark_list.into_iter().collect(),
            // );
        }

        // println!("cache: {:?}", cache);
        self.resolves = resolves;
        {
            let mut old_cache = self.cache.lock().await;
            *old_cache = cache;
            drop(old_cache);
        }

        let redirect_solution =
            info.redirect_rules.into_iter().map(RedirectSolution::new).collect();
        self.redirect_solution.store(Arc::new(redirect_solution));
    }

    pub async fn check_domain(&self, domain: &str, query_type: RecordType) -> CheckChainDnsResult {
        let mut result = CheckChainDnsResult::default();

        let records = {
            let mut records = vec![];
            let redirect_list = self.redirect_solution.load();
            for each in redirect_list.iter() {
                if each.is_match(&domain) {
                    result.redirect_id = Some(each.id);
                    records = each.lookup(&domain, query_type);
                    break;
                }
            }
            records
        };

        if records.is_empty() {
            for (_index, resolver) in self.resolves.iter() {
                if resolver.is_match(&domain) {
                    result.rule_id = Some(resolver.get_config_id());

                    match tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        resolver.lookup(&domain, query_type),
                    )
                    .await
                    {
                        Ok(Ok(rdata_vec)) => {
                            result.records = Some(rdata_vec);
                        }
                        Ok(Err(_)) => {
                            // lookup 返回了错误
                        }
                        Err(_) => {
                            tracing::error!("check domain timeout")
                        }
                    }
                    break;
                }
            }
        } else {
            result.records = Some(records);
        }

        if let Some((records, _)) = self.lookup_cache(domain, query_type).await {
            result.cache_records = Some(records);
        }

        result
    }

    // 检查缓存并根据 TTL 判断是否过期
    // 不同的记录可能的过期时间不同
    pub async fn lookup_cache(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, FilterResult)> {
        let mut cache = self.cache.lock().await;
        if let Some(records) = cache.get(&(domain.to_string(), query_type)) {
            let mut is_expire = false;
            let mut valid_records: Vec<Record> = vec![];
            let mut ret_fiter = FilterResult::Unfilter;
            'a_record: for CacheDNSItem { rdatas, insert_time, filter, .. } in records.iter() {
                ret_fiter = filter.clone();
                let insert_time = insert_time.elapsed().as_secs() as u32;
                for rdata in rdatas.iter() {
                    let ttl = rdata.ttl();
                    if insert_time > ttl {
                        is_expire = true;
                        break 'a_record;
                    }

                    let mut info = rdata.clone();
                    info.set_ttl(ttl - insert_time);
                    valid_records.push(info);
                    // tracing::debug!(
                    //     "query {domain} , filter: {filter:?}, result: {valid_records:?}"
                    // );
                }
            }

            if is_expire {
                return None;
            }

            // 如果有有效的记录，返回它们
            if !valid_records.is_empty() {
                return Some((valid_records, ret_fiter));
            }
        }
        None
    }

    pub async fn insert(
        &self,
        domain: &str,
        query_type: RecordType,
        rdata_ttl_vec: Vec<Record>,
        mark: &DnsRuntimeMarkInfo,
        filter: FilterResult,
    ) {
        let cache_item = CacheDNSItem {
            rdatas: rdata_ttl_vec,
            insert_time: Instant::now(),
            mark: mark.clone(),
            filter,
        };
        let update_dns_mark_list = cache_item.get_update_rules();

        let mut cache = self.cache.lock().await;
        // tracing::info!("setting ip into cache: {:?}", cache_item);
        cache.put((domain.to_string(), query_type), vec![cache_item]);
        drop(cache);
        // 将 mark 写入 mark ebpf map
        if mark.mark.need_insert_in_ebpf_map() {
            tracing::info!("setting ips: {:?}, Mark: {:?}", update_dns_mark_list, mark);
            // TODO: 如果写入错误 返回错误后 向客户端返回查询错误
            landscape_ebpf::map_setting::flow_dns::update_flow_dns_rule(
                self.flow_id,
                update_dns_mark_list.into_iter().collect(),
            );
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for ChainDnsRequestHandle {
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

        // let mut records = vec![];

        let mut records = {
            let mut records = vec![];
            let redirect_list = self.redirect_solution.load();
            for each in redirect_list.iter() {
                if each.is_match(&domain) {
                    records = each.lookup(&domain, query_type);
                    break;
                }
            }
            records
        };

        if records.is_empty() {
            if let Some((result, filter)) = self.lookup_cache(&domain, query_type).await {
                records = fiter_result(result, &filter);
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
                                        resolver.filter_mode(),
                                    )
                                    .await;
                                }
                                fiter_result(rdata_vec, &resolver.filter_mode())
                            }
                            Err(error_code) => {
                                // 构建并返回错误响应
                                header.set_response_code(error_code);
                                let response =
                                    MessageResponseBuilder::from_message_request(request)
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
        }

        // 如果没有找到记录，返回 NXDomain 响应
        if records.is_empty() {
            // header.set_response_code(ResponseCode::NXDomain);
            let response = response_builder.build_no_records(header);
            let result = response_handle.send_response(response).await;
            return match result {
                Err(e) => {
                    tracing::error!("Record Empty and response error: {}", e);
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

fn fiter_result(un_filter_records: Vec<Record>, filter: &FilterResult) -> Vec<Record> {
    let mut valid_records = Vec::with_capacity(un_filter_records.len());
    for rdata in un_filter_records.into_iter() {
        if matches!(filter, FilterResult::Unfilter) {
            valid_records.push(rdata.clone());
        } else {
            match (rdata.record_type(), filter) {
                (RecordType::A, FilterResult::OnlyIPv4) => {
                    valid_records.push(rdata.clone());
                }
                (RecordType::A, FilterResult::OnlyIPv6)
                | (RecordType::AAAA, FilterResult::OnlyIPv4) => {
                    // 过滤
                }
                (RecordType::AAAA, FilterResult::OnlyIPv6) => {
                    valid_records.push(rdata.clone());
                }
                _ => {
                    valid_records.push(rdata.clone());
                }
            }
        }
    }
    valid_records
}

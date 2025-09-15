use std::{collections::HashSet, num::NonZeroUsize, sync::Arc, time::Instant, vec};

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

use crate::{reuseport_server::FlowDnsServer, CacheDNSItem, CheckDnsResult, DNSCache};
use landscape_common::{
    config::dns::FilterResult,
    dns::DnsServerInitInfo,
    flow::{DnsRuntimeMarkInfo, FlowMarkInfo},
};

/// 整个 DNS 规则匹配树
#[derive(Clone)]
pub struct LandscapeDnsRequestHandle {
    resolves: Arc<ArcSwap<FlowDnsServer>>,
    pub cache: Arc<Mutex<DNSCache>>,
    pub flow_id: u32,
}

impl LandscapeDnsRequestHandle {
    pub fn new(info: DnsServerInitInfo, flow_id: u32) -> LandscapeDnsRequestHandle {
        let resolves = FlowDnsServer::new(info);

        let cache = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(2048).unwrap())));

        LandscapeDnsRequestHandle {
            resolves: Arc::new(ArcSwap::from_pointee(resolves)),
            cache,
            flow_id,
        }
    }

    pub async fn renew_rules(&mut self, info: DnsServerInitInfo) {
        // UPDATE CACHE

        // let mut resolves = BTreeMap::new();
        // for rule in dns_rules.into_iter() {
        //     // println!("dns_rules: {:?}", rule);
        //     resolves.insert(rule.index, Arc::new(ResolutionRule::new(rule, self.flow_id)));
        // }

        let new_resolve = FlowDnsServer::new(info);
        let mut cache = LruCache::new(NonZeroUsize::new(2048).unwrap());

        let mut old_cache = self.cache.lock().await;

        let mut update_dns_mark_list: HashSet<FlowMarkInfo> = HashSet::new();
        let mut del_dns_mark_list: HashSet<FlowMarkInfo> = HashSet::new();

        for ((domain, req_type), value) in old_cache.iter() {
            let info =
                new_resolve.matcher.match_value(&domain).or(new_resolve.default_resolver.as_ref());
            if let Some(info) = info {
                let new_mark = info.mark().clone();
                let mut cache_items = vec![];
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
                    new_record.filter = info.filter_mode();
                    cache_items.push(new_record);
                }

                if !cache_items.is_empty() {
                    cache.push((domain.clone(), req_type.clone()), cache_items);
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

        // println!("cache: {:?}", cache);
        // let cache = Arc::new(Mutex::new(cache));

        self.resolves.store(Arc::new(new_resolve));
        *old_cache = cache;
        drop(old_cache);
    }

    pub async fn check_domain(&self, domain: &str, query_type: RecordType) -> CheckDnsResult {
        let mut result = CheckDnsResult::default();

        let resolves = self.resolves.load();

        let info = resolves.matcher.match_value(&domain).or(resolves.default_resolver.as_ref());
        if let Some(info) = info {
            if let Some(resolver) = resolves.resolver_map.get(&info.resolver_id) {
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    resolver.lookup(domain, query_type),
                )
                .await
                {
                    Ok(Ok(rdata_vec)) => {
                        result.records = Some(rdata_vec.records().to_vec());
                    }
                    Ok(Err(_)) => {
                        // lookup 返回了错误
                    }
                    Err(_) => {
                        tracing::error!("check domain timeout")
                    }
                }
            }
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
        let min_ttl = rdata_ttl_vec.iter().map(|r| r.ttl()).min().unwrap_or(0);
        if min_ttl == 0 {
            return;
        }
        let cache_item = CacheDNSItem {
            rdatas: rdata_ttl_vec,
            insert_time: Instant::now(),
            mark: mark.clone(),
            filter,
            min_ttl,
        };
        let update_dns_mark_list = cache_item.get_update_rules();

        let mut cache = self.cache.lock().await;
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
impl RequestHandler for LandscapeDnsRequestHandle {
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

        let mut records = { self.resolves.load().redirect_lookup(&domain, query_type) };

        if records.is_empty() {
            // TODO: 修改逻辑
            if let Some((result, filter)) = self.lookup_cache(&domain, query_type).await {
                records = fiter_result(result, &filter);
            } else {
                let resolves = self.resolves.load();
                records = match resolves.lookup(&domain, query_type).await {
                    Ok((rdata_vec, info)) => {
                        // tracing::debug!(
                        //     "[flow_id: {}]: lookup success: {domain}, info: {info:?}",
                        //     self.flow_id
                        // );
                        if rdata_vec.len() > 0 {
                            self.insert(
                                &domain,
                                query_type,
                                rdata_vec.clone(),
                                info.mark(),
                                info.filter_mode(),
                            )
                            .await;
                        }
                        fiter_result(rdata_vec, &info.filter_mode())
                    }
                    Err(error_code) => {
                        // 构建并返回错误响应
                        header.set_response_code(error_code);
                        let response = MessageResponseBuilder::from_message_request(request)
                            .build_no_records(header);
                        let result = response_handle.send_response(response).await;
                        return match result {
                            Err(e) => {
                                tracing::error!("[{}] Request failed: {}", self.flow_id, e);
                                serve_failed()
                            }
                            Ok(info) => info,
                        };
                    }
                };
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

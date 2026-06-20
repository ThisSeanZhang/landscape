use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
    vec,
};

use arc_swap::ArcSwap;
#[cfg(test)]
use arc_swap::ArcSwapOption;
use hickory_proto::{
    op::{Header, Metadata, ResponseCode},
    rr::{
        rdata::{
            svcb::{Alpn, IpHint, SvcParamKey, SvcParamValue, SVCB},
            A, AAAA, HTTPS,
        },
        Name, RData, Record, RecordType,
    },
};
use hickory_server::{
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use moka::future::Cache;
use uuid::Uuid;

use crate::{
    server::preflight::{self, PreflightDecision},
    server::rule::{RedirectSolution, ResolutionRule},
    server::{CacheRuntimeConfig, DohAdvertiseProvider, LocalDnsAnswerProvider, MetricSenderState},
    CacheDNSItem, CheckChainDnsResult, DNSCache,
};
use landscape_common::{
    dns::check::DnsCheckError,
    dns::dnr::{normalize_advertise_domains, normalize_doh_path_template},
    dns::rule::FilterResult,
    dns::{DohRuntimeConfig, FlowDnsDesiredState, RuntimeDnsRule, RuntimeRedirectRule},
    event::DnsMetricMessage,
    flow::{DnsRuntimeMarkInfo, FlowMarkInfo},
    metric::dns::{DnsMetric, DnsResultStatus},
};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const RULE_REFRESH_TTL_CAP: u32 = 5;
const DDR_DISCOVERY_NAME: &str = "_dns.resolver.arpa.";
const DDR_ZONE_NAME: &str = "resolver.arpa.";
const DDR_TTL_SECS: u32 = 60;

#[derive(Clone)]
pub struct DnsRequestHandler {
    redirect_solution: Arc<ArcSwap<Vec<RedirectSolution>>>,
    resolves: Arc<ArcSwap<BTreeMap<u32, ResolutionRule>>>,
    pub cache: Arc<ArcSwap<DNSCache>>,
    pub flow_id: u32,
    pub msg_tx: MetricSenderState,
    runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    pub local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
    pub doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
    // Startup DoH endpoint snapshot used for DDR advertisements. Advertised
    // domains are loaded live from `doh_advertise_provider`; port/path changes
    // require a process restart so advertisements stay consistent with listener.
    doh_runtime: Option<DohRuntimeConfig>,
}

impl DnsRequestHandler {
    pub fn new(
        desired_state: FlowDnsDesiredState,
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        msg_tx: MetricSenderState,
        local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
        doh_runtime: Option<DohRuntimeConfig>,
    ) -> DnsRequestHandler {
        let FlowDnsDesiredState { dns_rules, redirect_rules, .. } = desired_state;
        let resolves = Self::build_resolves(flow_id, dns_rules);
        let cache_config = runtime_config.load();
        let cache = Self::build_cache(cache_config.as_ref());
        let redirect_solution = Self::build_redirects(redirect_rules);

        DnsRequestHandler {
            resolves: Arc::new(ArcSwap::from_pointee(resolves)),
            cache: Arc::new(ArcSwap::from_pointee(cache)),
            flow_id,
            redirect_solution: Arc::new(ArcSwap::from_pointee(redirect_solution)),
            msg_tx,
            runtime_config,
            local_answer_provider,
            doh_advertise_provider,
            doh_runtime,
        }
    }

    pub async fn renew_rules(&self, desired_state: FlowDnsDesiredState) {
        let FlowDnsDesiredState { dns_rules, redirect_rules, .. } = desired_state;
        self.renew_dns_rules(dns_rules).await;
        self.renew_redirect_rules(redirect_rules).await;
    }

    pub async fn renew_dns_rules(&self, dns_rules: Vec<RuntimeDnsRule>) {
        let resolves = Self::build_resolves(self.flow_id, dns_rules);
        let (new_cache, update_dns_mark_list) =
            self.rebuild_cache(&resolves, Some(RULE_REFRESH_TTL_CAP), true).await;

        tracing::info!("add_dns_marks: {:?}", update_dns_mark_list);
        self.refresh_flow_dns_map(update_dns_mark_list);

        // Update local state
        self.resolves.store(Arc::new(resolves));
        self.cache.store(Arc::new(new_cache));
        Self::recreate_route_cache();
    }

    pub async fn renew_redirect_rules(&self, redirect_rules: Vec<RuntimeRedirectRule>) {
        self.redirect_solution.store(Arc::new(Self::build_redirects(redirect_rules)));
    }

    pub async fn renew_runtime_config(&self, rebuild_cache: bool) {
        if rebuild_cache {
            let resolves = self.resolves.load();
            let (new_cache, _) = self.rebuild_cache(&resolves, None, false).await;
            self.cache.store(Arc::new(new_cache));
        }
    }

    async fn rebuild_cache(
        &self,
        resolves: &BTreeMap<u32, ResolutionRule>,
        ttl_cap: Option<u32>,
        collect_updates: bool,
    ) -> (DNSCache, HashSet<FlowMarkInfo>) {
        let new_cache = self.build_runtime_cache();
        let update_dns_mark_list =
            self.migrate_cache(&new_cache, resolves, ttl_cap, collect_updates).await;
        (new_cache, update_dns_mark_list)
    }

    async fn migrate_cache(
        &self,
        new_cache: &DNSCache,
        resolves: &BTreeMap<u32, ResolutionRule>,
        ttl_cap: Option<u32>,
        collect_updates: bool,
    ) -> HashSet<FlowMarkInfo> {
        let mut update_dns_mark_list = HashSet::new();
        let current_cache = self.cache.load();

        for (key, value) in current_cache.iter() {
            let (domain, req_type) = &*key;
            let cache_item = value;
            if let Some(resolver) = Self::find_cache_rule(resolves, domain, &cache_item) {
                let new_mark = resolver.mark().clone();
                let will_map = collect_updates && new_mark.mark.need_insert_in_ebpf_map();

                if will_map {
                    update_dns_mark_list.extend(cache_item.get_update_rules_with_mark(&new_mark));
                }

                let new_item = CacheDNSItem {
                    rdatas: cache_item.rdatas.clone(),
                    response_code: cache_item.response_code,
                    mark: new_mark.clone(),
                    insert_time: cache_item.insert_time,
                    min_ttl: ttl_cap.map_or(cache_item.min_ttl, |cap| cache_item.min_ttl.min(cap)),
                    filter: resolver.filter_mode(),
                    matched_rule_id: Some(resolver.get_config_id()),
                    matched_rule_order: Some(resolver.order()),
                };

                new_cache.insert((domain.clone(), req_type.clone()), Arc::new(new_item)).await;
            }
        }
        update_dns_mark_list
    }

    fn find_cache_rule<'a>(
        resolves: &'a BTreeMap<u32, ResolutionRule>,
        domain: &str,
        cache_item: &CacheDNSItem,
    ) -> Option<&'a ResolutionRule> {
        if let Some(rule_order) = cache_item.matched_rule_order {
            if let Some(resolver) = resolves.get(&rule_order) {
                if cache_item.matched_rule_id == Some(resolver.get_config_id())
                    && resolver.is_match(domain)
                {
                    return Some(resolver);
                }
            }
        }

        resolves.values().find(|resolver| resolver.is_match(domain))
    }

    fn build_resolves(
        flow_id: u32,
        dns_rules: Vec<RuntimeDnsRule>,
    ) -> BTreeMap<u32, ResolutionRule> {
        let mut resolves = BTreeMap::new();
        for rule in dns_rules {
            resolves.insert(rule.order, ResolutionRule::new(rule, flow_id));
        }
        resolves
    }

    fn build_cache(runtime_config: &CacheRuntimeConfig) -> DNSCache {
        Cache::builder()
            .max_capacity(runtime_config.cache_capacity as u64)
            .time_to_live(Duration::from_secs(runtime_config.cache_ttl as u64))
            .build()
    }

    fn build_runtime_cache(&self) -> DNSCache {
        let runtime_config = self.runtime_config.load();
        Self::build_cache(runtime_config.as_ref())
    }

    fn build_redirects(redirect_rules: Vec<RuntimeRedirectRule>) -> Vec<RedirectSolution> {
        redirect_rules.into_iter().map(RedirectSolution::new).collect()
    }

    fn refresh_flow_dns_map(&self, update_dns_mark_list: HashSet<FlowMarkInfo>) {
        landscape_ebpf::map_setting::flow_dns::refreash_flow_dns_inner_map(
            self.flow_id,
            update_dns_mark_list.into_iter().collect(),
        );
    }

    fn recreate_route_cache() {
        landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    }

    pub fn lookup_redirects(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, DnsResultStatus, Option<Uuid>, Option<String>)> {
        let redirect_list = self.redirect_solution.load();
        for each in redirect_list.iter() {
            if each.is_match(domain) {
                let records = if each.uses_local_answer_provider() {
                    let Some(provider) = self.local_answer_provider.as_ref() else {
                        continue;
                    };
                    let addrs = provider.load_local_answer_addrs(query_type);
                    each.lookup_with_addrs(domain, query_type, &addrs)
                } else {
                    each.lookup(domain, query_type)
                };

                if each.uses_local_answer_provider() && records.is_empty() {
                    continue;
                }

                let status =
                    if each.is_block() { DnsResultStatus::Block } else { DnsResultStatus::Local };
                return Some((
                    records,
                    status,
                    each.redirect_id,
                    each.dynamic_redirect_source.clone(),
                ));
            }
        }
        None
    }

    pub async fn check_domain(
        &self,
        domain: &str,
        query_type: RecordType,
        apply_filter: bool,
    ) -> CheckChainDnsResult {
        let mut result = CheckChainDnsResult::default();

        if let Some(local_result) = Self::check_result_from_preflight(
            preflight::classify_hard_local_zone(domain, query_type),
        ) {
            return local_result;
        }

        if let Some((records, _status, id, dynamic_source)) =
            self.lookup_redirects(domain, query_type)
        {
            result.redirect_id = id;
            result.dynamic_redirect_source = dynamic_source;
            result.records = Some(crate::to_common_records(records));
        } else if let Some(local_result) =
            Self::check_result_from_preflight(preflight::classify_overrideable_local_zone(domain))
        {
            return local_result;
        } else {
            let resolves = self.resolves.load();
            for (_index, resolver) in resolves.iter() {
                if resolver.is_match(domain) {
                    result.rule_id = Some(resolver.get_config_id());
                    let filter = resolver.filter_mode();
                    result.rule_filter = Some(filter.clone());

                    result.query_filtered = is_type_filtered(query_type, &filter);
                    if result.query_filtered && apply_filter {
                        result.records = Some(vec![]);
                        break;
                    }

                    if let Ok(rdata_vec) =
                        with_lookup_timeout(resolver.lookup(domain, query_type), LOOKUP_TIMEOUT)
                            .await
                    {
                        let records = if apply_filter {
                            filter_result(rdata_vec, &filter)
                        } else {
                            rdata_vec
                        };
                        result.records = Some(crate::to_common_records(records));
                    }
                    break;
                }
            }
        }

        if let Some((records, filter, _)) = self.lookup_cache(domain, query_type).await {
            let query_filtered = is_type_filtered(query_type, &filter);
            result.query_filtered |= query_filtered;
            if result.rule_filter.is_none() {
                result.rule_filter = Some(filter.clone());
            }
            result.cache_records = Some(if query_filtered && apply_filter {
                vec![]
            } else if apply_filter {
                crate::to_common_records(filter_result(records, &filter))
            } else {
                crate::to_common_records(records)
            });
        }

        result
    }

    pub async fn invalidate_cache_entry(&self, domain: &str, query_type: RecordType) {
        self.clear_cache_entry(domain, query_type).await;
        self.refresh_runtime_maps_from_cache();
    }

    pub async fn refresh_cache_entry(
        &self,
        domain: &str,
        query_type: RecordType,
        apply_filter: bool,
    ) -> Result<CheckChainDnsResult, DnsCheckError> {
        if let Some(local_result) = Self::check_result_from_preflight(
            preflight::classify_hard_local_zone(domain, query_type),
        ) {
            self.clear_cache_entry_and_refresh_maps_if_present(domain, query_type).await;
            return Ok(local_result);
        }

        if self.lookup_redirects(domain, query_type).is_some() {
            return Err(DnsCheckError::RefreshRedirected(domain.to_string()));
        }

        if let Some(local_result) =
            Self::check_result_from_preflight(preflight::classify_overrideable_local_zone(domain))
        {
            self.clear_cache_entry_and_refresh_maps_if_present(domain, query_type).await;
            return Ok(local_result);
        }

        let resolves = self.resolves.load();
        for (_index, resolver) in resolves.iter() {
            if !resolver.is_match(domain) {
                continue;
            }

            let filter = resolver.filter_mode();
            let query_filtered = is_type_filtered(query_type, &filter);
            let mut result = CheckChainDnsResult {
                rule_id: Some(resolver.get_config_id()),
                rule_filter: Some(filter.clone()),
                query_filtered,
                ..Default::default()
            };

            match with_lookup_timeout(resolver.lookup(domain, query_type), LOOKUP_TIMEOUT).await {
                Ok(rdata_vec) => {
                    let records = if apply_filter {
                        filter_result(rdata_vec.clone(), &filter)
                    } else {
                        rdata_vec.clone()
                    };
                    result.records = Some(crate::to_common_records(records));

                    if query_filtered {
                        self.clear_cache_entry(domain, query_type).await;
                    } else {
                        self.insert(
                            domain,
                            query_type,
                            rdata_vec,
                            ResponseCode::NoError,
                            resolver.mark(),
                            filter.clone(),
                            Some(resolver.get_config_id()),
                            Some(resolver.order()),
                        )
                        .await;
                    }
                }
                Err(err) => {
                    let code = err.to_response_code();
                    result.records = Some(vec![]);

                    if query_filtered {
                        self.clear_cache_entry(domain, query_type).await;
                    } else if code == ResponseCode::NXDomain || code == ResponseCode::NoError {
                        self.insert(
                            domain,
                            query_type,
                            vec![],
                            code,
                            resolver.mark(),
                            filter.clone(),
                            Some(resolver.get_config_id()),
                            Some(resolver.order()),
                        )
                        .await;
                    } else {
                        return Err(DnsCheckError::RefreshFailed(domain.to_string()));
                    }
                }
            }

            self.refresh_runtime_maps_from_cache();

            if let Some((records, cache_filter, _)) = self.lookup_cache(domain, query_type).await {
                let cache_query_filtered = is_type_filtered(query_type, &cache_filter);
                result.query_filtered |= cache_query_filtered;
                if result.rule_filter.is_none() {
                    result.rule_filter = Some(cache_filter.clone());
                }
                result.cache_records = Some(if cache_query_filtered && apply_filter {
                    vec![]
                } else if apply_filter {
                    crate::to_common_records(filter_result(records, &cache_filter))
                } else {
                    crate::to_common_records(records)
                });
            }

            return Ok(result);
        }

        Err(DnsCheckError::RefreshRequiresRule(domain.to_string()))
    }

    fn check_result_from_preflight(decision: PreflightDecision) -> Option<CheckChainDnsResult> {
        match decision {
            PreflightDecision::Respond { records, .. } => Some(CheckChainDnsResult {
                records: Some(crate::to_common_records(records)),
                ..Default::default()
            }),
            PreflightDecision::Continue => None,
        }
    }

    async fn clear_cache_entry(&self, domain: &str, query_type: RecordType) {
        let cache = self.cache.load();
        cache.invalidate(&(domain.to_string(), query_type)).await;
    }

    async fn clear_cache_entry_if_present(&self, domain: &str, query_type: RecordType) -> bool {
        let cache = self.cache.load();
        let key = (domain.to_string(), query_type);
        if cache.get(&key).await.is_none() {
            return false;
        }

        cache.invalidate(&key).await;
        true
    }

    async fn clear_cache_entry_and_refresh_maps_if_present(
        &self,
        domain: &str,
        query_type: RecordType,
    ) {
        if self.clear_cache_entry_if_present(domain, query_type).await {
            self.refresh_runtime_maps_from_cache();
        }
    }

    fn refresh_runtime_maps_from_cache(&self) {
        let cache = self.cache.load();
        let mut update_dns_mark_list = HashSet::new();
        for (_key, value) in cache.iter() {
            update_dns_mark_list.extend(value.get_update_rules());
        }

        self.refresh_flow_dns_map(update_dns_mark_list);
        Self::recreate_route_cache();
    }

    // 检查缓存并根据 TTL 判断是否过期
    // 不同的记录可能的过期时间不同
    pub async fn lookup_cache(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, FilterResult, ResponseCode)> {
        let cache = self.cache.load();
        if let Some(cache_item) = cache.get(&(domain.to_string(), query_type)).await {
            let CacheDNSItem {
                rdatas,
                response_code,
                insert_time,
                min_ttl,
                filter,
                ..
            } = &*cache_item;

            // 1. 检查过期
            let insert_time_elapsed = insert_time.elapsed().as_secs() as u32;
            if insert_time_elapsed > *min_ttl {
                // 如果发现过期，主动移除缓存（Lazy expiration）
                cache.invalidate(&(domain.to_string(), query_type)).await;
                return None;
            }

            // 2. 构造有效记录 (TTL 递减)
            // 如果 rdatas 为空（否定缓存），这里 valid_records 也会保持为空
            let valid_records = rdatas
                .iter()
                .cloned()
                .map(|mut d| {
                    d.ttl = *min_ttl - insert_time_elapsed;
                    d
                })
                .collect();

            return Some((valid_records, filter.clone(), *response_code));
        }
        None
    }

    pub async fn insert(
        &self,
        domain: &str,
        query_type: RecordType,
        rdata_ttl_vec: Vec<Record>,
        response_code: ResponseCode,
        mark: &DnsRuntimeMarkInfo,
        filter: FilterResult,
        matched_rule_id: Option<Uuid>,
        matched_rule_order: Option<u32>,
    ) {
        let min_ttl = rdata_ttl_vec
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or_else(|| self.runtime_config.load().negative_cache_ttl);

        if min_ttl == 0 {
            return;
        }
        let cache_item = CacheDNSItem {
            rdatas: rdata_ttl_vec,
            response_code,
            mark: mark.clone(),
            insert_time: Instant::now(),
            min_ttl,
            filter,
            matched_rule_id,
            matched_rule_order,
        };
        let update_dns_mark_list = cache_item.get_update_rules();

        let cache = self.cache.load();
        cache.insert((domain.to_string(), query_type), Arc::new(cache_item)).await;

        // 将 mark 写入 mark ebpf map
        if mark.mark.need_insert_in_ebpf_map() {
            tracing::info!(
                "[flow_id: {}]setting ips: {:?}, Mark: {:?}",
                self.flow_id,
                update_dns_mark_list,
                mark
            );
            // TODO: 如果写入错误 返回错误后 向客户端返回查询错误
            landscape_ebpf::map_setting::flow_dns::update_flow_dns_rule(
                self.flow_id,
                update_dns_mark_list.into_iter().collect(),
            );
        }
    }

    fn send_metric(
        &self,
        domain: String,
        query_type: RecordType,
        response_code: ResponseCode,
        status: DnsResultStatus,
        start_time: Instant,
        src_ip: std::net::IpAddr,
        answers: Vec<String>,
    ) {
        if let Some(msg_tx) = self.msg_tx.load_full() {
            let dns_metric = DnsMetric {
                flow_id: self.flow_id,
                domain,
                query_type: query_type.to_string(),
                response_code: response_code.to_string(),
                status,
                report_time: landscape_common::utils::time::get_current_time_ms()
                    .unwrap_or_default(),
                duration_ms: start_time.elapsed().as_millis() as u32,
                src_ip,
                answers,
            };
            let _ = msg_tx.try_send(DnsMetricMessage::Metric(dns_metric));
        }
    }

    async fn send_error_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        code: ResponseCode,
    ) -> ResponseInfo {
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = code;
        metadata.recursion_available = true;
        metadata.authoritative = true;
        let response =
            MessageResponseBuilder::from_message_request(request).build_no_records(metadata);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Error response failed: {}", e);
                serve_failed(&request.metadata)
            }
        }
    }

    async fn send_records_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        code: ResponseCode,
        records: Vec<Record>,
    ) -> ResponseInfo {
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = code;
        metadata.recursion_available = true;
        metadata.authoritative = true;

        let builder = MessageResponseBuilder::from_message_request(request);
        let result = if records.is_empty() {
            let response = builder.build_no_records(metadata);
            response_handle.send_response(response).await
        } else {
            let response = builder.build(
                metadata,
                records.iter(),
                vec![].into_iter(),
                vec![].into_iter(),
                vec![].into_iter(),
            );
            response_handle.send_response(response).await
        };

        match result {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Response failed: {}", e);
                serve_failed(&request.metadata)
            }
        }
    }

    async fn send_preflight_response<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        domain: String,
        query_type: RecordType,
        code: ResponseCode,
        records: Vec<Record>,
        status: DnsResultStatus,
        start_time: Instant,
        src_ip: std::net::IpAddr,
    ) -> ResponseInfo {
        let answers = records.iter().map(|r| r.to_string()).collect();
        let response = self.send_records_response(request, response_handle, code, records).await;
        self.send_metric(domain, query_type, code, status, start_time, src_ip, answers);
        response
    }

    async fn try_handle_resolver_arpa_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> Option<ResponseInfo> {
        let req = request.queries.queries().first()?;
        let query_name = req.name().to_string().to_ascii_lowercase();
        if !is_resolver_arpa_name(&query_name) {
            return None;
        }

        let records = if req.query_type() == RecordType::SVCB && query_name == DDR_DISCOVERY_NAME {
            self.build_ddr_records()
        } else {
            Vec::new()
        };

        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = ResponseCode::NoError;
        metadata.authoritative = true;
        metadata.recursion_available = true;

        let response = MessageResponseBuilder::from_message_request(request).build(
            metadata,
            records.iter(),
            vec![].into_iter(),
            vec![].into_iter(),
            vec![].into_iter(),
        );

        Some(match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("DDR response failed: {}", e);
                serve_failed(&request.metadata)
            }
        })
    }

    fn build_ddr_records(&self) -> Vec<Record> {
        let Some(doh_runtime) = self.doh_runtime.as_ref() else {
            return Vec::new();
        };
        let Some(provider) = self.doh_advertise_provider.as_ref() else {
            return Vec::new();
        };
        let domains = normalize_advertise_domains(provider.advertise_domains());
        if domains.is_empty() {
            return Vec::new();
        }

        build_ddr_records(
            &domains,
            doh_runtime.listen_port,
            &doh_runtime.http_endpoint,
            self.local_answer_provider.as_deref(),
        )
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsRequestHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let start_time = Instant::now();
        let queries = request.queries.queries();
        if !matches!(preflight::classify_query_count(queries.len()), PreflightDecision::Continue) {
            return self.send_error_response(request, response_handle, ResponseCode::FormErr).await;
        }

        let req = &queries[0];
        let domain = req.name().to_string();
        let query_type = req.query_type();
        let src_ip = request.src().ip();

        if let PreflightDecision::Respond { code, records, status } =
            preflight::classify_hard_query(request.metadata.op_code, req)
        {
            return self
                .send_preflight_response(
                    request,
                    response_handle,
                    domain,
                    query_type,
                    code,
                    records,
                    status,
                    start_time,
                    src_ip,
                )
                .await;
        }

        if let Some(info) =
            self.try_handle_resolver_arpa_request(request, &mut response_handle).await
        {
            return info;
        }

        if let PreflightDecision::Respond { code, records, status } =
            preflight::classify_hard_local_zone(&domain, query_type)
        {
            self.clear_cache_entry_and_refresh_maps_if_present(&domain, query_type).await;
            return self
                .send_preflight_response(
                    request,
                    response_handle,
                    domain,
                    query_type,
                    code,
                    records,
                    status,
                    start_time,
                    src_ip,
                )
                .await;
        }

        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = ResponseCode::NoError;
        metadata.authoritative = true;
        metadata.recursion_available = true;

        let mut records = vec![];
        let mut status = DnsResultStatus::Normal;

        // 1. Redirects
        if let Some((redirect_records, redirect_status, _, _)) =
            self.lookup_redirects(&domain, query_type)
        {
            records = redirect_records;
            status = redirect_status;
        }
        // 2. Built-in local zones that user redirects may override
        else if let PreflightDecision::Respond {
            code,
            records: local_records,
            status: local_status,
        } = preflight::classify_overrideable_local_zone(&domain)
        {
            self.clear_cache_entry_and_refresh_maps_if_present(&domain, query_type).await;
            return self
                .send_preflight_response(
                    request,
                    response_handle,
                    domain,
                    query_type,
                    code,
                    local_records,
                    local_status,
                    start_time,
                    src_ip,
                )
                .await;
        }
        // 3. Cache
        else if let Some((cached_records, filter, code)) =
            self.lookup_cache(&domain, query_type).await
        {
            metadata.response_code = code;
            if is_type_filtered(query_type, &filter) {
                status = DnsResultStatus::Filter;
            } else {
                records = filter_result(cached_records, &filter);
                status = DnsResultStatus::Hit;
            }
        }
        // 4. Resolution Rules (with Early Filter check)
        else {
            let resolves = self.resolves.load();
            let mut resolved = false;
            for (_index, resolver) in resolves.iter() {
                if resolver.is_match(&domain) {
                    resolved = true;
                    let filter = resolver.filter_mode();

                    // Early return if current query type is filtered by rule
                    if is_type_filtered(query_type, &filter) {
                        status = DnsResultStatus::Filter;
                        break;
                    }

                    match with_lookup_timeout(resolver.lookup(&domain, query_type), LOOKUP_TIMEOUT)
                        .await
                    {
                        Ok(rdata_vec) => {
                            self.insert(
                                &domain,
                                query_type,
                                rdata_vec.clone(),
                                ResponseCode::NoError,
                                resolver.mark(),
                                filter.clone(),
                                Some(resolver.get_config_id()),
                                Some(resolver.order()),
                            )
                            .await;

                            records = filter_result(rdata_vec, &filter);
                            status = DnsResultStatus::Normal;
                        }
                        Err(err) => {
                            let code = err.to_response_code();
                            status = match code {
                                ResponseCode::NXDomain => DnsResultStatus::NxDomain,
                                ResponseCode::NoError => DnsResultStatus::Normal,
                                _ => DnsResultStatus::Error,
                            };

                            if code == ResponseCode::NXDomain || code == ResponseCode::NoError {
                                self.insert(
                                    &domain,
                                    query_type,
                                    vec![],
                                    code,
                                    resolver.mark(),
                                    filter.clone(),
                                    Some(resolver.get_config_id()),
                                    Some(resolver.order()),
                                )
                                .await;
                            }
                            self.send_metric(
                                domain.clone(),
                                query_type,
                                code,
                                status,
                                start_time,
                                src_ip,
                                vec![],
                            );
                            return self.send_error_response(request, response_handle, code).await;
                        }
                    }
                    break;
                }
            }
            if !resolved {
                status = DnsResultStatus::Normal;
            }
        }

        // 5. Send Response
        let builder = MessageResponseBuilder::from_message_request(request);
        let result = if records.is_empty() {
            let response = builder.build_no_records(metadata);
            response_handle.send_response(response).await
        } else {
            let response = builder.build(
                metadata,
                records.iter(),
                vec![].into_iter(),
                vec![].into_iter(),
                vec![].into_iter(),
            );
            response_handle.send_response(response).await
        };
        let answers = records.iter().map(|r| r.to_string()).collect();
        self.send_metric(
            domain,
            query_type,
            metadata.response_code,
            status,
            start_time,
            src_ip,
            answers,
        );

        match result {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Response failed: {}", e);
                serve_failed(&request.metadata)
            }
        }
    }
}

fn serve_failed(req_metadata: &Metadata) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(req_metadata);
    metadata.response_code = ResponseCode::ServFail;
    metadata.recursion_available = true;
    metadata.authoritative = true;
    ResponseInfo::from(Header { metadata, counts: Default::default() })
}

fn is_resolver_arpa_name(name: &str) -> bool {
    name == DDR_ZONE_NAME || name.ends_with(".resolver.arpa.")
}

fn build_ddr_records(
    domains: &[String],
    port: u16,
    doh_path: &str,
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
) -> Vec<Record> {
    let Ok(owner) = Name::from_str(DDR_DISCOVERY_NAME) else {
        return Vec::new();
    };
    let Some(doh_path) = normalize_doh_path_template(doh_path) else {
        return Vec::new();
    };
    let ipv4_hints = load_ipv4_hints(local_answer_provider);
    let ipv6_hints = load_ipv6_hints(local_answer_provider);

    domains
        .iter()
        .filter_map(|domain| {
            let target = Name::from_str(&format!("{}.", domain)).ok()?;
            let mut params =
                vec![(SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])))];
            params.push((SvcParamKey::Port, SvcParamValue::Port(port)));
            if !ipv4_hints.is_empty() {
                params.push((
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(ipv4_hints.clone())),
                ));
            }
            if !ipv6_hints.is_empty() {
                params.push((
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(ipv6_hints.clone())),
                ));
            }
            params.push((
                SvcParamKey::Unknown(7),
                SvcParamValue::Unknown(landscape_common::dns::dnr::encode_unknown_svc_param_value(
                    doh_path.as_bytes(),
                )),
            ));
            Some(Record::from_rdata(
                owner.clone(),
                DDR_TTL_SECS,
                RData::SVCB(SVCB::new(1, target, params)),
            ))
        })
        .collect()
}

fn load_ipv4_hints(provider: Option<&dyn LocalDnsAnswerProvider>) -> Vec<A> {
    provider
        .map(|provider| provider.load_local_answer_addrs(RecordType::A))
        .unwrap_or_default()
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(ip) => Some(A(*ip)),
            _ => None,
        })
        .collect()
}

fn load_ipv6_hints(provider: Option<&dyn LocalDnsAnswerProvider>) -> Vec<AAAA> {
    provider
        .map(|provider| provider.load_local_answer_addrs(RecordType::AAAA))
        .unwrap_or_default()
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(ip) => Some(AAAA(*ip)),
            _ => None,
        })
        .collect()
}

async fn with_lookup_timeout<F, T>(future: F, timeout: Duration) -> crate::error::DnsResult<T>
where
    F: Future<Output = crate::error::DnsResult<T>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(crate::error::DnsError::Timeout),
    }
}

fn filter_result(un_filter_records: Vec<Record>, filter: &FilterResult) -> Vec<Record> {
    if matches!(filter, FilterResult::Unfilter) {
        return un_filter_records;
    }
    un_filter_records
        .into_iter()
        .filter(|r| match (r.record_type(), filter) {
            (RecordType::A, FilterResult::OnlyIPv4) => true,
            (RecordType::A, FilterResult::OnlyIPv6) => false,
            (RecordType::AAAA, FilterResult::OnlyIPv4) => false,
            (RecordType::AAAA, FilterResult::OnlyIPv6) => true,
            _ => true,
        })
        .map(|mut r| {
            // For HTTPS records, strip ipv4hint/ipv6hint SvcParams
            // that contradict the IP-version filter, so clients won't
            // use a hint to bypass the filter.
            if r.record_type() == RecordType::HTTPS {
                if let RData::HTTPS(https) = r.data.clone() {
                    let key_to_remove = match filter {
                        FilterResult::OnlyIPv4 => Some(SvcParamKey::Ipv6Hint),
                        FilterResult::OnlyIPv6 => Some(SvcParamKey::Ipv4Hint),
                        FilterResult::Unfilter => None,
                    };
                    if let Some(remove_key) = key_to_remove {
                        let filtered_params: Vec<_> = https
                            .0
                            .svc_params
                            .iter()
                            .filter(|(k, _)| *k != remove_key)
                            .cloned()
                            .collect();
                        let new_svcb = SVCB::new(
                            https.0.svc_priority,
                            https.0.target_name.clone(),
                            filtered_params,
                        );
                        r.data = RData::HTTPS(HTTPS(new_svcb));
                    }
                }
            }
            r
        })
        .collect()
}

fn is_type_filtered(query_type: RecordType, filter: &FilterResult) -> bool {
    match (query_type, filter) {
        (RecordType::A, FilterResult::OnlyIPv6) => true,
        (RecordType::AAAA, FilterResult::OnlyIPv4) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use landscape_common::{
        dns::ChainDnsServerInitInfo,
        dns::{
            config::DnsUpstreamConfig,
            redirect::{DNSRedirectRuntimeRule, DnsRedirectAnswerMode},
            rule::{DNSRuntimeRule, DomainConfig, DomainMatchType},
        },
        flow::mark::FlowMark,
    };
    use std::str::FromStr;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };
    use uuid::Uuid;

    struct MockLocalAnswerProvider {
        addrs: Vec<IpAddr>,
    }

    impl LocalDnsAnswerProvider for MockLocalAnswerProvider {
        fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
            let addrs = self
                .addrs
                .iter()
                .copied()
                .filter(|addr| {
                    matches!(
                        (addr, query_type),
                        (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)
                    )
                })
                .collect();
            Arc::new(addrs)
        }
    }

    fn run_async_test(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test);
    }

    fn test_cache_runtime_config(negative_cache_ttl: u32) -> CacheRuntimeConfig {
        CacheRuntimeConfig {
            cache_capacity: 16,
            cache_ttl: 60,
            negative_cache_ttl,
        }
    }

    fn shared_cache_runtime_config(negative_cache_ttl: u32) -> Arc<ArcSwap<CacheRuntimeConfig>> {
        Arc::new(ArcSwap::from_pointee(test_cache_runtime_config(negative_cache_ttl)))
    }

    fn test_runtime_rule() -> DNSRuntimeRule {
        DNSRuntimeRule {
            resolve_mode: DnsUpstreamConfig::default(),
            ..DNSRuntimeRule::default()
        }
    }

    fn sample_a_record(name: &str, ttl: u32, addr: Ipv4Addr) -> Record {
        Record::from_rdata(hickory_proto::rr::Name::from_str(name).unwrap(), ttl, RData::A(A(addr)))
    }

    #[test]
    fn test_serve_failed_flags() {
        let req_metadata = Metadata::new(
            0x1234,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );

        let res_info = serve_failed(&req_metadata);

        // ResponseInfo derefs to Header in the version of hickory-server used
        assert_eq!(res_info.id, 0x1234);
        assert_eq!(res_info.response_code, ResponseCode::ServFail);
        assert!(res_info.recursion_available, "RA flag must be true");
        assert!(res_info.authoritative, "AA flag must be true");
    }

    #[test]
    fn test_is_type_filtered() {
        assert!(is_type_filtered(RecordType::A, &FilterResult::OnlyIPv6));
        assert!(!is_type_filtered(RecordType::AAAA, &FilterResult::OnlyIPv6));
        assert!(is_type_filtered(RecordType::AAAA, &FilterResult::OnlyIPv4));
        assert!(!is_type_filtered(RecordType::A, &FilterResult::OnlyIPv4));
        assert!(!is_type_filtered(RecordType::A, &FilterResult::Unfilter));
    }

    #[test]
    fn test_filter_result() {
        let name = hickory_proto::rr::Name::from_str("test.com.").unwrap();
        let records = vec![
            Record::from_rdata(name.clone(), 60, RData::A(A(Ipv4Addr::new(1, 1, 1, 1)))),
            Record::from_rdata(
                name.clone(),
                60,
                RData::AAAA(AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
            ),
        ];

        let filtered_v4 = filter_result(records.clone(), &FilterResult::OnlyIPv4);
        assert_eq!(filtered_v4.len(), 1);
        assert_eq!(filtered_v4[0].record_type(), RecordType::A);

        let filtered_v6 = filter_result(records.clone(), &FilterResult::OnlyIPv6);
        assert_eq!(filtered_v6.len(), 1);
        assert_eq!(filtered_v6[0].record_type(), RecordType::AAAA);

        let filtered_none = filter_result(records.clone(), &FilterResult::Unfilter);
        assert_eq!(filtered_none.len(), 2);
    }

    #[test]
    fn build_ddr_records_encodes_svc_params_in_increasing_order() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 5, 1)), IpAddr::V6(Ipv6Addr::LOCALHOST)],
        };
        let records =
            build_ddr_records(&["api.example.com".to_string()], 443, "/dns-query", Some(&provider));

        assert_eq!(records.len(), 1);
        let svcb = match &records[0].data {
            RData::SVCB(svcb) => svcb.clone(),
            _ => panic!("expected SVCB record"),
        };

        let keys = svcb.svc_params.iter().map(|(key, _)| u16::from(*key)).collect::<Vec<_>>();
        assert_eq!(keys, vec![1, 3, 4, 6, 7]);

        let mut wire = Vec::new();
        let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut wire);
        svcb.emit(&mut encoder).expect("SVCB should encode successfully");
        assert!(wire.windows(b"/dns-query{?dns}".len()).any(|w| w == b"/dns-query{?dns}"));
    }

    #[test]
    fn resolver_arpa_name_matches_local_zone_only() {
        assert!(is_resolver_arpa_name("resolver.arpa."));
        assert!(is_resolver_arpa_name("_dns.resolver.arpa."));
        assert!(is_resolver_arpa_name("foo.bar.resolver.arpa."));
        assert!(!is_resolver_arpa_name("evilresolver.arpa."));
        assert!(!is_resolver_arpa_name("resolver.arpa.example."));
    }

    #[test]
    fn test_with_lookup_timeout_returns_timeout_error() {
        run_async_test(async {
            let result = with_lookup_timeout(
                async {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok::<_, crate::error::DnsError>(vec![1_u8])
                },
                Duration::from_millis(5),
            )
            .await;

            assert!(matches!(result, Err(crate::error::DnsError::Timeout)));
        });
    }

    #[test]
    fn test_with_lookup_timeout_returns_inner_result() {
        run_async_test(async {
            let result = with_lookup_timeout(
                async { Ok::<_, crate::error::DnsError>(vec![1_u8, 2_u8]) },
                Duration::from_millis(50),
            )
            .await;

            assert_eq!(result.unwrap(), vec![1_u8, 2_u8]);
        });
    }

    #[test]
    fn check_domain_applies_filter_when_requested() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![DNSRuntimeRule {
                        filter: FilterResult::OnlyIPv6,
                        source: vec![DomainConfig {
                            match_type: DomainMatchType::Full,
                            value: "example.com".to_string(),
                        }],
                        ..test_runtime_rule()
                    }],
                    redirect_rules: vec![],
                }
                .into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            let result = handler.check_domain("example.com.", RecordType::A, true).await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn check_domain_filters_cached_records_when_requested() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo::default().into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            handler
                .insert(
                    "cached-filter.example.",
                    RecordType::A,
                    vec![sample_a_record("cached-filter.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::OnlyIPv6,
                    None,
                    None,
                )
                .await;

            let result = handler.check_domain("cached-filter.example.", RecordType::A, true).await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert!(result.cache_records.as_ref().is_some_and(Vec::is_empty));
        });
    }

    #[test]
    fn check_domain_keeps_full_cached_records_without_filter_flag() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo::default().into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            handler
                .insert(
                    "cached-full.example.",
                    RecordType::A,
                    vec![sample_a_record("cached-full.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::OnlyIPv6,
                    None,
                    None,
                )
                .await;

            let result = handler.check_domain("cached-full.example.", RecordType::A, false).await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert_eq!(result.cache_records.as_ref().map(Vec::len), Some(1));
        });
    }

    #[test]
    fn check_domain_handles_overrideable_local_zones_before_upstream_rules() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![],
                }
                .into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            let result = handler.check_domain("printer.local.", RecordType::A, true).await;

            assert!(result.rule_id.is_none());
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn refresh_cache_entry_handles_local_zones_without_upstream_rule_refresh() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![],
                }
                .into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            let result = handler
                .refresh_cache_entry("foo.localhost.", RecordType::AAAA, true)
                .await
                .unwrap();

            assert!(result.rule_id.is_none());
            assert_eq!(result.records.as_ref().map(Vec::len), Some(1));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn test_negative_cache_ttl_updates_are_shared_across_clones() {
        run_async_test(async {
            let runtime_config = shared_cache_runtime_config(7);
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo::default().into(),
                runtime_config.clone(),
                9,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );
            let handler_clone = handler.clone();

            runtime_config.store(Arc::new(test_cache_runtime_config(33)));
            handler.renew_runtime_config(false).await;

            handler_clone
                .insert(
                    "negative-cache.example.",
                    RecordType::A,
                    vec![],
                    ResponseCode::NXDomain,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let cache_item = handler_clone
                .cache
                .load()
                .get(&("negative-cache.example.".to_string(), RecordType::A))
                .await
                .expect("cache item must exist");

            assert_eq!(cache_item.min_ttl, 33);
            assert_eq!(cache_item.response_code, ResponseCode::NXDomain);
            assert!(cache_item.rdatas.is_empty());
            assert_eq!(cache_item.mark.priority, 0);
        });
    }

    #[test]
    fn renew_redirect_rules_replaces_redirects_without_touching_resolves_or_cache() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![DNSRedirectRuntimeRule {
                        redirect_id: Some(Uuid::nil()),
                        dynamic_redirect_source: None,
                        answer_mode: DnsRedirectAnswerMode::StaticIps,
                        match_rules: vec![DomainConfig {
                            match_type: DomainMatchType::Full,
                            value: "old.example.com".to_string(),
                        }],
                        result_info: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                        ttl_secs: 17,
                    }],
                }
                .into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            let old_resolves = handler.resolves.load_full();
            let old_cache = handler.cache.load_full();
            let old_redirects = handler.redirect_solution.load_full();

            handler
                .renew_redirect_rules(vec![DNSRedirectRuntimeRule {
                    redirect_id: Some(Uuid::nil()),
                    dynamic_redirect_source: None,
                    answer_mode: DnsRedirectAnswerMode::StaticIps,
                    match_rules: vec![DomainConfig {
                        match_type: DomainMatchType::Full,
                        value: "new.example.com".to_string(),
                    }],
                    result_info: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
                    ttl_secs: 33,
                }
                .into()])
                .await;

            assert!(Arc::ptr_eq(&old_resolves, &handler.resolves.load_full()));
            assert!(Arc::ptr_eq(&old_cache, &handler.cache.load_full()));
            assert!(!Arc::ptr_eq(&old_redirects, &handler.redirect_solution.load_full()));
            assert!(handler.lookup_redirects("old.example.com.", RecordType::A).is_none());

            let (records, _, _, _) =
                handler.lookup_redirects("new.example.com.", RecordType::A).unwrap();
            assert_eq!(records[0].ttl, 33);
        });
    }

    #[test]
    fn renew_runtime_config_rebuilds_cache_without_reloading_rules_or_redirects() {
        run_async_test(async {
            let runtime_config = shared_cache_runtime_config(5);
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![DNSRedirectRuntimeRule {
                        redirect_id: Some(Uuid::nil()),
                        dynamic_redirect_source: None,
                        answer_mode: DnsRedirectAnswerMode::StaticIps,
                        match_rules: vec![DomainConfig {
                            match_type: DomainMatchType::Full,
                            value: "example.com".to_string(),
                        }],
                        result_info: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
                        ttl_secs: 17,
                    }],
                }
                .into(),
                runtime_config.clone(),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            handler
                .insert(
                    "cached.example.com.",
                    RecordType::A,
                    vec![sample_a_record("cached.example.com.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let old_resolves = handler.resolves.load_full();
            let old_cache = handler.cache.load_full();
            let old_redirects = handler.redirect_solution.load_full();

            runtime_config.store(Arc::new(CacheRuntimeConfig {
                cache_capacity: 16,
                cache_ttl: 120,
                negative_cache_ttl: 22,
            }));
            handler.renew_runtime_config(true).await;

            assert!(Arc::ptr_eq(&old_resolves, &handler.resolves.load_full()));
            assert!(!Arc::ptr_eq(&old_cache, &handler.cache.load_full()));
            assert!(Arc::ptr_eq(&old_redirects, &handler.redirect_solution.load_full()));
            assert_eq!(handler.runtime_config.load().negative_cache_ttl, 22);
            assert!(handler
                .cache
                .load()
                .get(&("cached.example.com.".to_string(), RecordType::A))
                .await
                .is_some());
        });
    }

    #[test]
    fn all_local_ips_redirect_uses_provider_records() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![],
                    redirect_rules: vec![DNSRedirectRuntimeRule {
                        redirect_id: Some(Uuid::nil()),
                        dynamic_redirect_source: None,
                        answer_mode: DnsRedirectAnswerMode::AllLocalIps,
                        match_rules: vec![DomainConfig {
                            match_type: DomainMatchType::Full,
                            value: "example.com".to_string(),
                        }],
                        result_info: vec![],
                        ttl_secs: 17,
                    }],
                }
                .into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                Some(Arc::new(MockLocalAnswerProvider {
                    addrs: vec![
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                        IpAddr::V6(Ipv6Addr::LOCALHOST),
                    ],
                })),
                None,
                None,
            );

            let (records, status, redirect_id, _) =
                handler.lookup_redirects("example.com.", RecordType::A).unwrap();

            assert_eq!(status, DnsResultStatus::Local);
            assert_eq!(redirect_id, Some(Uuid::nil()));
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].record_type(), RecordType::A);
            assert_eq!(records[0].ttl, 17);
            assert!(matches!(
                &records[0].data,
                RData::A(A(ip)) if *ip == Ipv4Addr::new(192, 168, 1, 1)
            ));
        });
    }

    #[test]
    fn all_local_ips_redirect_without_family_candidates_falls_through() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![],
                    redirect_rules: vec![DNSRedirectRuntimeRule {
                        redirect_id: Some(Uuid::nil()),
                        dynamic_redirect_source: None,
                        answer_mode: DnsRedirectAnswerMode::AllLocalIps,
                        match_rules: vec![DomainConfig {
                            match_type: DomainMatchType::Full,
                            value: "example.com".to_string(),
                        }],
                        result_info: vec![],
                        ttl_secs: 17,
                    }],
                }
                .into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                Some(Arc::new(MockLocalAnswerProvider {
                    addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                })),
                None,
                None,
            );

            assert!(handler.lookup_redirects("example.com.", RecordType::AAAA).is_none());
        });
    }

    #[test]
    fn static_redirect_without_matching_family_keeps_existing_no_record_behavior() {
        run_async_test(async {
            let handler = DnsRequestHandler::new(
                ChainDnsServerInitInfo {
                    dns_rules: vec![],
                    redirect_rules: vec![DNSRedirectRuntimeRule {
                        redirect_id: Some(Uuid::nil()),
                        dynamic_redirect_source: None,
                        answer_mode: DnsRedirectAnswerMode::StaticIps,
                        match_rules: vec![DomainConfig {
                            match_type: DomainMatchType::Full,
                            value: "example.com".to_string(),
                        }],
                        result_info: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                        ttl_secs: 17,
                    }],
                }
                .into(),
                shared_cache_runtime_config(5),
                1,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );

            let (records, status, redirect_id, _) =
                handler.lookup_redirects("example.com.", RecordType::AAAA).unwrap();

            assert!(records.is_empty());
            assert_eq!(status, DnsResultStatus::Local);
            assert_eq!(redirect_id, Some(Uuid::nil()));
        });
    }
}

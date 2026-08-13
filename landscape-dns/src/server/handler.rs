use std::{
    collections::HashSet,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
#[cfg(test)]
use arc_swap::ArcSwapOption;
use hickory_proto::{
    op::{Header, Metadata, OpCode, ResponseCode},
    rr::{
        rdata::{
            svcb::{SvcParamKey, SVCB},
            HTTPS,
        },
        DNSClass, RData, Record, RecordType,
    },
};
use hickory_server::{
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use moka::future::Cache;
use uuid::Uuid;

#[cfg(test)]
use crate::server::LocalDnsAnswerProvider;
use crate::{
    domain::ParsedDomain,
    server::{
        engine::{RedirectEngine, ResolveEngine},
        local::{LocalAnswer, LocalResolver},
        rule::DNSResolveRuntime,
        CacheRuntimeConfig, MetricSenderState,
    },
    CacheDNSItem, CheckChainDnsResult, DNSCache,
};
use landscape_common::{
    dns::error::DnsError,
    dns::rule::FilterResult,
    event::DnsMetricMessage,
    flow::{DnsRuntimeMarkInfo, FlowMarkInfo},
    metric::dns::{DnsMetric, DnsOutcome},
};
#[cfg(test)]
use landscape_core::lan_hostname::LanHostnameRegistry;
use landscape_core::time::get_current_time_ms;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const RULE_REFRESH_TTL_CAP: u32 = 5;

#[cfg(test)]
#[derive(Default, Debug)]
struct ChainDnsServerInitInfo {
    dns_rules: Vec<landscape_common::dns::rule::DNSRuntimeRule>,
    redirect_rules: Vec<landscape_common::dns::redirect::DNSRedirectRuntimeRule>,
}

#[derive(Debug)]
pub(crate) struct HandlerRuntime {
    pub redirect_engine: Arc<RedirectEngine>,
    pub resolve_engine: Arc<ResolveEngine>,
    pub cache: DNSCache,
}

/// Outcome of a matched rule's upstream lookup; the cache has already been
/// updated according to the write policy passed to
/// [`DnsRequestHandler::lookup_rule_and_cache`].
enum RuleLookupOutcome {
    /// Upstream answered (possibly an empty NOERROR answer).
    NoError { records: Vec<Record> },
    /// Upstream answered NXDOMAIN.
    NxDomain,
    /// Unrecoverable upstream failure (timeout, ServFail, ...).
    Failed,
}

#[derive(Clone)]
pub struct DnsRequestHandler {
    runtime: Arc<ArcSwap<HandlerRuntime>>,
    pub flow_id: u32,
    pub msg_tx: MetricSenderState,
    runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    local_resolver: Arc<LocalResolver>,
}

impl DnsRequestHandler {
    pub fn from_engines(
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        msg_tx: MetricSenderState,
        local_resolver: Arc<LocalResolver>,
    ) -> DnsRequestHandler {
        let cache_config = runtime_config.load();
        let cache = Self::build_cache(cache_config.as_ref());

        DnsRequestHandler {
            runtime: Arc::new(ArcSwap::from_pointee(HandlerRuntime {
                redirect_engine: Arc::new(redirect_engine),
                resolve_engine: Arc::new(resolve_engine),
                cache,
            })),
            flow_id,
            msg_tx,
            runtime_config,
            local_resolver,
        }
    }

    #[cfg(test)]
    fn new(
        init: ChainDnsServerInitInfo,
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        msg_tx: MetricSenderState,
        local_resolver: Arc<LocalResolver>,
    ) -> Self {
        let (redirect_engine, resolve_engine) = Self::test_engines_from_legacy(init);
        Self::from_engines(
            redirect_engine,
            resolve_engine,
            runtime_config,
            flow_id,
            msg_tx,
            local_resolver,
        )
    }

    #[cfg(test)]
    fn test_engines_from_legacy(init: ChainDnsServerInitInfo) -> (RedirectEngine, ResolveEngine) {
        use std::collections::BTreeMap;

        use crate::server::{
            matcher::RuntimeRuleMatcher,
            rule::{DNSRedirectRuntime, DNSResolveRuntime},
        };

        let redirects = init
            .redirect_rules
            .into_iter()
            .map(|rule| {
                DNSRedirectRuntime::new(
                    rule.redirect_id,
                    rule.dynamic_redirect_source,
                    rule.answer_mode,
                    RuntimeRuleMatcher::new(rule.match_rules, vec![], vec![], false),
                    rule.result_info,
                    rule.ttl_secs,
                )
            })
            .collect();
        let resolves = init
            .dns_rules
            .into_iter()
            .filter_map(|rule| {
                let order = rule.index;
                let match_all = rule.source.is_empty();
                let runtime = DNSResolveRuntime::new(
                    rule.id,
                    rule.index,
                    rule.filter,
                    rule.bind_config,
                    rule.mark,
                    rule.resolve_mode,
                    RuntimeRuleMatcher::new(rule.source, vec![], vec![], match_all),
                    rule.flow_id,
                )?;
                Some((order, runtime))
            })
            .collect::<BTreeMap<_, _>>();

        (RedirectEngine::new(redirects), ResolveEngine::new(resolves))
    }

    pub async fn renew_engines(
        &self,
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
    ) {
        self.swap_runtime(
            Arc::new(redirect_engine),
            Arc::new(resolve_engine),
            Some(RULE_REFRESH_TTL_CAP),
        )
        .await;
    }

    pub async fn renew_dns_rules(&self, resolve_engine: ResolveEngine) {
        let runtime = self.runtime.load_full();
        self.swap_runtime(
            runtime.redirect_engine.clone(),
            Arc::new(resolve_engine),
            Some(RULE_REFRESH_TTL_CAP),
        )
        .await;
    }

    pub async fn renew_redirect_rules(&self, redirect_engine: RedirectEngine) {
        let runtime = self.runtime.load_full();
        let new_cache = self.remove_redirected_cache(&runtime.cache, &redirect_engine).await;
        self.refresh_runtime_maps_from_cache(&new_cache);
        self.runtime.store(Arc::new(HandlerRuntime {
            redirect_engine: Arc::new(redirect_engine),
            resolve_engine: runtime.resolve_engine.clone(),
            cache: new_cache,
        }));
    }

    /// Rebuilds the cache, migrates surviving entries, publishes the new
    /// runtime snapshot and refreshes the eBPF mark/route maps.
    async fn swap_runtime(
        &self,
        redirect_engine: Arc<RedirectEngine>,
        resolve_engine: Arc<ResolveEngine>,
        ttl_cap: Option<u32>,
    ) {
        let (new_cache, update_dns_mark_list) =
            self.rebuild_cache(&redirect_engine, &resolve_engine, ttl_cap).await;

        tracing::debug!("add_dns_marks: {:?}", update_dns_mark_list);
        self.refresh_flow_dns_map(update_dns_mark_list);
        self.runtime.store(Arc::new(HandlerRuntime {
            redirect_engine,
            resolve_engine,
            cache: new_cache,
        }));
        Self::recreate_route_cache();
    }

    pub async fn renew_runtime_config(&self, rebuild_cache: bool) {
        if rebuild_cache {
            let runtime = self.runtime.load_full();
            self.swap_runtime(
                runtime.redirect_engine.clone(),
                runtime.resolve_engine.clone(),
                None,
            )
            .await;
        }
    }

    async fn rebuild_cache(
        &self,
        redirects: &RedirectEngine,
        resolves: &ResolveEngine,
        ttl_cap: Option<u32>,
    ) -> (DNSCache, HashSet<FlowMarkInfo>) {
        let new_cache = self.build_runtime_cache();
        self.migrate_cache(&new_cache, redirects, resolves, ttl_cap).await;
        new_cache.run_pending_tasks().await;
        let update_dns_mark_list = Self::cache_dns_mark_list(&new_cache);
        (new_cache, update_dns_mark_list)
    }

    async fn remove_redirected_cache(
        &self,
        current_cache: &DNSCache,
        redirects: &RedirectEngine,
    ) -> DNSCache {
        let new_cache = self.build_runtime_cache();
        for (key, value) in current_cache.iter() {
            let (domain, req_type) = &*key;
            let Ok(pd) = ParsedDomain::new(domain) else { continue };
            if redirects
                .lookup(&pd, *req_type, self.local_resolver.local_answer_provider())
                .is_none()
            {
                new_cache.insert((domain.clone(), *req_type), value).await;
            }
        }
        new_cache.run_pending_tasks().await;
        new_cache
    }

    async fn migrate_cache(
        &self,
        new_cache: &DNSCache,
        redirects: &RedirectEngine,
        resolves: &ResolveEngine,
        ttl_cap: Option<u32>,
    ) {
        let current_runtime = self.runtime.load();
        let current_cache = &current_runtime.cache;

        for (key, value) in current_cache.iter() {
            let (domain, req_type) = &*key;
            let Ok(pd) = ParsedDomain::new(domain) else { continue };
            let cache_item = value;
            if redirects
                .lookup(&pd, *req_type, self.local_resolver.local_answer_provider())
                .is_some()
            {
                continue;
            }
            if let Some(resolver) = Self::find_cache_rule(resolves, &pd, &cache_item) {
                let new_mark = resolver.mark().clone();

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

                new_cache.insert((domain.clone(), *req_type), Arc::new(new_item)).await;
            }
        }
    }

    fn find_cache_rule<'a>(
        resolves: &'a ResolveEngine,
        domain: &ParsedDomain,
        cache_item: &CacheDNSItem,
    ) -> Option<&'a crate::server::rule::DNSResolveRuntime> {
        if let Some(rule_order) = cache_item.matched_rule_order {
            if let Some(resolver) = resolves.get(rule_order) {
                if cache_item.matched_rule_id == Some(resolver.get_config_id())
                    && resolver.is_match(domain)
                {
                    return Some(resolver);
                }
            }
        }

        resolves.find_match(domain)
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

    fn refresh_flow_dns_map(&self, update_dns_mark_list: HashSet<FlowMarkInfo>) {
        #[cfg(test)]
        {
            let _ = update_dns_mark_list;
            return;
        }

        #[cfg(not(test))]
        landscape_ebpf::map_setting::flow_dns::refreash_flow_dns_inner_map(
            self.flow_id,
            update_dns_mark_list.into_iter().collect(),
        );
    }

    fn recreate_route_cache() {
        #[cfg(not(test))]
        landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    }

    pub fn lookup_redirects(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, DnsOutcome, Option<Uuid>, Option<String>)> {
        let runtime = self.runtime.load();
        self.lookup_redirects_with_runtime(&runtime, domain, query_type)
    }

    fn lookup_redirects_with_runtime(
        &self,
        runtime: &HandlerRuntime,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, DnsOutcome, Option<Uuid>, Option<String>)> {
        runtime.redirect_engine.lookup(
            domain,
            query_type,
            self.local_resolver.local_answer_provider(),
        )
    }

    /// The full resolution chain: (1) redirect → (2) local classification →
    /// (3) cache/upstream. One shared path for live queries, so tests drive
    /// the exact composition the server uses.
    async fn resolve_query(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> (Vec<Record>, DnsOutcome) {
        let runtime = self.runtime.load_full();

        // (1) Redirect (global check first)
        if let Some((records, status, _, _)) =
            self.lookup_redirects_with_runtime(&runtime, domain, query_type)
        {
            return (records, status);
        }

        // (2) Local classification (blocked TLDs, localhost, local zone,
        // `.arpa`). `None` means the resolver does not own the query and it
        // must continue to (3) Cache → (4) Upstream.
        match self.local_resolver.resolve_local(domain, query_type) {
            Some(LocalAnswer::Answered { records, outcome }) => (records, outcome),
            Some(LocalAnswer::Empty { outcome }) => (vec![], outcome),
            None => self.resolve_from_cache_or_upstream(&runtime, domain, query_type).await,
        }
    }

    async fn resolve_from_cache_or_upstream(
        &self,
        runtime: &HandlerRuntime,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> (Vec<Record>, DnsOutcome) {
        if let Some((cached_records, filter, code)) =
            Self::lookup_cache_in(&runtime.cache, domain, query_type).await
        {
            if is_type_filtered(query_type, &filter) {
                let outcome = if code == ResponseCode::NXDomain {
                    DnsOutcome::NxDomain
                } else {
                    DnsOutcome::Filter
                };
                return (vec![], outcome);
            }
            let outcome =
                if code == ResponseCode::NXDomain { DnsOutcome::NxDomain } else { DnsOutcome::Hit };
            return (filter_result(cached_records, &filter), outcome);
        }

        if let Some(resolver) = runtime.resolve_engine.find_match(domain) {
            let filter = resolver.filter_mode();
            if is_type_filtered(query_type, &filter) {
                return (vec![], DnsOutcome::Filter);
            }

            match self
                .lookup_rule_and_cache(&runtime.cache, resolver, domain, query_type, false, true)
                .await
            {
                RuleLookupOutcome::NoError { records } => {
                    return (filter_result(records, &filter), DnsOutcome::Normal);
                }
                RuleLookupOutcome::NxDomain => {
                    return (vec![], DnsOutcome::NxDomain);
                }
                RuleLookupOutcome::Failed => {
                    return (vec![], DnsOutcome::Error);
                }
            }
        }
        (vec![], DnsOutcome::Normal)
    }

    /// Runs a matched rule's upstream lookup under the shared timeout and
    /// persists the result to the cache when `write_cache` is set: filtered
    /// queries clear any stale entry, positive answers are cached with
    /// `NoError`, and negative answers (`NXDomain`/empty `NoError`) are
    /// cached as such. Non-representable failures (timeout, `ServFail`, ...)
    /// leave the cache untouched and are returned as `Failed`.
    async fn lookup_rule_and_cache(
        &self,
        cache: &DNSCache,
        resolver: &DNSResolveRuntime,
        domain: &ParsedDomain,
        query_type: RecordType,
        query_filtered: bool,
        write_cache: bool,
    ) -> RuleLookupOutcome {
        let filter = resolver.filter_mode();
        match with_lookup_timeout(resolver.lookup(domain.raw(), query_type), LOOKUP_TIMEOUT).await {
            Ok(rdata_vec) => {
                if write_cache {
                    if query_filtered {
                        Self::clear_cache_entry_in(cache, domain, query_type).await;
                    } else {
                        self.insert_into_cache(
                            cache,
                            domain.raw_arc(),
                            query_type,
                            rdata_vec.clone(),
                            ResponseCode::NoError,
                            resolver.mark(),
                            filter,
                            Some(resolver.get_config_id()),
                            Some(resolver.order()),
                        )
                        .await;
                    }
                }
                RuleLookupOutcome::NoError { records: rdata_vec }
            }
            Err(err) => {
                let code = err.to_response_code();
                let outcome = match code {
                    ResponseCode::NXDomain => RuleLookupOutcome::NxDomain,
                    ResponseCode::NoError => RuleLookupOutcome::NoError { records: vec![] },
                    _ => RuleLookupOutcome::Failed,
                };
                if write_cache {
                    if query_filtered {
                        Self::clear_cache_entry_in(cache, domain, query_type).await;
                    } else if matches!(outcome, RuleLookupOutcome::NxDomain) {
                        self.insert_into_cache(
                            cache,
                            domain.raw_arc(),
                            query_type,
                            vec![],
                            code,
                            resolver.mark(),
                            filter,
                            Some(resolver.get_config_id()),
                            Some(resolver.order()),
                        )
                        .await;
                    } else if let RuleLookupOutcome::NoError { records } = &outcome {
                        self.insert_into_cache(
                            cache,
                            domain.raw_arc(),
                            query_type,
                            records.clone(),
                            code,
                            resolver.mark(),
                            filter,
                            Some(resolver.get_config_id()),
                            Some(resolver.order()),
                        )
                        .await;
                    }
                }
                outcome
            }
        }
    }

    pub async fn check_domain(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) -> CheckChainDnsResult {
        let runtime = self.runtime.load_full();
        let mut result = CheckChainDnsResult::default();

        // (1) Redirect
        if let Some((records, _status, id, dynamic_source)) =
            self.lookup_redirects_with_runtime(&runtime, domain, query_type)
        {
            result.redirect_id = id;
            result.dynamic_redirect_source = dynamic_source;
            result.records = Some(crate::to_common_records(records));
        } else if let Some(answer) = self.local_resolver.resolve_local(domain, query_type) {
            // (2) Local classification
            if let LocalAnswer::Answered { records, .. } = answer {
                result.records = Some(crate::to_common_records(records));
            }
            return result;
        } else if let Some(resolver) = runtime.resolve_engine.find_match(domain) {
            // (3) Rules (read-only; the cache report below shows what a client
            // would currently see)
            result.rule_id = Some(resolver.get_config_id());
            let filter = resolver.filter_mode();
            result.rule_filter = Some(filter.clone());

            result.query_filtered = is_type_filtered(query_type, &filter);
            if result.query_filtered && apply_filter {
                result.records = Some(vec![]);
            } else {
                // Read-only: no cache writes here, the cache report below
                // shows what a client would currently see.
                if let RuleLookupOutcome::NoError { records } = self
                    .lookup_rule_and_cache(
                        &runtime.cache,
                        resolver,
                        domain,
                        query_type,
                        result.query_filtered,
                        false,
                    )
                    .await
                {
                    result.records = Some(crate::to_common_records(if apply_filter {
                        filter_result(records, &filter)
                    } else {
                        records
                    }));
                }
            }
        }

        // (4) Cache report
        Self::fill_cache_records(&mut result, &runtime.cache, domain, query_type, apply_filter)
            .await;

        result
    }

    pub async fn invalidate_cache_entry(&self, domain: &ParsedDomain, query_type: RecordType) {
        let runtime = self.runtime.load_full();
        Self::clear_cache_entry_in(&runtime.cache, domain, query_type).await;
        self.refresh_runtime_maps_from_cache(&runtime.cache);
    }

    pub async fn refresh_cache_entry(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) -> Result<CheckChainDnsResult, DnsError> {
        let runtime = self.runtime.load_full();

        // (1) Redirect
        if self.lookup_redirects_with_runtime(&runtime, domain, query_type).is_some() {
            return Err(DnsError::RefreshRedirected(domain.raw().to_string()));
        }

        // (2) Local classification. Local answers never enter the cache, but
        // any stale entry is cleared first (an entry can only exist if an
        // earlier config let this name reach the cache/upstream stage).
        if let Some(answer) = self.local_resolver.resolve_local(domain, query_type) {
            self.clear_cache_entry_and_refresh_maps_if_present(&runtime.cache, domain, query_type)
                .await;
            return Ok(match answer {
                LocalAnswer::Answered { records, .. } => CheckChainDnsResult {
                    records: Some(crate::to_common_records(records)),
                    ..Default::default()
                },
                LocalAnswer::Empty { .. } => CheckChainDnsResult::default(),
            });
        }

        // (2b) Non-local `.arpa` names (public reverse lookups, e.g.
        // `8.8.8.8.in-addr.arpa.`): the resolver is only a recursive
        // forwarder here, exactly like the live path. Clear any stale entry
        // first so the cache converges with what clients see, then resolve
        // through the rules engine. Without a matching rule the live path
        // answers NOERROR/empty, so refresh must return Ok as well, not
        // `RefreshRequiresRule`.
        if domain.name().ends_with(".arpa") {
            self.clear_cache_entry_and_refresh_maps_if_present(&runtime.cache, domain, query_type)
                .await;
            let (records, _) =
                self.resolve_from_cache_or_upstream(&runtime, domain, query_type).await;
            return Ok(CheckChainDnsResult {
                records: Some(crate::to_common_records(records)),
                ..Default::default()
            });
        }

        let Some(resolver) = runtime.resolve_engine.find_match(domain) else {
            return Err(DnsError::RefreshRequiresRule(domain.raw().to_string()));
        };

        let filter = resolver.filter_mode();
        let query_filtered = is_type_filtered(query_type, &filter);
        let mut result = CheckChainDnsResult {
            rule_id: Some(resolver.get_config_id()),
            rule_filter: Some(filter.clone()),
            query_filtered,
            ..Default::default()
        };

        match self
            .lookup_rule_and_cache(
                &runtime.cache,
                resolver,
                domain,
                query_type,
                query_filtered,
                true,
            )
            .await
        {
            RuleLookupOutcome::NoError { records } => {
                result.records = Some(if apply_filter {
                    crate::to_common_records(filter_result(records, &filter))
                } else {
                    crate::to_common_records(records)
                });
            }
            RuleLookupOutcome::NxDomain => {
                result.records = Some(vec![]);
            }
            RuleLookupOutcome::Failed => {
                // Filtered queries are served an empty answer, so a
                // failure is not an error here; anything else cannot be
                // resolved at all.
                result.records = Some(vec![]);
                if !query_filtered {
                    return Err(DnsError::RefreshFailed(domain.raw().to_string()));
                }
            }
        }

        self.refresh_runtime_maps_from_cache(&runtime.cache);

        Self::fill_cache_records(&mut result, &runtime.cache, domain, query_type, apply_filter)
            .await;

        Ok(result)
    }

    /// Shared cache report for check/refresh: projects the current cache entry
    /// into `cache_records` and merges its filter state into the result.
    async fn fill_cache_records(
        result: &mut CheckChainDnsResult,
        cache: &DNSCache,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) {
        if let Some((records, filter, _)) = Self::lookup_cache_in(cache, domain, query_type).await {
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
    }

    async fn clear_cache_entry_in(cache: &DNSCache, domain: &ParsedDomain, query_type: RecordType) {
        cache.invalidate(&(domain.raw_arc().clone(), query_type)).await;
    }

    async fn clear_cache_entry_if_present(
        cache: &DNSCache,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> bool {
        let key = (domain.raw_arc().clone(), query_type);
        if cache.get(&key).await.is_none() {
            return false;
        }

        cache.invalidate(&key).await;
        true
    }

    async fn clear_cache_entry_and_refresh_maps_if_present(
        &self,
        cache: &DNSCache,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) {
        if Self::clear_cache_entry_if_present(cache, domain, query_type).await {
            self.refresh_runtime_maps_from_cache(cache);
        }
    }

    fn refresh_runtime_maps_from_cache(&self, cache: &DNSCache) {
        self.refresh_flow_dns_map(Self::cache_dns_mark_list(cache));
        Self::recreate_route_cache();
    }

    fn cache_dns_mark_list(cache: &DNSCache) -> HashSet<FlowMarkInfo> {
        let mut update_dns_mark_list = HashSet::new();
        for (_key, value) in cache.iter() {
            update_dns_mark_list.extend(value.get_update_rules());
        }
        update_dns_mark_list
    }

    // check the cache and whether it has expired based on TTL
    // different record types may have different expiry times
    async fn lookup_cache_in(
        cache: &DNSCache,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, FilterResult, ResponseCode)> {
        let key = (domain.raw_arc().clone(), query_type);
        if let Some(cache_item) = cache.get(&key).await {
            let CacheDNSItem {
                rdatas,
                response_code,
                insert_time,
                min_ttl,
                filter,
                ..
            } = &*cache_item;

            // 1. check expiry
            let insert_time_elapsed = insert_time.elapsed().as_secs() as u32;
            if insert_time_elapsed > *min_ttl {
                // expired: proactively evict the entry (lazy expiration)
                cache.invalidate(&key).await;
                return None;
            }

            // 2. build valid records (TTL decremented)
            // if rdatas is empty (negative cache), valid_records stays empty too
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

    #[cfg(test)]
    async fn insert(
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
        let runtime = self.runtime.load_full();
        let domain_key = Arc::<str>::from(domain);
        self.insert_into_cache(
            &runtime.cache,
            &domain_key,
            query_type,
            rdata_ttl_vec,
            response_code,
            mark,
            filter,
            matched_rule_id,
            matched_rule_order,
        )
        .await;
    }

    async fn insert_into_cache(
        &self,
        cache: &DNSCache,
        domain_key: &Arc<str>,
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

        cache.insert((domain_key.clone(), query_type), Arc::new(cache_item)).await;

        // write the mark into the mark eBPF map
        if mark.mark.need_insert_in_ebpf_map() {
            // tracing::info!(
            //     "[flow_id: {}]setting ips: {:?}, Mark: {:?}",
            //     self.flow_id,
            //     update_dns_mark_list,
            //     mark
            // );
            // TODO: if the write fails, return an error and respond to the client with a query error
            #[cfg(not(test))]
            landscape_ebpf::map_setting::flow_dns::update_flow_dns_rule(
                self.flow_id,
                update_dns_mark_list.into_iter().collect(),
            );
            #[cfg(test)]
            let _ = update_dns_mark_list;
        }
    }

    fn send_metric(
        &self,
        domain: &str,
        query_type: RecordType,
        outcome: DnsOutcome,
        start_time: Instant,
        src_ip: std::net::IpAddr,
        answers: Vec<String>,
    ) {
        if let Some(msg_tx) = self.msg_tx.load_full() {
            let response_code = outcome_to_response_code(outcome);
            let dns_metric = DnsMetric {
                flow_id: self.flow_id,
                domain: domain.to_string(),
                query_type: query_type.to_string(),
                response_code: response_code.to_string(),
                status: outcome,
                report_time: get_current_time_ms().unwrap_or_default(),
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
        if queries.len() != 1 {
            return self.send_error_response(request, response_handle, ResponseCode::FormErr).await;
        }

        let req = &queries[0];
        let query_type = req.query_type();
        let src_ip = request.src().ip();

        // Validation
        if request.metadata.op_code != OpCode::Query {
            return self.send_error_response(request, response_handle, ResponseCode::NotImp).await;
        }
        if req.query_class() != DNSClass::IN {
            return self.send_error_response(request, response_handle, ResponseCode::Refused).await;
        }
        match query_type {
            RecordType::ANY | RecordType::AXFR | RecordType::IXFR => {
                return self
                    .send_error_response(request, response_handle, ResponseCode::Refused)
                    .await;
            }
            RecordType::OPT | RecordType::ZERO => {
                return self
                    .send_error_response(request, response_handle, ResponseCode::FormErr)
                    .await;
            }
            RecordType::TSIG | RecordType::Unknown(249) => {
                return self
                    .send_error_response(request, response_handle, ResponseCode::NotImp)
                    .await;
            }
            _ => {}
        }

        // Dispatch
        let pd = match ParsedDomain::new(&req.name().to_string()) {
            Ok(pd) => pd,
            Err(_) => {
                return self
                    .send_error_response(request, response_handle, ResponseCode::FormErr)
                    .await;
            }
        };
        let (records, outcome) = self.resolve_query(&pd, query_type).await;

        // Build response
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = outcome_to_response_code(outcome);
        metadata.authoritative = true;
        metadata.recursion_available = true;

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
        let answers = if self.msg_tx.load_full().is_some() {
            records.iter().map(|r| r.to_string()).collect()
        } else {
            vec![]
        };
        self.send_metric(pd.raw(), query_type, outcome, start_time, src_ip, answers);

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

fn outcome_to_response_code(outcome: DnsOutcome) -> ResponseCode {
    match outcome {
        DnsOutcome::NxDomain => ResponseCode::NXDomain,
        DnsOutcome::Error => ResponseCode::ServFail,
        _ => ResponseCode::NoError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record, RecordType};
    use landscape_common::{
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

    fn make_test_handler(
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules }.into(),
            shared_cache_runtime_config(5),
            1,
            Arc::new(ArcSwapOption::new(None)),
            test_local_resolver(test_lan_hostname_registry()),
        )
    }

    fn test_handler_with_local(
        registry: Arc<LanHostnameRegistry>,
        provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules }.into(),
            shared_cache_runtime_config(5),
            1,
            Arc::new(ArcSwapOption::new(None)),
            Arc::new(LocalResolver::new(registry, provider, None, None)),
        )
    }

    fn test_handler_with_config(
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules }.into(),
            runtime_config,
            flow_id,
            Arc::new(ArcSwapOption::new(None)),
            test_local_resolver(test_lan_hostname_registry()),
        )
    }

    fn test_local_resolver(registry: Arc<LanHostnameRegistry>) -> Arc<LocalResolver> {
        Arc::new(LocalResolver::new(registry, None, None, None))
    }

    fn test_lan_hostname_registry() -> Arc<LanHostnameRegistry> {
        LanHostnameRegistry::new_for_test(
            landscape_common::sys_service::lan_hostname::LanHostnameConfig::default(),
        )
    }

    fn test_runtime_rule() -> DNSRuntimeRule {
        DNSRuntimeRule {
            resolve_mode: DnsUpstreamConfig::default(),
            ..DNSRuntimeRule::default()
        }
    }

    fn test_dns_rule(filter: FilterResult, sources: &[&str]) -> DNSRuntimeRule {
        DNSRuntimeRule {
            filter,
            source: sources
                .iter()
                .map(|value| DomainConfig {
                    match_type: DomainMatchType::Full,
                    value: value.to_string(),
                })
                .collect(),
            ..test_runtime_rule()
        }
    }

    fn test_static_redirect_rule(
        domain: &str,
        ips: Vec<IpAddr>,
        ttl_secs: u32,
    ) -> DNSRedirectRuntimeRule {
        DNSRedirectRuntimeRule {
            redirect_id: Some(Uuid::nil()),
            dynamic_redirect_source: None,
            answer_mode: DnsRedirectAnswerMode::StaticIps,
            match_rules: vec![DomainConfig {
                match_type: DomainMatchType::Full,
                value: domain.to_string(),
            }],
            result_info: ips,
            ttl_secs,
        }
    }

    fn test_all_local_ips_redirect_rule(domain: &str, ttl_secs: u32) -> DNSRedirectRuntimeRule {
        DNSRedirectRuntimeRule {
            answer_mode: DnsRedirectAnswerMode::AllLocalIps,
            ..test_static_redirect_rule(domain, vec![], ttl_secs)
        }
    }

    fn sample_a_record(name: &str, ttl: u32, addr: Ipv4Addr) -> Record {
        Record::from_rdata(hickory_proto::rr::Name::from_str(name).unwrap(), ttl, RData::A(A(addr)))
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
    fn resolve_arpa_dispatches_by_second_level_label() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            // resolver.arpa. → resolver branch
            let (records, outcome) = handler
                .resolve_query(&ParsedDomain::new("resolver.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Local);

            // home.arpa. is not the default `lan` zone.
            let (records, outcome) = handler
                .resolve_query(&ParsedDomain::new("home.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);

            // in-addr.arpa. → reverse branch
            let (records, _outcome) = handler
                .resolve_query(
                    &ParsedDomain::new("1.0.0.10.in-addr.arpa.").unwrap(),
                    RecordType::PTR,
                )
                .await;
            assert!(records.is_empty());

            // ip6.arpa. → reverse branch
            let (records, _outcome) = handler
                .resolve_query(
                    &ParsedDomain::new(
                        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
                    )
                    .unwrap(),
                    RecordType::PTR,
                )
                .await;
            assert!(records.is_empty());

            // evilresolver.arpa. is not resolver → NXDOMAIN
            let (records, outcome) = handler
                .resolve_query(&ParsedDomain::new("evilresolver.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::NxDomain);
        });
    }

    #[test]
    fn disabled_lan_hostname_registry_does_not_own_private_ptr_queries() {
        run_async_test(async {
            let registry = LanHostnameRegistry::new_for_test(
                landscape_common::sys_service::lan_hostname::LanHostnameConfig {
                    enable: false,
                    lan_suffix: "lan".to_string(),
                },
            );
            let handler = test_handler_with_local(registry, None, vec![], vec![]);
            let domain = ParsedDomain::new("50.1.168.192.in-addr.arpa.").unwrap();

            // A disabled registry does not own private PTR queries: they fall
            // through to the cache/upstream stage (no rules → NOERROR/empty).
            let (records, outcome) = handler.resolve_query(&domain, RecordType::PTR).await;
            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Normal);

            let loopback_domain = ParsedDomain::new("1.0.0.127.in-addr.arpa.").unwrap();
            let (records, outcome) = handler.resolve_query(&loopback_domain, RecordType::PTR).await;
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(records.len(), 1);
        });
    }

    #[test]
    fn test_with_lookup_timeout_maps_timeout_and_passes_through_inner_result() {
        run_async_test(async {
            let timeout = with_lookup_timeout(
                async {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok::<_, crate::error::DnsError>(vec![1_u8])
                },
                Duration::from_millis(5),
            )
            .await;
            assert!(matches!(timeout, Err(crate::error::DnsError::Timeout)));

            let inner = with_lookup_timeout(
                async { Ok::<_, crate::error::DnsError>(vec![1_u8, 2_u8]) },
                Duration::from_millis(50),
            )
            .await;
            assert_eq!(inner.unwrap(), vec![1_u8, 2_u8]);
        });
    }

    #[test]
    fn check_domain_applies_filter_when_requested() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_dns_rule(FilterResult::OnlyIPv6, &["example.com"])],
                vec![],
            );

            let result = handler
                .check_domain(&ParsedDomain::new("example.com.").unwrap(), RecordType::A, true)
                .await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn check_domain_filters_cached_records_when_requested() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

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

            let result = handler
                .check_domain(
                    &ParsedDomain::new("cached-filter.example.").unwrap(),
                    RecordType::A,
                    true,
                )
                .await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert!(result.cache_records.as_ref().is_some_and(Vec::is_empty));
        });
    }

    #[test]
    fn check_domain_keeps_full_cached_records_without_filter_flag() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

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

            let result = handler
                .check_domain(
                    &ParsedDomain::new("cached-full.example.").unwrap(),
                    RecordType::A,
                    false,
                )
                .await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert_eq!(result.cache_records.as_ref().map(Vec::len), Some(1));
        });
    }

    #[test]
    fn check_domain_handles_local_tld_before_upstream_rules() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);

            let result = handler
                .check_domain(&ParsedDomain::new("printer.local.").unwrap(), RecordType::A, true)
                .await;

            assert!(result.rule_id.is_none());
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn refresh_cache_entry_handles_local_zones_without_upstream_rule_refresh() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);

            let result = handler
                .refresh_cache_entry(
                    &ParsedDomain::new("foo.localhost.").unwrap(),
                    RecordType::AAAA,
                    true,
                )
                .await
                .unwrap();

            assert!(result.rule_id.is_none());
            assert_eq!(result.records.as_ref().map(Vec::len), Some(1));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn refresh_cache_entry_clears_stale_unowned_arpa_entry() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            let domain = "8.8.8.8.in-addr.arpa.";
            handler
                .insert(
                    domain,
                    RecordType::PTR,
                    vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            // Public reverse names are not owned locally: without a rule the
            // live path answers NOERROR/empty, so refresh must return Ok and
            // drop the stale entry instead of failing with RefreshRequiresRule.
            let result = handler
                .refresh_cache_entry(&ParsedDomain::new(domain).unwrap(), RecordType::PTR, true)
                .await
                .unwrap();

            assert!(result.records.as_ref().is_some_and(Vec::is_empty));

            let runtime = handler.runtime.load_full();
            assert!(
                DnsRequestHandler::lookup_cache_in(
                    &runtime.cache,
                    &ParsedDomain::new(domain).unwrap(),
                    RecordType::PTR,
                )
                .await
                .is_none(),
                "stale reverse entry must be cleared"
            );
        });
    }

    #[test]
    fn refresh_cache_entry_arpa_with_matching_rule_clears_cache() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_dns_rule(FilterResult::OnlyIPv6, &["8.8.8.8.in-addr.arpa"])],
                vec![],
            );

            let domain = "8.8.8.8.in-addr.arpa.";
            handler
                .insert(
                    domain,
                    RecordType::A,
                    vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let result = handler
                .refresh_cache_entry(&ParsedDomain::new(domain).unwrap(), RecordType::A, true)
                .await
                .unwrap();

            // The OnlyIPv6 rule filters the A query, so no upstream lookup is
            // attempted and the result is empty — but the stale entry must be
            // gone so the cache converges with what clients see.
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));

            let runtime = handler.runtime.load_full();
            assert!(
                DnsRequestHandler::lookup_cache_in(
                    &runtime.cache,
                    &ParsedDomain::new(domain).unwrap(),
                    RecordType::A,
                )
                .await
                .is_none(),
                "stale reverse entry must be cleared"
            );
        });
    }

    #[test]
    fn check_domain_reports_only_cache_for_unowned_arpa() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            let domain = "8.8.8.8.in-addr.arpa.";
            handler
                .insert(
                    domain,
                    RecordType::PTR,
                    vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let result = handler
                .check_domain(&ParsedDomain::new(domain).unwrap(), RecordType::PTR, true)
                .await;

            // Check is read-only: unowned reverse names are not resolved
            // live, only projected from the cache.
            assert!(result.records.is_none());
            assert_eq!(result.cache_records.as_ref().map(Vec::len), Some(1));
        });
    }

    #[test]
    fn test_negative_cache_ttl_updates_are_shared_across_clones() {
        run_async_test(async {
            let runtime_config = shared_cache_runtime_config(7);
            let handler = test_handler_with_config(runtime_config.clone(), 9, vec![], vec![]);
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

            let runtime = handler_clone.runtime.load_full();
            let cache_item = runtime
                .cache
                .get(&(Arc::from("negative-cache.example."), RecordType::A))
                .await
                .expect("cache item must exist");

            assert_eq!(cache_item.min_ttl, 33);
            assert_eq!(cache_item.response_code, ResponseCode::NXDomain);
            assert!(cache_item.rdatas.is_empty());
            assert_eq!(cache_item.mark.priority, 0);
        });
    }

    #[test]
    fn renew_engines_publishes_one_new_runtime_snapshot() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_runtime_rule()],
                vec![test_static_redirect_rule(
                    "old.example.com",
                    vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                    17,
                )],
            );

            let old_runtime = handler.runtime.load_full();

            let (redirect_engine, resolve_engine) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![test_static_redirect_rule(
                        "new.example.com",
                        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
                        33,
                    )],
                });
            handler.renew_engines(redirect_engine, resolve_engine).await;

            let new_runtime = handler.runtime.load_full();
            assert!(!Arc::ptr_eq(&old_runtime, &new_runtime));
            assert!(!Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert!(!Arc::ptr_eq(&old_runtime.redirect_engine, &new_runtime.redirect_engine));
            assert!(handler
                .lookup_redirects(&ParsedDomain::new("old.example.com.").unwrap(), RecordType::A)
                .is_none());

            let (records, _, _, _) = handler
                .lookup_redirects(&ParsedDomain::new("new.example.com.").unwrap(), RecordType::A)
                .unwrap();
            assert_eq!(records[0].ttl, 33);
        });
    }

    #[test]
    fn renew_engines_drops_cache_entries_taken_over_by_redirects() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);
            handler
                .insert(
                    "redirected.example.",
                    RecordType::A,
                    vec![sample_a_record("redirected.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    Some(test_runtime_rule().id),
                    Some(test_runtime_rule().index),
                )
                .await;

            let (redirect_engine, resolve_engine) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![test_static_redirect_rule(
                        "redirected.example",
                        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                        30,
                    )],
                });

            handler.renew_engines(redirect_engine, resolve_engine).await;

            assert!(handler
                .runtime
                .load_full()
                .cache
                .get(&(Arc::from("redirected.example."), RecordType::A))
                .await
                .is_none());
        });
    }

    #[test]
    fn renew_dns_rules_preserves_redirects_and_caps_migrated_cache_ttl() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_runtime_rule()],
                vec![test_static_redirect_rule(
                    "redirect.example",
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                    30,
                )],
            );
            let rule = test_runtime_rule();
            handler
                .insert(
                    "cached.example.",
                    RecordType::A,
                    vec![sample_a_record("cached.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    Some(rule.id),
                    Some(rule.index),
                )
                .await;
            handler
                .insert(
                    "short.example.",
                    RecordType::A,
                    vec![sample_a_record("short.example.", 3, Ipv4Addr::new(1, 0, 0, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    Some(rule.id),
                    Some(rule.index),
                )
                .await;

            let old_runtime = handler.runtime.load_full();
            let (_, resolve_engine) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![rule],
                    redirect_rules: vec![],
                });
            handler.renew_dns_rules(resolve_engine).await;

            let new_runtime = handler.runtime.load_full();
            assert!(Arc::ptr_eq(&old_runtime.redirect_engine, &new_runtime.redirect_engine));
            assert!(!Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert_eq!(
                new_runtime
                    .cache
                    .get(&(Arc::from("cached.example."), RecordType::A))
                    .await
                    .unwrap()
                    .min_ttl,
                RULE_REFRESH_TTL_CAP
            );
            assert_eq!(
                new_runtime
                    .cache
                    .get(&(Arc::from("short.example."), RecordType::A))
                    .await
                    .unwrap()
                    .min_ttl,
                3
            );
        });
    }

    #[test]
    fn renew_redirect_rules_preserves_resolves_and_unclaimed_cache() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);
            let rule = test_runtime_rule();
            for domain in ["redirected.example.", "kept.example."] {
                handler
                    .insert(
                        domain,
                        RecordType::A,
                        vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                        ResponseCode::NoError,
                        &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                        FilterResult::Unfilter,
                        Some(rule.id),
                        Some(rule.index),
                    )
                    .await;
            }

            let old_runtime = handler.runtime.load_full();
            let old_kept =
                old_runtime.cache.get(&(Arc::from("kept.example."), RecordType::A)).await.unwrap();
            let (redirect_engine, _) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![],
                    redirect_rules: vec![test_static_redirect_rule(
                        "redirected.example",
                        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                        30,
                    )],
                });
            handler.renew_redirect_rules(redirect_engine).await;

            let new_runtime = handler.runtime.load_full();
            assert!(Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert!(new_runtime
                .cache
                .get(&(Arc::from("redirected.example."), RecordType::A))
                .await
                .is_none());
            let new_kept =
                new_runtime.cache.get(&(Arc::from("kept.example."), RecordType::A)).await.unwrap();
            assert!(Arc::ptr_eq(&old_kept, &new_kept));
            assert_eq!(new_kept.min_ttl, 60);
        });
    }

    #[test]
    fn renew_runtime_config_rebuilds_cache_without_reloading_rules_or_redirects() {
        run_async_test(async {
            let runtime_config = shared_cache_runtime_config(5);
            let handler = test_handler_with_config(
                runtime_config.clone(),
                1,
                vec![test_runtime_rule()],
                vec![test_static_redirect_rule(
                    "example.com",
                    vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
                    17,
                )],
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

            let old_runtime = handler.runtime.load_full();

            runtime_config.store(Arc::new(CacheRuntimeConfig {
                cache_capacity: 16,
                cache_ttl: 120,
                negative_cache_ttl: 22,
            }));
            handler.renew_runtime_config(true).await;

            let new_runtime = handler.runtime.load_full();
            assert!(!Arc::ptr_eq(&old_runtime, &new_runtime));
            assert!(Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert!(Arc::ptr_eq(&old_runtime.redirect_engine, &new_runtime.redirect_engine));
            assert_eq!(handler.runtime_config.load().negative_cache_ttl, 22);
            assert!(new_runtime
                .cache
                .get(&(Arc::from("cached.example.com."), RecordType::A))
                .await
                .is_some());
        });
    }

    #[test]
    fn all_local_ips_redirect_uses_provider_records() {
        run_async_test(async {
            let handler = test_handler_with_local(
                test_lan_hostname_registry(),
                Some(Arc::new(MockLocalAnswerProvider {
                    addrs: vec![
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                        IpAddr::V6(Ipv6Addr::LOCALHOST),
                    ],
                })),
                vec![],
                vec![test_all_local_ips_redirect_rule("example.com", 17)],
            );

            let (records, outcome, redirect_id, _) = handler
                .lookup_redirects(&ParsedDomain::new("example.com.").unwrap(), RecordType::A)
                .unwrap();

            assert_eq!(outcome, DnsOutcome::Local);
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
            let handler = test_handler_with_local(
                test_lan_hostname_registry(),
                Some(Arc::new(MockLocalAnswerProvider {
                    addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                })),
                vec![],
                vec![test_all_local_ips_redirect_rule("example.com", 17)],
            );

            assert!(handler
                .lookup_redirects(&ParsedDomain::new("example.com.").unwrap(), RecordType::AAAA)
                .is_none());
        });
    }

    #[test]
    fn static_redirect_without_matching_family_keeps_existing_no_record_behavior() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![],
                vec![test_static_redirect_rule(
                    "example.com",
                    vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                    17,
                )],
            );

            let (records, outcome, redirect_id, _) = handler
                .lookup_redirects(&ParsedDomain::new("example.com.").unwrap(), RecordType::AAAA)
                .unwrap();

            assert!(records.is_empty());
            assert_eq!(outcome, DnsOutcome::Local);
            assert_eq!(redirect_id, Some(Uuid::nil()));
        });
    }
}

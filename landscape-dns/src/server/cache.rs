use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use hickory_proto::{
    op::ResponseCode,
    rr::{Record, RecordType},
};
use moka::future::Cache;
use uuid::Uuid;

use landscape_common::{
    dns::rule::FilterResult,
    flow::{DnsResultSink, DnsRuntimeMarkInfo, FlowMarkInfo},
};

use crate::{
    domain::ParsedDomain,
    server::{rule::DNSResolveRuntime, CacheRuntimeConfig},
    CacheDNSItem, DNSCache,
};

/// Data required to write (or update) one cache entry.
pub(crate) struct CacheEntry {
    pub(crate) domain_key: Arc<str>,
    pub(crate) query_type: RecordType,
    pub(crate) rdatas: Vec<Record>,
    pub(crate) response_code: ResponseCode,
    pub(crate) mark: DnsRuntimeMarkInfo,
    pub(crate) filter: FilterResult,
    pub(crate) matched_rule_id: Option<Uuid>,
    pub(crate) matched_rule_order: Option<u32>,
}

/// Cache operations shared by the resolution chain, admin APIs and runtime
/// swaps: lookup with TTL decrement, insert with datapath side effects and
/// invalidation.
pub(crate) struct CacheHandle {
    cache: DNSCache,
    runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    flow_id: u32,
    sink: Arc<dyn DnsResultSink>,
}

impl std::fmt::Debug for CacheHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheHandle")
            .field("cache", &self.cache)
            .field("runtime_config", &self.runtime_config)
            .field("flow_id", &self.flow_id)
            .finish_non_exhaustive()
    }
}

impl CacheHandle {
    pub fn new(
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        sink: Arc<dyn DnsResultSink>,
    ) -> Self {
        Self {
            cache: Self::build_cache(runtime_config.load().as_ref()),
            runtime_config,
            flow_id,
            sink,
        }
    }

    fn build_cache(runtime_config: &CacheRuntimeConfig) -> DNSCache {
        Cache::builder()
            .max_capacity(runtime_config.cache_capacity as u64)
            .time_to_live(Duration::from_secs(runtime_config.cache_ttl as u64))
            .build()
    }

    /// Iterates over `(key, item)` pairs as owned `Arc`s, matching the
    /// underlying moka cache's iterator.
    pub fn iter(&self) -> moka::future::Iter<'_, (Arc<str>, RecordType), Arc<CacheDNSItem>> {
        self.cache.iter()
    }

    #[cfg(test)]
    pub async fn get(&self, key: &(Arc<str>, RecordType)) -> Option<Arc<CacheDNSItem>> {
        self.cache.get(key).await
    }

    /// Direct insert for cache migration paths (no TTL computation, no eBPF
    /// side effects): the item keeps its original bookkeeping.
    pub async fn insert_raw(&self, key: (Arc<str>, RecordType), item: Arc<CacheDNSItem>) {
        self.cache.insert(key, item).await;
    }

    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }

    /// All (mark, ip) pairs held by cached records that must live in the
    /// eBPF flow-dns map.
    pub fn dns_mark_list(&self) -> HashSet<FlowMarkInfo> {
        let mut update_dns_mark_list = HashSet::new();
        for (_key, value) in self.cache.iter() {
            update_dns_mark_list.extend(value.get_update_rules());
        }
        update_dns_mark_list
    }

    /// Returns valid (TTL-decremented) records for a live entry, or `None`
    /// when the entry is missing or expired (lazy eviction).
    pub async fn lookup(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, FilterResult, ResponseCode)> {
        let key = (domain.raw_arc().clone(), query_type);
        if let Some(cache_item) = self.cache.get(&key).await {
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
                self.cache.invalidate(&key).await;
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

    pub async fn invalidate(&self, domain: &ParsedDomain, query_type: RecordType) {
        self.cache.invalidate(&(domain.raw_arc().clone(), query_type)).await;
    }

    /// Invalidates the entry only when it exists; returns whether it did.
    pub async fn invalidate_if_present(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> bool {
        let key = (domain.raw_arc().clone(), query_type);
        if self.cache.get(&key).await.is_none() {
            return false;
        }

        self.cache.invalidate(&key).await;
        true
    }

    pub async fn insert(&self, entry: CacheEntry) {
        let CacheEntry {
            domain_key,
            query_type,
            rdatas,
            response_code,
            mark,
            filter,
            matched_rule_id,
            matched_rule_order,
        } = entry;
        let min_ttl = rdatas
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or_else(|| self.runtime_config.load().negative_cache_ttl);

        if min_ttl == 0 {
            return;
        }
        let cache_item = CacheDNSItem {
            rdatas,
            response_code,
            mark,
            insert_time: Instant::now(),
            min_ttl,
            filter,
            matched_rule_id,
            matched_rule_order,
        };
        let update_dns_mark_list = cache_item.get_update_rules();

        self.cache.insert((domain_key, query_type), Arc::new(cache_item)).await;

        // hand the resulting marks to the datapath sink
        if !update_dns_mark_list.is_empty() {
            self.sink.record_dns_answer(self.flow_id, update_dns_mark_list.into_iter().collect());
        }
    }

    pub fn resolver_cache_entry(
        resolver: &DNSResolveRuntime,
        domain_key: &Arc<str>,
        query_type: RecordType,
        rdatas: Vec<Record>,
        response_code: ResponseCode,
    ) -> CacheEntry {
        CacheEntry {
            domain_key: domain_key.clone(),
            query_type,
            rdatas,
            response_code,
            mark: resolver.mark().clone(),
            filter: resolver.filter_mode(),
            matched_rule_id: Some(resolver.get_config_id()),
            matched_rule_order: Some(resolver.order()),
        }
    }
}

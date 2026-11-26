use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use hickory_proto::rr::{RData, RecordType, rdata::svcb::SvcParamValue};
use moka::{Expiry, future::Cache};
use uuid::Uuid;

use landscape_common::{
    dns::rule::FilterResult,
    flow::{DnsResultSink, DnsRuntimeMarkInfo, FlowMarkInfo},
    sys_config::CacheRuntimeConfig,
};

use crate::domain::ParsedDomain;

use super::{answer::DnsAnswer, rule::DNSResolveRuntime};

#[derive(Clone, Debug)]
pub(crate) struct CacheDNSItem {
    pub answer: DnsAnswer,
    pub insert_time: Instant,

    pub min_ttl: u32,
    pub mark: DnsRuntimeMarkInfo,
    pub filter: FilterResult,
    pub matched_rule_id: Option<uuid::Uuid>,
    pub matched_rule_order: Option<u32>,
}

impl CacheDNSItem {
    fn remaining_ttl(&self) -> u32 {
        self.min_ttl
            .saturating_sub(u32::try_from(self.insert_time.elapsed().as_secs()).unwrap_or(u32::MAX))
    }

    pub(crate) fn is_live(&self) -> bool {
        self.remaining_ttl() > 0
    }

    pub(crate) fn get_update_rules(&self) -> HashSet<FlowMarkInfo> {
        self.get_update_rules_with_mark(&self.mark)
    }

    fn get_update_rules_with_mark(&self, info: &DnsRuntimeMarkInfo) -> HashSet<FlowMarkInfo> {
        let mut result = HashSet::new();
        if !info.mark.should_insert_dns_mark() {
            return result;
        }
        for rdata in self.answer.records.iter() {
            match &rdata.data {
                RData::A(a) => {
                    result.insert(FlowMarkInfo {
                        mark: info.mark.into(),
                        ip: std::net::IpAddr::V4(a.0),
                        priority: info.priority,
                    });
                }
                RData::AAAA(a) => {
                    result.insert(FlowMarkInfo {
                        mark: info.mark.into(),
                        ip: std::net::IpAddr::V6(a.0),
                        priority: info.priority,
                    });
                }
                // the ipv4hint / ipv6hint in HTTPS records may be used by the
                // client to connect directly, so write them into the eBPF map
                // as well to keep those connections under route mark control.
                RData::HTTPS(https) => {
                    for (_key, value) in https.0.svc_params.iter() {
                        match value {
                            SvcParamValue::Ipv4Hint(hint) => {
                                for a in hint.0.iter() {
                                    result.insert(FlowMarkInfo {
                                        mark: info.mark.into(),
                                        ip: std::net::IpAddr::V4(a.0),
                                        priority: info.priority,
                                    });
                                }
                            }
                            SvcParamValue::Ipv6Hint(hint) => {
                                for aaaa in hint.0.iter() {
                                    result.insert(FlowMarkInfo {
                                        mark: info.mark.into(),
                                        ip: std::net::IpAddr::V6(aaaa.0),
                                        priority: info.priority,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        result
    }
}

type CacheKey = (Arc<str>, RecordType);
pub(crate) type DNSCache = Cache<CacheKey, Arc<CacheDNSItem>>;

/// A cache rebuild reinserts the entry with its original timestamp.
struct CacheExpiry {
    max_age: Duration,
}

impl Expiry<CacheKey, Arc<CacheDNSItem>> for CacheExpiry {
    fn expire_after_create(
        &self,
        _: &CacheKey,
        item: &Arc<CacheDNSItem>,
        now: Instant,
    ) -> Option<Duration> {
        let lifetime = self.max_age.min(Duration::from_secs(item.min_ttl.into()));
        Some(lifetime.saturating_sub(now.saturating_duration_since(item.insert_time)))
    }

    fn expire_after_update(
        &self,
        key: &CacheKey,
        item: &Arc<CacheDNSItem>,
        now: Instant,
        _: Option<Duration>,
    ) -> Option<Duration> {
        self.expire_after_create(key, item, now)
    }
}

/// Data required to write (or update) one cache entry.
pub(crate) struct CacheEntry {
    pub(crate) domain_key: Arc<str>,
    pub(crate) query_type: RecordType,
    pub(crate) answer: DnsAnswer,
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
    // Retiring this snapshot waits for any synchronous datapath updates in progress.
    active: RwLock<bool>,
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
            active: RwLock::new(true),
        }
    }

    fn build_cache(runtime_config: &CacheRuntimeConfig) -> DNSCache {
        Cache::builder()
            .max_capacity(runtime_config.cache_capacity as u64)
            .expire_after(CacheExpiry {
                max_age: Duration::from_secs(runtime_config.cache_ttl.into()),
            })
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
            if value.is_live() {
                update_dns_mark_list.extend(value.get_update_rules());
            }
        }
        update_dns_mark_list
    }

    pub fn retire(&self) {
        *self.active.write().unwrap_or_else(|err| err.into_inner()) = false;
    }

    pub fn refresh_marks(&self) {
        let active = self.active.write().unwrap_or_else(|err| err.into_inner());
        if *active {
            self.sink.refresh_dns_marks(self.flow_id, self.dns_mark_list().into_iter().collect());
            self.sink.rebuild_route_cache();
        }
    }

    /// Returns valid (TTL-decremented) records for a live entry, or `None`
    /// when the entry is missing or expired.
    pub async fn lookup(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<(DnsAnswer, FilterResult)> {
        let key = (domain.raw_arc().clone(), query_type);
        let item = self.cache.get(&key).await?;
        let ttl = item.remaining_ttl();
        if ttl == 0 {
            // Moka will evict it. An unconditional removal here could erase a concurrent refresh.
            return None;
        }
        let mut answer = item.answer.clone();
        for record in &mut answer.records {
            record.ttl = ttl;
        }
        if let Some(soa) = &mut answer.soa {
            soa.ttl = ttl;
        }
        Some((answer, item.filter.clone()))
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
            answer,
            mark,
            filter,
            matched_rule_id,
            matched_rule_order,
        } = entry;
        let record_ttl = answer.records.iter().map(|r| r.ttl).min();
        let min_ttl = match record_ttl {
            Some(ttl) if !answer.is_negative => ttl,
            _ => {
                let cap = self.runtime_config.load().negative_cache_ttl;
                cap.min(record_ttl.unwrap_or(cap))
                    .min(answer.soa.as_ref().map_or(cap, |soa| soa.ttl))
            }
        };

        if min_ttl == 0 {
            self.cache.invalidate(&(domain_key, query_type)).await;
            return;
        }
        let cache_item = CacheDNSItem {
            answer,
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
            let active = self.active.read().unwrap_or_else(|err| err.into_inner());
            if *active {
                self.sink
                    .record_dns_answer(self.flow_id, update_dns_mark_list.into_iter().collect());
            }
        }
    }

    pub fn resolver_cache_entry(
        resolver: &DNSResolveRuntime,
        domain_key: &Arc<str>,
        query_type: RecordType,
        answer: DnsAnswer,
    ) -> CacheEntry {
        CacheEntry {
            domain_key: domain_key.clone(),
            query_type,
            answer,
            mark: resolver.mark().clone(),
            filter: resolver.filter_mode(),
            matched_rule_id: Some(resolver.get_config_id()),
            matched_rule_order: Some(resolver.order()),
        }
    }
}

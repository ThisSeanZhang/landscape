use std::sync::Arc;

use arc_swap::ArcSwap;
#[cfg(test)]
use arc_swap::Guard;

use landscape_common::flow::DnsResultSink;
use landscape_common::sys_config::CacheRuntimeConfig;

use crate::{
    domain::ParsedDomain,
    resolve::{
        RuntimeSnapshot,
        cache::{CacheDNSItem, CacheHandle},
        engine::ResolveEngine,
        local::LocalResolver,
        redirect::RedirectEngine,
    },
};

/// Migrated cache entries keep a TTL at most this long when rules are
/// refreshed, so stale answers converge quickly after a config change.
pub(crate) const RULE_REFRESH_TTL_CAP: u32 = 5;

/// What part of the runtime snapshot to replace on a config refresh.
pub(crate) enum SnapshotPatch {
    /// Replace both engines; migrated cache TTL is capped.
    Full { redirect_engine: RedirectEngine, resolve_engine: ResolveEngine },
    /// Replace only the resolve engine; migrated cache TTL is capped.
    Resolves { resolve_engine: ResolveEngine },
    /// Replace only the redirect engine, dropping cache entries now claimed
    /// by redirects.
    Redirects { redirect_engine: RedirectEngine },
    /// Rebuild the cache from the current config (capacity/TTL), keeping
    /// both engines.
    RebuildCache,
}

/// Owns the current [`RuntimeSnapshot`] and applies [`SnapshotPatch`]es with
/// cache migration and datapath side effects.
pub(crate) struct SnapshotStore {
    runtime: Arc<ArcSwap<RuntimeSnapshot>>,
    runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    flow_id: u32,
    local_resolver: Arc<LocalResolver>,
    sink: Arc<dyn DnsResultSink>,
}

impl SnapshotStore {
    pub fn new(
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        local_resolver: Arc<LocalResolver>,
        sink: Arc<dyn DnsResultSink>,
    ) -> Self {
        let cache = CacheHandle::new(runtime_config.clone(), flow_id, sink.clone());
        Self {
            runtime: Arc::new(ArcSwap::from_pointee(RuntimeSnapshot {
                redirect_engine: Arc::new(redirect_engine),
                resolve_engine: Arc::new(resolve_engine),
                cache,
            })),
            runtime_config,
            flow_id,
            local_resolver,
            sink,
        }
    }

    #[cfg(test)]
    pub fn runtime_config(&self) -> &Arc<ArcSwap<CacheRuntimeConfig>> {
        &self.runtime_config
    }

    pub fn local_resolver(&self) -> &Arc<LocalResolver> {
        &self.local_resolver
    }

    #[cfg(test)]
    pub fn load(&self) -> Guard<Arc<RuntimeSnapshot>> {
        self.runtime.load()
    }

    pub fn load_full(&self) -> Arc<RuntimeSnapshot> {
        self.runtime.load_full()
    }

    pub async fn apply(&self, patch: SnapshotPatch) {
        match patch {
            SnapshotPatch::Full { redirect_engine, resolve_engine } => {
                self.swap(
                    Arc::new(redirect_engine),
                    Arc::new(resolve_engine),
                    Some(RULE_REFRESH_TTL_CAP),
                )
                .await;
            }
            SnapshotPatch::Resolves { resolve_engine } => {
                let current = self.runtime.load_full();
                self.swap(
                    current.redirect_engine.clone(),
                    Arc::new(resolve_engine),
                    Some(RULE_REFRESH_TTL_CAP),
                )
                .await;
            }
            SnapshotPatch::Redirects { redirect_engine } => {
                let current = self.runtime.load_full();
                let new_cache =
                    self.remove_redirected_cache(&current.cache, &redirect_engine).await;
                self.publish(Arc::new(redirect_engine), current.resolve_engine.clone(), new_cache);
            }
            SnapshotPatch::RebuildCache => {
                let current = self.runtime.load_full();
                self.swap(current.redirect_engine.clone(), current.resolve_engine.clone(), None)
                    .await;
            }
        }
    }

    /// Rebuilds the cache, migrates surviving entries, publishes the new
    /// runtime snapshot and refreshes the eBPF mark/route maps.
    async fn swap(
        &self,
        redirect_engine: Arc<RedirectEngine>,
        resolve_engine: Arc<ResolveEngine>,
        ttl_cap: Option<u32>,
    ) {
        let new_cache =
            CacheHandle::new(self.runtime_config.clone(), self.flow_id, self.sink.clone());
        self.migrate_cache(&new_cache, &redirect_engine, &resolve_engine, ttl_cap).await;
        new_cache.run_pending_tasks().await;
        self.publish(redirect_engine, resolve_engine, new_cache);
    }

    fn publish(
        &self,
        redirect_engine: Arc<RedirectEngine>,
        resolve_engine: Arc<ResolveEngine>,
        new_cache: CacheHandle,
    ) {
        // Drain writes to the old map before replacing it. A query holding the
        // old snapshot may still finish and respond to its client.
        self.runtime.load().cache.retire();
        new_cache.refresh_marks();
        self.runtime.store(Arc::new(RuntimeSnapshot {
            redirect_engine,
            resolve_engine,
            cache: new_cache,
        }));
    }

    async fn remove_redirected_cache(
        &self,
        current_cache: &CacheHandle,
        redirects: &RedirectEngine,
    ) -> CacheHandle {
        let new_cache =
            CacheHandle::new(self.runtime_config.clone(), self.flow_id, self.sink.clone());
        for (key, value) in current_cache.iter() {
            let (domain, req_type) = &*key;
            let Ok(pd) = ParsedDomain::new(domain) else { continue };
            if value.is_live()
                && redirects
                    .lookup(&pd, *req_type, self.local_resolver.local_answer_provider())
                    .is_none()
            {
                new_cache.insert_raw((domain.clone(), *req_type), value).await;
            }
        }
        new_cache.run_pending_tasks().await;
        new_cache
    }

    async fn migrate_cache(
        &self,
        new_cache: &CacheHandle,
        redirects: &RedirectEngine,
        resolves: &ResolveEngine,
        ttl_cap: Option<u32>,
    ) {
        let current = self.runtime.load_full();

        for (key, cache_item) in current.cache.iter() {
            let (domain, req_type) = &*key;
            let Ok(pd) = ParsedDomain::new(domain) else { continue };
            if redirects
                .lookup(&pd, *req_type, self.local_resolver.local_answer_provider())
                .is_some()
            {
                continue;
            }
            if let Some(resolver) = resolves.find_match(&pd) {
                // Reuse only data obtained under the winning rule and upstream.
                let old = cache_item
                    .matched_rule_order
                    .and_then(|order| current.resolve_engine.get(order))
                    .or_else(|| current.resolve_engine.find_match(&pd));
                if cache_item.matched_rule_id.is_some_and(|id| id != resolver.get_config_id())
                    || !old.is_some_and(|old| old.can_reuse_answers_with(resolver))
                {
                    continue;
                }
                let new_item = CacheDNSItem {
                    answer: cache_item.answer.clone(),
                    mark: resolver.mark().clone(),
                    insert_time: cache_item.insert_time,
                    min_ttl: ttl_cap.map_or(cache_item.min_ttl, |cap| cache_item.min_ttl.min(cap)),
                    filter: resolver.filter_mode(),
                    matched_rule_id: Some(resolver.get_config_id()),
                    matched_rule_order: Some(resolver.order()),
                };

                if new_item.is_live() {
                    new_cache.insert_raw((domain.clone(), *req_type), Arc::new(new_item)).await;
                }
            }
        }
    }
}

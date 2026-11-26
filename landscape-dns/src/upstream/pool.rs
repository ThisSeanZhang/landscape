use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, Weak};

use landscape_common::dns::config::DnsUpstreamConfig;
use uuid::Uuid;

use crate::upstream::{LandscapeResolver, create_resolver};

/// Key under which resolvers are shared: the DNS mark (the SO_MARK applied to
/// upstream connections, i.e. the flow component plus the always-set reuse
/// port bit `0x8000`) plus the upstream server identity. The DNS mark never
/// encodes the rule action (Direct -> flow 0, Redirect -> target flow,
/// otherwise the owning flow), matching the legacy per-rule computation, so
/// rules with the same mark share one resolver instance and therefore one
/// connection pool to the upstream. Source-address binding lives on the
/// upstream config, so `upstream_id` already implies it and it needs no
/// separate key component.
type ResolverKey = (u32, Uuid);

/// Index of resolvers shared across flows. Rules own their active resolver, so
/// removing the last rule releases its connections once in-flight queries finish.
#[derive(Debug, Default)]
pub struct ResolvePool {
    resolvers: RwLock<HashMap<ResolverKey, Weak<LandscapeResolver>>>,
}

impl ResolvePool {
    /// Returns the shared resolver for `(dns_mark, upstream)`, building it
    /// on first use. A failed build is never cached so a later retry can
    /// succeed; the caller skips the rule, matching the pre-pool behaviour.
    pub(crate) fn get_or_create(
        &self,
        flow_id: u32,
        dns_mark: u32,
        upstream: &DnsUpstreamConfig,
    ) -> Option<Arc<LandscapeResolver>> {
        let key = (dns_mark, upstream.id);
        if let Some(resolver) = self
            .resolvers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .and_then(Weak::upgrade)
        {
            return Some(resolver);
        }

        let mut resolvers = self.resolvers.write().unwrap_or_else(|e| e.into_inner());
        if let Some(resolver) = resolvers.get(&key).and_then(Weak::upgrade) {
            return Some(resolver);
        }
        resolvers.retain(|_, resolver| resolver.strong_count() != 0);
        let resolver = Arc::new(create_resolver(flow_id, dns_mark, upstream.clone())?);
        resolvers.insert(key, Arc::downgrade(&resolver));
        Some(resolver)
    }

    /// Unconditionally drops every resolver for the given upstream ids. Old
    /// instances stay alive until the last `Arc` (in-flight queries, rules)
    /// is released, then their connections close naturally.
    pub(crate) fn invalidate(&self, upstream_ids: &HashSet<Uuid>) {
        if upstream_ids.is_empty() {
            return;
        }
        self.resolvers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, upstream_id), _| !upstream_ids.contains(upstream_id));
    }

    /// Test-only snapshot of the current pool keys.
    #[cfg(test)]
    pub(crate) fn keys(&self) -> Vec<(u32, Uuid)> {
        self.resolvers.read().unwrap_or_else(|e| e.into_inner()).keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream() -> DnsUpstreamConfig {
        DnsUpstreamConfig::default()
    }

    #[tokio::test]
    async fn same_key_reuses_resolver() {
        let pool = ResolvePool::default();
        let upstream = upstream();
        let first = pool.get_or_create(7, 0x8005, &upstream).unwrap();
        let second = pool.get_or_create(7, 0x8005, &upstream).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(pool.keys(), vec![(0x8005, upstream.id)]);
    }

    #[tokio::test]
    async fn different_marks_build_separate_resolvers() {
        let pool = ResolvePool::default();
        let upstream = upstream();
        let flow5 = pool.get_or_create(5, 0x8005, &upstream).unwrap();
        let flow7 = pool.get_or_create(7, 0x8007, &upstream).unwrap();

        assert!(!Arc::ptr_eq(&flow5, &flow7));
        let mut keys = pool.keys();
        keys.sort();
        assert_eq!(keys, vec![(0x8005, upstream.id), (0x8007, upstream.id)]);
    }

    #[tokio::test]
    async fn invalidate_drops_only_targeted_upstreams() {
        let pool = ResolvePool::default();
        let upstream_a = upstream();
        let upstream_b = upstream();
        let a = pool.get_or_create(7, 0x8000, &upstream_a).unwrap();
        let b = pool.get_or_create(7, 0x8000, &upstream_b).unwrap();

        pool.invalidate(&HashSet::from([upstream_a.id]));

        let a_rebuilt = pool.get_or_create(7, 0x8000, &upstream_a).unwrap();
        let b_kept = pool.get_or_create(7, 0x8000, &upstream_b).unwrap();
        assert!(!Arc::ptr_eq(&a, &a_rebuilt));
        assert!(Arc::ptr_eq(&b, &b_kept));
    }

    #[tokio::test]
    async fn last_rule_releases_resolver_and_a_new_mark_prunes_its_key() {
        let pool = ResolvePool::default();
        let upstream = DnsUpstreamConfig { use_experimental_pool: Some(true), ..upstream() };
        let resolver = pool.get_or_create(7, 0x8007, &upstream).unwrap();
        let old = Arc::downgrade(&resolver);
        drop(resolver);
        assert!(old.upgrade().is_none());
        let _new = pool.get_or_create(8, 0x8008, &upstream).unwrap();
        assert_eq!(pool.keys(), vec![(0x8008, upstream.id)]);
    }

    #[tokio::test]
    async fn invalidate_empty_set_is_noop() {
        let pool = ResolvePool::default();
        let upstream = upstream();
        let first = pool.get_or_create(7, 0x8005, &upstream).unwrap();

        pool.invalidate(&HashSet::new());

        let second = pool.get_or_create(7, 0x8005, &upstream).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }
}

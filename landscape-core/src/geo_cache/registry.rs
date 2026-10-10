use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use landscape_common::{
    config_service::geo::{GeoConfigKey, GeoFileCacheKey},
    dns::rule::DomainConfig,
};
use tokio::sync::Mutex;

use super::{SiteCacheRepository, matcher::DomainMatcher};

/// Cache identity of one compiled geo matcher: the source file key plus the
/// optional attribute filter. `inverse` is deliberately not part of the key —
/// positive and negative references share the same compiled matcher.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct GeoMatcherCacheKey {
    pub source: GeoFileCacheKey,
    pub attribute_key: Option<String>,
}

/// Owns the compiled [`DomainMatcher`]s of the geo site cache. Matchers are
/// lazily compiled per key on first use and kept warm across data updates:
/// [`SiteMatcherRegistry::refresh_matchers`] recompiles materialized entries
/// and swaps the new `Arc`s in place, so consumers rebuild engines from
/// ready matchers instead of re-reading raw rules.
#[derive(Clone)]
pub struct SiteMatcherRegistry {
    repo: SiteCacheRepository,
    matchers: Arc<Mutex<HashMap<GeoMatcherCacheKey, Arc<DomainMatcher>>>>,
}

impl SiteMatcherRegistry {
    pub fn new(repo: SiteCacheRepository) -> Self {
        Self {
            repo,
            matchers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the compiled matcher for `config`, compiling it on first use.
    ///
    /// Confirmed behavior: a missing, unreadable, or empty key (also empty
    /// after the attribute filter) yields `None` and is not cached, so a
    /// later update that populates the key is picked up by the next engine
    /// rebuild.
    pub async fn get_or_build(&self, config: &GeoConfigKey) -> Option<Arc<DomainMatcher>> {
        let cache_key = GeoMatcherCacheKey {
            source: config.get_file_cache_key(),
            attribute_key: config.attribute_key.clone(),
        };
        if let Some(matcher) = self.matchers.lock().await.get(&cache_key).cloned() {
            return Some(matcher);
        }

        let matcher = self.build_matcher(&cache_key).await?;
        let mut matchers = self.matchers.lock().await;
        Some(matchers.entry(cache_key).or_insert_with(|| Arc::new(matcher)).clone())
    }

    /// Recompiles every materialized matcher whose source key changed and
    /// swaps the new `Arc` in place; entries that became missing or empty
    /// are removed so the next [`SiteMatcherRegistry::get_or_build`]
    /// re-reads fresh data. Callers must run this *before* announcing the
    /// data change so the engine rebuilds triggered by the announcement
    /// observe fresh matchers.
    pub async fn refresh_matchers(&self, changed: &HashSet<GeoFileCacheKey>) {
        if changed.is_empty() {
            return;
        }

        let mut matchers = self.matchers.lock().await;
        let stale: Vec<GeoMatcherCacheKey> =
            matchers.keys().filter(|key| changed.contains(&key.source)).cloned().collect();

        for key in stale {
            if let Some(matcher) = self.build_matcher(&key).await {
                matchers.insert(key, Arc::new(matcher));
            } else {
                matchers.remove(&key);
            }
        }
    }

    /// Loads one key's rules and compiles them. `None` means missing,
    /// unreadable, or empty after the attribute filter.
    async fn build_matcher(&self, cache_key: &GeoMatcherCacheKey) -> Option<DomainMatcher> {
        let values = match self.repo.load_entry(&cache_key.source.name, &cache_key.source.key).await
        {
            Ok(Some(config)) => config.values,
            Ok(None) => {
                tracing::warn!(
                    name = %cache_key.source.name,
                    key = %cache_key.source.key,
                    "skip rule with missing GeoKey"
                );
                return None;
            }
            Err(error) => {
                tracing::error!(
                    name = %cache_key.source.name,
                    key = %cache_key.source.key,
                    %error,
                    "skip rule with unreadable GeoKey"
                );
                return None;
            }
        };

        let domains = values
            .into_iter()
            .filter(|domain| {
                cache_key
                    .attribute_key
                    .as_ref()
                    .is_none_or(|attribute| domain.attributes.contains(attribute))
            })
            .map(Into::into)
            .collect::<Vec<DomainConfig>>();
        // Confirmed behavior: a key that exists but yields no domains after
        // the attribute filter is treated the same as a missing key — the
        // source is skipped and nothing is cached, so a later update that
        // populates the key is picked up on the next engine rebuild.
        if domains.is_empty() {
            tracing::warn!(
                name = %cache_key.source.name,
                key = %cache_key.source.key,
                "skip rule with empty GeoKey"
            );
            return None;
        }

        spawn_blocking_compile(domains).await
    }
}

/// Automata compilation is CPU-heavy for large lists (seconds for tens of
/// thousands of rules); keep it off the async runtime workers.
async fn spawn_blocking_compile(domains: Vec<DomainConfig>) -> Option<DomainMatcher> {
    match tokio::task::spawn_blocking(move || DomainMatcher::new(domains)).await {
        Ok(matcher) => Some(matcher),
        Err(error) => {
            // JoinError only occurs on runtime shutdown or a panicking
            // build; report failure so callers keep the previous matcher
            // (refresh) or skip the source (lazy build).
            tracing::error!(%error, "geo matcher compile task failed");
            None
        }
    }
}

#[cfg(test)]
impl SiteMatcherRegistry {
    /// Number of materialized matcher entries (test introspection).
    pub(super) async fn materialized_len(&self) -> usize {
        self.matchers.lock().await.len()
    }
}

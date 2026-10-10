use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
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

/// Young orphans are protected: a matcher swapped just before a heartbeat
/// must survive until the event's consumer picks it up (milliseconds in a
/// healthy system — an hour is far above that, negligible against the
/// daily heartbeat). Unreferenced and older entries are collected.
const GC_GRACE: Duration = Duration::from_secs(60 * 60);

/// One materialized entry: the compiled matcher plus the `content_hash` of
/// the source data it was compiled from — the two terms the reconcile
/// probe compares. The hash lives here rather than inside `DomainMatcher`,
/// which also serves manual rules that have no source entry to hash.
struct CachedMatcher {
    matcher: Arc<DomainMatcher>,
    content_hash: String,
    /// When this entry was inserted or swapped; stamps the GC grace.
    swapped_at: Instant,
}

/// One entry per (source key, attribute filter) in use.
type MatcherMap = HashMap<GeoMatcherCacheKey, CachedMatcher>;

/// Outcome of loading and compiling one key.
enum BuiltMatcher {
    /// The matcher plus the `content_hash` of the data it was compiled from.
    Fresh(DomainMatcher, String),
    /// The key is legitimately gone (missing, or empty after the attribute
    /// filter): the data says the source must stop matching.
    Absent,
    /// The read or compile failed environmentally; the data may be fine.
    Failed,
}

/// Which entries one reconcile pass examines.
enum Scope<'a> {
    /// Every materialized entry, with a GC sweep first — heartbeat path.
    Full,
    /// Only entries of the given source keys — change-notify path.
    Sources(&'a HashSet<GeoFileCacheKey>),
}

/// Owns the compiled [`DomainMatcher`]s of the geo site cache: matchers are
/// lazily compiled per key on first use, and reconciliation swaps drifted
/// entries in place so consumers rebuild engines from ready matchers
/// instead of re-reading raw rules. A failure keeps the previous matcher
/// serving (last-known-good); drift detection is level-triggered, so
/// recovery needs no retry bookkeeping. Reconcile passes hold the registry
/// lock only for two short sync phases — probes and compiles run unlocked,
/// applies are guarded by the recorded hash. Engines hold plain `Arc`s: a
/// matcher swapped here only reaches them through the change event callers
/// are asked to announce with the returned keys.
#[derive(Clone)]
pub struct SiteMatcherRegistry {
    repo: SiteCacheRepository,
    matchers: Arc<Mutex<MatcherMap>>,
    gc_grace: Duration,
}

impl SiteMatcherRegistry {
    pub fn new(repo: SiteCacheRepository) -> Self {
        Self {
            repo,
            matchers: Arc::new(Mutex::new(MatcherMap::default())),
            gc_grace: GC_GRACE,
        }
    }

    /// Returns the compiled matcher for `config`, compiling it on first
    /// use. A missing, unreadable, or empty key (also empty after the
    /// attribute filter) yields `None` and is not cached; a cache hit
    /// returns the matcher as-is, including one kept from a failed
    /// reconciliation. Every `Arc` handed out is cloned under the registry
    /// mutex — the safety premise of the reconcile GC.
    pub async fn get_or_build(&self, config: &GeoConfigKey) -> Option<Arc<DomainMatcher>> {
        let cache_key = GeoMatcherCacheKey {
            source: config.get_file_cache_key(),
            attribute_key: config.attribute_key.clone(),
        };
        let cached = {
            let matchers = self.matchers.lock().await;
            matchers.get(&cache_key).map(|cached| cached.matcher.clone())
        };
        if let Some(matcher) = cached {
            return Some(matcher);
        }

        let BuiltMatcher::Fresh(matcher, content_hash) = self.build_matcher(&cache_key).await
        else {
            return None;
        };
        let mut matchers = self.matchers.lock().await;
        Some(
            matchers
                .entry(cache_key)
                .or_insert_with(|| CachedMatcher {
                    matcher: Arc::new(matcher),
                    content_hash,
                    swapped_at: Instant::now(),
                })
                .matcher
                .clone(),
        )
    }

    /// Full reconciliation heartbeat — the only path that GCs unreferenced
    /// entries and discovers drift beyond announced changes:
    ///
    /// - unreferenced entries older than the GC grace are collected,
    ///   silently — young swaps survive the consumer's pickup latency;
    /// - hash-drifted entries are recompiled and swapped in place;
    /// - entries whose source key is gone are removed and reported (they
    ///   survived the GC segment, so a consumer held the matcher — only an
    ///   engine rebuild drops the rule);
    /// - a read or compile failure keeps the previous matcher serving.
    ///
    /// Callers must announce the returned keys so engines rebuild.
    pub async fn reconcile(&self) -> HashSet<GeoFileCacheKey> {
        self.run_reconcile(Scope::Full).await
    }

    /// Scoped rebuild for a change notification: recompiles (or removes)
    /// only entries of the changed sources and returns the ones with a
    /// definite outcome — cost proportionate to `targets`, the same order
    /// as the pre-reconciliation refresh. Drift discovery and GC stay with
    /// [`SiteMatcherRegistry::reconcile`].
    pub async fn reconcile_sources(
        &self,
        targets: &HashSet<GeoFileCacheKey>,
    ) -> HashSet<GeoFileCacheKey> {
        if targets.is_empty() {
            return HashSet::new();
        }
        self.run_reconcile(Scope::Sources(targets)).await
    }

    /// Shared body of the two reconcile flavors. The registry lock is held
    /// only for the two short sync phases around the unlocked IO:
    ///
    /// - A (locked): optional GC, snapshot `(key, hash)` — no Arc, so
    ///   `get_or_build` traffic is never blocked by probes or compiles;
    /// - B (unlocked): hash probe per key, recompile drifted ones;
    /// - C (locked): guarded apply — a result lands only while the entry
    ///   still records the hash the pass started from; a racing
    ///   `get_or_build` or reconcile that advanced it first wins.
    async fn run_reconcile(&self, scope: Scope<'_>) -> HashSet<GeoFileCacheKey> {
        let stale: Vec<(GeoMatcherCacheKey, String)> = {
            let mut matchers = self.matchers.lock().await;
            if matches!(scope, Scope::Full) {
                // GC segment (sync): collect entries only the registry
                // holds and whose swap is past the grace (see GC_GRACE).
                // Safe because every consumer-facing Arc clone happens
                // under this mutex; drops only decrement lock-free, so a
                // racing drop can skip GC this round but never makes a
                // live entry look dead.
                let gc_grace = self.gc_grace;
                matchers.retain(|_, cached| {
                    Arc::strong_count(&cached.matcher) != 1
                        || cached.swapped_at.elapsed() < gc_grace
                });
            }
            matchers
                .iter()
                .filter(|(key, _)| match scope {
                    Scope::Full => true,
                    Scope::Sources(targets) => targets.contains(&key.source),
                })
                .map(|(key, cached)| (key.clone(), cached.content_hash.clone()))
                .collect()
        };

        let mut outcomes: Vec<(GeoMatcherCacheKey, String, BuiltMatcher)> = Vec::new();
        for (key, snapshot_hash) in stale {
            let source = &key.source;
            match self.repo.load_entry_hash(&source.name, &source.key).await {
                Ok(stored_hash) if stored_hash.as_deref() == Some(snapshot_hash.as_str()) => {
                    continue;
                }
                Err(error) => {
                    // last-known-good: the next pass re-examines anyway
                    tracing::error!(
                        name = %source.name,
                        key = %source.key,
                        %error,
                        "keep stale geo matcher after unreadable key"
                    );
                    continue;
                }
                Ok(_) => {}
            }
            let outcome = self.build_matcher(&key).await;
            outcomes.push((key, snapshot_hash, outcome));
        }

        let mut changed = HashSet::new();
        let mut matchers = self.matchers.lock().await;
        for (key, snapshot_hash, outcome) in outcomes {
            let source = key.source.clone();
            // guarded apply: a racing newer build of this key wins
            let up_to_date =
                matchers.get(&key).is_none_or(|cached| cached.content_hash == snapshot_hash);
            match outcome {
                BuiltMatcher::Fresh(matcher, content_hash) => {
                    if up_to_date {
                        matchers.insert(
                            key,
                            CachedMatcher {
                                matcher: Arc::new(matcher),
                                content_hash,
                                swapped_at: Instant::now(),
                            },
                        );
                        changed.insert(source);
                    }
                }
                BuiltMatcher::Absent => {
                    if up_to_date && matchers.remove(&key).is_some() {
                        changed.insert(source);
                    }
                }
                // compile failure: keep the previous matcher (last-known-good)
                BuiltMatcher::Failed => {}
            }
        }
        changed
    }

    /// Loads one key's rules and compiles them.
    async fn build_matcher(&self, cache_key: &GeoMatcherCacheKey) -> BuiltMatcher {
        let (values, content_hash) = match self
            .repo
            .load_entry_with_hash(&cache_key.source.name, &cache_key.source.key)
            .await
        {
            Ok(Some((config, content_hash))) => (config.values, content_hash),
            Ok(None) => {
                tracing::warn!(
                    name = %cache_key.source.name,
                    key = %cache_key.source.key,
                    "skip rule with missing GeoKey"
                );
                return BuiltMatcher::Absent;
            }
            Err(error) => {
                tracing::error!(
                    name = %cache_key.source.name,
                    key = %cache_key.source.key,
                    %error,
                    "skip rule with unreadable GeoKey"
                );
                return BuiltMatcher::Failed;
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
        // empty after the attribute filter: same as a missing key — skip
        // and cache nothing, a later update is picked up on next build
        if domains.is_empty() {
            tracing::warn!(
                name = %cache_key.source.name,
                key = %cache_key.source.key,
                "skip rule with empty GeoKey"
            );
            return BuiltMatcher::Absent;
        }

        match spawn_blocking_compile(domains).await {
            Some(matcher) => BuiltMatcher::Fresh(matcher, content_hash),
            None => BuiltMatcher::Failed,
        }
    }
}

/// Automata compilation is CPU-heavy for large lists (seconds for tens of
/// thousands of rules); keep it off the async runtime workers.
async fn spawn_blocking_compile(domains: Vec<DomainConfig>) -> Option<DomainMatcher> {
    match tokio::task::spawn_blocking(move || DomainMatcher::new(domains)).await {
        Ok(matcher) => Some(matcher),
        Err(error) => {
            // JoinError means runtime shutdown or a panicking build
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

    /// Test instances with a custom GC grace — `Duration::ZERO` disables
    /// the young-orphan protection, since an `Instant` older than the
    /// default grace cannot be fabricated on short-uptime machines.
    pub(super) fn with_gc_grace(repo: SiteCacheRepository, gc_grace: Duration) -> Self {
        Self {
            repo,
            matchers: Arc::new(Mutex::new(MatcherMap::default())),
            gc_grace,
        }
    }
}

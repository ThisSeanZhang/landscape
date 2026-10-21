use landscape_common::{
    concurrency::task_label,
    config_service::geo::{
        GeoDomainConfig, GeoError, GeoFileCacheKey, GeoSiteFileConfig, GeoSiteLookupResult,
        GeoSiteSource, GeoSourceKind, GeoTaskPhase, GeoTaskProgress, RawDatState,
    },
    database::store::{Change, ConfigStore},
    dns::domain::normalize_domain_name,
    memtrack::{TaggedFuture, subsystem_from_task_label},
    service::controller::ConfigStoreController,
    utils::time::get_f64_timestamp,
};
use uuid::Uuid;

use std::{
    collections::{HashMap, HashSet},
    fs,
    future::Future,
    sync::Arc,
    time::Duration,
};

use landscape_common::{
    args::LAND_HOME_PATH, config_service::geo::GeoSiteSourceConfig, event::dns::DnsEvent,
};
use landscape_core::geo_cache::{
    CacheWriteOutcome, GeoCacheDatabase, SiteCacheRepository, SiteMatcherRegistry, SiteRuleRow,
};
use landscape_database::{
    geo_site::repository::GeoSiteConfigRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use super::raw_file::{raw_dat_path, remove_raw_dat, sweep_orphan_raw_files};
use super::site_values::{geo_values_hash_hex, normalize_site_rule_value};
use super::storage::{geo_snapshot_path, remove_geo_snapshot, sweep_orphan_geo_snapshots};
use super::{GeoCacheApplyResult, GeoTaskMode, GeoTaskRegistry, TaskGuard};

mod snapshot_pipeline;

const A_DAY: u64 = 60 * 60 * 24;

#[derive(Clone)]
pub struct GeoSiteService {
    store: GeoSiteConfigRepository,
    cache: SiteCacheRepository,
    matcher_registry: Arc<SiteMatcherRegistry>,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    tasks: GeoTaskRegistry,
    stop_token: CancellationToken,
    tracker: TaskTracker,
}

impl GeoSiteService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
    ) -> Self {
        let store = store.geo_site_rule_store();

        let cache = SiteCacheRepository::new(
            GeoCacheDatabase::open_site(&LAND_HOME_PATH).await.expect("open geo site cache db"),
        );
        // compiled matchers live next to the data they are derived from; the
        // registry shares the cache's pool and is refreshed below before any
        // change event is announced
        let matcher_registry = Arc::new(SiteMatcherRegistry::new(cache.clone()));

        let service = Self {
            store,
            cache,
            matcher_registry,
            dns_events_tx,
            tasks: GeoTaskRegistry::default(),
            stop_token: CancellationToken::new(),
            tracker: TaskTracker::new(),
        };
        let service_clone = service.clone();
        let stop_token = service.stop_token.clone();
        service.spawn_tracked(task_label::task::GEO_SITE_OBSERVER, async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(A_DAY));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // The current network may not be ready; delaying the update check.
            tokio::select! {
                _ = stop_token.cancelled() => {},
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    loop {
                        tokio::select! {
                            _ = stop_token.cancelled() => break,
                            _ = ticker.tick() => {
                                service_clone.refresh(false).await;
                            }
                        }
                    }
                }
            }
            tracing::info!("geo site daily refresh loop stopped");
        });
        service
    }

    fn spawn_tracked<Fut>(
        &self,
        label: &'static str,
        future: Fut,
    ) -> tokio::task::JoinHandle<Fut::Output>
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let tag = subsystem_from_task_label(label);
        self.tracker.spawn(
            TaggedFuture::new(tag, future).instrument(tracing::info_span!("task", task = label)),
        )
    }

    pub async fn shutdown_and_wait(&self, timeout: Duration) {
        self.stop_token.cancel();
        self.tasks.cancel_all();
        self.tracker.close();
        match tokio::time::timeout(timeout, self.tracker.wait()).await {
            Ok(()) => tracing::info!("geo site background tasks stopped"),
            Err(_) => tracing::warn!(
                "geo site shutdown timed out after {timeout:?}; in-flight refresh may still be draining"
            ),
        }
    }

    pub fn task_progress_snapshot(&self) -> Vec<GeoTaskProgress> {
        self.tasks.progress_snapshot()
    }

    pub fn cancel_geo_task(&self, id: Uuid) -> bool {
        self.tasks.cancel_task(id)
    }

    /// Replace cache content with `entries` under `name`; keys that vanish
    /// from `entries` are deleted. Skip-writes are decided inside the
    /// repository via the stored content hash.
    async fn apply_geo_values(
        &self,
        name: &str,
        entries: Vec<(String, Vec<GeoSiteFileConfig>)>,
    ) -> GeoCacheApplyResult {
        let mut result = GeoCacheApplyResult::default();
        let mut stale_keys: HashSet<GeoFileCacheKey> =
            self.cache.keys_for_name(name).await.unwrap_or_default().into_iter().collect();

        for (key, values) in entries {
            let cache_key = GeoFileCacheKey {
                name: name.to_string(),
                key: key.to_ascii_uppercase(),
            };
            stale_keys.remove(&cache_key);

            let content_hash = geo_values_hash_hex(&values);
            let rules: Vec<SiteRuleRow> = values
                .into_iter()
                .map(|value| {
                    let domain = normalize_site_rule_value(&value.match_type, value.value);
                    SiteRuleRow::new(value.match_type, domain, value.attributes)
                })
                .collect();

            match self.cache.replace_by_name(name, &cache_key.key, &content_hash, rules).await {
                Ok(CacheWriteOutcome::Unchanged) => result.unchanged_keys += 1,
                Ok(_) => {
                    result.changed_keys.insert(cache_key);
                }
                Err(e) => {
                    tracing::error!("write geo site cache {}/{} failed: {}", name, cache_key.key, e)
                }
            }
        }

        for key in stale_keys {
            if self.delete_cache_key(&key).await {
                result.changed_keys.insert(key);
                result.deleted_keys += 1;
            }
        }

        result
    }

    async fn delete_cache_key(&self, key: &GeoFileCacheKey) -> bool {
        match self.cache.delete_by_name(&key.name, &key.key).await {
            Ok(deleted) => deleted,
            Err(e) => {
                tracing::error!("delete geo site cache {}/{} failed: {}", key.name, key.key, e);
                false
            }
        }
    }

    async fn notify_geo_changes(&self, changed_keys: HashSet<GeoFileCacheKey>) {
        if changed_keys.is_empty() {
            return;
        }
        // rebuild the changed sources' matchers first so the engine
        // rebuilds below observe fresh data; drift discovery and GC stay
        // with the daily heartbeat
        self.matcher_registry.reconcile_sources(&changed_keys).await;
        let _ = self
            .dns_events_tx
            .send(DnsEvent::GeoSitesChanged { changed_keys: Some(changed_keys) })
            .await;
    }

    fn spawn_geo_task(
        &self,
        config: GeoSiteSourceConfig,
        mode: GeoTaskMode,
        cancel: CancellationToken,
    ) {
        let service = self.clone();
        let source_id = config.id;
        self.spawn_tracked(task_label::task::GEO_SITE_OBSERVER, async move {
            let _guard = TaskGuard::new(service.tasks.clone(), source_id);
            service.run_geo_task(config, mode, &cancel).await;
        });
    }

    fn try_spawn_download_task(&self, config: GeoSiteSourceConfig) -> bool {
        match self.tasks.insert(config.id, GeoSourceKind::Site, GeoTaskPhase::Downloading) {
            Ok(cancel) => {
                self.spawn_geo_task(config, GeoTaskMode::Download, cancel);
                true
            }
            Err(()) => false,
        }
    }

    fn spawn_restore_task(&self, config: &GeoSiteSourceConfig) {
        if let Ok(cancel) =
            self.tasks.insert(config.id, GeoSourceKind::Site, GeoTaskPhase::Verifying)
        {
            self.spawn_geo_task(config.clone(), GeoTaskMode::RestoreOnly, cancel);
        }
    }

    async fn refresh_direct_config(
        &self,
        config: &GeoSiteSourceConfig,
    ) -> HashSet<GeoFileCacheKey> {
        let apply_result = if let GeoSiteSource::Direct { data } = &config.source {
            self.write_direct_to_cache(&config.name, data).await
        } else {
            GeoCacheApplyResult::default()
        };
        tracing::debug!(
            "refresh direct geo: name={} changed_keys={} unchanged_keys={} deleted_keys={}",
            config.name,
            apply_result.changed_keys.len(),
            apply_result.unchanged_keys,
            apply_result.deleted_keys,
        );
        apply_result.changed_keys
    }

    async fn has_cached_name(&self, name: &str) -> bool {
        self.cache.has_name(name).await.unwrap_or_else(|e| {
            tracing::error!("query geo site cache name '{name}' failed: {e}");
            false
        })
    }

    /// Legacy endpoint compatibility: only serve an existing raw file. New
    /// downloads produce snapshots and are exposed through the snapshot API.
    pub async fn get_legacy_raw_dat(&self, id: Uuid) -> Result<Vec<u8>, GeoError> {
        let dat_path = raw_dat_path("site", id);
        if dat_path.exists() {
            return fs::read(&dat_path)
                .map_err(|e| GeoError::RawDatReadFailed(format!("{dat_path:?}: {e}")));
        }
        let _ = self.find_by_id(id).await?;
        Err(GeoError::RawDatNotReady)
    }

    pub async fn get_snapshot_or_start_download(&self, id: Uuid) -> Result<RawDatState, GeoError> {
        let snapshot_path = geo_snapshot_path("site", id);
        if snapshot_path.exists() {
            let bytes = fs::read(&snapshot_path)
                .map_err(|e| GeoError::RawDatReadFailed(format!("{snapshot_path:?}: {e}")))?;
            return Ok(RawDatState::Ready(bytes));
        }

        let Some(config) = self.find_by_id(id).await? else {
            return Err(GeoError::SiteNotFound(id));
        };
        if !matches!(config.source, GeoSiteSource::Url { .. } | GeoSiteSource::AdguardHome { .. }) {
            return Err(GeoError::RawDatNotReady);
        }

        match self.tasks.insert(id, GeoSourceKind::Site, GeoTaskPhase::Downloading) {
            Ok(cancel) => {
                self.spawn_geo_task(config, GeoTaskMode::Download, cancel);
                Ok(RawDatState::Started)
            }
            Err(()) => Ok(RawDatState::Running),
        }
    }

    pub async fn refresh(&self, force: bool) {
        let configs: Vec<GeoSiteSourceConfig> = self.store.list().await.unwrap();

        let mut config_names = HashSet::new();
        let mut config_ids = HashSet::new();
        let now = get_f64_timestamp();

        for config in configs {
            config_names.insert(config.name.clone());
            config_ids.insert(config.id);

            match &config.source {
                GeoSiteSource::Url { next_update_at, .. }
                | GeoSiteSource::AdguardHome { next_update_at, .. } => {
                    let due = force || *next_update_at < now;
                    if !due {
                        let snapshot_exists = geo_snapshot_path("site", config.id).exists();
                        let legacy_raw_exists = raw_dat_path("site", config.id).exists();
                        if snapshot_exists
                            || legacy_raw_exists
                            || !self.has_cached_name(&config.name).await
                        {
                            self.spawn_restore_task(&config);
                        }
                    }
                    if due && !self.try_spawn_download_task(config.clone()) {
                        tracing::debug!("geo site source {} refresh already running", config.name);
                    }
                }
                GeoSiteSource::Direct { .. } => {
                    let changed = self.refresh_direct_config(&config).await;
                    self.notify_geo_changes(changed).await;
                }
            }
        }

        self.sweep_orphans(&config_names, &config_ids).await;

        // heartbeat: GC unreferenced matchers and self-heal drift (incl.
        // matchers kept from an earlier failure); a definite outcome gets
        // its own event so engines rebuild
        let drift = self.matcher_registry.reconcile().await;
        if !drift.is_empty() {
            let _ = self
                .dns_events_tx
                .send(DnsEvent::GeoSitesChanged { changed_keys: Some(drift) })
                .await;
        }
    }

    /// Remove cache rows, raw dat files, and snapshots whose source config no
    /// longer exists. Runs on every refresh so the daily tick also sweeps
    /// orphans left behind by deleted configs.
    async fn sweep_orphans(&self, config_names: &HashSet<String>, config_ids: &HashSet<Uuid>) {
        let need_to_remove = self
            .cache
            .list_keys()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|key| !config_names.contains(&key.name))
            .collect::<HashSet<GeoFileCacheKey>>();
        let mut removed = HashSet::new();
        for key in &need_to_remove {
            if self.delete_cache_key(key).await {
                removed.insert(key.clone());
            }
        }
        self.notify_geo_changes(removed).await;

        let swept = sweep_orphan_raw_files("site", config_ids);
        if !swept.is_empty() {
            tracing::debug!("swept {} orphan geo site raw file(s)", swept.len());
        }
        let swept = sweep_orphan_geo_snapshots("site", config_ids);
        if !swept.is_empty() {
            tracing::debug!("swept {} orphan geo site snapshot file(s)", swept.len());
        }
    }

    pub async fn refresh_one(&self, name: &str) -> Result<(), GeoError> {
        let configs: Vec<GeoSiteSourceConfig> = self.store.list().await?;
        let Some(config) = configs.into_iter().find(|c| c.name == name) else {
            return Err(GeoError::SiteConfigNotFound(name.to_string()));
        };

        match &config.source {
            GeoSiteSource::Url { .. } | GeoSiteSource::AdguardHome { .. } => {
                if !self.try_spawn_download_task(config) {
                    return Err(GeoError::TaskAlreadyRunning);
                }
            }
            GeoSiteSource::Direct { .. } => {
                let changed = self.refresh_direct_config(&config).await;
                self.notify_geo_changes(changed).await;
            }
        }
        Ok(())
    }

    async fn write_direct_to_cache(
        &self,
        name: &str,
        data: &[landscape_common::config_service::geo::GeoSiteDirectItem],
    ) -> GeoCacheApplyResult {
        self.apply_geo_values(
            name,
            data.iter().map(|item| (item.key.clone(), item.values.clone())).collect(),
        )
        .await
    }
}

impl GeoSiteService {
    /// Shared owner of the compiled geo matchers; consumers (the DNS rule
    /// builder) fetch ready `Arc<DomainMatcher>`s from it per rule.
    pub fn matcher_registry(&self) -> Arc<SiteMatcherRegistry> {
        self.matcher_registry.clone()
    }

    pub async fn list_all_keys(&self) -> Vec<GeoFileCacheKey> {
        self.cache.list_keys().await.unwrap_or_default()
    }

    pub async fn get_cache_value_by_key(&self, key: &GeoFileCacheKey) -> Option<GeoDomainConfig> {
        self.cache.load_entry(&key.name, &key.key).await.unwrap_or_else(|e| {
            tracing::error!("load geo site cache {}/{} failed: {}", key.name, key.key, e);
            None
        })
    }

    pub async fn query_geo_by_name(&self, name: Option<String>) -> Vec<GeoSiteSourceConfig> {
        self.store.query_by_name(name).await.unwrap()
    }

    pub async fn lookup_domain(&self, domain: &str) -> Result<Vec<GeoSiteLookupResult>, GeoError> {
        let normalized = normalize_domain_name(domain)
            .map_err(|_| GeoError::SiteInvalidLookupDomain(domain.to_string()))?;

        let hits = self.cache.lookup_rules_by_domain(&normalized).await.map_err(GeoError::from)?;

        let mut grouped: HashMap<GeoFileCacheKey, Vec<GeoSiteFileConfig>> = HashMap::new();
        for hit in hits {
            grouped.entry(hit.key).or_default().push(GeoSiteFileConfig {
                match_type: hit.match_type,
                value: hit.domain,
                attributes: hit.attributes,
            });
        }

        let mut result: Vec<GeoSiteLookupResult> =
            grouped.into_iter().map(|(key, values)| GeoSiteLookupResult { key, values }).collect();
        result.sort_by(|a, b| a.key.key.cmp(&b.key.key).then(a.key.name.cmp(&b.key.name)));
        Ok(result)
    }

    pub async fn update_geo_config_by_bytes(
        &self,
        name: String,
        file_bytes: impl Into<Vec<u8>>,
    ) -> Result<(), GeoError> {
        let Some(config) = self
            .query_geo_by_name(Some(name.clone()))
            .await
            .into_iter()
            .find(|config| config.name == name)
        else {
            tracing::warn!("update_geo_config_by_bytes: config '{}' not found", name);
            return Err(GeoError::SiteConfigNotFound(name));
        };
        let cancel = self
            .tasks
            .insert(config.id, GeoSourceKind::Site, GeoTaskPhase::Verifying)
            .map_err(|()| GeoError::TaskAlreadyRunning)?;
        self.spawn_geo_task(config, GeoTaskMode::Upload(file_bytes.into()), cancel);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ConfigStoreController for GeoSiteService {
    type Id = Uuid;

    type Config = GeoSiteSourceConfig;

    type Store = GeoSiteConfigRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        for change in changes {
            self.tasks.cancel_task(change.new.id);
            if let GeoSiteSource::Direct { ref data } = change.new.source {
                let apply_result = self.write_direct_to_cache(&change.new.name, data).await;
                tracing::debug!(
                    "update direct geo: name={} changed_keys={} unchanged_keys={} deleted_keys={}",
                    change.new.name,
                    apply_result.changed_keys.len(),
                    apply_result.unchanged_keys,
                    apply_result.deleted_keys,
                );
                self.notify_geo_changes(apply_result.changed_keys).await;
            }
        }
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.tasks.cancel_task(old.id);
        remove_raw_dat("site", old.id);
        remove_geo_snapshot("site", old.id);
    }
}

#[cfg(test)]
mod tests;

use landscape_common::{
    concurrency::task_label,
    config_service::geo::{
        GeoDomainConfig, GeoError, GeoFileCacheKey, GeoSiteFileConfig, GeoSiteLookupResult,
        GeoSiteSource, GeoSourceKind, GeoTaskPhase, GeoTaskProgress, RawDatState,
    },
    database::store::{Change, ConfigStore},
    dns::domain::{normalize_domain_name, normalize_domain_string},
    dns::rule::DomainMatchType,
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
    time::{Duration, Instant},
};

use landscape_common::{
    args::LAND_HOME_PATH,
    config_service::geo::{GeoSiteSourceConfig, normalize_adguard_key},
    event::dns::DnsEvent,
};
use landscape_core::geo_cache::{
    CacheWriteOutcome, GeoCacheDatabase, SiteCacheRepository, SiteMatcherRegistry, SiteRuleRow,
};
use landscape_database::{
    geo_site::repository::GeoSiteConfigRepository, provider::LandscapeDBServiceProvider,
};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use super::raw_file::{
    SealedRawFile, StreamToTmpError, raw_dat_path, remove_raw_dat, stream_to_tmp,
    sweep_orphan_raw_files, write_bytes_to_tmp,
};
use super::{GEO_PROGRESS_PUBLISH_INTERVAL, GeoTaskMode, GeoTaskRegistry, TaskGuard};

const A_DAY: u64 = 60 * 60 * 24;

type GeoContentHash = [u8; 32];

fn geo_values_hash(values: &[GeoSiteFileConfig]) -> GeoContentHash {
    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, values.len());

    for value in values {
        hasher.update([domain_match_type_tag(&value.match_type)]);
        update_len_prefixed(&mut hasher, value.value.len());
        hasher.update(value.value.as_bytes());

        // HashSet iteration order is intentionally randomized. Sort only the
        // borrowed attribute names so equivalent Geo entries get the same hash.
        let mut attributes: Vec<&str> = value.attributes.iter().map(String::as_str).collect();
        attributes.sort_unstable();
        update_len_prefixed(&mut hasher, attributes.len());
        for attribute in attributes {
            update_len_prefixed(&mut hasher, attribute.len());
            hasher.update(attribute.as_bytes());
        }
    }

    hasher.finalize().into()
}

fn update_len_prefixed(hasher: &mut Sha256, length: usize) {
    hasher.update((length as u64).to_be_bytes());
}

/// Hex content hash stored in the cache for skip-writes.
fn geo_values_hash_hex(values: &[GeoSiteFileConfig]) -> String {
    geo_values_hash(values).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn domain_match_type_tag(match_type: &DomainMatchType) -> u8 {
    match match_type {
        DomainMatchType::Plain => 0,
        DomainMatchType::Regex => 1,
        DomainMatchType::Domain => 2,
        DomainMatchType::Full => 3,
    }
}

/// Domain-matching values are normalized for SQL candidate probing; Regex
/// values are patterns where case and trailing `.` are significant, stored
/// verbatim.
fn normalize_site_rule_value(match_type: &DomainMatchType, value: String) -> String {
    match match_type {
        DomainMatchType::Regex => value,
        _ => normalize_domain_string(value),
    }
}

#[derive(Debug, Default)]
struct GeoCacheApplyResult {
    changed_keys: HashSet<GeoFileCacheKey>,
    unchanged_keys: usize,
    deleted_keys: usize,
}

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
        if let Ok(cancel) = self.tasks.insert(config.id, GeoSourceKind::Site, GeoTaskPhase::Parsing)
        {
            self.spawn_geo_task(config.clone(), GeoTaskMode::RestoreOnly, cancel);
        }
    }

    async fn download_to_sealed(
        &self,
        source_id: Uuid,
        url: &str,
        dat_path: &std::path::Path,
        cancel: &CancellationToken,
    ) -> Result<SealedRawFile, GeoError> {
        // Downloads run at most once a day per source, so connection reuse
        // across tasks would not pay for a shared client.
        let client = Client::new();
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| GeoError::RawDatReadFailed(format!("request {url} error: {e}")))?;
        if !response.status().is_success() {
            return Err(GeoError::RawDatReadFailed(format!(
                "{url} returned HTTP {}",
                response.status()
            )));
        }
        let bytes_total = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let registry = self.tasks.clone();
        let mut last_publish: Option<Instant> = None;
        let should_stop = || cancel.is_cancelled();
        stream_to_tmp(response.bytes_stream(), dat_path, &should_stop, &mut |written| {
            let now = Instant::now();
            let due = last_publish
                .is_none_or(|last| now.duration_since(last) >= GEO_PROGRESS_PUBLISH_INTERVAL);
            if due {
                registry.update_download(source_id, written, bytes_total);
                last_publish = Some(now);
            }
        })
        .await
        .map_err(|e| match e {
            StreamToTmpError::Cancelled => GeoError::TaskCancelled,
            StreamToTmpError::Io(e) => {
                GeoError::RawDatReadFailed(format!("download {} to {dat_path:?} failed: {e}", url))
            }
        })
    }

    async fn parse_dat_entries(
        &self,
        bytes: Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<Vec<(String, Vec<GeoSiteFileConfig>)>, GeoError> {
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        let result = tokio::task::spawn_blocking(move || {
            landscape_protobuf::read_geo_sites_from_bytes(bytes)
        })
        .await
        .map_err(|e| GeoError::RawDatReadFailed(format!("parse worker join failed: {e}")))??;
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        Ok(result.into_iter().collect())
    }

    async fn parse_source_bytes(
        &self,
        source: &GeoSiteSource,
        bytes: Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<Vec<(String, Vec<GeoSiteFileConfig>)>, GeoError> {
        match source {
            GeoSiteSource::Url { .. } => self.parse_dat_entries(bytes, cancel).await,
            GeoSiteSource::AdguardHome { key, .. } => {
                let key = normalize_adguard_key(key);
                let cancel = cancel.clone();
                let domains = tokio::task::spawn_blocking(move || {
                    landscape_protobuf::parse_adguard_rules_with(&bytes, &|| cancel.is_cancelled())
                })
                .await
                .map_err(|e| {
                    GeoError::RawDatReadFailed(format!("parse worker join failed: {e}"))
                })??;
                Ok(vec![(key, domains)])
            }
            GeoSiteSource::Direct { .. } => Ok(vec![]),
        }
    }

    async fn run_geo_task(
        &self,
        config: GeoSiteSourceConfig,
        mode: GeoTaskMode,
        cancel: &CancellationToken,
    ) {
        let source_id = config.id;
        let dat_path = raw_dat_path("site", source_id);
        let upload_mode = matches!(mode, GeoTaskMode::Upload(_));

        let sealed = match mode {
            GeoTaskMode::Download => {
                let url = match &config.source {
                    GeoSiteSource::Url { url, .. } | GeoSiteSource::AdguardHome { url, .. } => {
                        url.clone()
                    }
                    _ => return,
                };
                tracing::debug!("download file: {}", url);
                let time = Instant::now();
                match self.download_to_sealed(source_id, &url, &dat_path, cancel).await {
                    Ok(sealed) => {
                        tracing::debug!(
                            "handle file done: {}, time: {}ms",
                            url,
                            time.elapsed().as_millis()
                        );
                        Some(sealed)
                    }
                    Err(GeoError::TaskCancelled) => {
                        tracing::info!("refresh geo site source {} cancelled", config.name);
                        return;
                    }
                    Err(e) => {
                        tracing::error!("refresh geo site source {} error: {}", config.name, e);
                        return;
                    }
                }
            }
            GeoTaskMode::RestoreOnly => {
                let Ok(bytes) = fs::read(&dat_path) else {
                    return;
                };
                self.tasks.advance(source_id, GeoTaskPhase::Parsing);
                match self.parse_source_bytes(&config.source, bytes, cancel).await {
                    Ok(entries) if !entries.is_empty() => {
                        let apply_result = self.apply_geo_values(&config.name, entries).await;
                        tracing::info!(
                            "restored geo site cache '{}' from {:?}",
                            config.name,
                            dat_path
                        );
                        self.notify_geo_changes(apply_result.changed_keys).await;
                    }
                    Ok(_) => {}
                    Err(GeoError::TaskCancelled) => {}
                    Err(e) => {
                        tracing::warn!("restore geo site cache from {:?} failed: {}", dat_path, e);
                    }
                }
                return;
            }
            GeoTaskMode::Upload(file_bytes) => {
                if matches!(config.source, GeoSiteSource::Direct { .. }) {
                    tracing::warn!(
                        "upload is not supported for direct geo site source '{}'",
                        config.name
                    );
                    return;
                }
                match write_bytes_to_tmp(&dat_path, &file_bytes) {
                    Ok(sealed) => Some(sealed),
                    Err(e) => {
                        tracing::warn!("persist raw geo site file {:?} failed: {}", dat_path, e);
                        return;
                    }
                }
            }
        };

        let Some(sealed) = sealed else { return };
        if cancel.is_cancelled() {
            sealed.abort();
            return;
        }

        self.tasks.advance(source_id, GeoTaskPhase::Verifying);
        let bytes = match sealed.read_back() {
            Ok(bytes) => bytes,
            Err(e) => {
                sealed.abort();
                tracing::error!("read back {:?} failed: {}", dat_path, e);
                return;
            }
        };

        self.tasks.advance(source_id, GeoTaskPhase::Parsing);
        let parsed = if upload_mode {
            self.parse_dat_entries(bytes, cancel).await
        } else {
            self.parse_source_bytes(&config.source, bytes, cancel).await
        };
        let entries = match parsed {
            Ok(entries) => entries,
            Err(GeoError::TaskCancelled) => {
                sealed.abort();
                return;
            }
            Err(e) => {
                sealed.abort();
                tracing::error!("parse geo site data for '{}' failed: {}", config.name, e);
                return;
            }
        };
        if cancel.is_cancelled() {
            sealed.abort();
            return;
        }

        // A config deleted mid-flight can still commit here and resurrect the
        // raw dat file that `notify_deleted` removed; the daily refresh sweep
        // removes such orphans.
        if let Err(e) = sealed.commit() {
            tracing::warn!("persist raw geo site file {:?} failed: {}", dat_path, e);
        }
        self.tasks.advance(source_id, GeoTaskPhase::Applying);
        let apply_result = self.apply_geo_values(&config.name, entries).await;

        match self.store.bump_refresh_schedule(source_id).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    "geo site config {} deleted during task; skip schedule update",
                    config.name
                );
            }
            Err(e) => {
                tracing::warn!("bump geo site refresh schedule {} failed: {}", config.name, e);
            }
        }

        tracing::debug!(
            "apply geo site done: name={} changed_keys={} unchanged_keys={} deleted_keys={}",
            config.name,
            apply_result.changed_keys.len(),
            apply_result.unchanged_keys,
            apply_result.deleted_keys,
        );
        self.notify_geo_changes(apply_result.changed_keys).await;
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

    pub async fn get_raw_dat_or_start_download(&self, id: Uuid) -> Result<RawDatState, GeoError> {
        let dat_path = raw_dat_path("site", id);
        if dat_path.exists() {
            let bytes = fs::read(&dat_path)
                .map_err(|e| GeoError::RawDatReadFailed(format!("{dat_path:?}: {e}")))?;
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
                    if !due && !self.has_cached_name(&config.name).await {
                        self.spawn_restore_task(&config);
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

    /// Remove cache rows and raw dat files whose source config no longer
    /// exists. Runs on every refresh so the daily tick also sweeps orphans
    /// left behind by deleted configs.
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
        // Refresh Direct configs immediately when updated
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
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use landscape_common::config_service::geo::GeoSiteFileConfig;
    use landscape_common::dns::rule::{DomainConfig, DomainMatchType};
    use landscape_core::geo_cache::{GeoCacheDatabase, SiteCacheRepository, SiteRuleRow};

    use super::{
        GeoContentHash, domain_match_type_tag, geo_values_hash, normalize_site_rule_value,
    };

    fn geo_value(value: &str, attributes: &[&str]) -> GeoSiteFileConfig {
        GeoSiteFileConfig {
            match_type: DomainMatchType::Domain,
            value: value.to_string(),
            attributes: attributes.iter().map(|attribute| (*attribute).to_string()).collect(),
        }
    }

    #[test]
    fn geo_hash_ignores_attribute_hashset_order() {
        let first = vec![geo_value("example.com", &["cn", "ads"])];
        let second = vec![geo_value("example.com", &["ads", "cn"])];

        assert_eq!(geo_values_hash(&first), geo_values_hash(&second));
    }

    #[test]
    fn geo_hash_changes_for_matching_content() {
        let first = vec![geo_value("example.com", &["cn"])];
        let changed_domain = vec![geo_value("changed.example.com", &["cn"])];
        let changed_attribute = vec![geo_value("example.com", &["ads"])];

        assert_ne!(geo_values_hash(&first), geo_values_hash(&changed_domain));
        assert_ne!(geo_values_hash(&first), geo_values_hash(&changed_attribute));
    }

    #[test]
    fn geo_hash_distinguishes_match_types() {
        assert_ne!(
            domain_match_type_tag(&DomainMatchType::Domain),
            domain_match_type_tag(&DomainMatchType::Full)
        );
    }

    #[test]
    fn geo_hash_is_a_fixed_size_digest() {
        let hash: GeoContentHash = geo_values_hash(&[]);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn storage_normalization_trims_and_lowercases_domain_types() {
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Domain, "Example.COM.".to_string()),
            "example.com"
        );
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Full, "WWW.Example.com..".to_string()),
            "www.example.com"
        );
        assert_eq!(normalize_site_rule_value(&DomainMatchType::Plain, "Foo.".to_string()), "foo");
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Domain, "example.com".to_string()),
            "example.com"
        );
    }

    #[test]
    fn storage_normalization_keeps_regex_verbatim() {
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Regex, "[A-Z]+\\.".to_string()),
            "[A-Z]+\\."
        );
        assert_eq!(
            normalize_site_rule_value(&DomainMatchType::Regex, "^abc.".to_string()),
            "^abc."
        );
    }

    #[test]
    fn source_domain_conversion_does_not_include_attributes() {
        let value = geo_value("example.com", &["cn"]);
        let converted: DomainConfig = value.clone().into();
        assert_eq!(converted.value, value.value);
        assert_eq!(converted.match_type, value.match_type);
        assert_eq!(value.attributes, HashSet::from(["cn".to_string()]));
    }

    #[test]
    fn hashes_can_be_compared_by_cache_key() {
        let key = landscape_common::config_service::geo::GeoFileCacheKey {
            name: "site".to_string(),
            key: "CN".to_string(),
        };
        let mut hashes = HashMap::new();
        hashes.insert(key.clone(), geo_values_hash(&[geo_value("example.com", &[])]));
        assert!(hashes.contains_key(&key));
    }

    #[tokio::test]
    async fn sql_semantics_ground_truth() {
        // Golden semantics table shared with the DomainMatcher ground truth
        // (landscape-core/src/geo_cache/tests.rs) — keep both copies in sync.
        // Non-ASCII Domain rules never match on this side without an
        // explicit guard: queries arrive punycoded ASCII, so suffix
        // candidates can never equal non-ASCII rule text.
        let cases: Vec<(DomainMatchType, &'static str, &'static str, bool)> = vec![
            (DomainMatchType::Domain, "example.com", "example.com", true),
            (DomainMatchType::Domain, "example.com", "www.example.com", true),
            (DomainMatchType::Domain, "ogle.com", "www.google.com", false),
            (DomainMatchType::Domain, "Example.COM.", "www.example.com", true),
            (DomainMatchType::Full, "sub.example.com", "sub.example.com", true),
            (DomainMatchType::Full, "example.com", "www.example.com", false),
            (DomainMatchType::Full, "Sub.Example.COM.", "sub.example.com", true),
            (DomainMatchType::Plain, "cloud", "www.cloudflare.com", true),
            (DomainMatchType::Plain, "Foo.", "www.foo.com", true),
            (DomainMatchType::Plain, "cloud", "example.com", false),
            (DomainMatchType::Plain, "goog_e", "www.google.com", false),
            (DomainMatchType::Plain, "100%", "www.google.com", false),
            (DomainMatchType::Regex, "^[a-z]+\\.", "www.example.com", true),
            (DomainMatchType::Regex, "[A-Z]+", "www.example.com", false),
            (DomainMatchType::Regex, "(invalid", "anything.com", false),
            (DomainMatchType::Domain, "例子.com", "www.xn--fsqu00a.com", false),
        ];

        let dir = tempfile::tempdir().unwrap();
        let repo = SiteCacheRepository::new(GeoCacheDatabase::open_site(dir.path()).await.unwrap());

        // one key per case (rule-per-key mirrors the matcher side's
        // rule-per-matcher), written through the production path: storage
        // normalization + write-time pattern validation
        for (index, (match_type, value, _query, _expected)) in cases.iter().enumerate() {
            let row = SiteRuleRow::new(
                match_type.clone(),
                normalize_site_rule_value(match_type, value.to_string()),
                HashSet::new(),
            );
            repo.replace_by_name("geosite", &format!("R{index}"), "hash", vec![row]).await.unwrap();
        }

        for (index, (match_type, value, query, expected)) in cases.iter().enumerate() {
            let hits = repo.lookup_rules_by_domain(query).await.unwrap();
            let hit = hits.iter().find(|hit| hit.key.key == format!("R{index}"));
            assert_eq!(
                hit.is_some(),
                *expected,
                "rule {value:?} ({match_type:?}) vs query {query:?}"
            );
            if *expected {
                let hit = hit.expect("checked above");
                assert_eq!(hit.match_type, *match_type);
                assert_eq!(hit.domain, normalize_site_rule_value(match_type, value.to_string()));
            }
        }

        // a multi-rule key pins grouping and within-key seq order
        repo.replace_by_name(
            "geosite",
            "PRIVATE",
            "hash",
            vec![
                SiteRuleRow::new(DomainMatchType::Domain, "lan".into(), HashSet::new()),
                SiteRuleRow::new(DomainMatchType::Full, "router.lan".into(), HashSet::new()),
            ],
        )
        .await
        .unwrap();

        let hits = repo.lookup_rules_by_domain("router.lan").await.unwrap();
        let private: Vec<&str> = hits
            .iter()
            .filter(|hit| hit.key.key == "PRIVATE")
            .map(|hit| hit.domain.as_str())
            .collect();
        assert_eq!(private, vec!["lan", "router.lan"]);
        let myhost = repo.lookup_rules_by_domain("myhost.lan").await.unwrap();
        assert!(myhost.iter().any(|hit| hit.key.key == "PRIVATE" && hit.domain == "lan"));
    }
}

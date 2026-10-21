use landscape_common::{
    concurrency::task_label,
    config_service::geo::{
        GeoError, GeoFileCacheKey, GeoIpConfig, GeoIpLookupResult, GeoIpSource, GeoIpSourceConfig,
        GeoSourceKind, GeoTaskPhase, GeoTaskProgress, RawDatState,
    },
    database::store::{Change, ConfigStore},
    flow::ip_mark::{IpMarkInfo, WanIPRuleSource, WanIpRuleConfig},
    memtrack::{TaggedFuture, subsystem_from_task_label},
    service::controller::ConfigStoreController,
    utils::time::get_f64_timestamp,
};
use uuid::Uuid;

use std::{
    collections::HashMap, collections::HashSet, fs, future::Future, net::IpAddr, time::Duration,
};

use landscape_common::{args::LAND_HOME_PATH, event::dns::DstIpEvent};
use landscape_core::geo_cache::{GeoCacheDatabase, IpCacheRepository, IpCidrRow};
use landscape_database::{
    geo_ip::repository::GeoIpSourceConfigRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::broadcast;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use super::ip_values::geo_ip_content_hash;
use super::raw_file::{raw_dat_path, remove_raw_dat, sweep_orphan_raw_files};
use super::storage::{geo_snapshot_path, remove_geo_snapshot, sweep_orphan_geo_snapshots};
use super::{GeoTaskMode, GeoTaskRegistry, TaskGuard};

mod snapshot_pipeline;
#[cfg(test)]
mod tests;

const A_DAY: u64 = 60 * 60 * 24;

#[derive(Clone)]
pub struct GeoIpService {
    store: GeoIpSourceConfigRepository,
    cache: IpCacheRepository,
    dst_ip_events_tx: broadcast::Sender<DstIpEvent>,
    tasks: GeoTaskRegistry,
    stop_token: CancellationToken,
    tracker: TaskTracker,
}

impl GeoIpService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dst_ip_events_tx: broadcast::Sender<DstIpEvent>,
    ) -> Self {
        let store = store.geo_ip_rule_store();

        let cache = IpCacheRepository::new(
            GeoCacheDatabase::open_ip(&LAND_HOME_PATH).await.expect("open geo ip cache db"),
        );

        let service = Self {
            store,
            cache,
            dst_ip_events_tx,
            tasks: GeoTaskRegistry::default(),
            stop_token: CancellationToken::new(),
            tracker: TaskTracker::new(),
        };
        let service_clone = service.clone();
        let stop_token = service.stop_token.clone();
        service.spawn_tracked(task_label::task::GEO_IP_OBSERVER, async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(A_DAY));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            // The current network may not be ready; delaying the update check.
            tokio::select! {
                _ = stop_token.cancelled() => {},
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    loop {
                        service_clone.refresh(false).await;
                        tokio::select! {
                            _ = stop_token.cancelled() => break,
                            _ = ticker.tick() => {},
                        }
                    }
                }
            }
            tracing::info!("geo ip daily refresh loop stopped");
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
            Ok(()) => tracing::info!("geo ip background tasks stopped"),
            Err(_) => tracing::warn!(
                "geo ip shutdown timed out after {timeout:?}; in-flight refresh may still be draining"
            ),
        }
    }

    pub fn task_progress_snapshot(&self) -> Vec<GeoTaskProgress> {
        self.tasks.progress_snapshot()
    }

    pub fn cancel_geo_task(&self, id: Uuid) -> bool {
        self.tasks.cancel_task(id)
    }

    pub async fn resolve_geo_key_to_ips(
        &self,
        geo_key: &landscape_common::config_service::geo::GeoConfigKey,
    ) -> Vec<landscape_common::flow::ip_mark::IpConfig> {
        match self.cache.load_entry(&geo_key.name, &geo_key.key).await {
            Ok(Some(geo_ip_config)) => geo_ip_config.values,
            Ok(None) => vec![],
            Err(e) => {
                tracing::error!("load geo ip cache {}/{} failed: {}", geo_key.name, geo_key.key, e);
                vec![]
            }
        }
    }

    fn notify_dst_ip_updated(&self) {
        let _ = self.dst_ip_events_tx.send(DstIpEvent::GeoIpUpdated);
    }

    pub async fn convert_config_to_runtime_rule(
        &self,
        configs: Vec<WanIpRuleConfig>,
    ) -> Vec<IpMarkInfo> {
        // Deduplicate by cidr (ip + prefix) — keep the first occurrence (highest priority).
        // Configs are sorted by ascending index before calling, so the first seen = highest priority.
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::with_capacity(configs.len());
        for config in configs.into_iter() {
            let priority = config.index as u16;
            let mark = config.mark;
            for each in config.source.into_iter() {
                match each {
                    WanIPRuleSource::GeoKey(config_key) => {
                        match self.cache.load_entry(&config_key.name, &config_key.key).await {
                            Ok(Some(ips)) => {
                                result.reserve(ips.values.len());
                                for cidr in ips.values {
                                    if seen.insert(cidr.clone()) {
                                        result.push(IpMarkInfo { mark, cidr, priority });
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => tracing::error!(
                                "load geo ip cache {}/{} failed: {}",
                                config_key.name,
                                config_key.key,
                                e
                            ),
                        }
                    }
                    WanIPRuleSource::Config(c) => {
                        if seen.insert(c.clone()) {
                            result.push(IpMarkInfo { mark, cidr: c, priority });
                        }
                    }
                }
            }
        }
        result
    }

    fn spawn_geo_task(
        &self,
        config: GeoIpSourceConfig,
        mode: GeoTaskMode,
        cancel: CancellationToken,
    ) {
        let service = self.clone();
        let source_id = config.id;
        self.spawn_tracked(task_label::task::GEO_IP_OBSERVER, async move {
            let _guard = TaskGuard::new(service.tasks.clone(), source_id);
            service.run_geo_task(config, mode, &cancel).await;
        });
    }

    fn try_spawn_download_task(&self, config: GeoIpSourceConfig) -> bool {
        match self.tasks.insert(config.id, GeoSourceKind::Ip, GeoTaskPhase::Downloading) {
            Ok(cancel) => {
                self.spawn_geo_task(config, GeoTaskMode::Download, cancel);
                true
            }
            Err(()) => false,
        }
    }

    fn spawn_restore_task(&self, config: &GeoIpSourceConfig) {
        if let Ok(cancel) = self.tasks.insert(config.id, GeoSourceKind::Ip, GeoTaskPhase::Verifying)
        {
            self.spawn_geo_task(config.clone(), GeoTaskMode::RestoreOnly, cancel);
        }
    }

    async fn has_cached_name(&self, name: &str) -> bool {
        self.cache.has_name(name).await.unwrap_or_else(|e| {
            tracing::error!("query geo ip cache name '{name}' failed: {e}");
            false
        })
    }

    pub async fn get_raw_dat_or_start_download(&self, id: Uuid) -> Result<RawDatState, GeoError> {
        let dat_path = raw_dat_path("ip", id);
        if dat_path.exists() {
            let bytes = fs::read(&dat_path)
                .map_err(|e| GeoError::RawDatReadFailed(format!("{dat_path:?}: {e}")))?;
            return Ok(RawDatState::Ready(bytes));
        }

        let Some(config) = self.find_by_id(id).await? else {
            return Err(GeoError::IpNotFound(id));
        };
        if !matches!(config.source, GeoIpSource::Url { .. }) {
            return Err(GeoError::RawDatNotReady);
        }

        match self.tasks.insert(id, GeoSourceKind::Ip, GeoTaskPhase::Downloading) {
            Ok(cancel) => {
                self.spawn_geo_task(config, GeoTaskMode::Download, cancel);
                Ok(RawDatState::Started)
            }
            Err(()) => Ok(RawDatState::Running),
        }
    }

    pub async fn get_snapshot_or_start_download(&self, id: Uuid) -> Result<RawDatState, GeoError> {
        let snapshot_path = geo_snapshot_path("ip", id);
        if snapshot_path.exists() {
            let bytes = fs::read(&snapshot_path)
                .map_err(|e| GeoError::RawDatReadFailed(format!("{snapshot_path:?}: {e}")))?;
            return Ok(RawDatState::Ready(bytes));
        }

        let Some(config) = self.find_by_id(id).await? else {
            return Err(GeoError::IpNotFound(id));
        };
        if !matches!(config.source, GeoIpSource::Url { .. }) {
            return Err(GeoError::RawDatNotReady);
        }

        match self.tasks.insert(id, GeoSourceKind::Ip, GeoTaskPhase::Downloading) {
            Ok(cancel) => {
                self.spawn_geo_task(config, GeoTaskMode::Download, cancel);
                Ok(RawDatState::Started)
            }
            Err(()) => Ok(RawDatState::Running),
        }
    }

    pub async fn refresh(&self, force: bool) {
        let configs: Vec<GeoIpSourceConfig> = self.store.list().await.unwrap();

        let mut config_names = HashSet::new();
        let mut config_ids = HashSet::new();
        let now = get_f64_timestamp();

        for config in configs {
            config_names.insert(config.name.clone());
            config_ids.insert(config.id);

            match &config.source {
                GeoIpSource::Url { next_update_at, .. } => {
                    let due = force || *next_update_at < now;
                    if !due {
                        let snapshot_exists = geo_snapshot_path("ip", config.id).exists();
                        let legacy_raw_exists = raw_dat_path("ip", config.id).exists();
                        if snapshot_exists
                            || legacy_raw_exists
                            || !self.has_cached_name(&config.name).await
                        {
                            self.spawn_restore_task(&config);
                        }
                    }
                    if due && !self.try_spawn_download_task(config.clone()) {
                        tracing::debug!("geo ip source {} refresh already running", config.name);
                    }
                }
                GeoIpSource::Direct { data } => {
                    self.write_direct_to_cache(&config.name, data).await;
                    self.notify_dst_ip_updated();
                }
            }
        }

        self.sweep_orphans(&config_names, &config_ids).await;
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
            .collect::<Vec<GeoFileCacheKey>>();
        for key in need_to_remove {
            if let Err(e) = self.cache.delete_by_name(&key.name, &key.key).await {
                tracing::error!("delete geo ip cache {}/{} failed: {}", key.name, key.key, e);
            }
        }

        let removed = sweep_orphan_raw_files("ip", config_ids);
        if !removed.is_empty() {
            tracing::debug!("swept {} orphan geo ip raw file(s)", removed.len());
        }
        let removed = sweep_orphan_geo_snapshots("ip", config_ids);
        if !removed.is_empty() {
            tracing::debug!("swept {} orphan geo ip snapshot file(s)", removed.len());
        }
    }

    pub async fn refresh_one(&self, name: &str) -> Result<(), GeoError> {
        let configs: Vec<GeoIpSourceConfig> =
            self.store.list().await.map_err(|e| GeoError::IpConfigStoreFailed(e.to_string()))?;
        let Some(config) = configs.into_iter().find(|c| c.name == name) else {
            return Err(GeoError::IpConfigNotFound(name.to_string()));
        };

        match &config.source {
            GeoIpSource::Url { .. } => {
                if !self.try_spawn_download_task(config) {
                    return Err(GeoError::TaskAlreadyRunning);
                }
            }
            GeoIpSource::Direct { data } => {
                self.write_direct_to_cache(&config.name, data).await;
                self.store
                    .upsert(config.clone())
                    .await
                    .map_err(|e| GeoError::IpConfigStoreFailed(e.to_string()))?;
                self.notify_dst_ip_updated();
            }
        }
        Ok(())
    }

    async fn write_direct_to_cache(
        &self,
        name: &str,
        data: &[landscape_common::config_service::geo::GeoIpDirectItem],
    ) {
        let result: HashMap<String, Vec<landscape_common::flow::ip_mark::IpConfig>> =
            data.iter().map(|item| (item.key.clone(), item.values.clone())).collect();
        self.replace_cache_by_name(name, result).await;
    }

    async fn replace_cache_by_name(
        &self,
        name: &str,
        result: HashMap<String, Vec<landscape_common::flow::ip_mark::IpConfig>>,
    ) {
        let mut stale_keys: HashSet<GeoFileCacheKey> =
            self.cache.keys_for_name(name).await.unwrap_or_default().into_iter().collect();

        for (key, values) in result {
            let geo_key = key.to_ascii_uppercase();
            stale_keys.remove(&GeoFileCacheKey { name: name.to_string(), key: geo_key.clone() });

            let content_hash = geo_ip_content_hash(&values);
            let cidrs: Vec<IpCidrRow> = values
                .iter()
                .map(|config| IpCidrRow {
                    network: config.ip,
                    prefix_len: config.prefix.min(u8::MAX as u32) as u8,
                })
                .collect();

            if let Err(e) = self.cache.replace_by_name(name, &geo_key, &content_hash, cidrs).await {
                tracing::error!("write geo ip cache {}/{} failed: {}", name, geo_key, e);
            }
        }

        for key in stale_keys {
            if let Err(e) = self.cache.delete_by_name(&key.name, &key.key).await {
                tracing::error!("delete geo ip cache {}/{} failed: {}", key.name, key.key, e);
            }
        }
    }
}

impl GeoIpService {
    pub async fn list_all_keys(&self) -> Vec<GeoFileCacheKey> {
        self.cache.list_keys().await.unwrap_or_default()
    }

    pub async fn get_cache_value_by_key(&self, key: &GeoFileCacheKey) -> Option<GeoIpConfig> {
        self.cache.load_entry(&key.name, &key.key).await.unwrap_or_else(|e| {
            tracing::error!("load geo ip cache {}/{} failed: {}", key.name, key.key, e);
            None
        })
    }

    pub async fn lookup_ip(&self, input: &str) -> Result<Vec<GeoIpLookupResult>, GeoError> {
        let ip = input
            .parse::<IpAddr>()
            .map_err(|_| GeoError::IpInvalidLookupAddress(input.to_string()))?;

        let hits = self.cache.lookup_ip(ip).await.map_err(GeoError::from)?;

        let mut grouped: HashMap<GeoFileCacheKey, Vec<landscape_common::flow::ip_mark::IpConfig>> =
            HashMap::new();
        for hit in hits {
            grouped.entry(hit.key).or_default().push(landscape_common::flow::ip_mark::IpConfig {
                ip: hit.network,
                prefix: hit.prefix_len as u32,
            });
        }

        let mut result = grouped
            .into_iter()
            .map(|(key, values)| GeoIpLookupResult { key, values })
            .collect::<Vec<_>>();
        result.sort_by(|a, b| a.key.key.cmp(&b.key.key).then(a.key.name.cmp(&b.key.name)));
        Ok(result)
    }

    pub async fn query_geo_by_name(&self, name: Option<String>) -> Vec<GeoIpSourceConfig> {
        self.store.query_by_name(name).await.unwrap()
    }

    pub async fn update_geo_config_by_bytes(
        &self,
        name: String,
        file_bytes: impl Into<Vec<u8>>,
    ) -> Result<(), GeoError> {
        let config = self
            .query_geo_by_name(Some(name.clone()))
            .await
            .into_iter()
            .find(|config| config.name == name)
            .ok_or_else(|| GeoError::IpConfigNotFound(name.clone()))?;
        let cancel = self
            .tasks
            .insert(config.id, GeoSourceKind::Ip, GeoTaskPhase::Verifying)
            .map_err(|()| GeoError::TaskAlreadyRunning)?;
        self.spawn_geo_task(config, GeoTaskMode::Upload(file_bytes.into()), cancel);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ConfigStoreController for GeoIpService {
    type Id = Uuid;

    type Config = GeoIpSourceConfig;

    type Store = GeoIpSourceConfigRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        for change in changes {
            self.tasks.cancel_task(change.new.id);
            if let GeoIpSource::Direct { ref data } = change.new.source {
                self.write_direct_to_cache(&change.new.name, data).await;
                self.notify_dst_ip_updated();
            }
        }
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.tasks.cancel_task(old.id);
        remove_raw_dat("ip", old.id);
        remove_geo_snapshot("ip", old.id);
    }
}

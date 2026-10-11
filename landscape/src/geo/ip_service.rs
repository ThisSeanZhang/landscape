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
    collections::HashMap,
    collections::HashSet,
    fs,
    future::Future,
    net::IpAddr,
    time::{Duration, Instant},
};

use landscape_common::{args::LAND_HOME_PATH, event::dns::DstIpEvent};
use landscape_core::geo_cache::{GeoCacheDatabase, IpCacheRepository, IpCidrRow};
use landscape_database::{
    geo_ip::repository::GeoIpSourceConfigRepository, provider::LandscapeDBServiceProvider,
};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
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

/// Content hash over the deduplicated, sorted, host-bit-masked CIDR set.
fn geo_ip_content_hash(values: &[landscape_common::flow::ip_mark::IpConfig]) -> String {
    fn masked(ip: IpAddr, prefix_len: u32) -> Vec<u8> {
        match ip {
            IpAddr::V4(addr) => {
                let mask = if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len.min(32)) };
                (u32::from(addr) & mask).to_be_bytes().to_vec()
            }
            IpAddr::V6(addr) => {
                let mask =
                    if prefix_len == 0 { 0 } else { u128::MAX << (128 - prefix_len.min(128)) };
                (u128::from(addr) & mask).to_be_bytes().to_vec()
            }
        }
    }

    let mut canonical: Vec<(u8, u32, Vec<u8>)> = values
        .iter()
        .map(|config| {
            let family = match config.ip {
                IpAddr::V4(_) => 4u8,
                IpAddr::V6(_) => 6u8,
            };
            (family, config.prefix, masked(config.ip, config.prefix))
        })
        .collect();
    canonical.sort_unstable();
    canonical.dedup();

    let mut hasher = Sha256::new();
    hasher.update((canonical.len() as u64).to_be_bytes());
    for (family, prefix, network) in canonical {
        hasher.update([family]);
        hasher.update(prefix.to_be_bytes());
        hasher.update((network.len() as u64).to_be_bytes());
        hasher.update(&network);
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

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
        if let Ok(cancel) = self.tasks.insert(config.id, GeoSourceKind::Ip, GeoTaskPhase::Parsing) {
            self.spawn_geo_task(config.clone(), GeoTaskMode::RestoreOnly, cancel);
        }
    }

    async fn run_geo_task(
        &self,
        config: GeoIpSourceConfig,
        mode: GeoTaskMode,
        cancel: &CancellationToken,
    ) {
        let source_id = config.id;
        let dat_path = raw_dat_path("ip", source_id);

        let sealed = match mode {
            GeoTaskMode::Download => {
                let url = match &config.source {
                    GeoIpSource::Url { url, .. } => url.clone(),
                    _ => return,
                };
                tracing::debug!("download file: {}", url);
                let time = Instant::now();
                match self.download_to_sealed(source_id, &url, &dat_path, cancel).await {
                    Ok(sealed) => {
                        tracing::debug!(
                            "download file done: {}, time: {}s",
                            url,
                            time.elapsed().as_secs()
                        );
                        Some(sealed)
                    }
                    Err(GeoError::TaskCancelled) => {
                        tracing::info!("refresh geo ip source {} cancelled", config.name);
                        return;
                    }
                    Err(e) => {
                        tracing::error!("refresh geo ip source {} error: {}", config.name, e);
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
                    Ok(result) if !result.is_empty() => {
                        self.replace_cache_by_name(&config.name, result).await;
                        tracing::info!(
                            "restored geo ip cache '{}' from {:?}",
                            config.name,
                            dat_path
                        );
                    }
                    Ok(_) => {}
                    Err(GeoError::TaskCancelled) => {}
                    Err(e) => {
                        tracing::warn!("restore geo ip cache from {:?} failed: {}", dat_path, e);
                    }
                }
                return;
            }
            GeoTaskMode::Upload(file_bytes) => {
                if matches!(config.source, GeoIpSource::Direct { .. }) {
                    tracing::warn!(
                        "upload is not supported for direct geo ip source '{}'",
                        config.name
                    );
                    return;
                }
                match write_bytes_to_tmp(&dat_path, &file_bytes) {
                    Ok(sealed) => Some(sealed),
                    Err(e) => {
                        tracing::error!("persist raw geo ip file {:?} failed: {}", dat_path, e);
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
        let result = match self.parse_source_bytes(&config.source, bytes, cancel).await {
            Ok(result) => result,
            Err(GeoError::TaskCancelled) => {
                sealed.abort();
                return;
            }
            Err(e) => {
                sealed.abort();
                tracing::error!("refresh geo ip source {} error: {}", config.name, e);
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
            tracing::warn!("persist raw geo ip file {:?} failed: {}", dat_path, e);
        }
        self.tasks.advance(source_id, GeoTaskPhase::Applying);
        self.replace_cache_by_name(&config.name, result).await;

        match self.store.bump_refresh_schedule(source_id).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    "geo ip config {} deleted during task; skip schedule update",
                    config.name
                );
            }
            Err(e) => {
                tracing::error!("bump geo ip refresh schedule {} failed: {}", config.name, e);
            }
        }
        self.notify_dst_ip_updated();
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
            .map_err(|e| GeoError::IpSourceRequestFailed(e.to_string()))?;
        if !response.status().is_success() {
            return Err(GeoError::IpSourceRequestFailed(format!(
                "{} returned HTTP {}",
                url,
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
                GeoError::IpSourceRequestFailed(format!("stream to {dat_path:?}: {e}"))
            }
        })
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

    pub async fn refresh(&self, force: bool) {
        // 读取当前规则
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
                    if !due && !self.has_cached_name(&config.name).await {
                        self.spawn_restore_task(&config);
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

    async fn parse_source_bytes(
        &self,
        source: &GeoIpSource,
        bytes: impl Into<Vec<u8>>,
        cancel: &CancellationToken,
    ) -> Result<HashMap<String, Vec<landscape_common::flow::ip_mark::IpConfig>>, GeoError> {
        let bytes = bytes.into();
        match source {
            GeoIpSource::Url { format, txt_key, .. } => {
                if cancel.is_cancelled() {
                    return Err(GeoError::TaskCancelled);
                }
                let is_txt =
                    matches!(format, landscape_common::config_service::geo::GeoIpFileFormat::Txt);
                let format = format.clone();
                let txt_key = txt_key.clone();
                let cancel = cancel.clone();
                let result = tokio::task::spawn_blocking(move || {
                    landscape_protobuf::read_geo_ips_from_bytes_by_format(
                        bytes,
                        &format,
                        txt_key.as_deref(),
                        &|| cancel.is_cancelled(),
                    )
                })
                .await
                .map_err(|e| {
                    GeoError::IpSourceRequestFailed(format!("parse worker join failed: {e}"))
                })??;
                if is_txt {
                    tracing::info!(
                        "parsed geo ip txt with {} valid lines and {} skipped lines",
                        result.valid_lines,
                        result.skipped_lines
                    );
                }
                Ok(result.entries)
            }
            GeoIpSource::Direct { data } => {
                let mut result = HashMap::new();
                for item in data {
                    result.insert(item.key.to_ascii_uppercase(), item.values.clone());
                }
                Ok(result)
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
        // Refresh Direct configs immediately when updated
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
    }
}

#[cfg(test)]
mod tests {

    use std::{net::IpAddr, str::FromStr};

    #[test]
    fn content_hash_is_masked_and_dedup_stable() {
        let config = |network: &str, prefix: u32| landscape_common::flow::ip_mark::IpConfig {
            ip: IpAddr::from_str(network).unwrap(),
            prefix,
        };
        let masked_variants = vec![config("10.1.2.3", 8), config("10.200.0.9", 8)];
        let canonical = vec![config("10.0.0.0", 8)];

        assert_eq!(
            super::geo_ip_content_hash(&masked_variants),
            super::geo_ip_content_hash(&canonical)
        );
        assert_ne!(
            super::geo_ip_content_hash(&masked_variants),
            super::geo_ip_content_hash(&[config("11.0.0.0", 8)])
        );
    }
}

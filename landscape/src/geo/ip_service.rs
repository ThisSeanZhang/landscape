use landscape_common::geo_cache::file_store::GeoStoreKeyProvider;
use landscape_common::{
    concurrency::{spawn_task, task_label},
    config_service::geo::{
        GeoError, GeoFileCacheKey, GeoIpConfig, GeoIpLookupResult, GeoIpSource, GeoIpSourceConfig,
        RawDatState,
    },
    database::LandscapeStore,
    flow::ip_mark::{IpMarkInfo, WanIPRuleSource, WanIpRuleConfig},
    service::controller::ConfigController,
    utils::time::{get_f64_timestamp, MILL_A_DAY},
};
use uuid::Uuid;

use std::{
    collections::HashMap,
    collections::HashSet,
    fs,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use landscape_common::{
    args::LAND_HOME_PATH, event::dns::DstIpEvent, geo_cache::file_store::GeoCacheStore,
    LANDSCAPE_GEO_CACHE_TMP_DIR,
};
use landscape_database::{
    geo_ip::repository::GeoIpSourceConfigRepository, provider::LandscapeDBServiceProvider,
};
use reqwest::Client;
use tokio::sync::{broadcast, Mutex};

use super::raw_file::{
    raw_dat_path, remove_raw_dat, stream_to_tmp, write_bytes_to_tmp, SealedRawFile,
};

const A_DAY: u64 = 60 * 60 * 24;

pub type GeoDomainCacheStore = Arc<Mutex<GeoCacheStore<GeoFileCacheKey, GeoIpConfig>>>;

#[derive(Clone)]
pub struct GeoIpService {
    store: GeoIpSourceConfigRepository,
    file_cache: GeoDomainCacheStore,
    dst_ip_events_tx: broadcast::Sender<DstIpEvent>,
    raw_downloading: Arc<Mutex<HashSet<Uuid>>>,
}

impl GeoIpService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dst_ip_events_tx: broadcast::Sender<DstIpEvent>,
    ) -> Self {
        let store = store.geo_ip_rule_store();

        let file_cache = Arc::new(Mutex::new(GeoCacheStore::new(
            LAND_HOME_PATH.join(LANDSCAPE_GEO_CACHE_TMP_DIR),
            "ip".to_string(),
        )));

        let service = Self {
            store,
            file_cache,
            dst_ip_events_tx,
            raw_downloading: Arc::new(Mutex::new(HashSet::new())),
        };
        let service_clone = service.clone();
        spawn_task(task_label::task::GEO_IP_OBSERVER, async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(A_DAY));

            // The current network may not be ready; delaying the update check.
            tokio::time::sleep(Duration::from_secs(30)).await;

            loop {
                service_clone.refresh(false).await;
                ticker.tick().await;
            }
        });
        service
    }

    pub async fn resolve_geo_key_to_ips(
        &self,
        geo_key: &landscape_common::config_service::geo::GeoConfigKey,
    ) -> Vec<landscape_common::flow::ip_mark::IpConfig> {
        let mut lock = self.file_cache.lock().await;
        if let Some(geo_ip_config) = lock.get(&geo_key.get_file_cache_key()) {
            geo_ip_config.values
        } else {
            vec![]
        }
    }

    fn notify_dst_ip_updated(&self) {
        let _ = self.dst_ip_events_tx.send(DstIpEvent::GeoIpUpdated);
    }

    pub async fn convert_config_to_runtime_rule(
        &self,
        configs: Vec<WanIpRuleConfig>,
    ) -> Vec<IpMarkInfo> {
        let mut lock = self.file_cache.lock().await;
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
                        if let Some(ips) = lock.get(&config_key.get_file_cache_key()) {
                            result.reserve(ips.values.len());
                            for cidr in ips.values {
                                if seen.insert(cidr.clone()) {
                                    result.push(IpMarkInfo { mark, cidr, priority });
                                }
                            }
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

    async fn refresh_url_config(
        &self,
        client: &Client,
        config: &mut GeoIpSourceConfig,
    ) -> Result<(), GeoError> {
        let url = match &config.source {
            GeoIpSource::Url { url, .. } => url.clone(),
            _ => return Ok(()),
        };

        tracing::debug!("download file: {}", url);
        let time = Instant::now();

        let response = client
            .get(&url)
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
        let dat_path = raw_dat_path("ip", config.id);
        let sealed = stream_to_tmp(response.bytes_stream(), &dat_path)
            .await
            .map_err(|e| GeoError::IpSourceRequestFailed(format!("stream to {dat_path:?}: {e}")))?;
        let result =
            match self.parse_source_bytes(&config.source, read_back(&sealed, &dat_path)?).await {
                Ok(result) => result,
                Err(e) => {
                    sealed.abort();
                    return Err(e);
                }
            };
        if let Err(e) = sealed.commit() {
            tracing::warn!("persist raw geo ip file {:?} failed: {}", dat_path, e);
        }
        self.replace_cache_by_name(&config.name, result).await;

        if let GeoIpSource::Url { next_update_at, .. } = &mut config.source {
            *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
        }
        self.store
            .set(config.clone())
            .await
            .map_err(|e| GeoError::IpConfigStoreFailed(e.to_string()))?;

        tracing::debug!("handle file done: {}, time: {}s", url, time.elapsed().as_secs());
        self.notify_dst_ip_updated();
        Ok(())
    }

    async fn has_cached_name(&self, name: &str) -> bool {
        let lock = self.file_cache.lock().await;
        lock.keys().into_iter().any(|key| key.name == name)
    }

    async fn try_restore_from_raw(&self, config: &GeoIpSourceConfig) {
        let dat_path = raw_dat_path("ip", config.id);
        let Ok(bytes) = fs::read(&dat_path) else {
            return;
        };
        match self.parse_source_bytes(&config.source, bytes).await {
            Ok(result) if !result.is_empty() => {
                self.replace_cache_by_name(&config.name, result).await;
                tracing::info!("restored geo ip cache '{}' from {:?}", config.name, dat_path);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("restore geo ip cache from {:?} failed: {}", dat_path, e);
            }
        }
    }

    pub async fn get_raw_dat_or_start_download(&self, id: Uuid) -> Result<RawDatState, GeoError> {
        let dat_path = raw_dat_path("ip", id);
        if dat_path.exists() {
            let bytes = fs::read(&dat_path)
                .map_err(|e| GeoError::RawDatReadFailed(format!("{dat_path:?}: {e}")))?;
            return Ok(RawDatState::Ready(bytes));
        }

        let Some(config) = self.find_by_id(id).await else {
            return Err(GeoError::IpNotFound(id));
        };
        if !matches!(config.source, GeoIpSource::Url { .. }) {
            return Err(GeoError::RawDatNotReady);
        }

        let mut tasks = self.raw_downloading.lock().await;
        if !tasks.insert(id) {
            return Ok(RawDatState::Running);
        }
        drop(tasks);

        let service = self.clone();
        let name = config.name.clone();
        spawn_task(task_label::task::GEO_IP_OBSERVER, async move {
            if let Err(e) = service.refresh_one(&name).await {
                tracing::error!("background download geo ip dat for '{}' failed: {}", name, e);
            }
            service.raw_downloading.lock().await.remove(&id);
        });
        Ok(RawDatState::Started)
    }

    pub async fn refresh(&self, force: bool) {
        // 读取当前规则
        let configs: Vec<GeoIpSourceConfig> = self.store.list().await.unwrap();

        let client = Client::new();
        let mut config_names = HashSet::new();
        let now = get_f64_timestamp();

        for mut config in configs {
            config_names.insert(config.name.clone());

            match &config.source {
                GeoIpSource::Url { next_update_at, .. } => {
                    if !self.has_cached_name(&config.name).await {
                        self.try_restore_from_raw(&config).await;
                    }
                    if !force && *next_update_at >= now {
                        continue;
                    }
                    if let Err(e) = self.refresh_url_config(&client, &mut config).await {
                        tracing::error!("refresh geo ip source {} error: {}", config.name, e);
                    }
                }
                GeoIpSource::Direct { data } => {
                    self.write_direct_to_cache(&config.name, data).await;
                    self.notify_dst_ip_updated();
                }
            }
        }

        if force {
            let mut file_cache_lock = self.file_cache.lock().await;
            let need_to_remove = file_cache_lock
                .keys()
                .into_iter()
                .filter(|k| !config_names.contains(&k.name))
                .collect::<HashSet<GeoFileCacheKey>>();
            for key in need_to_remove {
                file_cache_lock.del(&key);
            }
        }
    }

    pub async fn refresh_one(&self, name: &str) -> Result<(), GeoError> {
        let configs: Vec<GeoIpSourceConfig> =
            self.store.list().await.map_err(|e| GeoError::IpConfigStoreFailed(e.to_string()))?;
        let Some(mut config) = configs.into_iter().find(|c| c.name == name) else {
            return Err(GeoError::IpConfigNotFound(name.to_string()));
        };

        let client = Client::new();

        match &config.source {
            GeoIpSource::Url { .. } => self.refresh_url_config(&client, &mut config).await?,
            GeoIpSource::Direct { data } => {
                self.write_direct_to_cache(&config.name, data).await;
                self.store
                    .set(config.clone())
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
        let mut file_cache_lock = self.file_cache.lock().await;

        let exist_keys = file_cache_lock
            .keys()
            .into_iter()
            .filter(|k| k.name == name)
            .collect::<HashSet<GeoFileCacheKey>>();

        let mut new_keys = HashSet::new();
        for item in data {
            let info = GeoIpConfig {
                name: name.to_string(),
                key: item.key.to_ascii_uppercase(),
                values: item.values.clone(),
            };
            new_keys.insert(info.get_store_key());
            file_cache_lock.set(info);
        }

        for key in exist_keys {
            if !new_keys.contains(&key) {
                file_cache_lock.del(&key);
            }
        }
    }

    async fn replace_cache_by_name(
        &self,
        name: &str,
        result: HashMap<String, Vec<landscape_common::flow::ip_mark::IpConfig>>,
    ) {
        let mut file_cache_lock = self.file_cache.lock().await;
        let mut exist_keys = file_cache_lock
            .keys()
            .into_iter()
            .filter(|k| k.name == name)
            .collect::<HashSet<GeoFileCacheKey>>();

        for (key, values) in result {
            let info = GeoIpConfig {
                name: name.to_string(),
                key: key.to_ascii_uppercase(),
                values,
            };
            exist_keys.remove(&info.get_store_key());
            file_cache_lock.set(info);
        }

        for key in exist_keys {
            file_cache_lock.del(&key);
        }
    }

    async fn parse_source_bytes(
        &self,
        source: &GeoIpSource,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<HashMap<String, Vec<landscape_common::flow::ip_mark::IpConfig>>, GeoError> {
        let bytes = bytes.into();
        match source {
            GeoIpSource::Url { format, txt_key, .. } => {
                let result = landscape_protobuf::read_geo_ips_from_bytes_by_format(
                    bytes,
                    format,
                    txt_key.as_deref(),
                )
                .await?;
                if matches!(format, landscape_common::config_service::geo::GeoIpFileFormat::Txt) {
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
        let lock = self.file_cache.lock().await;
        lock.keys()
    }

    pub async fn get_cache_value_by_key(&self, key: &GeoFileCacheKey) -> Option<GeoIpConfig> {
        let mut lock = self.file_cache.lock().await;
        lock.get(key)
    }

    pub async fn lookup_ip(&self, input: &str) -> Result<Vec<GeoIpLookupResult>, GeoError> {
        let ip = input
            .parse::<IpAddr>()
            .map_err(|_| GeoError::IpInvalidLookupAddress(input.to_string()))?;
        let mut lock = self.file_cache.lock().await;
        let mut result = Vec::new();
        for key in lock.keys() {
            let Some(config) = lock.get(&key) else { continue };
            let values = config
                .values
                .into_iter()
                .filter(|cidr| cidr_contains(cidr.ip, cidr.prefix, ip))
                .collect::<Vec<_>>();
            if !values.is_empty() {
                result.push(GeoIpLookupResult { key, values });
            }
        }
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
        let file_bytes = file_bytes.into();
        let dat_path = raw_dat_path("ip", config.id);
        let sealed = write_bytes_to_tmp(&dat_path, &file_bytes)
            .map_err(|e| GeoError::RawDatReadFailed(format!("{dat_path:?}: {e}")))?;
        drop(file_bytes);
        let result =
            match self.parse_source_bytes(&config.source, read_back(&sealed, &dat_path)?).await {
                Ok(result) => result,
                Err(e) => {
                    sealed.abort();
                    return Err(e);
                }
            };
        if let Err(e) = sealed.commit() {
            tracing::warn!("persist raw geo ip file {:?} failed: {}", dat_path, e);
        }
        self.replace_cache_by_name(&name, result).await;
        self.store.set(config).await.map_err(|e| GeoError::IpConfigStoreFailed(e.to_string()))?;
        self.notify_dst_ip_updated();
        Ok(())
    }
}

fn read_back(sealed: &SealedRawFile, dat_path: &std::path::Path) -> Result<Vec<u8>, GeoError> {
    sealed.read_back().map_err(|e| GeoError::RawDatReadFailed(format!("{dat_path:?}: {e}")))
}

fn cidr_contains(network: IpAddr, prefix: u32, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) if prefix <= 32 => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            u32::from(network) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) if prefix <= 128 => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            u128::from(network) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

#[async_trait::async_trait]
impl ConfigController for GeoIpService {
    type Id = Uuid;

    type Config = GeoIpSourceConfig;

    type DatabseAction = GeoIpSourceConfigRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn after_update_config(
        &self,
        new_configs: Vec<Self::Config>,
        _old_configs: Vec<Self::Config>,
    ) {
        // Refresh Direct configs immediately when updated
        for config in new_configs {
            if let GeoIpSource::Direct { ref data } = config.source {
                self.write_direct_to_cache(&config.name, data).await;
                self.notify_dst_ip_updated();
            }
        }
    }

    async fn delete(&self, id: Self::Id) {
        ConfigController::delete(self, id).await;
        remove_raw_dat("ip", id);
    }
}

#[cfg(test)]
mod tests {

    use landscape_common::{
        config_service::geo::{GeoFileCacheKey, GeoIpConfig},
        geo_cache::file_store::GeoCacheStore,
        LANDSCAPE_GEO_CACHE_TMP_DIR,
    };
    use std::{net::IpAddr, path::PathBuf, str::FromStr};

    use super::cidr_contains;

    #[test]
    fn matches_ipv4_and_ipv6_cidrs() {
        let ip = |value| IpAddr::from_str(value).unwrap();
        assert!(cidr_contains(ip("10.0.0.0"), 8, ip("10.1.2.3")));
        assert!(!cidr_contains(ip("10.0.0.0"), 8, ip("11.1.2.3")));
        assert!(cidr_contains(ip("2001:db8::"), 32, ip("2001:db8::1")));
        assert!(!cidr_contains(ip("2001:db8::"), 32, ip("2001:db9::1")));
    }

    // cargo test --package landscape --lib -- config_service::geo_ip_service::tests --show-output
    #[test]
    fn load_test() {
        let file_cache: GeoCacheStore<GeoFileCacheKey, GeoIpConfig> = GeoCacheStore::new(
            PathBuf::from("/root/.landscape-router").join(LANDSCAPE_GEO_CACHE_TMP_DIR),
            "ip".to_string(),
        );

        let keys = file_cache.keys();
        println!("keys: {:?}", keys.len())
    }
}

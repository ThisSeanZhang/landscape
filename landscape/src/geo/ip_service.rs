use landscape_common::store::storev4::LandscapeStoreTrait;
use landscape_common::{
    config_service::geo::{GeoError, GeoFileCacheKey, GeoIpConfig, GeoIpSource, GeoIpSourceConfig},
    database::LandscapeStore,
    flow::ip_mark::{IpMarkInfo, WanIPRuleSource, WanIpRuleConfig},
    service::controller::ConfigController,
    utils::time::{get_f64_timestamp, MILL_A_DAY},
};
use uuid::Uuid;

use std::{
    collections::HashMap,
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use landscape_common::{
    args::LAND_HOME_PATH, event::dns::DstIpEvent, store::storev4::StoreFileManager,
    LANDSCAPE_GEO_CACHE_TMP_DIR,
};
use landscape_database::{
    geo_ip::repository::GeoIpSourceConfigRepository, provider::LandscapeDBServiceProvider,
};
use reqwest::Client;
use tokio::sync::{broadcast, Mutex};

const A_DAY: u64 = 60 * 60 * 24;

pub type GeoDomainCacheStore = Arc<Mutex<StoreFileManager<GeoFileCacheKey, GeoIpConfig>>>;

#[derive(Clone)]
pub struct GeoIpService {
    store: GeoIpSourceConfigRepository,
    file_cache: GeoDomainCacheStore,
    dst_ip_events_tx: broadcast::Sender<DstIpEvent>,
}

impl GeoIpService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dst_ip_events_tx: broadcast::Sender<DstIpEvent>,
    ) -> Self {
        let store = store.geo_ip_rule_store();

        let file_cache = Arc::new(Mutex::new(StoreFileManager::new(
            LAND_HOME_PATH.join(LANDSCAPE_GEO_CACHE_TMP_DIR),
            "ip".to_string(),
        )));

        let service = Self { store, file_cache, dst_ip_events_tx };
        let service_clone = service.clone();
        tokio::spawn(async move {
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

    async fn refresh_url_config(&self, client: &Client, config: &mut GeoIpSourceConfig) {
        let url = match &config.source {
            GeoIpSource::Url { url, .. } => url.clone(),
            _ => return,
        };

        tracing::debug!("download file: {}", url);
        let time = Instant::now();

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(bytes) => {
                    let parse_result = self.parse_source_bytes(&config.source, bytes).await;

                    match parse_result {
                        Ok(result) => {
                            self.replace_cache_by_name(&config.name, result).await;

                            // Update next_update_at in the source
                            if let GeoIpSource::Url { next_update_at, .. } = &mut config.source {
                                *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
                            }
                            let _ = self.store.set(config.clone()).await;

                            tracing::debug!(
                                "handle file done: {}, time: {}s",
                                url,
                                time.elapsed().as_secs()
                            );
                            self.notify_dst_ip_updated();
                        }
                        Err(e) => {
                            tracing::error!("parse geo ip source {} error: {}", config.name, e);
                        }
                    }
                }
                Err(e) => tracing::error!("read {} response error: {}", url, e),
            },
            Ok(resp) => {
                tracing::error!("download {} error, HTTP status: {}", url, resp.status());
            }
            Err(e) => {
                tracing::error!("request {} error: {}", url, e);
            }
        }
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
                    if !force && *next_update_at >= now {
                        continue;
                    }
                    self.refresh_url_config(&client, &mut config).await;
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

    pub async fn refresh_one(&self, name: &str) {
        let configs: Vec<GeoIpSourceConfig> = self.store.list().await.unwrap();
        let Some(mut config) = configs.into_iter().find(|c| c.name == name) else {
            tracing::warn!("refresh_one: config '{}' not found", name);
            return;
        };

        let client = Client::new();

        match &config.source {
            GeoIpSource::Url { .. } => self.refresh_url_config(&client, &mut config).await,
            GeoIpSource::Direct { data } => {
                self.write_direct_to_cache(&config.name, data).await;
                self.notify_dst_ip_updated();
            }
        }
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
        let result = self.parse_source_bytes(&config.source, file_bytes).await?;
        self.replace_cache_by_name(&name, result).await;
        self.notify_dst_ip_updated();
        Ok(())
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
}

#[cfg(test)]
mod tests {

    use landscape_common::{
        config_service::geo::{GeoFileCacheKey, GeoIpConfig},
        store::storev4::StoreFileManager,
        LANDSCAPE_GEO_CACHE_TMP_DIR,
    };
    use std::path::PathBuf;

    // cargo test --package landscape --lib -- config_service::geo_ip_service::tests --show-output
    #[test]
    fn load_test() {
        let file_cache: StoreFileManager<GeoFileCacheKey, GeoIpConfig> = StoreFileManager::new(
            PathBuf::from("/root/.landscape-router").join(LANDSCAPE_GEO_CACHE_TMP_DIR),
            "ip".to_string(),
        );

        let keys = file_cache.keys();
        println!("keys: {:?}", keys.len())
    }
}

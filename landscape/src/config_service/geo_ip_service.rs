use landscape_common::store::storev4::LandscapeStoreTrait;
use landscape_common::{
    config::geo::{GeoFileCacheKey, GeoIpConfig, GeoIpSourceConfig},
    database::LandscapeDBTrait,
    ip_mark::{IpMarkInfo, WanIPRuleSource, WanIpRuleConfig},
    service::controller_service::ConfigController,
    utils::time::{get_f64_timestamp, MILL_A_DAY},
};
use uuid::Uuid;

use std::{
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
use tokio::sync::{mpsc, Mutex};

const A_DAY: u64 = 60 * 60 * 24;

pub type GeoDomainCacheStore = Arc<Mutex<StoreFileManager<GeoFileCacheKey, GeoIpConfig>>>;

#[derive(Clone)]
pub struct GeoIpService {
    store: GeoIpSourceConfigRepository,
    file_cache: GeoDomainCacheStore,
    dst_ip_events_tx: mpsc::Sender<DstIpEvent>,
}

impl GeoIpService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dst_ip_events_tx: mpsc::Sender<DstIpEvent>,
    ) -> Self {
        let store = store.geo_ip_rule_store();

        let file_cache = Arc::new(Mutex::new(StoreFileManager::new(
            LAND_HOME_PATH.join(LANDSCAPE_GEO_CACHE_TMP_DIR),
            "ip".to_string(),
        )));

        let service = Self { store, file_cache, dst_ip_events_tx };
        let service_clone = service.clone();
        tokio::spawn(async move {
            //
            let mut ticker = tokio::time::interval(Duration::from_secs(A_DAY));
            loop {
                service_clone.refresh(false).await;
                // 等待下一次 tick
                ticker.tick().await;
            }
        });
        service
    }

    pub async fn convert_config_to_runtime_rule(
        &self,
        configs: Vec<WanIpRuleConfig>,
    ) -> Vec<IpMarkInfo> {
        let mut lock = self.file_cache.lock().await;
        let mut result = vec![];
        for config in configs.into_iter() {
            let mut source = vec![];
            for each in config.source.iter() {
                match each {
                    WanIPRuleSource::GeoKey(config_key) => {
                        if let Some(ips) = lock.get(&config_key.get_file_cache_key()) {
                            source.extend(ips.values.iter().cloned());
                        }
                    }
                    WanIPRuleSource::Config(c) => {
                        source.push(c.clone());
                    }
                }
            }

            let ip_marks = source.into_iter().map(|cidr| IpMarkInfo {
                mark: config.mark,
                cidr,
                priority: config.index as u16,
            });
            result.extend(ip_marks);
        }
        result
    }

    pub async fn refresh(&self, force: bool) {
        // 读取当前规则
        let mut configs: Vec<GeoIpSourceConfig> = self.store.list().await.unwrap();

        if !force {
            let now = get_f64_timestamp();
            configs = configs.into_iter().filter(|e| e.next_update_at < now).collect();
        }

        let client = Client::new();
        let mut config_names = HashSet::new();
        for mut config in configs {
            let url = config.url.clone();
            config_names.insert(config.name.clone());

            tracing::debug!("download file: {}", url);
            let time = Instant::now();

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                    Ok(bytes) => {
                        let result = landscape_protobuf::read_geo_ips_from_bytes(bytes).await;
                        // tracing::debug!("get response file: {:?}", result);

                        let mut file_cache_lock = self.file_cache.lock().await;
                        let mut exist_keys = file_cache_lock
                            .keys()
                            .into_iter()
                            .filter(|k| k.name == config.name)
                            .collect::<HashSet<GeoFileCacheKey>>();

                        for (key, values) in result {
                            let info = GeoIpConfig {
                                name: config.name.clone(),
                                key: key.to_ascii_uppercase(),
                                values,
                            };
                            exist_keys.remove(&info.get_store_key());
                            file_cache_lock.set(info);
                        }

                        for key in exist_keys {
                            file_cache_lock.del(&key);
                        }

                        drop(file_cache_lock);

                        config.next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
                        let _ = self.store.set(config).await;

                        tracing::debug!(
                            "handle file done: {}, time: {}s",
                            url,
                            time.elapsed().as_secs()
                        );
                        let _ = self.dst_ip_events_tx.send(DstIpEvent::GeoIpUpdated).await;
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

    pub async fn update_geo_config_by_bytes(&self, name: String, file_bytes: impl Into<Vec<u8>>) {
        let result = landscape_protobuf::read_geo_ips_from_bytes(file_bytes).await;
        {
            let mut file_cache_lock = self.file_cache.lock().await;
            for (key, values) in result {
                let info = GeoIpConfig {
                    name: name.clone(),
                    key: key.to_ascii_uppercase(),
                    values,
                };
                file_cache_lock.set(info);
            }
        }
        let _ = self.dst_ip_events_tx.send(DstIpEvent::GeoIpUpdated).await;
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
        _new_configs: Vec<Self::Config>,
        _old_configs: Vec<Self::Config>,
    ) {
    }
}

#[cfg(test)]
mod tests {

    use landscape_common::{
        config::geo::{GeoFileCacheKey, GeoIpConfig},
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

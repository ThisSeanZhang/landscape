use landscape_common::{
    database::LandscapeStore,
    dns::{
        config::DnsUpstreamConfig,
        redirect::{
            DNSRedirectRule, DNSRedirectRuntimeRule, DynamicDnsRedirectBatch,
            DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
        },
        rule::{DNSRuleConfig, DNSRuntimeRule, DomainConfig, RuleSource},
        ChainDnsServerInitInfo,
    },
    geo::{GeoDomainConfig, GeoFileCacheKey, GeoSiteSource},
    service::controller::ConfigController,
    store::storev4::LandscapeStoreTrait,
    utils::time::{get_f64_timestamp, MILL_A_DAY},
};
use uuid::Uuid;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use landscape_common::{
    args::LAND_HOME_PATH,
    event::dns::DnsEvent,
    geo::{normalize_adguard_key, GeoSiteSourceConfig},
    store::storev4::StoreFileManager,
    LANDSCAPE_GEO_CACHE_TMP_DIR,
};
use landscape_database::{
    geo_site::repository::GeoSiteConfigRepository, provider::LandscapeDBServiceProvider,
};
use reqwest::Client;
use tokio::sync::{mpsc, Mutex};

const A_DAY: u64 = 60 * 60 * 24;

pub type GeoDomainCacheStore = Arc<Mutex<StoreFileManager<GeoFileCacheKey, GeoDomainConfig>>>;

#[derive(Debug, Default)]
pub struct ExpandedRuleSources {
    pub domains: Vec<DomainConfig>,
    pub used_geo_keys: HashSet<GeoFileCacheKey>,
}

#[derive(Clone)]
pub struct GeoSiteService {
    store: GeoSiteConfigRepository,
    file_cache: GeoDomainCacheStore,
    dns_events_tx: mpsc::Sender<DnsEvent>,
}

impl GeoSiteService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
    ) -> Self {
        let store = store.geo_site_rule_store();

        let file_cache = Arc::new(Mutex::new(StoreFileManager::new(
            LAND_HOME_PATH.join(LANDSCAPE_GEO_CACHE_TMP_DIR),
            "site".to_string(),
        )));

        let service = Self { store, file_cache, dns_events_tx };
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

    pub async fn convert_to_chain_init_config(
        &self,
        mut rules: Vec<DNSRuleConfig>,
        redirects: Vec<DNSRedirectRule>,
        dynamic_redirects: Vec<DynamicDnsRedirectBatch>,
        upstream_configs: Vec<DnsUpstreamConfig>,
    ) -> ChainDnsServerInitInfo {
        let upstream_dict: HashMap<Uuid, DnsUpstreamConfig> =
            upstream_configs.into_iter().map(|e| (e.id, e)).collect();

        let time = Instant::now();
        let mut applied_config = HashSet::new();

        let mut redirect_rules = Vec::with_capacity(redirects.len());
        // redirect
        for redirect in redirects.into_iter() {
            if !redirect.enable {
                continue;
            }

            if redirect.match_rules.len() > 0 {
                let source =
                    self.expand_rule_sources(redirect.match_rules, &mut applied_config).await;

                redirect_rules.push(DNSRedirectRuntimeRule {
                    redirect_id: Some(redirect.id),
                    dynamic_redirect_source: None,
                    answer_mode: redirect.answer_mode,
                    match_rules: source.domains,
                    result_info: redirect.result_info,
                    ttl_secs: DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
                });
            }
        }

        for dynamic_batch in dynamic_redirects {
            let source_id = dynamic_batch.source_id;
            for record in dynamic_batch.records {
                redirect_rules.push(DNSRedirectRuntimeRule {
                    redirect_id: None,
                    dynamic_redirect_source: Some(source_id.clone()),
                    answer_mode: record.answer_mode,
                    match_rules: vec![record.match_rule.into()],
                    result_info: record.result_info,
                    ttl_secs: record.ttl_secs,
                });
            }
        }

        let mut dns_rules = Vec::with_capacity(rules.len());

        rules.sort_by(|a, b| a.index.cmp(&b.index));

        for config in rules.into_iter() {
            if !config.enable {
                continue;
            }

            let insert_source = if config.source.len() > 0 {
                let source = self.expand_rule_sources(config.source, &mut applied_config).await;
                if source.domains.is_empty() {
                    // 去重后匹配的规则为空 不设置
                    tracing::info!("[{}:{}] final DNS match rule is: 0", config.index, config.name);
                    None
                } else {
                    tracing::info!(
                        "[{}:{}] match rule size is: {}",
                        config.index,
                        config.name,
                        source.domains.len()
                    );
                    Some(source.domains)
                }
            } else {
                Some(vec![])
            };

            tracing::debug!(
                "[{}:{}] covert config current time: {:?}ms",
                config.index,
                config.name,
                time.elapsed().as_millis()
            );

            if let Some(source) = insert_source {
                if let Some(upstream_config) = upstream_dict.get(&config.upstream_id) {
                    dns_rules.push(DNSRuntimeRule {
                        source,
                        id: config.id,
                        name: config.name,
                        index: config.index,
                        enable: config.enable,
                        filter: config.filter,
                        resolve_mode: upstream_config.clone(),
                        bind_config: config.bind_config,
                        mark: config.mark,
                        flow_id: config.flow_id,
                    });
                }
            }
        }
        ChainDnsServerInitInfo { dns_rules, redirect_rules }
    }

    // pub async fn convert_config_to_runtime_rule(
    //     &self,
    //     mut configs: Vec<DNSRuleConfig>,
    // ) -> Vec<DNSRuntimeRule> {
    //     let time = Instant::now();
    //     let mut result = Vec::with_capacity(configs.len());

    //     let mut applied_config = HashSet::new();
    //     configs.sort_by(|a, b| a.index.cmp(&b.index));

    //     for config in configs.into_iter() {
    //         if !config.enable {
    //             continue;
    //         }

    //         let insert_source = if config.source.len() > 0 {
    //             let source = self.get_geo_key_rules_v2(config.source, &mut applied_config).await;
    //             if source.len() == 0 {
    //                 // 去重后匹配的规则为空 不设置
    //                 tracing::info!("[{}:{}] final DNS match rule is: 0", config.index, config.name);
    //                 None
    //             } else {
    //                 tracing::info!(
    //                     "[{}:{}] match rule size is: {}",
    //                     config.index,
    //                     config.name,
    //                     source.len()
    //                 );
    //                 Some(source)
    //             }
    //         } else {
    //             // 本就是空的 那就直接设置
    //             Some(vec![])
    //         };

    //         tracing::debug!(
    //             "[{}:{}] covert config current time: {:?}ms",
    //             config.index,
    //             config.name,
    //             time.elapsed().as_millis()
    //         );

    //         if let Some(source) = insert_source {
    //             result.push(DNSRuntimeRule {
    //                 source,
    //                 id: config.id,
    //                 name: config.name,
    //                 index: config.index,
    //                 enable: config.enable,
    //                 filter: config.filter,
    //                 resolve_mode: config.resolve_mode,
    //                 mark: config.mark,
    //                 flow_id: config.flow_id,
    //             });
    //         }
    //     }
    //     result
    // }

    pub async fn expand_rule_sources(
        &self,
        rule_source: Vec<RuleSource>,
        applied_config: &mut HashSet<GeoFileCacheKey>,
    ) -> ExpandedRuleSources {
        let mut lock = self.file_cache.lock().await;

        let mut source = Vec::with_capacity(rule_source.len());
        let mut used_geo_keys = HashSet::with_capacity(rule_source.len());

        let mut inverse_keys: HashMap<String, HashSet<String>> = HashMap::new();
        for each in rule_source.into_iter() {
            match each {
                RuleSource::GeoKey(k) if k.inverse => {
                    inverse_keys.entry(k.name).or_default().insert(k.key);
                }
                RuleSource::GeoKey(k) => {
                    let attr_key = k.attribute_key.clone();
                    let file_cache_key = k.get_file_cache_key();
                    if applied_config.contains(&file_cache_key) {
                        continue;
                    }
                    if let Some(domains) = lock.get(&file_cache_key) {
                        source.reserve(domains.values.len());
                        match attr_key {
                            Some(attr) => source.extend(
                                domains
                                    .values
                                    .into_iter()
                                    .filter(|config| config.attributes.contains(&attr))
                                    .map(Into::into),
                            ),
                            None => source.extend(domains.values.into_iter().map(Into::into)),
                        }
                    }
                    applied_config.insert(file_cache_key);
                    used_geo_keys.insert(k.get_file_cache_key());
                }
                RuleSource::Config(c) => {
                    source.push(c);
                }
            }
        }

        if inverse_keys.len() > 0 {
            let time = Instant::now();
            tracing::debug!("{:?}", inverse_keys);
            for (inverse_key, excluded_names) in inverse_keys {
                let all_keys: Vec<_> =
                    lock.filter_keys(|k| k.name == inverse_key).cloned().collect();
                for key in all_keys.iter() {
                    if !excluded_names.contains(&key.key) {
                        if !applied_config.contains(key) {
                            if let Some(domains) = lock.get(key) {
                                source.reserve(domains.values.len());
                                applied_config.insert(key.clone());
                                used_geo_keys.insert(key.clone());
                                source.extend(domains.values.into_iter().map(Into::into));
                            }
                        }
                        // } else {
                        //     tracing::debug!("excluded_names: {:#?}", key);
                    }
                }
            }
            tracing::debug!("inverse insert time: {}ms", time.elapsed().as_millis());
        }

        ExpandedRuleSources { domains: source, used_geo_keys }
    }

    async fn snapshot_key_hashes_for_name(&self, name: &str) -> HashMap<GeoFileCacheKey, String> {
        let mut lock = self.file_cache.lock().await;
        let keys: Vec<_> = lock.keys().into_iter().filter(|key| key.name == name).collect();
        let mut result = HashMap::with_capacity(keys.len());
        for key in keys {
            if let Some(config) = lock.get(&key) {
                let hash = serde_json::to_string(&config.values).unwrap_or_default();
                result.insert(key, hash);
            }
        }
        result
    }

    fn diff_key_hashes(
        before: &HashMap<GeoFileCacheKey, String>,
        after: &HashMap<GeoFileCacheKey, String>,
    ) -> HashSet<GeoFileCacheKey> {
        before
            .keys()
            .chain(after.keys())
            .filter(|key| before.get(*key) != after.get(*key))
            .cloned()
            .collect()
    }

    async fn notify_geo_changes(&self, changed_keys: HashSet<GeoFileCacheKey>) {
        if changed_keys.is_empty() {
            return;
        }
        let _ = self
            .dns_events_tx
            .send(DnsEvent::GeoSitesChanged { changed_keys: Some(changed_keys) })
            .await;
    }

    async fn refresh_url_config(
        &self,
        client: &Client,
        config: &mut GeoSiteSourceConfig,
    ) -> HashSet<GeoFileCacheKey> {
        let url = match &config.source {
            GeoSiteSource::Url { url, .. } => url.clone(),
            _ => return HashSet::new(),
        };

        let before_hashes = self.snapshot_key_hashes_for_name(&config.name).await;
        tracing::debug!("download file: {}", url);
        let time = Instant::now();

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(bytes) => {
                    let result = landscape_protobuf::read_geo_sites_from_bytes(bytes).await;

                    let mut file_cache_lock = self.file_cache.lock().await;
                    let mut exist_keys = file_cache_lock
                        .keys()
                        .into_iter()
                        .filter(|k| k.name == config.name)
                        .collect::<HashSet<GeoFileCacheKey>>();

                    for (key, values) in result {
                        let info = GeoDomainConfig {
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

                    if let GeoSiteSource::Url { next_update_at, .. } = &mut config.source {
                        *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
                    }
                    let _ = self.store.set(config.clone()).await;

                    tracing::debug!(
                        "handle file done: {}, time: {}s",
                        url,
                        time.elapsed().as_secs()
                    );

                    let after_hashes = self.snapshot_key_hashes_for_name(&config.name).await;
                    Self::diff_key_hashes(&before_hashes, &after_hashes)
                }
                Err(e) => {
                    tracing::error!("read {} response error: {}", url, e);
                    HashSet::new()
                }
            },
            Ok(resp) => {
                tracing::error!("download {} error, HTTP status: {}", url, resp.status());
                HashSet::new()
            }
            Err(e) => {
                tracing::error!("request {} error: {}", url, e);
                HashSet::new()
            }
        }
    }

    async fn refresh_adguard_config(
        &self,
        client: &Client,
        config: &mut GeoSiteSourceConfig,
    ) -> HashSet<GeoFileCacheKey> {
        let (url, key) = match &config.source {
            GeoSiteSource::AdguardHome { url, key, .. } => {
                (url.clone(), normalize_adguard_key(key))
            }
            _ => return HashSet::new(),
        };

        tracing::debug!("download adguard rules: {}", url);
        let time = Instant::now();
        let before_hashes = self.snapshot_key_hashes_for_name(&config.name).await;

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(bytes) => {
                    let domains = landscape_protobuf::parse_adguard_rules(&bytes);

                    let cache_key = GeoFileCacheKey { name: config.name.clone(), key: key.clone() };

                    let mut file_cache_lock = self.file_cache.lock().await;
                    let exist_keys = file_cache_lock
                        .keys()
                        .into_iter()
                        .filter(|k| k.name == config.name)
                        .collect::<HashSet<GeoFileCacheKey>>();

                    let info = GeoDomainConfig { name: config.name.clone(), key, values: domains };
                    file_cache_lock.set(info);

                    for old_key in exist_keys {
                        if old_key != cache_key {
                            file_cache_lock.del(&old_key);
                        }
                    }
                    drop(file_cache_lock);

                    if let GeoSiteSource::AdguardHome { next_update_at, key, .. } =
                        &mut config.source
                    {
                        *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
                        *key = normalize_adguard_key(key);
                    }
                    let _ = self.store.set(config.clone()).await;

                    tracing::debug!(
                        "handle adguard rules done: {}, time: {}ms",
                        url,
                        time.elapsed().as_millis()
                    );

                    let after_hashes = self.snapshot_key_hashes_for_name(&config.name).await;
                    Self::diff_key_hashes(&before_hashes, &after_hashes)
                }
                Err(e) => {
                    tracing::error!("read {} response error: {}", url, e);
                    HashSet::new()
                }
            },
            Ok(resp) => {
                tracing::error!("download {} error, HTTP status: {}", url, resp.status());
                HashSet::new()
            }
            Err(e) => {
                tracing::error!("request {} error: {}", url, e);
                HashSet::new()
            }
        }
    }

    async fn refresh_direct_config(
        &self,
        config: &GeoSiteSourceConfig,
    ) -> HashSet<GeoFileCacheKey> {
        let before_hashes = self.snapshot_key_hashes_for_name(&config.name).await;
        if let GeoSiteSource::Direct { data } = &config.source {
            self.write_direct_to_cache(&config.name, data).await;
        }
        let after_hashes = self.snapshot_key_hashes_for_name(&config.name).await;
        Self::diff_key_hashes(&before_hashes, &after_hashes)
    }

    pub async fn refresh(&self, force: bool) {
        let configs: Vec<GeoSiteSourceConfig> = self.store.list().await.unwrap();

        let client = Client::new();
        let mut config_names = HashSet::new();
        let now = get_f64_timestamp();

        for mut config in configs {
            config_names.insert(config.name.clone());

            let changed = match &config.source {
                GeoSiteSource::Url { next_update_at, .. } => {
                    if !force && *next_update_at >= now {
                        continue;
                    }
                    self.refresh_url_config(&client, &mut config).await
                }
                GeoSiteSource::Direct { .. } => self.refresh_direct_config(&config).await,
                GeoSiteSource::AdguardHome { next_update_at, .. } => {
                    if !force && *next_update_at >= now {
                        continue;
                    }
                    self.refresh_adguard_config(&client, &mut config).await
                }
            };
            self.notify_geo_changes(changed).await;
        }

        if force {
            let mut file_cache_lock = self.file_cache.lock().await;
            let need_to_remove = file_cache_lock
                .keys()
                .into_iter()
                .filter(|k| !config_names.contains(&k.name))
                .collect::<HashSet<GeoFileCacheKey>>();
            for key in &need_to_remove {
                file_cache_lock.del(&key);
            }
            drop(file_cache_lock);
            self.notify_geo_changes(need_to_remove).await;
        }
    }

    pub async fn refresh_one(&self, name: &str) {
        let configs: Vec<GeoSiteSourceConfig> = self.store.list().await.unwrap();
        let Some(mut config) = configs.into_iter().find(|c| c.name == name) else {
            tracing::warn!("refresh_one: config '{}' not found", name);
            return;
        };

        let client = Client::new();

        let changed = match &config.source {
            GeoSiteSource::Url { .. } => self.refresh_url_config(&client, &mut config).await,
            GeoSiteSource::AdguardHome { .. } => {
                self.refresh_adguard_config(&client, &mut config).await
            }
            GeoSiteSource::Direct { .. } => self.refresh_direct_config(&config).await,
        };
        self.notify_geo_changes(changed).await;
    }

    async fn write_direct_to_cache(
        &self,
        name: &str,
        data: &[landscape_common::geo::GeoSiteDirectItem],
    ) {
        let mut file_cache_lock = self.file_cache.lock().await;

        // Remove existing keys for this name
        let exist_keys = file_cache_lock
            .keys()
            .into_iter()
            .filter(|k| k.name == name)
            .collect::<HashSet<GeoFileCacheKey>>();

        let mut new_keys = HashSet::new();
        for item in data {
            let info = GeoDomainConfig {
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
}

impl GeoSiteService {
    pub async fn list_all_keys(&self) -> Vec<GeoFileCacheKey> {
        let lock = self.file_cache.lock().await;
        lock.keys()
    }

    pub async fn get_cache_value_by_key(&self, key: &GeoFileCacheKey) -> Option<GeoDomainConfig> {
        let mut lock = self.file_cache.lock().await;
        lock.get(key)
    }

    pub async fn query_geo_by_name(&self, name: Option<String>) -> Vec<GeoSiteSourceConfig> {
        self.store.query_by_name(name).await.unwrap()
    }

    pub async fn update_geo_config_by_bytes(&self, name: String, file_bytes: impl Into<Vec<u8>>) {
        let before_hashes = self.snapshot_key_hashes_for_name(&name).await;
        let result = landscape_protobuf::read_geo_sites_from_bytes(file_bytes).await;
        {
            let mut file_cache_lock = self.file_cache.lock().await;
            for (key, values) in result {
                let info = GeoDomainConfig {
                    name: name.clone(),
                    key: key.to_ascii_uppercase(),
                    values,
                };
                file_cache_lock.set(info);
            }
        }
        let after_hashes = self.snapshot_key_hashes_for_name(&name).await;
        let changed_keys = Self::diff_key_hashes(&before_hashes, &after_hashes);
        self.notify_geo_changes(changed_keys).await;
    }
}

#[async_trait::async_trait]
impl ConfigController for GeoSiteService {
    type Id = Uuid;

    type Config = GeoSiteSourceConfig;

    type DatabseAction = GeoSiteConfigRepository;

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
            if let GeoSiteSource::Direct { ref data } = config.source {
                let before_hashes = self.snapshot_key_hashes_for_name(&config.name).await;
                self.write_direct_to_cache(&config.name, data).await;
                let after_hashes = self.snapshot_key_hashes_for_name(&config.name).await;
                let changed_keys = Self::diff_key_hashes(&before_hashes, &after_hashes);
                self.notify_geo_changes(changed_keys).await;
            }
        }
    }
}

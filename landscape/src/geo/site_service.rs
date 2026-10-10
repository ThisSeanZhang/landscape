use landscape_common::{
    concurrency::{spawn_task, task_label},
    config_service::geo::{
        GeoDomainConfig, GeoError, GeoFileCacheKey, GeoMatcherSource, GeoSiteFileConfig,
        GeoSiteLookupResult, GeoSiteSource, RawDatState,
    },
    database::store::{Change, ConfigStore},
    dns::domain::{normalize_domain_name, normalize_domain_text},
    dns::rule::DomainMatchType,
    service::controller::ConfigStoreController,
    utils::time::{MILL_A_DAY, get_f64_timestamp},
};
use uuid::Uuid;

use std::{
    collections::{HashMap, HashSet},
    fs,
    sync::Arc,
    time::{Duration, Instant},
};

use landscape_common::{
    args::LAND_HOME_PATH,
    config_service::geo::{GeoSiteSourceConfig, normalize_adguard_key},
    event::dns::DnsEvent,
};
use landscape_core::geo_cache::{
    CacheWriteOutcome, GeoCacheDatabase, SiteCacheRepository, SiteRuleRow,
};
use landscape_database::{
    geo_site::repository::GeoSiteConfigRepository, provider::LandscapeDBServiceProvider,
};
use landscape_dns::server::domain_rule_matches_normalized;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, mpsc};

use super::raw_file::{raw_dat_path, remove_raw_dat, stream_to_tmp, write_bytes_to_tmp};

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

fn geo_value_matches_lookup(value: &GeoSiteFileConfig, normalized: &str) -> bool {
    domain_rule_matches_normalized(&value.match_type, &value.value, normalized)
}

/// Domain-matching values are normalized for SQL candidate probing; Regex
/// values are patterns where case and trailing `.` are significant, stored
/// verbatim.
fn normalize_site_rule_value(match_type: &DomainMatchType, value: &str) -> String {
    match match_type {
        DomainMatchType::Regex => value.to_string(),
        _ => normalize_domain_text(value).into_owned(),
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
    dns_events_tx: mpsc::Sender<DnsEvent>,
    raw_downloading: Arc<Mutex<HashSet<Uuid>>>,
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

        let service = Self {
            store,
            cache,
            dns_events_tx,
            raw_downloading: Arc::new(Mutex::new(HashSet::new())),
        };
        let service_clone = service.clone();
        spawn_task(task_label::task::GEO_SITE_OBSERVER, async move {
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
                    let domain = normalize_site_rule_value(&value.match_type, &value.value);
                    SiteRuleRow {
                        match_type: value.match_type,
                        domain,
                        attributes: value.attributes,
                    }
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

        tracing::debug!("download file: {}", url);
        let time = Instant::now();

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let dat_path = raw_dat_path("site", config.id);
                let sealed = match stream_to_tmp(resp.bytes_stream(), &dat_path).await {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        tracing::error!("download {} to {dat_path:?} failed: {}", url, e);
                        return HashSet::new();
                    }
                };
                let bytes = match sealed.read_back() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        sealed.abort();
                        tracing::error!("read back {dat_path:?} failed: {}", e);
                        return HashSet::new();
                    }
                };
                match landscape_protobuf::read_geo_sites_from_bytes(bytes).await {
                    Ok(result) => {
                        if let Err(e) = sealed.commit() {
                            tracing::warn!(
                                "persist raw geo site file {:?} failed: {}",
                                dat_path,
                                e
                            );
                        }

                        let apply_result =
                            self.apply_geo_values(&config.name, result.into_iter().collect()).await;

                        if let GeoSiteSource::Url { next_update_at, .. } = &mut config.source {
                            *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
                        }
                        let _ = self.store.upsert(config.clone()).await;

                        tracing::debug!(
                            "handle file done: {}, time: {}ms changed_keys={} unchanged_keys={} deleted_keys={}",
                            url,
                            time.elapsed().as_millis(),
                            apply_result.changed_keys.len(),
                            apply_result.unchanged_keys,
                            apply_result.deleted_keys,
                        );
                        apply_result.changed_keys
                    }
                    Err(e) => {
                        sealed.abort();
                        tracing::error!("parse geosite dat from {} failed: {}", url, e);
                        HashSet::new()
                    }
                }
            }
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

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let dat_path = raw_dat_path("site", config.id);
                let sealed = match stream_to_tmp(resp.bytes_stream(), &dat_path).await {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        tracing::error!("download {} to {dat_path:?} failed: {}", url, e);
                        return HashSet::new();
                    }
                };
                let bytes = match sealed.read_back() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        sealed.abort();
                        tracing::error!("read back {dat_path:?} failed: {}", e);
                        return HashSet::new();
                    }
                };
                let domains = landscape_protobuf::parse_adguard_rules(&bytes);
                drop(bytes);
                if let Err(e) = sealed.commit() {
                    tracing::warn!("persist raw geo site file {:?} failed: {}", dat_path, e);
                }

                let apply_result =
                    self.apply_geo_values(&config.name, vec![(key.clone(), domains)]).await;

                if let GeoSiteSource::AdguardHome { next_update_at, key, .. } = &mut config.source {
                    *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
                    *key = normalize_adguard_key(key);
                }
                let _ = self.store.upsert(config.clone()).await;

                tracing::debug!(
                    "handle adguard rules done: {}, time: {}ms changed_keys={} unchanged_keys={} deleted_keys={}",
                    url,
                    time.elapsed().as_millis(),
                    apply_result.changed_keys.len(),
                    apply_result.unchanged_keys,
                    apply_result.deleted_keys,
                );
                apply_result.changed_keys
            }
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

    async fn try_restore_from_raw(&self, config: &GeoSiteSourceConfig) -> HashSet<GeoFileCacheKey> {
        let dat_path = raw_dat_path("site", config.id);
        let Ok(bytes) = fs::read(&dat_path) else {
            return HashSet::new();
        };

        match &config.source {
            GeoSiteSource::Url { .. } => {
                match landscape_protobuf::read_geo_sites_from_bytes(bytes).await {
                    Ok(result) => {
                        let apply_result =
                            self.apply_geo_values(&config.name, result.into_iter().collect()).await;
                        tracing::info!(
                            "restored geo site cache '{}' from {:?}",
                            config.name,
                            dat_path
                        );
                        apply_result.changed_keys
                    }
                    Err(e) => {
                        tracing::warn!("restore geo site cache from {:?} failed: {}", dat_path, e);
                        HashSet::new()
                    }
                }
            }
            GeoSiteSource::AdguardHome { key, .. } => {
                let domains = landscape_protobuf::parse_adguard_rules(&bytes);
                let apply_result = self
                    .apply_geo_values(&config.name, vec![(normalize_adguard_key(key), domains)])
                    .await;
                tracing::info!("restored geo site cache '{}' from {:?}", config.name, dat_path);
                apply_result.changed_keys
            }
            GeoSiteSource::Direct { .. } => HashSet::new(),
        }
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

        let mut tasks = self.raw_downloading.lock().await;
        if !tasks.insert(id) {
            return Ok(RawDatState::Running);
        }
        drop(tasks);

        let service = self.clone();
        let name = config.name.clone();
        spawn_task(task_label::task::GEO_SITE_OBSERVER, async move {
            service.refresh_one(&name).await;
            service.raw_downloading.lock().await.remove(&id);
        });
        Ok(RawDatState::Started)
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
                    if !self.has_cached_name(&config.name).await {
                        let changed = self.try_restore_from_raw(&config).await;
                        self.notify_geo_changes(changed).await;
                    }
                    if !force && *next_update_at >= now {
                        continue;
                    }
                    self.refresh_url_config(&client, &mut config).await
                }
                GeoSiteSource::Direct { .. } => self.refresh_direct_config(&config).await,
                GeoSiteSource::AdguardHome { next_update_at, .. } => {
                    if !self.has_cached_name(&config.name).await {
                        let changed = self.try_restore_from_raw(&config).await;
                        self.notify_geo_changes(changed).await;
                    }
                    if !force && *next_update_at >= now {
                        continue;
                    }
                    self.refresh_adguard_config(&client, &mut config).await
                }
            };
            self.notify_geo_changes(changed).await;
        }

        if force {
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
        data: &[landscape_common::config_service::geo::GeoSiteDirectItem],
    ) -> GeoCacheApplyResult {
        self.apply_geo_values(
            name,
            data.iter().map(|item| (item.key.clone(), item.values.clone())).collect(),
        )
        .await
    }
}

#[async_trait::async_trait]
impl GeoMatcherSource for GeoSiteService {
    async fn load_geo_domains(
        &self,
        key: &GeoFileCacheKey,
    ) -> Result<Option<Vec<GeoSiteFileConfig>>, GeoError> {
        self.cache
            .load_entry(&key.name, &key.key)
            .await
            .map_err(GeoError::from)
            .map(|config| config.map(|config| config.values))
    }
}

impl GeoSiteService {
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
            let candidate = GeoSiteFileConfig {
                match_type: hit.match_type,
                value: hit.domain,
                attributes: hit.attributes,
            };
            if geo_value_matches_lookup(&candidate, &normalized) {
                grouped.entry(hit.key).or_default().push(candidate);
            }
        }

        let mut result: Vec<GeoSiteLookupResult> =
            grouped.into_iter().map(|(key, values)| GeoSiteLookupResult { key, values }).collect();
        result.sort_by(|a, b| a.key.key.cmp(&b.key.key).then(a.key.name.cmp(&b.key.name)));
        Ok(result)
    }

    pub async fn update_geo_config_by_bytes(&self, name: String, file_bytes: impl Into<Vec<u8>>) {
        let file_bytes = file_bytes.into();
        let Some(config) = self
            .query_geo_by_name(Some(name.clone()))
            .await
            .into_iter()
            .find(|config| config.name == name)
        else {
            tracing::warn!("update_geo_config_by_bytes: config '{}' not found", name);
            return;
        };

        let dat_path = raw_dat_path("site", config.id);
        let sealed = match write_bytes_to_tmp(&dat_path, &file_bytes) {
            Ok(sealed) => sealed,
            Err(e) => {
                tracing::warn!("persist raw geo site file {:?} failed: {}", dat_path, e);
                return;
            }
        };
        drop(file_bytes);
        let bytes = match sealed.read_back() {
            Ok(bytes) => bytes,
            Err(e) => {
                sealed.abort();
                tracing::warn!("read back {dat_path:?} failed: {}", e);
                return;
            }
        };

        match landscape_protobuf::read_geo_sites_from_bytes(bytes).await {
            Ok(result) => {
                if let Err(e) = sealed.commit() {
                    tracing::warn!("persist raw geo site file {:?} failed: {}", dat_path, e);
                }

                let apply_result = self.apply_geo_values(&name, result.into_iter().collect()).await;
                tracing::debug!(
                    "update geo bytes: name={} changed_keys={} unchanged_keys={} deleted_keys={}",
                    name,
                    apply_result.changed_keys.len(),
                    apply_result.unchanged_keys,
                    apply_result.deleted_keys,
                );
                self.notify_geo_changes(apply_result.changed_keys).await;
            }
            Err(e) => {
                sealed.abort();
                tracing::error!("parse uploaded geosite dat for '{}' failed: {}", name, e);
            }
        }
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
        remove_raw_dat("site", old.id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use landscape_common::config_service::geo::GeoSiteFileConfig;
    use landscape_common::dns::rule::{DomainConfig, DomainMatchType};

    use super::{
        GeoContentHash, domain_match_type_tag, geo_value_matches_lookup, geo_values_hash,
        normalize_site_rule_value,
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
            normalize_site_rule_value(&DomainMatchType::Domain, "Example.COM."),
            "example.com"
        );
        assert_eq!(normalize_site_rule_value(&DomainMatchType::Full, "WWW.Example.com.."), "www.example.com");
        assert_eq!(normalize_site_rule_value(&DomainMatchType::Plain, "Foo."), "foo");
        assert_eq!(normalize_site_rule_value(&DomainMatchType::Domain, "example.com"), "example.com");
    }

    #[test]
    fn storage_normalization_keeps_regex_verbatim() {
        assert_eq!(normalize_site_rule_value(&DomainMatchType::Regex, "[A-Z]+\\."), "[A-Z]+\\.");
        assert_eq!(normalize_site_rule_value(&DomainMatchType::Regex, "^abc."), "^abc.");
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

    #[test]
    fn lookup_uses_dns_rule_matching_semantics() {
        let plain = GeoSiteFileConfig {
            match_type: DomainMatchType::Plain,
            value: "cloudflare".to_string(),
            attributes: HashSet::new(),
        };
        let domain = geo_value("cloudflare.com", &[]);
        let generic_regex = GeoSiteFileConfig {
            match_type: DomainMatchType::Regex,
            value: "^[a-z][a-z0-9-]+$".to_string(),
            attributes: HashSet::new(),
        };

        assert!(geo_value_matches_lookup(&plain, "cloudflare"));
        assert!(!geo_value_matches_lookup(&domain, "cloudflare"));
        assert!(geo_value_matches_lookup(&domain, "www.cloudflare.com"));
        assert!(geo_value_matches_lookup(&generic_regex, "cloudflare"));
    }
}

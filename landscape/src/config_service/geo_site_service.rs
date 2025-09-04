use landscape_common::{
    config::{
        dns::{DNSRuleConfig, DNSRuntimeRule, DomainConfig, RuleSource},
        geo::{GeoDomainConfig, GeoFileCacheKey, GeoSiteFileConfig},
    },
    database::LandscapeDBTrait,
    dns::{
        config::DnsUpstreamConfig,
        redirect::{DNSRedirectRule, DNSRedirectRuntimeRule},
        ChainDnsServerInitInfo,
    },
    service::controller_service::ConfigController,
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
    args::LAND_HOME_PATH, config::geo::GeoSiteSourceConfig, event::dns::DnsEvent,
    store::storev4::StoreFileManager, LANDSCAPE_GEO_CACHE_TMP_DIR,
};
use landscape_database::{
    geo_site::repository::GeoSiteConfigRepository, provider::LandscapeDBServiceProvider,
};
use reqwest::Client;
use tokio::sync::{mpsc, Mutex};

const A_DAY: u64 = 60 * 60 * 24;

pub type GeoDomainCacheStore = Arc<Mutex<StoreFileManager<GeoFileCacheKey, GeoDomainConfig>>>;

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

    // pub async fn convert_config_to_init_info(
    //     &self,
    //     rules: Vec<DNSRuleConfig>,
    // ) -> DnsServerInitInfo {
    //     let mut rules: Vec<DNSRuleConfig> = rules.into_iter().filter(|e| e.enable).collect();
    //     rules.sort_by(|a, b| b.index.cmp(&a.index));

    //     let mut init_info = DnsServerInitInfo::default();

    //     for each in rules {
    //         let resolve_mode = match each.resolve_mode {
    //             DNSResolveMode::Redirect { ips } => {
    //                 let info = Arc::new(RedirectInfo { result_ip: ips });

    //                 for domain_config in self.get_geo_key_rules(each.source).await.into_iter() {
    //                     init_info.redirect_rules.insert(domain_config, info.clone());
    //                 }
    //                 break;
    //             }
    //             DNSResolveMode::Upstream { upstream, ips, port } => {
    //                 DnsUpstreamMode::Upstream { upstream, ips, port }
    //             }
    //             DNSResolveMode::Cloudflare { mode } => DnsUpstreamMode::Cloudflare { mode },
    //         };
    //         let resolver_config = DnsResolverConfig {
    //             id: Uuid::new_v4(),
    //             resolve_mode: resolve_mode,
    //             mark: each.mark,
    //             flow_id: each.flow_id,
    //         };

    //         let info = RuleHandlerInfo {
    //             rule_id: each.id,
    //             flow_id: each.flow_id,
    //             resolver_id: resolver_config.id,
    //             mark: DnsRuntimeMarkInfo { mark: each.mark, priority: each.index as u16 },
    //             filter: each.filter,
    //         };

    //         init_info.resolver_configs.push(resolver_config);

    //         if each.source.is_empty() {
    //             init_info.default_resolver = Some(info);
    //         } else {
    //             let info = Arc::new(info);

    //             for domain_config in self.get_geo_key_rules(each.source).await.into_iter() {
    //                 init_info.rules.insert(domain_config, info.clone());
    //             }
    //         }
    //     }

    //     init_info
    // }

    // async fn get_geo_key_rules(&self, rule_source: Vec<RuleSource>) -> Vec<DomainConfig> {
    //     let mut lock = self.file_cache.lock().await;

    //     let mut usage_keys = HashSet::new();
    //     let mut source = vec![];

    //     let mut inverse_keys: HashMap<String, HashSet<String>> = HashMap::new();
    //     for each in rule_source.into_iter() {
    //         match each {
    //             RuleSource::GeoKey(k) if k.inverse => {
    //                 inverse_keys.entry(k.name).or_default().insert(k.key);
    //             }
    //             RuleSource::GeoKey(k) => {
    //                 let file_cache_key = k.get_file_cache_key();
    //                 let predicate: Box<dyn Fn(&GeoSiteFileConfig) -> bool> =
    //                     if let Some(attr) = k.attribute_key {
    //                         let attr = attr.clone();
    //                         Box::new(move |config: &GeoSiteFileConfig| {
    //                             config.attributes.contains(&attr)
    //                         })
    //                     } else {
    //                         Box::new(move |_: &GeoSiteFileConfig| true)
    //                     };
    //                 if let Some(domains) = lock.get(&file_cache_key) {
    //                     source.extend(domains.values.into_iter().filter(predicate).map(Into::into));
    //                 }
    //                 usage_keys.insert(file_cache_key);
    //             }
    //             RuleSource::Config(c) => {
    //                 source.push(c);
    //             }
    //         }
    //     }

    //     if inverse_keys.len() > 0 {
    //         let time = Instant::now();
    //         tracing::debug!("{:?}", inverse_keys);
    //         for (inverse_key, excluded_names) in inverse_keys {
    //             let all_keys: Vec<_> =
    //                 lock.filter_keys(|k| k.name == inverse_key).cloned().collect();
    //             for key in all_keys.iter() {
    //                 if !excluded_names.contains(&key.key) {
    //                     if !usage_keys.contains(key) {
    //                         if let Some(domains) = lock.get(key) {
    //                             usage_keys.insert(key.clone());
    //                             source.extend(domains.values.into_iter().map(Into::into));
    //                         }
    //                     }
    //                     // } else {
    //                     //     tracing::debug!("excluded_names: {:#?}", key);
    //                 }
    //             }
    //         }
    //         tracing::debug!(
    //             "using key len: {:#?}, all len: {}, time: {}",
    //             usage_keys.len(),
    //             lock.len(),
    //             time.elapsed().as_secs()
    //         );
    //     }

    //     source
    // }

    pub async fn convert_to_chain_init_config(
        &self,
        mut rules: Vec<DNSRuleConfig>,
        redirects: Vec<DNSRedirectRule>,
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
                    self.get_geo_key_rules_v2(redirect.match_rules, &mut applied_config).await;

                redirect_rules.push(DNSRedirectRuntimeRule {
                    id: redirect.id,
                    match_rules: source,
                    result_info: redirect.result_info,
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
                let source = self.get_geo_key_rules_v2(config.source, &mut applied_config).await;
                if source.len() == 0 {
                    // 去重后匹配的规则为空 不设置
                    tracing::info!("[{}:{}] final DNS match rule is: 0", config.index, config.name);
                    None
                } else {
                    tracing::info!(
                        "[{}:{}] match rule size is: {}",
                        config.index,
                        config.name,
                        source.len()
                    );
                    Some(source)
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

    async fn get_geo_key_rules_v2(
        &self,
        rule_source: Vec<RuleSource>,
        applied_config: &mut HashSet<GeoFileCacheKey>,
    ) -> Vec<DomainConfig> {
        let mut lock = self.file_cache.lock().await;

        let mut source = vec![];

        let mut inverse_keys: HashMap<String, HashSet<String>> = HashMap::new();
        for each in rule_source.into_iter() {
            match each {
                RuleSource::GeoKey(k) if k.inverse => {
                    inverse_keys.entry(k.name).or_default().insert(k.key);
                }
                RuleSource::GeoKey(k) => {
                    let file_cache_key = k.get_file_cache_key();
                    if applied_config.contains(&file_cache_key) {
                        continue;
                    }
                    let predicate: Box<dyn Fn(&GeoSiteFileConfig) -> bool> =
                        if let Some(attr) = k.attribute_key {
                            let attr = attr.clone();
                            Box::new(move |config: &GeoSiteFileConfig| {
                                config.attributes.contains(&attr)
                            })
                        } else {
                            Box::new(move |_: &GeoSiteFileConfig| true)
                        };
                    if let Some(domains) = lock.get(&file_cache_key) {
                        source.extend(domains.values.into_iter().filter(predicate).map(Into::into));
                    }
                    applied_config.insert(file_cache_key);
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
                                applied_config.insert(key.clone());
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

        source
    }

    pub async fn refresh(&self, force: bool) {
        // 读取当前规则
        let mut configs: Vec<GeoSiteSourceConfig> = self.store.list().await.unwrap();

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
                        let result = landscape_protobuf::read_geo_sites_from_bytes(bytes).await;
                        // tracing::debug!("get response file: {:?}", result);

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

                        config.next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
                        let _ = self.store.set(config).await;

                        tracing::debug!(
                            "handle file done: {}, time: {}s",
                            url,
                            time.elapsed().as_secs()
                        );

                        let _ = self.dns_events_tx.send(DnsEvent::GeositeUpdated).await;
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
        let _ = self.dns_events_tx.send(DnsEvent::GeositeUpdated).await;
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
}

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use landscape_common::{
    config_service::geo::{GeoConfigKey, GeoFileCacheKey, GeoMatcherSource},
    dns::{
        config::DnsUpstreamConfig,
        redirect::{
            DNSRedirectRule, DynamicDnsRedirectBatch, DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
        },
        rule::{DNSRuleConfig, DomainConfig, RuleSource},
        FlowDnsDependencies,
    },
};
use tokio::sync::Mutex;

use crate::server::{
    engine::{RedirectEngine, ResolveEngine},
    matcher::{DomainMatcher, RuntimeRuleMatcher},
    rule::{DNSRedirectRuntime, DNSResolveRuntime},
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct GeoMatcherCacheKey {
    source: GeoFileCacheKey,
    attribute_key: Option<String>,
}

#[derive(Clone)]
pub struct MatcherBuilder {
    source: Arc<dyn GeoMatcherSource>,
    geo_matchers: Arc<Mutex<HashMap<GeoMatcherCacheKey, Arc<DomainMatcher>>>>,
}

impl MatcherBuilder {
    pub fn new(source: Arc<dyn GeoMatcherSource>) -> Self {
        Self {
            source,
            geo_matchers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn build_flow(
        &self,
        flow_id: u32,
        mut dns_rules: Vec<DNSRuleConfig>,
        redirects: Vec<DNSRedirectRule>,
        dynamic_redirects: Vec<DynamicDnsRedirectBatch>,
        upstreams: Vec<DnsUpstreamConfig>,
    ) -> (RedirectEngine, ResolveEngine, FlowDnsDependencies) {
        let upstreams = upstreams
            .into_iter()
            .map(|upstream| (upstream.id, upstream))
            .collect::<HashMap<_, _>>();
        let mut dependencies = FlowDnsDependencies::default();
        let mut redirect_runtimes = Vec::new();

        for redirect in redirects {
            if !redirect.enable || redirect.match_rules.is_empty() {
                continue;
            }
            let Some(matcher) =
                self.build_rule_matcher(redirect.match_rules, false, &mut dependencies).await
            else {
                continue;
            };
            redirect_runtimes.push(DNSRedirectRuntime::new(
                Some(redirect.id),
                None,
                redirect.answer_mode,
                matcher,
                redirect.result_info,
                DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
            ));
        }

        for batch in dynamic_redirects {
            dependencies.dynamic_redirect_sources.insert(batch.source_id.clone());
            for record in batch.records {
                let matcher =
                    RuntimeRuleMatcher::new(vec![record.match_rule.into()], vec![], vec![], false);
                redirect_runtimes.push(DNSRedirectRuntime::new(
                    None,
                    Some(batch.source_id.clone()),
                    record.answer_mode,
                    matcher,
                    record.result_info,
                    record.ttl_secs,
                ));
            }
        }

        dns_rules.sort_by_key(|rule| rule.index);
        let mut resolve_runtimes = BTreeMap::new();
        for rule in dns_rules {
            if !rule.enable {
                continue;
            }
            dependencies.upstream_ids.insert(rule.upstream_id);
            let Some(upstream) = upstreams.get(&rule.upstream_id) else {
                tracing::warn!(rule_id = %rule.id, upstream_id = %rule.upstream_id, "skip DNS rule with missing upstream");
                continue;
            };
            let Some(matcher) = self.build_rule_matcher(rule.source, true, &mut dependencies).await
            else {
                continue;
            };
            resolve_runtimes.insert(
                rule.index,
                DNSResolveRuntime::new(
                    rule.id,
                    rule.index,
                    rule.filter,
                    rule.bind_config,
                    rule.mark,
                    upstream.clone(),
                    matcher,
                    flow_id,
                ),
            );
        }

        (RedirectEngine::new(redirect_runtimes), ResolveEngine::new(resolve_runtimes), dependencies)
    }

    pub async fn invalidate_geo_matchers(&self, changed_keys: Option<&HashSet<GeoFileCacheKey>>) {
        let mut matchers = self.geo_matchers.lock().await;
        match changed_keys {
            Some(changed_keys) => {
                matchers.retain(|key, _| !changed_keys.contains(&key.source));
            }
            None => matchers.clear(),
        }
    }

    async fn build_rule_matcher(
        &self,
        sources: Vec<RuleSource>,
        match_all_if_empty: bool,
        dependencies: &mut FlowDnsDependencies,
    ) -> Option<RuntimeRuleMatcher> {
        let match_all = match_all_if_empty && sources.is_empty();
        dependencies.geo_keys.extend(sources.iter().filter_map(|source| match source {
            RuleSource::GeoKey(config) => Some(config.get_file_cache_key()),
            RuleSource::Config(_) => None,
        }));
        let mut manual = Vec::<DomainConfig>::new();
        let mut positive_geo = Vec::new();
        let mut negative_geo = Vec::new();

        for source in sources {
            match source {
                RuleSource::Config(config) => manual.push(config),
                RuleSource::GeoKey(config) => {
                    let inverse = config.inverse;
                    // Needs fix: any geo key that fails to load drops the whole
                    // rule/redirect here. This differs from the previous behavior —
                    // the old code only dropped the geo part and kept the manual
                    // domains; mixed-source rules (manual + missing geo key) are
                    // currently skipped entirely.
                    let Some(matcher) = self.get_or_build_geo_matcher(config).await else {
                        return None;
                    };
                    if inverse {
                        negative_geo.push(matcher);
                    } else {
                        positive_geo.push(matcher);
                    }
                }
            }
        }

        Some(RuntimeRuleMatcher::new(manual, positive_geo, negative_geo, match_all))
    }

    async fn get_or_build_geo_matcher(&self, config: GeoConfigKey) -> Option<Arc<DomainMatcher>> {
        let cache_key = GeoMatcherCacheKey {
            source: config.get_file_cache_key(),
            attribute_key: config.attribute_key.clone(),
        };
        if let Some(matcher) = self.geo_matchers.lock().await.get(&cache_key).cloned() {
            return Some(matcher);
        }

        let values = match self.source.load_geo_domains(&cache_key.source).await {
            Ok(Some(values)) => values,
            Ok(None) => {
                tracing::warn!(name = %cache_key.source.name, key = %cache_key.source.key, "skip rule with missing GeoKey");
                return None;
            }
            Err(error) => {
                tracing::error!(name = %cache_key.source.name, key = %cache_key.source.key, %error, "skip rule with unreadable GeoKey");
                return None;
            }
        };
        let domains = values
            .into_iter()
            .filter(|domain| {
                cache_key
                    .attribute_key
                    .as_ref()
                    .is_none_or(|attribute| domain.attributes.contains(attribute))
            })
            .map(Into::into)
            .collect();
        // Situation note: when the key exists but yields no domains after filtering,
        // an empty matcher is built here — a positive (forward) rule stays registered
        // but never matches, while a negative (inverse) rule matches every domain.
        // This differs from the previous behavior (empty expansion used to skip the
        // rule entirely). Needs fix: an empty matcher should be treated as "source has
        // no effective domains" and the rule/redirect should not be kept in the engine.
        let matcher = Arc::new(DomainMatcher::new(domains));

        let mut matchers = self.geo_matchers.lock().await;
        Some(matchers.entry(cache_key).or_insert_with(|| matcher.clone()).clone())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use landscape_common::{
        config_service::geo::{
            GeoConfigKey, GeoFileCacheKey, GeoMatcherSource, GeoMatcherSourceError,
            GeoSiteFileConfig,
        },
        dns::{
            config::DnsUpstreamConfig,
            rule::{DNSRuleConfig, DomainMatchType, RuleSource},
        },
    };

    use super::MatcherBuilder;

    struct TestGeoSource {
        values: HashMap<GeoFileCacheKey, Vec<GeoSiteFileConfig>>,
        reads: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl GeoMatcherSource for TestGeoSource {
        async fn load_geo_domains(
            &self,
            key: &GeoFileCacheKey,
        ) -> Result<Option<Vec<GeoSiteFileConfig>>, GeoMatcherSourceError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.values.get(key).cloned())
        }
    }

    fn geo_key(attribute_key: Option<&str>) -> GeoConfigKey {
        GeoConfigKey {
            name: "geosite".to_string(),
            key: "TEST".to_string(),
            inverse: false,
            attribute_key: attribute_key.map(str::to_string),
        }
    }

    fn domain(value: &str, attributes: &[&str]) -> GeoSiteFileConfig {
        GeoSiteFileConfig {
            match_type: DomainMatchType::Full,
            value: value.to_string(),
            attributes: attributes.iter().map(|value| value.to_string()).collect(),
        }
    }

    fn builder() -> (MatcherBuilder, Arc<TestGeoSource>) {
        let source = Arc::new(TestGeoSource {
            values: HashMap::from([(
                geo_key(None).get_file_cache_key(),
                vec![domain("all.example", &[]), domain("tagged.example", &["tagged"])],
            )]),
            reads: AtomicUsize::new(0),
        });
        (MatcherBuilder::new(source.clone()), source)
    }

    #[tokio::test]
    async fn shares_matchers_by_name_key_and_attribute() {
        let (builder, source) = builder();

        let first = builder.get_or_build_geo_matcher(geo_key(None)).await.unwrap();
        let same = builder.get_or_build_geo_matcher(geo_key(None)).await.unwrap();
        let tagged = builder.get_or_build_geo_matcher(geo_key(Some("tagged"))).await.unwrap();

        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &tagged));
        assert_eq!(source.reads.load(Ordering::Relaxed), 2);
        assert!(first.is_match("all.example"));
        assert!(!tagged.is_match("all.example"));
        assert!(tagged.is_match("tagged.example"));
    }

    #[tokio::test]
    async fn invalidating_a_geo_key_rebuilds_all_attribute_variants() {
        let (builder, source) = builder();
        let first = builder.get_or_build_geo_matcher(geo_key(None)).await.unwrap();
        let tagged = builder.get_or_build_geo_matcher(geo_key(Some("tagged"))).await.unwrap();
        let changed = HashSet::from([geo_key(None).get_file_cache_key()]);

        builder.invalidate_geo_matchers(Some(&changed)).await;

        let rebuilt = builder.get_or_build_geo_matcher(geo_key(None)).await.unwrap();
        let rebuilt_tagged =
            builder.get_or_build_geo_matcher(geo_key(Some("tagged"))).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert!(!Arc::ptr_eq(&tagged, &rebuilt_tagged));
        assert_eq!(source.reads.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn missing_geo_key_disables_rule_but_records_every_dependency() {
        let source = Arc::new(TestGeoSource { values: HashMap::new(), reads: AtomicUsize::new(0) });
        let builder = MatcherBuilder::new(source);
        let upstream = DnsUpstreamConfig::default();
        let missing_a = geo_key(None);
        let missing_b = GeoConfigKey {
            name: "geosite".to_string(),
            key: "OTHER".to_string(),
            inverse: true,
            attribute_key: None,
        };
        let rule = DNSRuleConfig {
            id: uuid::Uuid::new_v4(),
            name: "missing geo".to_string(),
            index: 10,
            enable: true,
            filter: Default::default(),
            upstream_id: upstream.id,
            bind_config: Default::default(),
            mark: Default::default(),
            source: vec![
                RuleSource::GeoKey(missing_a.clone()),
                RuleSource::GeoKey(missing_b.clone()),
            ],
            flow_id: 7,
            update_at: 0.0,
        };

        let (_, resolve_engine, dependencies) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert_eq!(resolve_engine.iter().count(), 0);
        assert!(dependencies.geo_keys.contains(&missing_a.get_file_cache_key()));
        assert!(dependencies.geo_keys.contains(&missing_b.get_file_cache_key()));
        assert_eq!(dependencies.upstream_ids.len(), 1);
    }
}

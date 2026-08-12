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
                    // Confirmed behavior: a missing, unreadable, or empty GeoKey only
                    // drops that single source — the other sources (manual domains or
                    // valid geo keys) are kept. An inverse (negative) key with no
                    // effective domains is skipped like a positive one; it is NOT
                    // treated as an empty exclusion set, which would turn the rule
                    // into a match-all and shadow all later rules.
                    let Some(matcher) = self.get_or_build_geo_matcher(config).await else {
                        continue;
                    };
                    if inverse {
                        negative_geo.push(matcher);
                    } else {
                        positive_geo.push(matcher);
                    }
                }
            }
        }

        // Confirmed behavior: a rule/redirect whose sources all failed to load or
        // produced no effective domains is dropped entirely. It must not be kept as
        // a never-matching (positive) rule, nor as a match-everything (inverse) rule.
        // The only exception is an intentionally empty source list with match_all.
        let has_effective =
            !manual.is_empty() || !positive_geo.is_empty() || !negative_geo.is_empty();
        if !has_effective && !match_all {
            return None;
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
            .collect::<Vec<_>>();
        // Confirmed behavior: a key that exists but yields no domains after the
        // attribute filter is treated the same as a missing key — the source is
        // skipped and nothing is cached, so a later update that populates the key
        // is picked up on the next flow rebuild.
        if domains.is_empty() {
            tracing::warn!(name = %cache_key.source.name, key = %cache_key.source.key, "skip rule with empty GeoKey");
            return None;
        }
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
            redirect::{DNSRedirectRule, DnsRedirectAnswerMode},
            rule::{DNSRuleConfig, DomainConfig, DomainMatchType, RuleSource},
        },
    };
    use std::net::IpAddr;

    use super::MatcherBuilder;
    use hickory_proto::rr::RecordType;

    struct TestGeoSource {
        values: HashMap<GeoFileCacheKey, Vec<GeoSiteFileConfig>>,
        reads: AtomicUsize,
        errors: HashSet<GeoFileCacheKey>,
    }

    #[async_trait::async_trait]
    impl GeoMatcherSource for TestGeoSource {
        async fn load_geo_domains(
            &self,
            key: &GeoFileCacheKey,
        ) -> Result<Option<Vec<GeoSiteFileConfig>>, GeoMatcherSourceError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if self.errors.contains(key) {
                return Err(GeoMatcherSourceError::ReadFailed {
                    name: key.name.clone(),
                    key: key.key.clone(),
                });
            }
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
            errors: HashSet::new(),
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
        let source = Arc::new(TestGeoSource {
            values: HashMap::new(),
            reads: AtomicUsize::new(0),
            errors: HashSet::new(),
        });
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

    fn manual(value: &str) -> RuleSource {
        RuleSource::Config(DomainConfig {
            match_type: DomainMatchType::Full,
            value: value.to_string(),
        })
    }

    fn missing_key(name: &str, inverse: bool) -> GeoConfigKey {
        GeoConfigKey {
            name: "geosite".to_string(),
            key: name.to_string(),
            inverse,
            attribute_key: None,
        }
    }

    fn dns_rule(index: u32, source: Vec<RuleSource>, upstream_id: uuid::Uuid) -> DNSRuleConfig {
        DNSRuleConfig {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            index,
            enable: true,
            filter: Default::default(),
            upstream_id,
            bind_config: Default::default(),
            mark: Default::default(),
            source,
            flow_id: 7,
            update_at: 0.0,
        }
    }

    fn redirect(match_rules: Vec<RuleSource>) -> DNSRedirectRule {
        DNSRedirectRule {
            id: uuid::Uuid::new_v4(),
            remark: "test".to_string(),
            enable: true,
            match_rules,
            answer_mode: DnsRedirectAnswerMode::StaticIps,
            result_info: vec![IpAddr::from([192, 0, 2, 1])],
            apply_flows: vec![],
            update_at: 0.0,
        }
    }

    #[tokio::test]
    async fn missing_geo_key_keeps_manual_domains_in_mixed_rule() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let missing = missing_key("MISSING", false);
        let rule = dns_rule(
            10,
            vec![manual("manual.example"), RuleSource::GeoKey(missing.clone())],
            upstream.id,
        );

        let (_, resolve_engine, dependencies) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert_eq!(resolve_engine.iter().count(), 1);
        assert!(resolve_engine.find_match("manual.example").is_some());
        assert!(resolve_engine.find_match("all.example").is_none());
        assert!(dependencies.geo_keys.contains(&missing.get_file_cache_key()));
    }

    #[tokio::test]
    async fn empty_geo_key_disables_rule_and_redirect() {
        let source = Arc::new(TestGeoSource {
            values: HashMap::from([(geo_key(None).get_file_cache_key(), vec![])]),
            reads: AtomicUsize::new(0),
            errors: HashSet::new(),
        });
        let builder = MatcherBuilder::new(source);
        let upstream = DnsUpstreamConfig::default();
        let rule = dns_rule(10, vec![RuleSource::GeoKey(geo_key(None))], upstream.id);

        let (redirect_engine, resolve_engine, dependencies) = builder
            .build_flow(
                7,
                vec![rule],
                vec![redirect(vec![RuleSource::GeoKey(geo_key(None))])],
                vec![],
                vec![upstream],
            )
            .await;

        assert_eq!(resolve_engine.iter().count(), 0);
        assert!(redirect_engine.lookup("all.example", RecordType::A, None).is_none());
        assert!(dependencies.geo_keys.contains(&geo_key(None).get_file_cache_key()));
    }

    #[tokio::test]
    async fn attribute_filter_emptying_geo_key_keeps_only_manual_domains() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let no_match = geo_key(Some("no-such-attribute"));
        let rule = dns_rule(
            10,
            vec![manual("manual.example"), RuleSource::GeoKey(no_match.clone())],
            upstream.id,
        );

        let (_, resolve_engine, _) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert_eq!(resolve_engine.iter().count(), 1);
        assert!(resolve_engine.find_match("manual.example").is_some());
        assert!(resolve_engine.find_match("all.example").is_none());
        assert!(resolve_engine.find_match("tagged.example").is_none());
    }

    #[tokio::test]
    async fn empty_inverse_geo_key_is_skipped_not_match_all() {
        let source = Arc::new(TestGeoSource {
            values: HashMap::from([(missing_key("EMPTY", true).get_file_cache_key(), vec![])]),
            reads: AtomicUsize::new(0),
            errors: HashSet::new(),
        });
        let builder = MatcherBuilder::new(source);
        let upstream = DnsUpstreamConfig::default();
        let inverse = missing_key("EMPTY", true);
        let inverse_rule = dns_rule(10, vec![RuleSource::GeoKey(inverse.clone())], upstream.id);
        let fallback_rule = dns_rule(20, vec![manual("fallback.example")], upstream.id);

        let (_, resolve_engine, dependencies) = builder
            .build_flow(7, vec![inverse_rule, fallback_rule], vec![], vec![], vec![upstream])
            .await;

        assert_eq!(resolve_engine.iter().count(), 1);
        assert!(resolve_engine
            .find_match("fallback.example")
            .is_some_and(|rule| rule.order() == 20));
        assert!(dependencies.geo_keys.contains(&inverse.get_file_cache_key()));
    }

    #[tokio::test]
    async fn rule_with_empty_source_stays_match_all() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let rule = dns_rule(10, vec![], upstream.id);

        let (_, resolve_engine, _) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert_eq!(resolve_engine.iter().count(), 1);
        assert!(resolve_engine.find_match("anything.example").is_some());
    }

    #[tokio::test]
    async fn redirect_with_missing_geo_key_is_skipped() {
        let source = Arc::new(TestGeoSource {
            values: HashMap::new(),
            reads: AtomicUsize::new(0),
            errors: HashSet::new(),
        });
        let builder = MatcherBuilder::new(source);

        let (redirect_engine, _, _) = builder
            .build_flow(
                7,
                vec![],
                vec![redirect(vec![RuleSource::GeoKey(missing_key("MISSING", false))])],
                vec![],
                vec![],
            )
            .await;

        assert!(redirect_engine.lookup("anything.example", RecordType::A, None).is_none());
    }

    #[tokio::test]
    async fn mixed_geo_keys_keep_valid_and_skip_missing() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let valid = geo_key(None);
        let missing = missing_key("MISSING", false);
        let rule = dns_rule(
            10,
            vec![RuleSource::GeoKey(valid.clone()), RuleSource::GeoKey(missing.clone())],
            upstream.id,
        );

        let (_, resolve_engine, dependencies) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert_eq!(resolve_engine.iter().count(), 1);
        assert!(resolve_engine.find_match("all.example").is_some());
        assert!(resolve_engine.find_match("tagged.example").is_some());
        assert!(resolve_engine.find_match("other.example").is_none());
        assert!(dependencies.geo_keys.contains(&valid.get_file_cache_key()));
        assert!(dependencies.geo_keys.contains(&missing.get_file_cache_key()));
    }

    #[tokio::test]
    async fn read_failure_keeps_manual_domains() {
        let source = Arc::new(TestGeoSource {
            values: HashMap::new(),
            reads: AtomicUsize::new(0),
            errors: HashSet::from([geo_key(None).get_file_cache_key()]),
        });
        let builder = MatcherBuilder::new(source);
        let upstream = DnsUpstreamConfig::default();
        let rule = dns_rule(
            10,
            vec![manual("manual.example"), RuleSource::GeoKey(geo_key(None))],
            upstream.id,
        );

        let (_, resolve_engine, dependencies) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert_eq!(resolve_engine.iter().count(), 1);
        assert!(resolve_engine.find_match("manual.example").is_some());
        assert!(resolve_engine.find_match("all.example").is_none());
        assert!(dependencies.geo_keys.contains(&geo_key(None).get_file_cache_key()));
    }
}

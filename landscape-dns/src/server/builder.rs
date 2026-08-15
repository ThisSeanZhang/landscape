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
use uuid::Uuid;

use crate::connection::pool::ResolvePool;
use crate::server::{
    matcher::{DomainMatcher, RuntimeRuleMatcher},
    redirect_engine::RedirectEngine,
    resolve_engine::ResolveEngine,
    rule::{DNSRedirectRuntime, DNSResolveRuntime, RedirectRuleParams, ResolveRuleParams},
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
    resolvers: Arc<ResolvePool>,
}

impl MatcherBuilder {
    pub fn new(source: Arc<dyn GeoMatcherSource>) -> Self {
        Self {
            source,
            geo_matchers: Arc::new(Mutex::new(HashMap::new())),
            resolvers: Arc::new(ResolvePool::default()),
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
            redirect_runtimes.push(DNSRedirectRuntime::new(RedirectRuleParams {
                redirect_id: Some(redirect.id),
                dynamic_redirect_source: None,
                answer_mode: redirect.answer_mode,
                matcher,
                result_info: redirect.result_info,
                ttl_secs: DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
                block_metadata_queries: redirect.block_metadata_queries,
            }));
        }

        for batch in dynamic_redirects {
            dependencies.dynamic_redirect_sources.insert(batch.source_id.clone());
            for record in batch.records {
                let matcher =
                    RuntimeRuleMatcher::new(vec![record.match_rule.into()], vec![], vec![], false);
                redirect_runtimes.push(DNSRedirectRuntime::new(RedirectRuleParams {
                    redirect_id: None,
                    dynamic_redirect_source: Some(batch.source_id.clone()),
                    answer_mode: record.answer_mode,
                    matcher,
                    result_info: record.result_info,
                    ttl_secs: record.ttl_secs,
                    block_metadata_queries: record.block_metadata_queries,
                }));
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
            let Some(resolve_runtime) = DNSResolveRuntime::new(ResolveRuleParams {
                rule_id: rule.id,
                order: rule.index,
                filter: rule.filter,
                mark: rule.mark,
                upstream: upstream.clone(),
                matcher,
                flow_id,
                pool: self.resolvers.clone(),
            }) else {
                continue;
            };
            resolve_runtimes.insert(rule.index, resolve_runtime);
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

    /// Drops every pooled resolver for the given upstream ids so the next
    /// flow refresh rebuilds them unconditionally. Called on
    /// `UpstreamsChanged` before the dependent flows are refreshed.
    pub fn invalidate_upstreams(&self, upstream_ids: &HashSet<Uuid>) {
        self.resolvers.invalidate(upstream_ids);
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
        flow::mark::FlowMark,
    };
    use std::net::IpAddr;

    use super::MatcherBuilder;
    use crate::domain::ParsedDomain;
    use crate::server::resolve_engine::ResolveEngine;
    use hickory_proto::rr::RecordType;

    fn pd(name: &str) -> ParsedDomain {
        ParsedDomain::new(name).unwrap()
    }

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
        assert!(first.is_match_normalized(pd("all.example").name()));
        assert!(!tagged.is_match_normalized(pd("all.example").name()));
        assert!(tagged.is_match_normalized(pd("tagged.example").name()));
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
            block_metadata_queries: true,
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
        assert!(resolve_engine.find_match(&pd("manual.example")).is_some());
        assert!(resolve_engine.find_match(&pd("all.example")).is_none());
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
        assert!(redirect_engine.lookup(&pd("all.example"), RecordType::A, None).is_none());
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
        assert!(resolve_engine.find_match(&pd("manual.example")).is_some());
        assert!(resolve_engine.find_match(&pd("all.example")).is_none());
        assert!(resolve_engine.find_match(&pd("tagged.example")).is_none());
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
            .find_match(&pd("fallback.example"))
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
        assert!(resolve_engine.find_match(&pd("anything.example")).is_some());
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

        assert!(redirect_engine.lookup(&pd("anything.example"), RecordType::A, None).is_none());
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
        assert!(resolve_engine.find_match(&pd("all.example")).is_some());
        assert!(resolve_engine.find_match(&pd("tagged.example")).is_some());
        assert!(resolve_engine.find_match(&pd("other.example")).is_none());
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
        assert!(resolve_engine.find_match(&pd("manual.example")).is_some());
        assert!(resolve_engine.find_match(&pd("all.example")).is_none());
        assert!(dependencies.geo_keys.contains(&geo_key(None).get_file_cache_key()));
    }

    fn direct_rule(index: u32, source: Vec<RuleSource>, upstream_id: uuid::Uuid) -> DNSRuleConfig {
        DNSRuleConfig {
            id: uuid::Uuid::new_v4(),
            name: "direct".to_string(),
            index,
            enable: true,
            filter: Default::default(),
            upstream_id,
            // Direct action: SO_MARK stays 0x8000 regardless of the flow.
            mark: FlowMark::from(0x0100),
            source,
            flow_id: 7,
            update_at: 0.0,
        }
    }

    fn first_resolver(engine: &ResolveEngine) -> Arc<crate::connection::LandscapeMarkDNSResolver> {
        engine.iter().next().expect("expected a resolve rule").1.shared_resolver().clone()
    }

    #[tokio::test]
    async fn shares_resolver_for_same_mark_and_upstream() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let rules = vec![
            dns_rule(10, vec![manual("a.example")], upstream.id),
            dns_rule(20, vec![manual("b.example")], upstream.id),
        ];

        let (_, resolve_engine, _) =
            builder.build_flow(7, rules, vec![], vec![], vec![upstream]).await;

        let mut resolvers = resolve_engine.iter().map(|(_, rule)| rule.shared_resolver().clone());
        let first = resolvers.next().unwrap();
        assert!(resolvers.all(|resolver| Arc::ptr_eq(&first, &resolver)));
    }

    #[tokio::test]
    async fn keeps_resolver_across_builds_and_rebuilds_after_invalidate() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let rule = dns_rule(10, vec![manual("a.example")], upstream.id);

        let (_, first_engine, _) =
            builder.build_flow(7, vec![rule.clone()], vec![], vec![], vec![upstream.clone()]).await;
        let first = first_resolver(&first_engine);

        // Same pool, unchanged upstream: the same resolver is reused.
        let (_, second_engine, _) =
            builder.build_flow(7, vec![rule.clone()], vec![], vec![], vec![upstream.clone()]).await;
        assert!(Arc::ptr_eq(&first, &first_resolver(&second_engine)));

        // UpstreamsChanged evicts the entry; the next build starts fresh.
        builder.invalidate_upstreams(&HashSet::from([upstream.id]));
        let (_, third_engine, _) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;
        assert!(!Arc::ptr_eq(&first, &first_resolver(&third_engine)));
    }

    #[tokio::test]
    async fn different_mark_does_not_share_resolver() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let rule = dns_rule(10, vec![manual("a.example")], upstream.id);

        // KeepGoing rules get marked with their owning flow id, so flows 5
        // and 7 differ in SO_MARK and must not share connections.
        let (_, flow5_engine, _) =
            builder.build_flow(5, vec![rule.clone()], vec![], vec![], vec![upstream.clone()]).await;
        let (_, flow7_engine, _) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert!(!Arc::ptr_eq(&first_resolver(&flow5_engine), &first_resolver(&flow7_engine)));
    }

    #[tokio::test]
    async fn direct_rules_share_across_flows() {
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let rule = direct_rule(10, vec![manual("a.example")], upstream.id);

        // Direct rules always resolve to SO_MARK 0x8000, so different flows
        // hitting the same upstream share one connection pool.
        let (_, flow5_engine, _) =
            builder.build_flow(5, vec![rule.clone()], vec![], vec![], vec![upstream.clone()]).await;
        let (_, flow7_engine, _) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;

        assert!(Arc::ptr_eq(&first_resolver(&flow5_engine), &first_resolver(&flow7_engine)));
    }

    #[tokio::test]
    async fn different_upstream_does_not_share_resolver() {
        let (builder, _) = builder();
        let upstream_a = DnsUpstreamConfig::default();
        let upstream_b = DnsUpstreamConfig::default();

        let rules = vec![
            dns_rule(10, vec![manual("a.example")], upstream_a.id),
            dns_rule(20, vec![manual("b.example")], upstream_b.id),
        ];
        let (_, resolve_engine, _) =
            builder.build_flow(7, rules, vec![], vec![], vec![upstream_a, upstream_b]).await;

        let mut resolvers = resolve_engine.iter().map(|(_, rule)| rule.shared_resolver().clone());
        let first = resolvers.next().unwrap();
        assert!(resolvers.all(|resolver| !Arc::ptr_eq(&first, &resolver)));
    }

    #[tokio::test]
    async fn pool_key_matches_legacy_mark_computation() {
        // Every pooled resolver key must equal the per-rule mark the legacy
        // code applied: `mark.get_dns_mark(flow_id)`. This pins the SO_MARK put
        // on shared upstream connections to exactly the old per-rule value.
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let upstream_id = upstream.id;
        let keepgoing5 = dns_rule(10, vec![manual("a.example")], upstream_id);
        let keepgoing7 = dns_rule(20, vec![manual("b.example")], upstream_id);
        let direct = direct_rule(30, vec![manual("c.example")], upstream_id);
        let redirect_to_5 = DNSRuleConfig {
            mark: FlowMark::from(0x0305),
            ..dns_rule(40, vec![manual("d.example")], upstream_id)
        };

        let (_, flow5_engine, _) =
            builder.build_flow(5, vec![keepgoing5], vec![], vec![], vec![upstream.clone()]).await;
        let (_, flow7_engine, _) = builder
            .build_flow(7, vec![keepgoing7, direct, redirect_to_5], vec![], vec![], vec![upstream])
            .await;
        let _ = (first_resolver(&flow5_engine), first_resolver(&flow7_engine));

        let mut keys = builder.resolvers.keys();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                (FlowMark::from(0x0100).get_dns_mark(7), upstream_id), // direct: 0x8000
                (FlowMark::default().get_dns_mark(5), upstream_id),    // keepgoing flow 5: 0x8005
                (FlowMark::default().get_dns_mark(7), upstream_id),    // keepgoing flow 7: 0x8007
            ],
        );
    }

    #[tokio::test]
    async fn flow_change_without_invalidate_routes_by_new_flow() {
        // RulesChanged does a ResolveOnly refresh and never invalidates: a rule
        // moved to another flow must still be served by a resolver carrying the
        // new flow's mark (correctness), while the old entry stays pooled
        // (documented leak that is safe to keep).
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let upstream_id = upstream.id;
        let rule = dns_rule(10, vec![manual("a.example")], upstream_id);

        let (_, flow5_engine, _) =
            builder.build_flow(5, vec![rule.clone()], vec![], vec![], vec![upstream.clone()]).await;
        let first = first_resolver(&flow5_engine);

        let (_, flow7_engine, _) =
            builder.build_flow(7, vec![rule], vec![], vec![], vec![upstream]).await;
        let second = first_resolver(&flow7_engine);

        assert!(!Arc::ptr_eq(&first, &second));
        let mut keys = builder.resolvers.keys();
        keys.sort();
        assert_eq!(
            keys,
            vec![(FlowMark::default().get_dns_mark(5), upstream_id), (0x8007, upstream_id)],
        );
    }

    #[tokio::test]
    async fn keepgoing_and_redirect_to_same_flow_share() {
        // A KeepGoing rule in flow 5 and a Redirect-to-flow-5 rule in flow 7
        // compute the same SO_MARK (0x8005), so the legacy behaviour already
        // sent both through the same marked path and pooling must share them.
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let keepgoing5 = dns_rule(10, vec![manual("a.example")], upstream.id);
        let redirect_to_5 = DNSRuleConfig {
            mark: FlowMark::from(0x0305),
            ..dns_rule(20, vec![manual("b.example")], upstream.id)
        };

        let (_, flow5_engine, _) =
            builder.build_flow(5, vec![keepgoing5], vec![], vec![], vec![upstream.clone()]).await;
        let (_, flow7_engine, _) =
            builder.build_flow(7, vec![redirect_to_5], vec![], vec![], vec![upstream]).await;

        assert!(Arc::ptr_eq(&first_resolver(&flow5_engine), &first_resolver(&flow7_engine)));
    }

    #[tokio::test]
    async fn different_actions_in_same_flow_do_not_share_resolver() {
        // The SO_MARK is the routing identity: KeepGoing in flow 7 marks
        // 0x8007 but Direct in the same flow marks 0x8000. Keying by the
        // owning flow alone would merge them into one pool and the first-built
        // resolver would serve the other rule with the wrong mark.
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let keepgoing = dns_rule(10, vec![manual("a.example")], upstream.id);
        let direct = direct_rule(20, vec![manual("b.example")], upstream.id);

        let (_, resolve_engine, _) =
            builder.build_flow(7, vec![keepgoing, direct], vec![], vec![], vec![upstream]).await;

        let mut resolvers = resolve_engine.iter().map(|(_, rule)| rule.shared_resolver().clone());
        let first = resolvers.next().unwrap();
        assert!(resolvers.all(|resolver| !Arc::ptr_eq(&first, &resolver)));
    }

    #[tokio::test]
    async fn redirect_marks_target_flow_not_owning_flow() {
        // Redirect rules are marked with their *target* flow id: in flow 7 a
        // KeepGoing rule (0x8007) and a Redirect->5 rule (0x8005) must not
        // share, even though both belong to flow 7.
        let (builder, _) = builder();
        let upstream = DnsUpstreamConfig::default();
        let upstream_id = upstream.id;
        let keepgoing = dns_rule(10, vec![manual("a.example")], upstream_id);
        let redirect_to_5 = DNSRuleConfig {
            mark: FlowMark::from(0x0305),
            ..dns_rule(20, vec![manual("b.example")], upstream_id)
        };

        let (_, resolve_engine, _) = builder
            .build_flow(7, vec![keepgoing, redirect_to_5], vec![], vec![], vec![upstream])
            .await;

        let mut resolvers = resolve_engine.iter().map(|(_, rule)| rule.shared_resolver().clone());
        let first = resolvers.next().unwrap();
        assert!(resolvers.all(|resolver| !Arc::ptr_eq(&first, &resolver)));
        let mut keys = builder.resolvers.keys();
        keys.sort();
        assert_eq!(keys, vec![(0x8005, upstream_id), (0x8007, upstream_id)]);
    }
}

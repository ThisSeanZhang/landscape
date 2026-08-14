use super::*;
use crate::server::LocalDnsAnswerProvider;
use arc_swap::ArcSwapOption;
use landscape_common::dns::rule::FilterResult;
use landscape_common::flow::DnsRuntimeMarkInfo;
use landscape_core::lan_hostname::LanHostnameRegistry;
use uuid::Uuid;

#[derive(Default, Debug)]
struct ChainDnsServerInitInfo {
    dns_rules: Vec<landscape_common::dns::rule::DNSRuntimeRule>,
    redirect_rules: Vec<landscape_common::dns::redirect::DNSRedirectRuntimeRule>,
}

#[cfg(test)]
impl DnsRequestHandler {
    fn new(
        init: ChainDnsServerInitInfo,
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        msg_tx: MetricSenderState,
        local_resolver: Arc<LocalResolver>,
    ) -> Self {
        let (redirect_engine, resolve_engine) = Self::test_engines_from_legacy(init);
        Self::from_engines(
            redirect_engine,
            resolve_engine,
            runtime_config,
            flow_id,
            msg_tx,
            local_resolver,
        )
    }

    fn test_engines_from_legacy(init: ChainDnsServerInitInfo) -> (RedirectEngine, ResolveEngine) {
        use std::collections::BTreeMap;

        use crate::server::{
            matcher::RuntimeRuleMatcher,
            rule::{DNSRedirectRuntime, DNSResolveRuntime, RedirectRuleParams, ResolveRuleParams},
        };

        let redirects = init
            .redirect_rules
            .into_iter()
            .map(|rule| {
                DNSRedirectRuntime::new(RedirectRuleParams {
                    redirect_id: rule.redirect_id,
                    dynamic_redirect_source: rule.dynamic_redirect_source,
                    answer_mode: rule.answer_mode,
                    matcher: RuntimeRuleMatcher::new(rule.match_rules, vec![], vec![], false),
                    result_info: rule.result_info,
                    ttl_secs: rule.ttl_secs,
                    block_metadata_queries: rule.block_metadata_queries,
                })
            })
            .collect();
        let resolves = init
            .dns_rules
            .into_iter()
            .filter_map(|rule| {
                let order = rule.index;
                let match_all = rule.source.is_empty();
                let runtime = DNSResolveRuntime::new(ResolveRuleParams {
                    rule_id: rule.id,
                    order: rule.index,
                    filter: rule.filter,
                    bind_config: rule.bind_config,
                    mark: rule.mark,
                    upstream: rule.resolve_mode,
                    matcher: RuntimeRuleMatcher::new(rule.source, vec![], vec![], match_all),
                    flow_id: rule.flow_id,
                })?;
                Some((order, runtime))
            })
            .collect::<BTreeMap<_, _>>();

        (RedirectEngine::new(redirects), ResolveEngine::new(resolves))
    }

    async fn insert(
        &self,
        domain: &str,
        query_type: RecordType,
        rdata_ttl_vec: Vec<Record>,
        response_code: ResponseCode,
        mark: &DnsRuntimeMarkInfo,
        filter: FilterResult,
        matched_rule_id: Option<Uuid>,
        matched_rule_order: Option<u32>,
    ) {
        let runtime = self.snapshot.load_full();
        runtime
            .cache
            .insert(crate::server::cache::CacheEntry {
                domain_key: Arc::<str>::from(domain),
                query_type,
                rdatas: rdata_ttl_vec,
                response_code,
                mark: mark.clone(),
                filter,
                matched_rule_id,
                matched_rule_order,
            })
            .await;
    }
}

mod tests {
    use super::*;
    use crate::server::snapshot::RULE_REFRESH_TTL_CAP;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record, RecordType};
    use landscape_common::{
        dns::{
            config::DnsUpstreamConfig,
            redirect::{DNSRedirectRuntimeRule, DnsRedirectAnswerMode},
            rule::{DNSRuntimeRule, DomainConfig, DomainMatchType, FilterResult},
        },
        flow::mark::FlowMark,
    };
    use std::str::FromStr;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };
    use uuid::Uuid;

    struct MockLocalAnswerProvider {
        addrs: Vec<IpAddr>,
    }

    impl LocalDnsAnswerProvider for MockLocalAnswerProvider {
        fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
            let addrs = self
                .addrs
                .iter()
                .copied()
                .filter(|addr| {
                    matches!(
                        (addr, query_type),
                        (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)
                    )
                })
                .collect();
            Arc::new(addrs)
        }
    }

    fn run_async_test(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test);
    }

    fn test_cache_runtime_config(negative_cache_ttl: u32) -> CacheRuntimeConfig {
        CacheRuntimeConfig {
            cache_capacity: 16,
            cache_ttl: 60,
            negative_cache_ttl,
        }
    }

    fn shared_cache_runtime_config(negative_cache_ttl: u32) -> Arc<ArcSwap<CacheRuntimeConfig>> {
        Arc::new(ArcSwap::from_pointee(test_cache_runtime_config(negative_cache_ttl)))
    }

    fn make_test_handler(
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules }.into(),
            shared_cache_runtime_config(5),
            1,
            Arc::new(ArcSwapOption::new(None)),
            test_local_resolver(test_lan_hostname_registry()),
        )
    }

    fn test_handler_with_local(
        registry: Arc<LanHostnameRegistry>,
        provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules }.into(),
            shared_cache_runtime_config(5),
            1,
            Arc::new(ArcSwapOption::new(None)),
            Arc::new(LocalResolver::new(registry, provider, None, None)),
        )
    }

    fn test_handler_with_config(
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules }.into(),
            runtime_config,
            flow_id,
            Arc::new(ArcSwapOption::new(None)),
            test_local_resolver(test_lan_hostname_registry()),
        )
    }

    fn test_local_resolver(registry: Arc<LanHostnameRegistry>) -> Arc<LocalResolver> {
        Arc::new(LocalResolver::new(registry, None, None, None))
    }

    fn test_lan_hostname_registry() -> Arc<LanHostnameRegistry> {
        LanHostnameRegistry::new_for_test(
            landscape_common::sys_service::lan_hostname::LanHostnameConfig::default(),
        )
    }

    fn test_runtime_rule() -> DNSRuntimeRule {
        DNSRuntimeRule {
            resolve_mode: DnsUpstreamConfig::default(),
            ..DNSRuntimeRule::default()
        }
    }

    fn test_dns_rule(filter: FilterResult, sources: &[&str]) -> DNSRuntimeRule {
        DNSRuntimeRule {
            filter,
            source: sources
                .iter()
                .map(|value| DomainConfig {
                    match_type: DomainMatchType::Full,
                    value: value.to_string(),
                })
                .collect(),
            ..test_runtime_rule()
        }
    }

    fn test_static_redirect_rule(
        domain: &str,
        ips: Vec<IpAddr>,
        ttl_secs: u32,
    ) -> DNSRedirectRuntimeRule {
        DNSRedirectRuntimeRule {
            redirect_id: Some(Uuid::nil()),
            dynamic_redirect_source: None,
            answer_mode: DnsRedirectAnswerMode::StaticIps,
            match_rules: vec![DomainConfig {
                match_type: DomainMatchType::Full,
                value: domain.to_string(),
            }],
            result_info: ips,
            ttl_secs,
            block_metadata_queries: true,
        }
    }

    fn test_all_local_ips_redirect_rule(domain: &str, ttl_secs: u32) -> DNSRedirectRuntimeRule {
        DNSRedirectRuntimeRule {
            answer_mode: DnsRedirectAnswerMode::AllLocalIps,
            ..test_static_redirect_rule(domain, vec![], ttl_secs)
        }
    }

    fn sample_a_record(name: &str, ttl: u32, addr: Ipv4Addr) -> Record {
        Record::from_rdata(hickory_proto::rr::Name::from_str(name).unwrap(), ttl, RData::A(A(addr)))
    }

    #[test]
    fn resolve_arpa_dispatches_by_second_level_label() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            // resolver.arpa. → resolver branch
            let answer = handler
                .resolve_query(&ParsedDomain::new("resolver.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(answer.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::Local);

            // home.arpa. is not the default `lan` zone.
            let answer = handler
                .resolve_query(&ParsedDomain::new("home.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(answer.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::NxDomain);

            // in-addr.arpa. → reverse branch
            let answer = handler
                .resolve_query(
                    &ParsedDomain::new("1.0.0.10.in-addr.arpa.").unwrap(),
                    RecordType::PTR,
                )
                .await;
            assert!(answer.records.is_empty());

            // ip6.arpa. → reverse branch
            let answer = handler
                .resolve_query(
                    &ParsedDomain::new(
                        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
                    )
                    .unwrap(),
                    RecordType::PTR,
                )
                .await;
            assert!(answer.records.is_empty());

            // evilresolver.arpa. is not resolver → NXDOMAIN
            let answer = handler
                .resolve_query(&ParsedDomain::new("evilresolver.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(answer.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::NxDomain);
        });
    }

    #[test]
    fn disabled_lan_hostname_registry_does_not_own_private_ptr_queries() {
        run_async_test(async {
            let registry = LanHostnameRegistry::new_for_test(
                landscape_common::sys_service::lan_hostname::LanHostnameConfig {
                    enable: false,
                    lan_suffix: "lan".to_string(),
                },
            );
            let handler = test_handler_with_local(registry, None, vec![], vec![]);
            let domain = ParsedDomain::new("50.1.168.192.in-addr.arpa.").unwrap();

            // A disabled registry does not own private PTR queries: they fall
            // through to the cache/upstream stage (no rules → NOERROR/empty).
            let answer = handler.resolve_query(&domain, RecordType::PTR).await;
            assert!(answer.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::Normal);

            let loopback_domain = ParsedDomain::new("1.0.0.127.in-addr.arpa.").unwrap();
            let answer = handler.resolve_query(&loopback_domain, RecordType::PTR).await;
            assert_eq!(answer.outcome, DnsOutcome::Local);
            assert_eq!(answer.records.len(), 1);
        });
    }

    #[test]
    fn check_domain_applies_filter_when_requested() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_dns_rule(FilterResult::OnlyIPv6, &["example.com"])],
                vec![],
            );

            let result = handler
                .check_domain(&ParsedDomain::new("example.com.").unwrap(), RecordType::A, true)
                .await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn check_domain_filters_cached_records_when_requested() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            handler
                .insert(
                    "cached-filter.example.",
                    RecordType::A,
                    vec![sample_a_record("cached-filter.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::OnlyIPv6,
                    None,
                    None,
                )
                .await;

            let result = handler
                .check_domain(
                    &ParsedDomain::new("cached-filter.example.").unwrap(),
                    RecordType::A,
                    true,
                )
                .await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert!(result.cache_records.as_ref().is_some_and(Vec::is_empty));
        });
    }

    #[test]
    fn check_domain_keeps_full_cached_records_without_filter_flag() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            handler
                .insert(
                    "cached-full.example.",
                    RecordType::A,
                    vec![sample_a_record("cached-full.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::OnlyIPv6,
                    None,
                    None,
                )
                .await;

            let result = handler
                .check_domain(
                    &ParsedDomain::new("cached-full.example.").unwrap(),
                    RecordType::A,
                    false,
                )
                .await;

            assert_eq!(result.rule_filter, Some(FilterResult::OnlyIPv6));
            assert!(result.query_filtered);
            assert_eq!(result.cache_records.as_ref().map(Vec::len), Some(1));
        });
    }

    #[test]
    fn check_domain_handles_local_tld_before_upstream_rules() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);

            let result = handler
                .check_domain(&ParsedDomain::new("printer.local.").unwrap(), RecordType::A, true)
                .await;

            assert!(result.rule_id.is_none());
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn refresh_cache_entry_handles_local_zones_without_upstream_rule_refresh() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);

            let result = handler
                .refresh_cache_entry(
                    &ParsedDomain::new("foo.localhost.").unwrap(),
                    RecordType::AAAA,
                    true,
                )
                .await
                .unwrap();

            assert!(result.rule_id.is_none());
            assert_eq!(result.records.as_ref().map(Vec::len), Some(1));
            assert!(result.cache_records.is_none());
        });
    }

    #[test]
    fn refresh_cache_entry_clears_stale_unowned_arpa_entry() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            let domain = "8.8.8.8.in-addr.arpa.";
            handler
                .insert(
                    domain,
                    RecordType::PTR,
                    vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            // Public reverse names are not owned locally: without a rule the
            // live path answers NOERROR/empty, so refresh must return Ok and
            // drop the stale entry instead of failing with RefreshRequiresRule.
            let result = handler
                .refresh_cache_entry(&ParsedDomain::new(domain).unwrap(), RecordType::PTR, true)
                .await
                .unwrap();

            assert!(result.records.as_ref().is_some_and(Vec::is_empty));

            let runtime = handler.snapshot.load_full();
            assert!(
                runtime
                    .cache
                    .lookup(&ParsedDomain::new(domain).unwrap(), RecordType::PTR)
                    .await
                    .is_none(),
                "stale reverse entry must be cleared"
            );
        });
    }

    #[test]
    fn refresh_cache_entry_arpa_with_matching_rule_clears_cache() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_dns_rule(FilterResult::OnlyIPv6, &["8.8.8.8.in-addr.arpa"])],
                vec![],
            );

            let domain = "8.8.8.8.in-addr.arpa.";
            handler
                .insert(
                    domain,
                    RecordType::A,
                    vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let result = handler
                .refresh_cache_entry(&ParsedDomain::new(domain).unwrap(), RecordType::A, true)
                .await
                .unwrap();

            // The OnlyIPv6 rule filters the A query, so no upstream lookup is
            // attempted and the result is empty — but the stale entry must be
            // gone so the cache converges with what clients see.
            assert!(result.records.as_ref().is_some_and(Vec::is_empty));

            let runtime = handler.snapshot.load_full();
            assert!(
                runtime
                    .cache
                    .lookup(&ParsedDomain::new(domain).unwrap(), RecordType::A)
                    .await
                    .is_none(),
                "stale reverse entry must be cleared"
            );
        });
    }

    #[test]
    fn check_domain_reports_only_cache_for_unowned_arpa() {
        run_async_test(async {
            let handler = make_test_handler(vec![], vec![]);

            let domain = "8.8.8.8.in-addr.arpa.";
            handler
                .insert(
                    domain,
                    RecordType::PTR,
                    vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let result = handler
                .check_domain(&ParsedDomain::new(domain).unwrap(), RecordType::PTR, true)
                .await;

            // Check is read-only: unowned reverse names are not resolved
            // live, only projected from the cache.
            assert!(result.records.is_none());
            assert_eq!(result.cache_records.as_ref().map(Vec::len), Some(1));
        });
    }

    #[test]
    fn test_negative_cache_ttl_updates_are_shared_across_clones() {
        run_async_test(async {
            let runtime_config = shared_cache_runtime_config(7);
            let handler = test_handler_with_config(runtime_config.clone(), 9, vec![], vec![]);
            let handler_clone = handler.clone();

            runtime_config.store(Arc::new(test_cache_runtime_config(33)));
            handler.renew_runtime_config(false).await;

            handler_clone
                .insert(
                    "negative-cache.example.",
                    RecordType::A,
                    vec![],
                    ResponseCode::NXDomain,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let runtime = handler_clone.snapshot.load_full();
            let cache_item = runtime
                .cache
                .get(&(Arc::from("negative-cache.example."), RecordType::A))
                .await
                .expect("cache item must exist");

            assert_eq!(cache_item.min_ttl, 33);
            assert_eq!(cache_item.response_code, ResponseCode::NXDomain);
            assert!(cache_item.rdatas.is_empty());
            assert_eq!(cache_item.mark.priority, 0);
        });
    }

    #[test]
    fn renew_engines_publishes_one_new_runtime_snapshot() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_runtime_rule()],
                vec![test_static_redirect_rule(
                    "old.example.com",
                    vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                    17,
                )],
            );

            let old_runtime = handler.snapshot.load_full();

            let (redirect_engine, resolve_engine) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![test_static_redirect_rule(
                        "new.example.com",
                        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
                        33,
                    )],
                });
            handler.renew_engines(redirect_engine, resolve_engine).await;

            let new_runtime = handler.snapshot.load_full();
            assert!(!Arc::ptr_eq(&old_runtime, &new_runtime));
            assert!(!Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert!(!Arc::ptr_eq(&old_runtime.redirect_engine, &new_runtime.redirect_engine));
            assert!(handler
                .lookup_redirects(&ParsedDomain::new("old.example.com.").unwrap(), RecordType::A)
                .is_none());

            let records = handler
                .lookup_redirects(&ParsedDomain::new("new.example.com.").unwrap(), RecordType::A)
                .unwrap()
                .records;
            assert_eq!(records[0].ttl, 33);
        });
    }

    #[test]
    fn renew_engines_drops_cache_entries_taken_over_by_redirects() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);
            handler
                .insert(
                    "redirected.example.",
                    RecordType::A,
                    vec![sample_a_record("redirected.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    Some(test_runtime_rule().id),
                    Some(test_runtime_rule().index),
                )
                .await;

            let (redirect_engine, resolve_engine) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![test_runtime_rule()],
                    redirect_rules: vec![test_static_redirect_rule(
                        "redirected.example",
                        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                        30,
                    )],
                });

            handler.renew_engines(redirect_engine, resolve_engine).await;

            assert!(handler
                .snapshot
                .load_full()
                .cache
                .get(&(Arc::from("redirected.example."), RecordType::A))
                .await
                .is_none());
        });
    }

    #[test]
    fn renew_dns_rules_preserves_redirects_and_caps_migrated_cache_ttl() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![test_runtime_rule()],
                vec![test_static_redirect_rule(
                    "redirect.example",
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                    30,
                )],
            );
            let rule = test_runtime_rule();
            handler
                .insert(
                    "cached.example.",
                    RecordType::A,
                    vec![sample_a_record("cached.example.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    Some(rule.id),
                    Some(rule.index),
                )
                .await;
            handler
                .insert(
                    "short.example.",
                    RecordType::A,
                    vec![sample_a_record("short.example.", 3, Ipv4Addr::new(1, 0, 0, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    Some(rule.id),
                    Some(rule.index),
                )
                .await;

            let old_runtime = handler.snapshot.load_full();
            let (_, resolve_engine) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![rule],
                    redirect_rules: vec![],
                });
            handler.renew_dns_rules(resolve_engine).await;

            let new_runtime = handler.snapshot.load_full();
            assert!(Arc::ptr_eq(&old_runtime.redirect_engine, &new_runtime.redirect_engine));
            assert!(!Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert_eq!(
                new_runtime
                    .cache
                    .get(&(Arc::from("cached.example."), RecordType::A))
                    .await
                    .unwrap()
                    .min_ttl,
                RULE_REFRESH_TTL_CAP
            );
            assert_eq!(
                new_runtime
                    .cache
                    .get(&(Arc::from("short.example."), RecordType::A))
                    .await
                    .unwrap()
                    .min_ttl,
                3
            );
        });
    }

    #[test]
    fn renew_redirect_rules_preserves_resolves_and_unclaimed_cache() {
        run_async_test(async {
            let handler = make_test_handler(vec![test_runtime_rule()], vec![]);
            let rule = test_runtime_rule();
            for domain in ["redirected.example.", "kept.example."] {
                handler
                    .insert(
                        domain,
                        RecordType::A,
                        vec![sample_a_record(domain, 60, Ipv4Addr::new(1, 1, 1, 1))],
                        ResponseCode::NoError,
                        &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                        FilterResult::Unfilter,
                        Some(rule.id),
                        Some(rule.index),
                    )
                    .await;
            }

            let old_runtime = handler.snapshot.load_full();
            let old_kept =
                old_runtime.cache.get(&(Arc::from("kept.example."), RecordType::A)).await.unwrap();
            let (redirect_engine, _) =
                DnsRequestHandler::test_engines_from_legacy(ChainDnsServerInitInfo {
                    dns_rules: vec![],
                    redirect_rules: vec![test_static_redirect_rule(
                        "redirected.example",
                        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                        30,
                    )],
                });
            handler.renew_redirect_rules(redirect_engine).await;

            let new_runtime = handler.snapshot.load_full();
            assert!(Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert!(new_runtime
                .cache
                .get(&(Arc::from("redirected.example."), RecordType::A))
                .await
                .is_none());
            let new_kept =
                new_runtime.cache.get(&(Arc::from("kept.example."), RecordType::A)).await.unwrap();
            assert!(Arc::ptr_eq(&old_kept, &new_kept));
            assert_eq!(new_kept.min_ttl, 60);
        });
    }

    #[test]
    fn renew_runtime_config_rebuilds_cache_without_reloading_rules_or_redirects() {
        run_async_test(async {
            let runtime_config = shared_cache_runtime_config(5);
            let handler = test_handler_with_config(
                runtime_config.clone(),
                1,
                vec![test_runtime_rule()],
                vec![test_static_redirect_rule(
                    "example.com",
                    vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
                    17,
                )],
            );

            handler
                .insert(
                    "cached.example.com.",
                    RecordType::A,
                    vec![sample_a_record("cached.example.com.", 60, Ipv4Addr::new(1, 1, 1, 1))],
                    ResponseCode::NoError,
                    &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 0 },
                    FilterResult::Unfilter,
                    None,
                    None,
                )
                .await;

            let old_runtime = handler.snapshot.load_full();

            runtime_config.store(Arc::new(CacheRuntimeConfig {
                cache_capacity: 16,
                cache_ttl: 120,
                negative_cache_ttl: 22,
            }));
            handler.renew_runtime_config(true).await;

            let new_runtime = handler.snapshot.load_full();
            assert!(!Arc::ptr_eq(&old_runtime, &new_runtime));
            assert!(Arc::ptr_eq(&old_runtime.resolve_engine, &new_runtime.resolve_engine));
            assert!(Arc::ptr_eq(&old_runtime.redirect_engine, &new_runtime.redirect_engine));
            assert_eq!(handler.snapshot.runtime_config().load().negative_cache_ttl, 22);
            assert!(new_runtime
                .cache
                .get(&(Arc::from("cached.example.com."), RecordType::A))
                .await
                .is_some());
        });
    }

    #[test]
    fn all_local_ips_redirect_uses_provider_records() {
        run_async_test(async {
            let handler = test_handler_with_local(
                test_lan_hostname_registry(),
                Some(Arc::new(MockLocalAnswerProvider {
                    addrs: vec![
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                        IpAddr::V6(Ipv6Addr::LOCALHOST),
                    ],
                })),
                vec![],
                vec![test_all_local_ips_redirect_rule("example.com", 17)],
            );

            let answer = handler
                .lookup_redirects(&ParsedDomain::new("example.com.").unwrap(), RecordType::A)
                .unwrap();

            assert_eq!(answer.outcome, DnsOutcome::Local);
            assert_eq!(answer.redirect_id, Some(Uuid::nil()));
            assert_eq!(answer.records.len(), 1);
            assert_eq!(answer.records[0].record_type(), RecordType::A);
            assert_eq!(answer.records[0].ttl, 17);
            assert!(matches!(
                &answer.records[0].data,
                RData::A(A(ip)) if *ip == Ipv4Addr::new(192, 168, 1, 1)
            ));
        });
    }

    #[test]
    fn all_local_ips_redirect_without_family_candidates_falls_through() {
        run_async_test(async {
            let handler = test_handler_with_local(
                test_lan_hostname_registry(),
                Some(Arc::new(MockLocalAnswerProvider {
                    addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                })),
                vec![],
                vec![test_all_local_ips_redirect_rule("example.com", 17)],
            );

            assert!(handler
                .lookup_redirects(&ParsedDomain::new("example.com.").unwrap(), RecordType::AAAA)
                .is_none());
        });
    }

    #[test]
    fn static_redirect_without_matching_family_keeps_existing_no_record_behavior() {
        run_async_test(async {
            let handler = make_test_handler(
                vec![],
                vec![test_static_redirect_rule(
                    "example.com",
                    vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                    17,
                )],
            );

            let answer = handler
                .lookup_redirects(&ParsedDomain::new("example.com.").unwrap(), RecordType::AAAA)
                .unwrap();

            assert!(answer.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::Local);
            assert_eq!(answer.redirect_id, Some(Uuid::nil()));
        });
    }
}

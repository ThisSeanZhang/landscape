use super::*;
use crate::resolve::LocalDnsAnswerProvider;
use crate::upstream::pool::ResolvePool;
use arc_swap::ArcSwap;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Record;
use landscape_common::dns::redirect::{DNSRedirectRuntimeRule, DnsRedirectAnswerMode};
use landscape_common::dns::rule::{DomainConfig, DomainMatchType, FilterResult};
use landscape_common::flow::{DnsRuntimeMarkInfo, NoopDnsResultSink};
use landscape_common::metric::dns::DnsOutcome;
use landscape_common::sys_config::LanHostnameRuntimeConfig;
use landscape_core::lan_device::LanDeviceDirectory;
use std::net::IpAddr;
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
        metric_reporter: DnsMetricReporter,
        local_resolver: Arc<LocalResolver>,
    ) -> Self {
        let (redirect_engine, resolve_engine) = Self::test_engines_from_legacy(init);
        Self::from_engines(
            redirect_engine,
            resolve_engine,
            HandlerDeps {
                runtime_config,
                flow_id,
                metric_reporter,
                local_resolver,
                sink: Arc::new(NoopDnsResultSink),
            },
        )
    }

    fn test_engines_from_legacy(init: ChainDnsServerInitInfo) -> (RedirectEngine, ResolveEngine) {
        Self::test_engines_with_pool(init, &Arc::new(ResolvePool::default()))
    }

    fn test_engines_with_pool(
        init: ChainDnsServerInitInfo,
        pool: &Arc<ResolvePool>,
    ) -> (RedirectEngine, ResolveEngine) {
        use std::collections::BTreeMap;

        use crate::resolve::{
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
                    mark: rule.mark,
                    upstream: rule.resolve_mode,
                    matcher: RuntimeRuleMatcher::new(rule.source, vec![], vec![], match_all),
                    flow_id: rule.flow_id,
                    pool: pool.clone(),
                })?;
                Some((order, runtime))
            })
            .collect::<BTreeMap<_, _>>();

        (RedirectEngine::new(redirects), ResolveEngine::new(resolves))
    }

    #[allow(clippy::too_many_arguments)]
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
            .insert(crate::resolve::cache::CacheEntry {
                domain_key: Arc::<str>::from(domain),
                query_type,
                answer: crate::resolve::answer::DnsAnswer::new(rdata_ttl_vec, response_code),
                mark: mark.clone(),
                filter,
                matched_rule_id,
                matched_rule_order,
            })
            .await;
    }
}

/// Handler for listener-level end-to-end tests: a single static redirect rule
/// answering `domain` with `addr`, no upstreams.
pub(crate) fn redirect_test_handler(
    domain: &str,
    addr: IpAddr,
    ttl_secs: u32,
) -> DnsRequestHandler {
    redirect_test_handler_with_addrs(domain, vec![addr], ttl_secs)
}

/// Same as [`redirect_test_handler`], with several answers so listener tests
/// can produce responses larger than the 512-byte UDP limit.
pub(crate) fn redirect_test_handler_with_addrs(
    domain: &str,
    addrs: Vec<IpAddr>,
    ttl_secs: u32,
) -> DnsRequestHandler {
    DnsRequestHandler::new(
        ChainDnsServerInitInfo {
            dns_rules: vec![],
            redirect_rules: vec![DNSRedirectRuntimeRule {
                redirect_id: Some(Uuid::nil()),
                dynamic_redirect_source: None,
                answer_mode: DnsRedirectAnswerMode::StaticIps,
                match_rules: vec![DomainConfig {
                    match_type: DomainMatchType::Full,
                    value: domain.to_string(),
                }],
                result_info: addrs,
                ttl_secs,
                block_metadata_queries: true,
            }],
        },
        Arc::new(ArcSwap::from_pointee(CacheRuntimeConfig {
            cache_capacity: 16,
            cache_ttl: 60,
            negative_cache_ttl: 5,
        })),
        1,
        DnsMetricReporter::default(),
        Arc::new(LocalResolver::new(
            LanDeviceDirectory::new_for_test(),
            Arc::new(ArcSwap::from_pointee(LanHostnameRuntimeConfig::default())),
            None,
            None,
            Default::default(),
        )),
    )
}

#[allow(clippy::module_inception)]
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

    #[derive(Default)]
    struct RecordingSink(std::sync::Mutex<Vec<landscape_common::flow::FlowMarkInfo>>);

    impl DnsResultSink for RecordingSink {
        fn record_dns_answer(&self, _: u32, marks: Vec<landscape_common::flow::FlowMarkInfo>) {
            self.0.lock().unwrap().extend(marks);
        }
        fn refresh_dns_marks(&self, _: u32, marks: Vec<landscape_common::flow::FlowMarkInfo>) {
            *self.0.lock().unwrap() = marks;
        }
        fn rebuild_route_cache(&self) {}
    }

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
            ChainDnsServerInitInfo { dns_rules, redirect_rules },
            shared_cache_runtime_config(5),
            1,
            DnsMetricReporter::default(),
            test_local_resolver(),
        )
    }

    fn handler_with_pool(
        init: ChainDnsServerInitInfo,
        pool: &Arc<ResolvePool>,
        sink: Arc<dyn landscape_common::flow::DnsResultSink>,
    ) -> DnsRequestHandler {
        let (redirect, resolve) = DnsRequestHandler::test_engines_with_pool(init, pool);
        DnsRequestHandler::from_engines(
            redirect,
            resolve,
            HandlerDeps {
                runtime_config: shared_cache_runtime_config(5),
                flow_id: 1,
                metric_reporter: Default::default(),
                local_resolver: test_local_resolver(),
                sink,
            },
        )
    }

    fn test_handler_with_local(
        hostname_config: Arc<ArcSwap<LanHostnameRuntimeConfig>>,
        provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules },
            shared_cache_runtime_config(5),
            1,
            DnsMetricReporter::default(),
            Arc::new(LocalResolver::new(
                LanDeviceDirectory::new_for_test(),
                hostname_config,
                provider,
                None,
                Default::default(),
            )),
        )
    }

    fn test_handler_with_config(
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        dns_rules: Vec<DNSRuntimeRule>,
        redirect_rules: Vec<DNSRedirectRuntimeRule>,
    ) -> DnsRequestHandler {
        DnsRequestHandler::new(
            ChainDnsServerInitInfo { dns_rules, redirect_rules },
            runtime_config,
            flow_id,
            DnsMetricReporter::default(),
            test_local_resolver(),
        )
    }

    fn test_local_resolver() -> Arc<LocalResolver> {
        Arc::new(LocalResolver::new(
            LanDeviceDirectory::new_for_test(),
            test_lan_hostname_config(),
            None,
            None,
            Default::default(),
        ))
    }

    fn test_lan_hostname_config() -> Arc<ArcSwap<LanHostnameRuntimeConfig>> {
        Arc::new(ArcSwap::from_pointee(LanHostnameRuntimeConfig::default()))
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
            assert!(answer.dns.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::Local);

            // home.arpa. is not the default `lan` zone.
            let answer = handler
                .resolve_query(&ParsedDomain::new("home.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(answer.dns.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::NxDomain);

            // in-addr.arpa. → reverse branch
            let answer = handler
                .resolve_query(
                    &ParsedDomain::new("1.0.0.10.in-addr.arpa.").unwrap(),
                    RecordType::PTR,
                )
                .await;
            assert!(answer.dns.records.is_empty());

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
            assert!(answer.dns.records.is_empty());

            // evilresolver.arpa. is not resolver → NXDOMAIN
            let answer = handler
                .resolve_query(&ParsedDomain::new("evilresolver.arpa.").unwrap(), RecordType::A)
                .await;
            assert!(answer.dns.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::NxDomain);
        });
    }

    #[test]
    fn disabled_lan_hostname_config_does_not_own_private_ptr_queries() {
        run_async_test(async {
            let disabled_config = Arc::new(ArcSwap::from_pointee(LanHostnameRuntimeConfig {
                enable: false,
                lan_suffix: "lan".to_string(),
            }));
            let handler = test_handler_with_local(disabled_config, None, vec![], vec![]);
            let domain = ParsedDomain::new("50.1.168.192.in-addr.arpa.").unwrap();

            // A disabled config does not own private PTR queries: they fall
            // through to the cache/upstream stage (no rules → NOERROR/empty).
            let answer = handler.resolve_query(&domain, RecordType::PTR).await;
            assert!(answer.dns.records.is_empty());
            assert_eq!(answer.outcome, DnsOutcome::Normal);

            let loopback_domain = ParsedDomain::new("1.0.0.127.in-addr.arpa.").unwrap();
            let answer = handler.resolve_query(&loopback_domain, RecordType::PTR).await;
            assert_eq!(answer.outcome, DnsOutcome::Local);
            assert_eq!(answer.dns.records.len(), 1);
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

    #[cfg(feature = "pool-native")]
    mod upstream_answers {
        use super::*;
        use crate::listener::wire::{self, DecodeOutcome, Protocol};
        use crate::upstream::test_util::{
            ScriptedAction, ScriptedDnsServer, mark_supported_or_fail,
        };
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::Name;
        use std::time::Duration;

        fn server_rule(server: &ScriptedDnsServer, native: bool) -> DNSRuntimeRule {
            DNSRuntimeRule {
                resolve_mode: DnsUpstreamConfig {
                    use_experimental_pool: Some(native),
                    ips: vec![Ipv4Addr::LOCALHOST.into()],
                    port: Some(server.port()),
                    ..Default::default()
                },
                ..test_runtime_rule()
            }
        }

        fn handler_for(server: &ScriptedDnsServer, native: bool) -> DnsRequestHandler {
            make_test_handler(vec![server_rule(server, native)], vec![])
        }

        fn request() -> DnsRequest {
            let mut query = Message::new(42, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii("www.example.com.").unwrap(),
                RecordType::A,
            ));
            let DecodeOutcome::Request(req) = wire::decode(
                &query.to_vec().unwrap(),
                "127.0.0.1:53000".parse().unwrap(),
                Protocol::Udp,
            ) else {
                panic!("expected valid test query");
            };
            req
        }

        async fn wire_answer(handler: &DnsRequestHandler, req: &DnsRequest) -> Message {
            let message = handler.handle(req).await;
            Message::from_vec(&wire::encode_response(&message, req.edns_max_size)).unwrap()
        }

        #[tokio::test]
        async fn admin_check_and_refresh_resolve_the_same_name_as_wire_queries() {
            if !mark_supported_or_fail() {
                return;
            }
            let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
            let handler = handler_for(&server, true);
            let domain = ParsedDomain::new("WWW.Example.COM").unwrap();
            let checked = handler.check_domain(&domain, RecordType::A, false).await;
            assert_eq!(checked.records.unwrap()[0].data, "1.2.3.4");
            assert!(checked.cache_records.is_none());

            let refreshed =
                handler.refresh_cache_entry(&domain, RecordType::A, false).await.unwrap();
            assert_eq!(refreshed.cache_records.unwrap()[0].data, "1.2.3.4");
            let answer = wire_answer(&handler, &request()).await;
            assert_eq!(answer.answers[0].data.to_string(), "1.2.3.4");
            assert_eq!(server.queries(), 2);
        }

        #[tokio::test]
        async fn partial_udp_answer_after_failed_tcp_retry_keeps_tc_and_bypasses_cache() {
            if !mark_supported_or_fail() {
                return;
            }
            let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
            server.push_udp(ScriptedAction::Truncate);
            for _ in 0..3 {
                server.push_tcp(ScriptedAction::Reset);
            }
            let handler = handler_for(&server, true);
            let req = request();
            let partial = wire_answer(&handler, &req).await;
            assert!(partial.metadata.truncation);
            assert_eq!(partial.answers.len(), 1);
            let queries = server.queries();
            assert!(queries >= 2);
            let full = wire_answer(&handler, &req).await;
            assert!(!full.metadata.truncation);
            assert_eq!(full.answers.len(), 1);
            assert_eq!(server.queries(), queries + 1);
            assert_eq!(wire_answer(&handler, &req).await.answers, full.answers);
            assert_eq!(server.queries(), queries + 1);
        }

        #[tokio::test]
        async fn negative_soa_survives_cache_hit_and_expires_on_time() {
            if !mark_supported_or_fail() {
                return;
            }
            for native in [true, false] {
                for (code, ttl, minimum) in [
                    (ResponseCode::NXDomain, 90, 3),
                    (ResponseCode::NoError, 4, 60),
                    (ResponseCode::NXDomain, 90, 60),
                ] {
                    let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
                    server.push_udp(ScriptedAction::Negative {
                        code,
                        soa: Some((ttl, minimum)),
                        alias_ttl: None,
                    });
                    let handler = handler_for(&server, native);
                    let req = request();
                    let first = wire_answer(&handler, &req).await;
                    assert_eq!(first.metadata.response_code, code);
                    assert!(!first.metadata.authoritative);
                    assert!(first.answers.is_empty());
                    assert_eq!(first.authorities.len(), 1);
                    let mut soa = first.authorities[0].clone();
                    assert_eq!(soa.record_type(), RecordType::SOA);
                    assert_eq!(soa.ttl, ttl.min(minimum));
                    let queries = server.queries();
                    let runtime = handler.snapshot.load_full();
                    let key = (req.domain.raw_arc().clone(), req.query_type);
                    let original = runtime.cache.get(&key).await.unwrap();
                    let mut item = (*original).clone();
                    item.insert_time -= Duration::from_secs(2);
                    runtime.cache.insert_raw(key.clone(), Arc::new(item)).await;
                    let hit = wire_answer(&handler, &req).await;
                    soa.ttl = soa.ttl.min(5) - 2;
                    assert_eq!(hit.metadata.response_code, code);
                    assert!(!hit.metadata.authoritative);
                    assert_eq!(hit.authorities, [soa]);
                    assert_eq!(server.queries(), queries);

                    let mut item = (*original).clone();
                    item.insert_time -= Duration::from_secs(u64::from(item.min_ttl));
                    runtime.cache.insert_raw(key, Arc::new(item)).await;
                    assert_eq!(wire_answer(&handler, &req).await.answers.len(), 1);
                    assert!(server.queries() > queries);
                }
            }
        }

        #[tokio::test]
        async fn negative_alias_is_served_and_cached_without_a_follow_up() {
            if !mark_supported_or_fail() {
                return;
            }
            for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
                let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
                server.push_udp(ScriptedAction::Negative {
                    code,
                    soa: Some((60, 4)),
                    alias_ttl: Some(2),
                });
                let handler = handler_for(&server, true);
                let req = request();
                for cached in [false, true] {
                    let answer = wire_answer(&handler, &req).await;
                    assert_eq!(answer.metadata.response_code, code);
                    assert!(!answer.metadata.authoritative);
                    assert_eq!(answer.answers.len(), 1);
                    assert_eq!(answer.answers[0].record_type(), RecordType::CNAME);
                    assert_eq!(answer.answers[0].ttl, 2);
                    assert_eq!(answer.authorities.len(), 1);
                    assert_eq!(answer.authorities[0].ttl, if cached { 2 } else { 4 });
                    assert_eq!(server.queries(), 1);
                }
            }
        }

        #[tokio::test]
        async fn admin_check_and_refresh_preserve_nxdomain_answer_records() {
            if !mark_supported_or_fail() {
                return;
            }
            for alias_ttl in [Some(40), None] {
                let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
                let negative = ScriptedAction::Negative {
                    code: ResponseCode::NXDomain,
                    soa: Some((60, 30)),
                    alias_ttl,
                };
                server.push_udp(negative.clone());
                server.push_udp(negative);
                let handler = handler_for(&server, true);
                let req = request();

                let checked = handler.check_domain(&req.domain, req.query_type, false).await;
                assert!(checked.cache_records.is_none());
                assert_eq!(checked.records.is_some(), alias_ttl.is_some());
                let refreshed =
                    handler.refresh_cache_entry(&req.domain, req.query_type, true).await.unwrap();
                let wire = wire_answer(&handler, &req).await;
                assert_eq!(wire.response_code, ResponseCode::NXDomain);
                assert_eq!(server.queries(), 2);
                assert_eq!(wire.answers.len(), usize::from(alias_ttl.is_some()));
                for records in [
                    checked.records.unwrap_or_default(),
                    refreshed.records.unwrap(),
                    refreshed.cache_records.unwrap(),
                ] {
                    assert_eq!(records.len(), wire.answers.len());
                    for (record, answer) in records.iter().zip(&wire.answers) {
                        assert_eq!(record.name, answer.name.to_string());
                        assert_eq!(record.rr_type, answer.record_type().to_string());
                        assert_eq!(record.data, answer.data.to_string());
                    }
                }
            }
        }

        #[tokio::test]
        async fn admin_refresh_only_shows_a_filtered_nxdomain_alias_in_the_raw_report() {
            if !mark_supported_or_fail() {
                return;
            }
            let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
            let rule = DNSRuntimeRule {
                filter: FilterResult::OnlyIPv6,
                ..server_rule(&server, true)
            };
            let handler = make_test_handler(vec![rule], vec![]);
            let req = request();
            for apply_filter in [false, true] {
                server.push_udp(ScriptedAction::Negative {
                    code: ResponseCode::NXDomain,
                    soa: None,
                    alias_ttl: Some(40),
                });
                let report = handler
                    .refresh_cache_entry(&req.domain, req.query_type, apply_filter)
                    .await
                    .unwrap();
                assert!(report.query_filtered);
                assert!(report.cache_records.is_none());
                let records = report.records.unwrap();
                if apply_filter {
                    assert!(records.is_empty());
                } else {
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0].rr_type, "CNAME");
                }
            }
        }

        #[tokio::test]
        async fn alias_ending_in_nodata_without_soa_respects_negative_cache_ttl() {
            if !mark_supported_or_fail() {
                return;
            }
            for cap in [5, 0] {
                let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
                for alias_ttl in [Some(40), None] {
                    server.push_udp(ScriptedAction::Negative {
                        code: ResponseCode::NoError,
                        soa: None,
                        alias_ttl,
                    });
                }
                let handler = test_handler_with_config(
                    shared_cache_runtime_config(cap),
                    1,
                    vec![server_rule(&server, true)],
                    vec![],
                );
                let req = request();
                let first = wire_answer(&handler, &req).await;
                assert_eq!(first.response_code, ResponseCode::NoError);
                assert!(first.authorities.is_empty());
                assert_eq!(first.answers.len(), 1);
                assert_eq!(first.answers[0].record_type(), RecordType::CNAME);
                assert_eq!(server.queries(), 2);

                let key = (req.domain.raw_arc().clone(), req.query_type);
                let runtime = handler.snapshot.load_full();
                if cap > 0 {
                    let hit = wire_answer(&handler, &req).await;
                    assert_eq!(hit.answers[0].record_type(), RecordType::CNAME);
                    assert!(hit.answers[0].ttl <= cap);
                    assert_eq!(server.queries(), 2);
                    let mut item = (*runtime.cache.get(&key).await.unwrap()).clone();
                    item.insert_time -= Duration::from_secs(u64::from(cap));
                    runtime.cache.insert_raw(key, Arc::new(item)).await;
                }
                let fresh = wire_answer(&handler, &req).await;
                assert_eq!(fresh.answers[0].record_type(), RecordType::A);
                assert_eq!(server.queries(), 3);
            }
        }

        #[tokio::test]
        async fn lookup_completing_after_rule_removal_cannot_restore_old_marks() {
            if !mark_supported_or_fail() {
                return;
            }
            let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
            let release = Arc::new(tokio::sync::Notify::new());
            server.push_udp(ScriptedAction::AnswerOn(release.clone()));
            let rule = DNSRuntimeRule {
                mark: FlowMark::from(0x0100),
                ..server_rule(&server, true)
            };
            let sink = Arc::new(RecordingSink::default());
            let handler = handler_with_pool(
                ChainDnsServerInitInfo { dns_rules: vec![rule], ..Default::default() },
                &Arc::new(ResolvePool::default()),
                sink.clone(),
            );
            let old = handler.snapshot.load_full();
            let req = request();
            let refresh = async {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while server.queries() == 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                handler.renew_dns_rules(ResolveEngine::default()).await;
                release.notify_one();
            };
            let (answer, ()) = tokio::join!(wire_answer(&handler, &req), refresh);
            assert_eq!(answer.answers.len(), 1);
            old.cache.run_pending_tasks().await;
            assert_eq!(old.cache.dns_mark_list().len(), 1);
            old.cache.refresh_marks();
            assert!(sink.0.lock().unwrap().is_empty());
            assert!(handler.snapshot.load_full().cache.dns_mark_list().is_empty());
        }

        #[tokio::test]
        async fn zero_soa_minimum_allows_next_query_to_recover() {
            if !mark_supported_or_fail() {
                return;
            }
            let server = ScriptedDnsServer::spawn(Ipv4Addr::LOCALHOST.into()).await;
            server.push_udp(ScriptedAction::Negative {
                code: ResponseCode::NXDomain,
                soa: Some((60, 0)),
                alias_ttl: None,
            });
            let handler = handler_for(&server, true);
            let req = request();
            let negative = wire_answer(&handler, &req).await;
            assert_eq!(negative.metadata.response_code, ResponseCode::NXDomain);
            assert_eq!(negative.authorities[0].ttl, 0);
            let queries = server.queries();
            assert_eq!(wire_answer(&handler, &req).await.answers.len(), 1);
            assert_eq!(server.queries(), queries + 1);
        }
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
            assert_eq!(cache_item.answer.response_code, ResponseCode::NXDomain);
            assert!(cache_item.answer.records.is_empty());
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
            assert!(
                handler
                    .lookup_redirects(
                        &ParsedDomain::new("old.example.com.").unwrap(),
                        RecordType::A
                    )
                    .is_none()
            );

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

            assert!(
                handler
                    .snapshot
                    .load_full()
                    .cache
                    .get(&(Arc::from("redirected.example."), RecordType::A))
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn renew_dns_rules_preserves_redirects_and_caps_migrated_cache_ttl() {
        run_async_test(async {
            let pool = Arc::new(ResolvePool::default());
            let rule = test_runtime_rule();
            let handler = handler_with_pool(
                ChainDnsServerInitInfo {
                    dns_rules: vec![rule.clone()],
                    redirect_rules: vec![test_static_redirect_rule(
                        "redirect.example",
                        vec![Ipv4Addr::LOCALHOST.into()],
                        30,
                    )],
                },
                &pool,
                Arc::new(NoopDnsResultSink),
            );
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
            let (_, resolve_engine) = DnsRequestHandler::test_engines_with_pool(
                ChainDnsServerInitInfo { dns_rules: vec![rule], redirect_rules: vec![] },
                &pool,
            );
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

    #[tokio::test]
    async fn higher_priority_rule_takes_effect_on_a_previously_cached_name() {
        let pool = Arc::new(ResolvePool::default());
        let rule = DNSRuntimeRule { index: 100, ..test_runtime_rule() };
        let name = "cached.example.";
        let init = |rules| ChainDnsServerInitInfo { dns_rules: rules, ..Default::default() };
        let handler =
            handler_with_pool(init(vec![rule.clone()]), &pool, Arc::new(NoopDnsResultSink));
        handler
            .insert(
                name,
                RecordType::A,
                vec![sample_a_record(name, 60, Ipv4Addr::LOCALHOST)],
                ResponseCode::NoError,
                &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 100 },
                FilterResult::Unfilter,
                Some(rule.id),
                Some(rule.index),
            )
            .await;
        let domain = ParsedDomain::new(name).unwrap();
        assert_eq!(handler.resolve_query(&domain, RecordType::A).await.outcome, DnsOutcome::Hit);
        let higher = DNSRuntimeRule {
            id: Uuid::new_v4(),
            index: 1,
            filter: FilterResult::OnlyIPv6,
            ..rule.clone()
        };
        let (_, next) = DnsRequestHandler::test_engines_with_pool(init(vec![higher, rule]), &pool);
        handler.renew_dns_rules(next).await;
        let answer = handler.resolve_query(&domain, RecordType::A).await;
        assert_eq!(answer.outcome, DnsOutcome::Filter);
        assert!(answer.dns.records.is_empty());
        assert!(
            handler
                .snapshot
                .load_full()
                .cache
                .get(&(Arc::from(name), RecordType::A))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn upstream_replaced_under_same_id_drops_answers_on_rule_reload() {
        let pool = Arc::new(ResolvePool::default());
        let rule = test_runtime_rule();
        let init = || ChainDnsServerInitInfo {
            dns_rules: vec![rule.clone()],
            ..Default::default()
        };
        let handler = handler_with_pool(init(), &pool, Arc::new(NoopDnsResultSink));
        let name = "changed-upstream.example.";
        handler
            .insert(
                name,
                RecordType::A,
                vec![sample_a_record(name, 60, Ipv4Addr::LOCALHOST)],
                ResponseCode::NoError,
                &DnsRuntimeMarkInfo { mark: rule.mark, priority: 1 },
                FilterResult::Unfilter,
                Some(rule.id),
                Some(rule.index),
            )
            .await;
        let key = (Arc::from(name), RecordType::A);
        assert!(handler.snapshot.load_full().cache.get(&key).await.is_some());
        pool.invalidate(&std::collections::HashSet::from([rule.resolve_mode.id]));
        let (_, rules) = DnsRequestHandler::test_engines_with_pool(init(), &pool);
        handler.renew_dns_rules(rules).await;
        assert!(handler.snapshot.load_full().cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn lowering_cache_lifetime_uses_original_insertion_time() {
        let config = shared_cache_runtime_config(5);
        let handler =
            test_handler_with_config(config.clone(), 1, vec![test_runtime_rule()], vec![]);
        let name = "cache-age.example.";
        let key = (Arc::from(name), RecordType::A);
        handler
            .insert(
                name,
                RecordType::A,
                vec![sample_a_record(name, 600, Ipv4Addr::LOCALHOST)],
                ResponseCode::NoError,
                &DnsRuntimeMarkInfo { mark: FlowMark::default(), priority: 1 },
                FilterResult::Unfilter,
                None,
                None,
            )
            .await;
        let old = handler.snapshot.load_full();
        let mut item = (*old.cache.get(&key).await.unwrap()).clone();
        item.insert_time -= std::time::Duration::from_secs(30);
        old.cache.insert_raw(key.clone(), Arc::new(item)).await;
        assert!(old.cache.get(&key).await.is_some());
        config
            .store(Arc::new(CacheRuntimeConfig { cache_ttl: 10, ..test_cache_runtime_config(5) }));
        handler.renew_runtime_config(true).await;
        assert!(handler.snapshot.load_full().cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn rebuilding_marks_skips_expired_entries_before_and_after_migration() {
        let pool = Arc::new(ResolvePool::default());
        let rule = DNSRuntimeRule {
            mark: FlowMark::from(0x0100),
            ..test_runtime_rule()
        };
        let sink = Arc::new(RecordingSink::default());
        let init = ChainDnsServerInitInfo {
            dns_rules: vec![rule.clone()],
            ..Default::default()
        };
        let handler = handler_with_pool(init, &pool, sink.clone());
        let name = "expired.example.";
        let key = (Arc::from(name), RecordType::A);
        handler
            .insert(
                name,
                RecordType::A,
                vec![sample_a_record(name, 1, Ipv4Addr::LOCALHOST)],
                ResponseCode::NoError,
                &DnsRuntimeMarkInfo { mark: rule.mark, priority: 1 },
                FilterResult::Unfilter,
                Some(rule.id),
                Some(rule.index),
            )
            .await;
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        let old = handler.snapshot.load_full();
        let mut item = (*old.cache.get(&key).await.unwrap()).clone();
        item.insert_time -= std::time::Duration::from_secs(2);
        old.cache.insert_raw(key.clone(), Arc::new(item)).await;
        old.cache.run_pending_tasks().await;
        old.cache.refresh_marks();
        assert!(sink.0.lock().unwrap().is_empty());
        handler.renew_runtime_config(true).await;
        assert!(handler.snapshot.load_full().cache.get(&key).await.is_none());
        assert!(sink.0.lock().unwrap().is_empty());
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
            assert!(
                new_runtime
                    .cache
                    .get(&(Arc::from("redirected.example."), RecordType::A))
                    .await
                    .is_none()
            );
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
            assert!(
                new_runtime
                    .cache
                    .get(&(Arc::from("cached.example.com."), RecordType::A))
                    .await
                    .is_some()
            );
        });
    }

    #[test]
    fn all_local_ips_redirect_uses_provider_records() {
        run_async_test(async {
            let handler = test_handler_with_local(
                test_lan_hostname_config(),
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
                test_lan_hostname_config(),
                Some(Arc::new(MockLocalAnswerProvider {
                    addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                })),
                vec![],
                vec![test_all_local_ips_redirect_rule("example.com", 17)],
            );

            assert!(
                handler
                    .lookup_redirects(&ParsedDomain::new("example.com.").unwrap(), RecordType::AAAA)
                    .is_none()
            );
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

#[tokio::test]
async fn metric_reporter_switches_targets_without_rebuilding_handler_or_affecting_answers() {
    use crate::listener::wire::{DecodeOutcome, Protocol, decode};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::Name;
    use tokio::sync::mpsc;

    let handler = redirect_test_handler("example.com", "192.0.2.1".parse().unwrap(), 60);
    let owner = handler.metric_reporter.clone();
    let mut message = Message::new(123, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
    let bytes = message.to_vec().unwrap();
    let DecodeOutcome::Request(req) =
        decode(&bytes, "127.0.0.1:12345".parse().unwrap(), Protocol::Udp)
    else {
        panic!("valid DNS request expected");
    };
    let (first_tx, mut first_rx) = mpsc::channel(1);
    owner.replace_sender(Some(first_tx));
    let response = handler.handle(&req).await;
    assert!(response.metadata.authoritative);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(first_rx.recv().await.unwrap().flow_id, handler.flow_id);

    let (next_tx, mut next_rx) = mpsc::channel(1);
    owner.replace_sender(Some(next_tx));
    assert_eq!(handler.handle(&req).await.answers.len(), 1);
    assert_eq!(next_rx.recv().await.unwrap().domain.as_ref(), "example.com.");
    assert!(first_rx.recv().await.is_none());
    // Fill the queue and verify a subsequent query still returns its DNS answer.
    assert_eq!(handler.handle(&req).await.answers.len(), 1);
    assert_eq!(handler.handle(&req).await.answers.len(), 1);
    owner.replace_sender(None);
    assert_eq!(handler.handle(&req).await.answers.len(), 1);
    drop(next_rx);
    assert_eq!(handler.handle(&req).await.answers.len(), 1);
}

use std::collections::{HashMap, HashSet};

use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::redirect::{
    DNSRedirectRule, DynamicDnsRedirectBatch, DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
};
use landscape_common::dns::rule::DNSRuleConfig;
use landscape_common::dns::{
    CacheRuntimeConfig, DohRuntimeConfig, FlowDnsDependencies, FlowDnsDesiredState, RuntimeDnsRule,
    RuntimeRedirectRule, RuntimeUpstreamTarget,
};
use uuid::Uuid;

use crate::geo::site_service::GeoSiteService;

#[derive(Clone)]
pub struct FlowDnsCompiler {
    geo_site_service: GeoSiteService,
}

pub struct CompiledFlowDnsState {
    pub desired_state: FlowDnsDesiredState,
    pub dependencies: FlowDnsDependencies,
}

impl FlowDnsCompiler {
    pub fn new(geo_site_service: GeoSiteService) -> Self {
        Self { geo_site_service }
    }

    pub async fn compile_flow(
        &self,
        flow_id: u32,
        mut rules: Vec<DNSRuleConfig>,
        redirects: Vec<DNSRedirectRule>,
        dynamic_redirects: Vec<DynamicDnsRedirectBatch>,
        upstream_configs: Vec<DnsUpstreamConfig>,
        cache_runtime: CacheRuntimeConfig,
        doh_runtime: Option<DohRuntimeConfig>,
    ) -> CompiledFlowDnsState {
        let upstream_dict: HashMap<Uuid, DnsUpstreamConfig> =
            upstream_configs.into_iter().map(|config| (config.id, config)).collect();

        let mut dependencies = FlowDnsDependencies::default();
        let mut applied_geo_keys = HashSet::new();
        let mut redirect_rules = Vec::new();

        for (order, redirect) in redirects.into_iter().enumerate() {
            if !redirect.enable || redirect.match_rules.is_empty() {
                continue;
            }

            let expanded = self
                .geo_site_service
                .expand_rule_sources(redirect.match_rules, &mut applied_geo_keys)
                .await;
            dependencies.geo_keys.extend(expanded.used_geo_keys);

            redirect_rules.push(RuntimeRedirectRule {
                redirect_id: Some(redirect.id),
                dynamic_source_id: None,
                order: order as u32,
                answer_mode: redirect.answer_mode,
                match_rules: expanded.domains,
                result_ips: redirect.result_info,
                ttl_secs: DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
            });
        }

        let mut next_dynamic_order = redirect_rules.len() as u32;
        for dynamic_batch in dynamic_redirects {
            dependencies.dynamic_redirect_sources.insert(dynamic_batch.source_id.clone());
            for record in dynamic_batch.records {
                redirect_rules.push(RuntimeRedirectRule {
                    redirect_id: None,
                    dynamic_source_id: Some(dynamic_batch.source_id.clone()),
                    order: next_dynamic_order,
                    answer_mode: record.answer_mode,
                    match_rules: vec![record.match_rule.into()],
                    result_ips: record.result_info,
                    ttl_secs: record.ttl_secs,
                });
                next_dynamic_order += 1;
            }
        }

        let mut dns_rules = Vec::new();
        rules.sort_by(|left, right| left.index.cmp(&right.index));
        for rule in rules {
            if !rule.enable {
                continue;
            }
            let Some(upstream_config) = upstream_dict.get(&rule.upstream_id) else {
                continue;
            };

            let sources = if rule.source.is_empty() {
                Vec::new()
            } else {
                let expanded = self
                    .geo_site_service
                    .expand_rule_sources(rule.source, &mut applied_geo_keys)
                    .await;
                dependencies.geo_keys.extend(expanded.used_geo_keys);
                if expanded.domains.is_empty() {
                    continue;
                }
                expanded.domains
            };

            dependencies.upstream_ids.insert(rule.upstream_id);
            dns_rules.push(RuntimeDnsRule {
                rule_id: rule.id,
                order: rule.index,
                filter: rule.filter,
                upstream: RuntimeUpstreamTarget::from(upstream_config),
                bind_config: rule.bind_config,
                mark: rule.mark,
                sources,
            });
        }

        CompiledFlowDnsState {
            desired_state: FlowDnsDesiredState {
                flow_id,
                dns_rules,
                redirect_rules,
                cache_runtime,
                doh_runtime,
            },
            dependencies,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    use landscape_common::dns::config::DnsUpstreamConfig;
    use landscape_common::dns::redirect::{
        DNSRedirectRule, DnsRedirectAnswerMode, DynamicDnsMatch, DynamicDnsRedirectBatch,
        DynamicDnsRedirectRecord, DynamicDnsRedirectScope,
    };
    use landscape_common::dns::rule::{DNSRuleConfig, DomainConfig, DomainMatchType, RuleSource};
    use landscape_common::dns::upstream::DnsUpstreamMode;
    use landscape_common::dns::{CacheRuntimeConfig, DohRuntimeConfig};
    use landscape_common::geo::{
        GeoSiteDirectItem, GeoSiteFileConfig, GeoSiteSource, GeoSiteSourceConfig,
    };
    use landscape_common::service::controller::ConfigController;
    use landscape_database::provider::LandscapeDBServiceProvider;
    use tokio::sync::mpsc;

    use super::FlowDnsCompiler;
    use crate::geo::site_service::GeoSiteService;

    async fn test_geo_service() -> GeoSiteService {
        let db = LandscapeDBServiceProvider::mem_test_db().await;
        let (tx, _rx) = mpsc::channel(8);
        GeoSiteService::new(db, tx).await
    }

    fn test_cache_runtime() -> CacheRuntimeConfig {
        CacheRuntimeConfig {
            cache_capacity: 64,
            cache_ttl: 60,
            negative_cache_ttl: 10,
            lan_suffix: "lan".to_string(),
        }
    }

    fn test_doh_runtime() -> DohRuntimeConfig {
        DohRuntimeConfig {
            listen_port: 8443,
            http_endpoint: "/dns-query".to_string(),
        }
    }

    fn test_upstream() -> DnsUpstreamConfig {
        DnsUpstreamConfig::default()
    }

    #[tokio::test]
    async fn compile_flow_keeps_static_then_dynamic_redirect_order() {
        let geo_service = test_geo_service().await;
        let compiler = FlowDnsCompiler::new(geo_service);
        let upstream = test_upstream();
        let redirects = vec![DNSRedirectRule {
            id: uuid::Uuid::new_v4(),
            remark: "static".into(),
            enable: true,
            match_rules: vec![RuleSource::Config(DomainConfig {
                match_type: DomainMatchType::Full,
                value: "static.example".into(),
            })],
            answer_mode: Default::default(),
            result_info: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            apply_flows: vec![7],
            update_at: 0.0,
        }];
        let dynamic_redirects = vec![DynamicDnsRedirectBatch {
            source_id: "dynamic-a".into(),
            scope: DynamicDnsRedirectScope::Flow(7),
            records: vec![DynamicDnsRedirectRecord {
                match_rule: DynamicDnsMatch::Full("dynamic.example".into()),
                answer_mode: DnsRedirectAnswerMode::StaticIps,
                result_info: vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
                ttl_secs: 30,
            }],
        }];

        let compiled = compiler
            .compile_flow(
                7,
                vec![],
                redirects,
                dynamic_redirects,
                vec![upstream],
                test_cache_runtime(),
                Some(test_doh_runtime()),
            )
            .await;

        assert_eq!(compiled.desired_state.redirect_rules.len(), 2);
        assert_eq!(compiled.desired_state.redirect_rules[0].redirect_id.is_some(), true);
        assert_eq!(compiled.desired_state.redirect_rules[0].order, 0);
        assert_eq!(
            compiled.desired_state.redirect_rules[1].dynamic_source_id.as_deref(),
            Some("dynamic-a")
        );
        assert_eq!(compiled.desired_state.redirect_rules[1].order, 1);
        assert_eq!(
            compiled.desired_state.redirect_rules[1].answer_mode,
            DnsRedirectAnswerMode::StaticIps
        );
    }

    #[tokio::test]
    async fn compile_flow_preserves_dynamic_redirect_answer_mode() {
        let geo_service = test_geo_service().await;
        let compiler = FlowDnsCompiler::new(geo_service);
        let upstream = test_upstream();
        let dynamic_redirects = vec![DynamicDnsRedirectBatch {
            source_id: "dynamic-local".into(),
            scope: DynamicDnsRedirectScope::Global,
            records: vec![DynamicDnsRedirectRecord {
                match_rule: DynamicDnsMatch::Domain("example.com".into()),
                answer_mode: DnsRedirectAnswerMode::AllLocalIps,
                result_info: vec![],
                ttl_secs: 10,
            }],
        }];

        let compiled = compiler
            .compile_flow(
                7,
                vec![],
                vec![],
                dynamic_redirects,
                vec![upstream],
                test_cache_runtime(),
                Some(test_doh_runtime()),
            )
            .await;

        assert_eq!(compiled.desired_state.redirect_rules.len(), 1);
        assert_eq!(
            compiled.desired_state.redirect_rules[0].answer_mode,
            DnsRedirectAnswerMode::AllLocalIps
        );
    }

    #[tokio::test]
    async fn compile_flow_preserves_shared_geo_dedupe_between_redirects_and_rules() {
        let geo_service = test_geo_service().await;
        geo_service
            .set(GeoSiteSourceConfig {
                id: uuid::Uuid::new_v4(),
                update_at: 0.0,
                name: "shared".into(),
                enable: true,
                source: GeoSiteSource::Direct {
                    data: vec![GeoSiteDirectItem {
                        key: "CN".into(),
                        values: vec![GeoSiteFileConfig {
                            match_type: DomainMatchType::Domain,
                            value: "example.cn".into(),
                            attributes: HashSet::new(),
                        }],
                    }],
                },
            })
            .await;

        let compiler = FlowDnsCompiler::new(geo_service.clone());
        let upstream = test_upstream();
        let geo_source = RuleSource::GeoKey(landscape_common::geo::GeoConfigKey {
            name: "shared".into(),
            key: "CN".into(),
            inverse: false,
            attribute_key: None,
        });

        let compiled = compiler
            .compile_flow(
                9,
                vec![DNSRuleConfig {
                    id: uuid::Uuid::new_v4(),
                    name: "rule".into(),
                    index: 10,
                    enable: true,
                    filter: Default::default(),
                    upstream_id: upstream.id,
                    bind_config: Default::default(),
                    mark: Default::default(),
                    source: vec![geo_source.clone()],
                    flow_id: 9,
                    update_at: 0.0,
                }],
                vec![DNSRedirectRule {
                    id: uuid::Uuid::new_v4(),
                    remark: "redirect".into(),
                    enable: true,
                    match_rules: vec![geo_source],
                    answer_mode: Default::default(),
                    result_info: vec![],
                    apply_flows: vec![9],
                    update_at: 0.0,
                }],
                vec![],
                vec![upstream],
                test_cache_runtime(),
                None,
            )
            .await;

        assert_eq!(compiled.desired_state.redirect_rules.len(), 1);
        assert_eq!(compiled.desired_state.redirect_rules[0].match_rules.len(), 1);
        // Current semantics share the geo dedupe set across redirects and rules.
        assert_eq!(compiled.desired_state.dns_rules.len(), 0);
        assert_eq!(compiled.dependencies.geo_keys.len(), 1);
    }

    #[tokio::test]
    async fn compile_flow_ignores_upstream_metadata_only_changes() {
        let geo_service = test_geo_service().await;
        let compiler = FlowDnsCompiler::new(geo_service);
        let upstream = test_upstream();
        let rule = DNSRuleConfig {
            id: uuid::Uuid::new_v4(),
            name: "rule".into(),
            index: 1,
            enable: true,
            filter: Default::default(),
            upstream_id: upstream.id,
            bind_config: Default::default(),
            mark: Default::default(),
            source: vec![],
            flow_id: 3,
            update_at: 0.0,
        };

        let first = compiler
            .compile_flow(
                3,
                vec![rule.clone()],
                vec![],
                vec![],
                vec![upstream.clone()],
                test_cache_runtime(),
                None,
            )
            .await;

        let mut changed_upstream = upstream.clone();
        changed_upstream.remark = "other".into();
        changed_upstream.update_at = 42.0;

        let second = compiler
            .compile_flow(
                3,
                vec![rule],
                vec![],
                vec![],
                vec![changed_upstream],
                test_cache_runtime(),
                None,
            )
            .await;

        assert_eq!(first.desired_state.dns_rules, second.desired_state.dns_rules);
        assert_eq!(first.desired_state.dns_rules[0].upstream.mode, DnsUpstreamMode::Plaintext);
    }
}

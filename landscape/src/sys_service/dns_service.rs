use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_common::{
    config::DnsRuntimeConfig,
    dns::error::DnsError,
    dns::redirect::DynamicDnsRedirectScope,
    dns::{CacheRuntimeConfig, DohRuntimeConfig, FlowDnsDependencies},
    event::{dns::DnsEvent, DnsMetricMessage},
    service::{
        controller::{ConfigController, ConfigStoreFlowController, FlowConfigController},
        ServiceStatus, WatchService,
    },
};
use landscape_core::lan_hostname::LanHostnameRegistry;
use landscape_dns::{
    prepare_system_dns,
    server::{
        DohTimeouts, EffectiveDohListenerConfig, FlowRuntimeRefreshKind, LandscapeDnsServer,
        LocalDnsAnswerProvider, MatcherBuilder,
    },
    CheckChainDnsResult, CheckDnsReq,
};
use rustls::server::ResolvesServerCert;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::sync::mpsc;

use crate::dns::{
    redirect_service::DNSRedirectService, rule_service::DNSRuleService,
    upstream_service::DnsUpstreamService,
};
use crate::{
    cert::order_service::CertService, geo::site_service::GeoSiteService,
    sys_service::route::IpRouteService,
};

#[derive(Clone)]
#[allow(dead_code)]
pub struct LandscapeDnsService {
    dns_service: LandscapeDnsServer,
    dns_rule_service: DNSRuleService,
    dns_redirect_rule_service: DNSRedirectService,
    dns_upstream_service: DnsUpstreamService,
    matcher_builder: MatcherBuilder,
    flow_dependencies: Arc<tokio::sync::RwLock<HashMap<u32, FlowDnsDependencies>>>,
}

impl LandscapeDnsService {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        mut receiver: mpsc::Receiver<DnsEvent>,
        dns_rule_service: DNSRuleService,
        dns_redirect_rule_service: DNSRedirectService,
        geo_site_service: GeoSiteService,
        dns_upstream_service: DnsUpstreamService,
        route_service: IpRouteService,
        dns_config: DnsRuntimeConfig,
        cert_service: CertService,
        msg_tx: Option<mpsc::Sender<DnsMetricMessage>>,
        lan_hostname_registry: Arc<LanHostnameRegistry>,
    ) -> Self {
        let (cache_runtime, doh_runtime) = split_dns_runtime_config(&dns_config);
        if prepare_system_dns() {
            tracing::info!("system DNS redirected to local DNS service");
        } else {
            tracing::error!("failed to redirect system DNS to local DNS service");
        }
        let api_tls_resolver = cert_service.api_tls_resolver();
        let doh = Some(EffectiveDohListenerConfig {
            addr: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                doh_runtime.listen_port,
                0,
                0,
            )),
            timeouts: DohTimeouts::default(),
            server_cert_resolver: Arc::new(api_tls_resolver.clone()) as Arc<dyn ResolvesServerCert>,
            dns_hostname: None,
            http_endpoint: doh_runtime.http_endpoint.clone(),
        });
        let dns_service = LandscapeDnsServer::new(
            53,
            msg_tx,
            cache_runtime.clone(),
            doh,
            Some(Arc::new(route_service) as Arc<dyn LocalDnsAnswerProvider>),
            Some(Arc::new(api_tls_resolver) as Arc<dyn landscape_dns::server::DohAdvertiseProvider>),
            lan_hostname_registry,
        );

        // dns_service.restart(53).await;
        // dns_service.update_flow_map(&flow_rule_service.list().await).await;
        let matcher_builder = MatcherBuilder::new(Arc::new(geo_site_service));

        let dns_service = Self {
            dns_service,
            dns_rule_service,
            dns_redirect_rule_service,
            dns_upstream_service,
            matcher_builder,
            flow_dependencies: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        };
        dns_service.dns_service.status.just_change_status(ServiceStatus::Staring);
        let flow_count = dns_service.refresh_all_flows().await;
        let live = dns_service.dns_service.has_live_flow_runtime().await;
        let status =
            if flow_count > 0 && !live { ServiceStatus::Failed } else { ServiceStatus::Running };
        tracing::info!(
            "DNS service started: flow_count: {flow_count}, live_runtime: {live}, status: {status:?}"
        );
        dns_service.dns_service.status.just_change_status(status);
        let dns_service_clone = dns_service.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    DnsEvent::RulesChanged { flow_id: None } => {
                        dns_service_clone
                            .refresh_all_flows_kind(FlowRuntimeRefreshKind::ResolveOnly)
                            .await;
                    }
                    DnsEvent::RedirectsChanged { flow_id: None } => {
                        dns_service_clone
                            .refresh_all_flows_kind(FlowRuntimeRefreshKind::RedirectOnly)
                            .await;
                    }
                    DnsEvent::RuntimeConfigChanged => {
                        dns_service_clone.dns_service.renew_runtime_config(true).await;
                    }
                    DnsEvent::GeoSitesChanged { changed_keys: None } => {
                        dns_service_clone.matcher_builder.invalidate_geo_matchers(None).await;
                        dns_service_clone.refresh_all_flows().await;
                    }
                    DnsEvent::RulesChanged { flow_id: Some(flow_id) } => {
                        dns_service_clone
                            .refresh_flow_kind(flow_id, FlowRuntimeRefreshKind::ResolveOnly)
                            .await;
                    }
                    DnsEvent::RedirectsChanged { flow_id: Some(flow_id) } => {
                        dns_service_clone
                            .refresh_flow_kind(flow_id, FlowRuntimeRefreshKind::RedirectOnly)
                            .await;
                    }
                    DnsEvent::DynamicRedirectsChanged { flow_id: Some(flow_id), .. } => {
                        dns_service_clone
                            .refresh_flow_kind(flow_id, FlowRuntimeRefreshKind::RedirectOnly)
                            .await;
                    }
                    DnsEvent::DynamicRedirectsChanged { flow_id: None, source_id } => {
                        let flow_ids = dns_service_clone
                            .collect_dependent_flows(|deps| {
                                deps.dynamic_redirect_sources.contains(&source_id)
                            })
                            .await;

                        if flow_ids.is_empty() {
                            dns_service_clone
                                .refresh_all_flows_kind(FlowRuntimeRefreshKind::RedirectOnly)
                                .await;
                        } else {
                            dns_service_clone
                                .refresh_flow_ids_kind(
                                    flow_ids,
                                    FlowRuntimeRefreshKind::RedirectOnly,
                                )
                                .await;
                        }
                    }
                    DnsEvent::UpstreamsChanged { upstream_ids } => {
                        let upstream_ids = upstream_ids.into_iter().collect::<HashSet<_>>();
                        // Unconditionally drop pooled resolvers for the changed
                        // upstreams so the refresh below rebuilds them.
                        dns_service_clone.matcher_builder.invalidate_upstreams(&upstream_ids);
                        let flow_ids = dns_service_clone
                            .collect_dependent_flows(|deps| {
                                deps.upstream_ids
                                    .iter()
                                    .any(|upstream_id| upstream_ids.contains(upstream_id))
                            })
                            .await;
                        dns_service_clone
                            .refresh_flow_ids_kind(flow_ids, FlowRuntimeRefreshKind::ResolveOnly)
                            .await;
                    }
                    DnsEvent::GeoSitesChanged { changed_keys: Some(changed_keys) } => {
                        dns_service_clone
                            .matcher_builder
                            .invalidate_geo_matchers(Some(&changed_keys))
                            .await;
                        let flow_ids = dns_service_clone
                            .collect_dependent_flows(|deps| {
                                deps.geo_keys.iter().any(|key| changed_keys.contains(key))
                            })
                            .await;
                        dns_service_clone
                            .refresh_flow_ids_kind(flow_ids, FlowRuntimeRefreshKind::Full)
                            .await;
                    }
                    DnsEvent::FlowUpdated => {
                        // let flow_rules = flow_rule_service_clone.list().await;

                        // dns_service_clone.update_flow_map(&flow_rules).await;
                        // tracing::info!("update flow dispatch rule in DNS server");
                    }
                }
            }
        });
        dns_service
    }

    pub async fn get_status(&self) -> WatchService {
        self.dns_service.status.clone()
    }

    pub async fn start_dns_service(&self) {
        tracing::info!("starting DNS service");
        self.dns_service.status.just_change_status(ServiceStatus::Staring);
        self.dns_service.status.just_change_status(ServiceStatus::Running);
        tracing::info!("DNS service status set to running");
    }

    pub async fn stop(&self) {
        tracing::info!("stopping DNS service");
        self.dns_service.status.just_change_status(ServiceStatus::Stopping);
        landscape_dns::restore_resolver_conf();
        self.dns_service.status.just_change_status(ServiceStatus::Stop);
        tracing::info!("DNS service stopped");
    }

    pub fn update_metric_sender(&self, msg_tx: Option<mpsc::Sender<DnsMetricMessage>>) {
        self.dns_service.update_metric_sender(msg_tx);
    }

    pub fn update_lan_hostname_config(&self, config: LanHostnameConfig) {
        self.dns_service.update_lan_hostname_config(config);
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckChainDnsResult {
        self.dns_service.check_domain(req).await
    }

    pub async fn invalidate_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsError> {
        self.dns_service.invalidate_domain_cache(req).await
    }

    pub async fn refresh_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsError> {
        self.dns_service.refresh_domain_cache(req).await
    }

    pub async fn apply_runtime_config(&self, dns_config: DnsRuntimeConfig) {
        let (cache_runtime, doh_runtime) = split_dns_runtime_config(&dns_config);
        let (previous_cache_runtime, startup_doh_runtime) =
            self.dns_service.current_live_runtime_config();
        if startup_doh_runtime.as_ref() != Some(&doh_runtime) {
            // Product policy: cert/SNI domains hot-reload through the shared
            // resolver, but DoH port/path are bound at process startup.
            tracing::warn!(
                "DoH listen_port/http_endpoint changes require process restart to take effect"
            );
        }
        let rebuild_cache = previous_cache_runtime.cache_capacity != cache_runtime.cache_capacity
            || previous_cache_runtime.cache_ttl != cache_runtime.cache_ttl;
        self.dns_service.update_runtime_config(cache_runtime);
        self.dns_service.renew_runtime_config(rebuild_cache).await;
    }

    async fn refresh_all_flows(&self) -> usize {
        self.refresh_all_flows_kind(FlowRuntimeRefreshKind::Full).await
    }

    async fn refresh_all_flows_kind(&self, kind: FlowRuntimeRefreshKind) -> usize {
        let time = Instant::now();
        let mut flow_rules = self.dns_rule_service.get_flow_hashmap().await.unwrap();
        let redirect_flow_ids = self
            .dns_redirect_rule_service
            .list()
            .await
            .into_iter()
            .flat_map(|rule| rule.apply_flows)
            .collect::<HashSet<_>>();
        let dynamic_redirect_flow_ids = self
            .dns_redirect_rule_service
            .list_dynamic_batches()
            .await
            .into_iter()
            .filter_map(|batch| match batch.scope {
                DynamicDnsRedirectScope::Flow(flow_id) => Some(flow_id),
                DynamicDnsRedirectScope::Global => None,
            })
            .collect::<HashSet<_>>();
        let tracked_flow_ids = {
            let dependencies = self.flow_dependencies.read().await;
            dependencies.keys().copied().collect::<HashSet<_>>()
        };
        let mut flow_ids = flow_rules.keys().copied().collect::<HashSet<_>>();
        flow_ids.extend(tracked_flow_ids);
        flow_ids.extend(redirect_flow_ids);
        flow_ids.extend(dynamic_redirect_flow_ids);

        for flow_id in &flow_ids {
            let rules = flow_rules.remove(flow_id).unwrap_or_default();
            self.refresh_flow_with_rules_kind(*flow_id, rules, kind).await;
        }
        tracing::info!(
            "refresh all dns flows: flow_count: {}, {:?}ms",
            flow_ids.len(),
            time.elapsed().as_millis()
        );
        flow_ids.len()
    }

    async fn refresh_flow_ids_kind(&self, flow_ids: Vec<u32>, kind: FlowRuntimeRefreshKind) {
        for flow_id in flow_ids {
            self.refresh_flow_kind(flow_id, kind).await;
        }
    }

    async fn refresh_flow_kind(&self, flow_id: u32, kind: FlowRuntimeRefreshKind) {
        let flow_rules = self.dns_rule_service.list_flow_configs(flow_id).await.unwrap();
        self.refresh_flow_with_rules_kind(flow_id, flow_rules, kind).await;
    }

    async fn refresh_flow_with_rules_kind(
        &self,
        flow_id: u32,
        flow_dns_rules: Vec<landscape_common::dns::rule::DNSRuleConfig>,
        kind: FlowRuntimeRefreshKind,
    ) {
        tracing::info!("refresh dns rule: flow_id: {flow_id}");
        let time = Instant::now();
        let upstream_ids = flow_dns_rules.iter().map(|rule| rule.upstream_id).collect();
        let upstream_configs = self.dns_upstream_service.find_by_ids(upstream_ids).await;
        let dns_redirect_rules = self.dns_redirect_rule_service.list_flow_configs(flow_id).await;
        let dynamic_dns_redirects =
            self.dns_redirect_rule_service.list_flow_dynamic_batches(flow_id).await;
        let (redirect_engine, resolve_engine, dependencies) = self
            .matcher_builder
            .build_flow(
                flow_id,
                flow_dns_rules,
                dns_redirect_rules,
                dynamic_dns_redirects,
                upstream_configs,
            )
            .await;

        self.store_flow_dependencies(flow_id, dependencies).await;
        self.dns_service
            .refresh_flow_runtime_kind(flow_id, redirect_engine, resolve_engine, kind)
            .await;
        tracing::info!(
            "[flow_id: {flow_id}] build and refresh DNS runtime: {:?}ms",
            time.elapsed().as_millis()
        );
    }

    async fn store_flow_dependencies(&self, flow_id: u32, dependencies: FlowDnsDependencies) {
        self.flow_dependencies.write().await.insert(flow_id, dependencies);
    }

    async fn collect_dependent_flows<F>(&self, predicate: F) -> Vec<u32>
    where
        F: Fn(&FlowDnsDependencies) -> bool,
    {
        self.flow_dependencies
            .read()
            .await
            .iter()
            .filter_map(|(flow_id, dependencies)| predicate(dependencies).then_some(*flow_id))
            .collect()
    }
}

fn split_dns_runtime_config(
    dns_config: &DnsRuntimeConfig,
) -> (CacheRuntimeConfig, DohRuntimeConfig) {
    (
        CacheRuntimeConfig {
            cache_capacity: dns_config.cache_capacity,
            cache_ttl: dns_config.cache_ttl,
            negative_cache_ttl: dns_config.negative_cache_ttl,
        },
        DohRuntimeConfig {
            listen_port: dns_config.doh_listen_port,
            http_endpoint: dns_config.doh_http_endpoint.clone(),
        },
    )
}

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use landscape_common::{
    config::DnsRuntimeConfig,
    dns::check::DnsCheckError,
    dns::{CacheRuntimeConfig, DohRuntimeConfig, FlowDnsDependencies},
    enrolled_device::EnrolledDevice,
    event::{dns::DnsEvent, hub::EnrolledDeviceEventReader, DnsMetricMessage},
    service::{
        controller::{ConfigController, FlowConfigController},
        WatchService,
    },
};
use landscape_dns::{
    prepare_system_dns,
    server::{DohTimeouts, EffectiveDohListenerConfig, LandscapeDnsServer, LocalDnsAnswerProvider},
    CheckChainDnsResult, CheckDnsReq,
};
use rustls::server::ResolvesServerCert;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::sync::mpsc;

use crate::dns::{
    compiler::{CompiledFlowDnsState, FlowDnsCompiler},
    redirect_service::DNSRedirectService,
    rule_service::DNSRuleService,
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
    geo_site_service: GeoSiteService,
    dns_upstream_service: DnsUpstreamService,
    compiler: FlowDnsCompiler,
    flow_dependencies: Arc<tokio::sync::RwLock<HashMap<u32, FlowDnsDependencies>>>,
}

impl LandscapeDnsService {
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
        device_reader: EnrolledDeviceEventReader,
        initial_devices: Vec<EnrolledDevice>,
    ) -> Self {
        let (cache_runtime, doh_runtime) = split_dns_runtime_config(&dns_config);
        prepare_system_dns();
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
            device_reader,
            initial_devices,
        );

        // dns_service.restart(53).await;
        // dns_service.update_flow_map(&flow_rule_service.list().await).await;
        let compiler = FlowDnsCompiler::new(geo_site_service.clone());

        let dns_service = Self {
            dns_service,
            dns_rule_service,
            dns_redirect_rule_service,
            geo_site_service,
            dns_upstream_service,
            compiler,
            flow_dependencies: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        };
        dns_service.refresh_all_flows().await;
        let dns_service_clone = dns_service.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    DnsEvent::RulesChanged { flow_id: None }
                    | DnsEvent::RedirectsChanged { flow_id: None }
                    | DnsEvent::GeoSitesChanged { changed_keys: None }
                    | DnsEvent::RuntimeConfigChanged => {
                        dns_service_clone.refresh_all_flows().await;
                    }
                    DnsEvent::RulesChanged { flow_id: Some(flow_id) }
                    | DnsEvent::RedirectsChanged { flow_id: Some(flow_id) } => {
                        dns_service_clone.refresh_flow(flow_id).await;
                    }
                    DnsEvent::DynamicRedirectsChanged { flow_id: Some(flow_id), .. } => {
                        dns_service_clone.refresh_flow(flow_id).await;
                    }
                    DnsEvent::DynamicRedirectsChanged { flow_id: None, source_id } => {
                        let flow_ids = dns_service_clone
                            .collect_dependent_flows(|deps| {
                                deps.dynamic_redirect_sources.contains(&source_id)
                            })
                            .await;

                        if flow_ids.is_empty() {
                            dns_service_clone.refresh_all_flows().await;
                        } else {
                            dns_service_clone.refresh_flow_ids(flow_ids).await;
                        }
                    }
                    DnsEvent::UpstreamsChanged { upstream_ids } => {
                        let upstream_ids = upstream_ids.into_iter().collect::<HashSet<_>>();
                        let flow_ids = dns_service_clone
                            .collect_dependent_flows(|deps| {
                                deps.upstream_ids
                                    .iter()
                                    .any(|upstream_id| upstream_ids.contains(upstream_id))
                            })
                            .await;
                        dns_service_clone.refresh_flow_ids(flow_ids).await;
                    }
                    DnsEvent::GeoSitesChanged { changed_keys: Some(changed_keys) } => {
                        let flow_ids = dns_service_clone
                            .collect_dependent_flows(|deps| {
                                deps.geo_keys.iter().any(|key| changed_keys.contains(key))
                            })
                            .await;
                        dns_service_clone.refresh_flow_ids(flow_ids).await;
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
        // let dns_rules = self.dns_rule_service.list().await;
        // let flow_rules = self.flow_rule_service.list().await;
        // let dns_rules = self.geo_site_service.convert_config_to_runtime_rule(dns_rules).await;
        // // TODO 重置 Flow 相关 map 信息
        // self.dns_service.init_handle(dns_rules).await;
        // self.dns_service.update_flow_map(&flow_rules).await;
        // self.dns_service.restart(53).await;
    }

    pub async fn stop(&self) {
        landscape_dns::restore_resolver_conf();
    }

    pub fn update_metric_sender(&self, msg_tx: Option<mpsc::Sender<DnsMetricMessage>>) {
        self.dns_service.update_metric_sender(msg_tx);
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckChainDnsResult {
        self.dns_service.check_domain(req).await
    }

    pub async fn invalidate_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsCheckError> {
        self.dns_service.invalidate_domain_cache(req).await
    }

    pub async fn refresh_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsCheckError> {
        self.dns_service.refresh_domain_cache(req).await
    }

    pub async fn apply_runtime_config(&self, dns_config: DnsRuntimeConfig) {
        let (cache_runtime, doh_runtime) = split_dns_runtime_config(&dns_config);
        let (_, startup_doh_runtime) = self.dns_service.current_live_runtime_config();
        if startup_doh_runtime.as_ref() != Some(&doh_runtime) {
            // Product policy: cert/SNI domains hot-reload through the shared
            // resolver, but DoH port/path are bound at process startup.
            tracing::warn!(
                "DoH listen_port/http_endpoint changes require process restart to take effect"
            );
        }
        self.dns_service.update_runtime_config(cache_runtime);
        let tracked_flows = {
            let dependencies = self.flow_dependencies.read().await;
            dependencies.keys().copied().collect::<Vec<_>>()
        };
        if tracked_flows.is_empty() {
            self.refresh_all_flows().await;
        } else {
            self.refresh_flow_ids(tracked_flows).await;
        }
    }

    async fn refresh_all_flows(&self) {
        let time = Instant::now();
        let mut flow_rules = self.dns_rule_service.get_flow_hashmap().await;
        let tracked_flow_ids = {
            let dependencies = self.flow_dependencies.read().await;
            dependencies.keys().copied().collect::<HashSet<_>>()
        };
        let mut flow_ids = flow_rules.keys().copied().collect::<HashSet<_>>();
        flow_ids.extend(tracked_flow_ids);

        for flow_id in flow_ids {
            let rules = flow_rules.remove(&flow_id).unwrap_or_default();
            self.refresh_flow_with_rules(flow_id, rules).await;
        }
        tracing::info!("refresh all dns flows: {:?}ms", time.elapsed().as_millis());
    }

    async fn refresh_flow_ids(&self, flow_ids: Vec<u32>) {
        for flow_id in flow_ids {
            self.refresh_flow(flow_id).await;
        }
    }

    async fn refresh_flow(&self, flow_id: u32) {
        let flow_rules = self.dns_rule_service.list_flow_configs(flow_id).await;
        self.refresh_flow_with_rules(flow_id, flow_rules).await;
    }

    async fn refresh_flow_with_rules(
        &self,
        flow_id: u32,
        flow_dns_rules: Vec<landscape_common::dns::rule::DNSRuleConfig>,
    ) {
        tracing::info!("refresh dns rule: flow_id: {flow_id}");
        let time = Instant::now();
        if let Some(compiled) = self.compile_flow_state(flow_id, flow_dns_rules).await {
            self.store_flow_dependencies(flow_id, compiled.dependencies).await;
            self.dns_service.refresh_flow_server(compiled.desired_state).await;
        }
        tracing::info!(
            "[flow_id: {flow_id}] compile and refresh DNS rule: {:?}ms",
            time.elapsed().as_millis()
        );
    }

    async fn compile_flow_state(
        &self,
        flow_id: u32,
        flow_dns_rules: Vec<landscape_common::dns::rule::DNSRuleConfig>,
    ) -> Option<CompiledFlowDnsState> {
        let upstream_ids = flow_dns_rules.iter().map(|rule| rule.upstream_id).collect();
        let upstream_configs = self.dns_upstream_service.find_by_ids(upstream_ids).await;
        let dns_redirect_rules = self.dns_redirect_rule_service.list_flow_configs(flow_id).await;
        let dynamic_dns_redirects =
            self.dns_redirect_rule_service.list_flow_dynamic_batches(flow_id).await;
        let (cache_runtime, doh_runtime) = self.dns_service.current_live_runtime_config();

        Some(
            self.compiler
                .compile_flow(
                    flow_id,
                    flow_dns_rules,
                    dns_redirect_rules,
                    dynamic_dns_redirects,
                    upstream_configs,
                    cache_runtime,
                    doh_runtime,
                )
                .await,
        )
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
            lan_suffix: dns_config.lan_suffix.clone(),
        },
        DohRuntimeConfig {
            listen_port: dns_config.doh_listen_port,
            http_endpoint: dns_config.doh_http_endpoint.clone(),
        },
    )
}

use std::{collections::HashSet, sync::Arc, time::Instant};

use landscape_common::{
    concurrency::{spawn_task, task_label},
    config::DnsRuntimeConfig,
    event::dns::DnsEvent,
};
use landscape_core::geo_cache::SiteMatcherRegistry;
use tokio::sync::mpsc;

use crate::server::{
    EngineBuilder, FlowDependencySelector, FlowRuntimeRefreshKind, LandscapeDnsServer,
};

mod source;
pub use source::{DnsConfigError, DnsConfigSource, FlowConfigBundle};

/// Drives the DNS server from configuration and change events. It owns the
/// engine builder and the config source, while the server owns listeners and
/// per-flow runtime state.
pub struct DnsCoordinator {
    server: LandscapeDnsServer,
    builder: EngineBuilder,
    source: Arc<dyn DnsConfigSource>,
}

impl DnsCoordinator {
    pub fn new(
        server: LandscapeDnsServer,
        matcher_registry: Arc<SiteMatcherRegistry>,
        source: Arc<dyn DnsConfigSource>,
    ) -> Self {
        Self {
            server,
            builder: EngineBuilder::new(matcher_registry),
            source,
        }
    }

    pub fn server(&self) -> &LandscapeDnsServer {
        &self.server
    }

    pub async fn apply_runtime_config(&self, dns_config: DnsRuntimeConfig) {
        let cache_runtime = dns_config.cache_runtime();
        let doh_runtime = dns_config.doh_runtime();
        let (previous_cache_runtime, startup_doh_runtime) =
            self.server.current_live_runtime_config();
        if startup_doh_runtime.as_ref() != Some(&doh_runtime) {
            // Product policy: cert/SNI domains hot-reload through the shared
            // resolver, but DoH port/path are bound at process startup.
            tracing::warn!(
                "DoH listen_port/http_endpoint changes require process restart to take effect"
            );
        }
        let rebuild_cache = previous_cache_runtime.cache_capacity != cache_runtime.cache_capacity
            || previous_cache_runtime.cache_ttl != cache_runtime.cache_ttl;
        self.server.update_runtime_config(cache_runtime);
        self.server.renew_runtime_config(rebuild_cache).await;
    }

    /// Consumes DNS change events until the channel closes. A failed refresh
    /// is logged and does not stop the observer.
    pub fn spawn_event_loop(self: &Arc<Self>, mut receiver: mpsc::Receiver<DnsEvent>) {
        let coordinator = self.clone();
        spawn_task(task_label::task::DNS_SERVICE_OBSERVER, async move {
            while let Some(event) = receiver.recv().await {
                if let Err(error) = coordinator.handle_event(event).await {
                    tracing::error!(%error, "failed to apply DNS event");
                }
            }
        });
    }

    pub async fn refresh_all(&self, kind: FlowRuntimeRefreshKind) -> Result<usize, DnsConfigError> {
        let time = Instant::now();
        let mut flow_rules = self.source.all_flow_rules().await?;
        let redirect_flow_ids = self.source.redirect_flow_ids().await?;
        let dynamic_redirect_flow_ids = self.source.dynamic_redirect_flow_ids().await?;
        let tracked_flow_ids = self.server.tracked_flow_ids().await;

        let mut flow_ids = flow_rules.keys().copied().collect::<HashSet<_>>();
        flow_ids.extend(tracked_flow_ids);
        flow_ids.extend(redirect_flow_ids);
        flow_ids.extend(dynamic_redirect_flow_ids);

        for flow_id in &flow_ids {
            let rules = flow_rules.remove(flow_id).unwrap_or_default();
            self.refresh_flow_with_rules(*flow_id, rules, kind).await?;
        }
        tracing::info!(
            "refresh all dns flows: flow_count: {}, {:?}ms",
            flow_ids.len(),
            time.elapsed().as_millis()
        );
        Ok(flow_ids.len())
    }

    pub async fn refresh_flow(
        &self,
        flow_id: u32,
        kind: FlowRuntimeRefreshKind,
    ) -> Result<(), DnsConfigError> {
        let rules = self.source.flow_rules(flow_id).await?;
        self.refresh_flow_with_rules(flow_id, rules, kind).await
    }

    pub async fn refresh_flows(
        &self,
        flow_ids: Vec<u32>,
        kind: FlowRuntimeRefreshKind,
    ) -> Result<(), DnsConfigError> {
        for flow_id in flow_ids {
            self.refresh_flow(flow_id, kind).await?;
        }
        Ok(())
    }

    pub async fn refresh_dependent_flows(
        &self,
        selector: FlowDependencySelector,
        kind: FlowRuntimeRefreshKind,
    ) -> Result<usize, DnsConfigError> {
        let flow_ids = self.server.flows_matching_dependencies(&selector).await;
        let count = flow_ids.len();
        self.refresh_flows(flow_ids, kind).await?;
        Ok(count)
    }

    async fn handle_event(&self, event: DnsEvent) -> Result<(), DnsConfigError> {
        match event {
            DnsEvent::RulesChanged { flow_id: None } => {
                self.refresh_all(FlowRuntimeRefreshKind::ResolveOnly).await?;
            }
            DnsEvent::RedirectsChanged { flow_id: None } => {
                self.refresh_all(FlowRuntimeRefreshKind::RedirectOnly).await?;
            }
            DnsEvent::GeoSitesChanged { changed_keys: None } => {
                self.refresh_all(FlowRuntimeRefreshKind::Full).await?;
            }
            DnsEvent::RulesChanged { flow_id: Some(flow_id) } => {
                self.refresh_flow(flow_id, FlowRuntimeRefreshKind::ResolveOnly).await?;
            }
            DnsEvent::RedirectsChanged { flow_id: Some(flow_id) } => {
                self.refresh_flow(flow_id, FlowRuntimeRefreshKind::RedirectOnly).await?;
            }
            DnsEvent::DynamicRedirectsChanged { flow_id: Some(flow_id), .. } => {
                self.refresh_flow(flow_id, FlowRuntimeRefreshKind::RedirectOnly).await?;
            }
            DnsEvent::DynamicRedirectsChanged { flow_id: None, source_id } => {
                let refreshed = self
                    .refresh_dependent_flows(
                        FlowDependencySelector::DynamicRedirectSource(source_id),
                        FlowRuntimeRefreshKind::RedirectOnly,
                    )
                    .await?;
                if refreshed == 0 {
                    self.refresh_all(FlowRuntimeRefreshKind::RedirectOnly).await?;
                }
            }
            DnsEvent::UpstreamsChanged { upstream_ids } => {
                let upstream_ids = upstream_ids.into_iter().collect::<HashSet<_>>();
                // Drop pooled resolvers unconditionally so the dependent flows
                // below rebuild them.
                self.builder.invalidate_upstreams(&upstream_ids);
                self.refresh_dependent_flows(
                    FlowDependencySelector::Upstreams(upstream_ids),
                    FlowRuntimeRefreshKind::ResolveOnly,
                )
                .await?;
            }
            DnsEvent::GeoSitesChanged { changed_keys: Some(changed_keys) } => {
                self.refresh_dependent_flows(
                    FlowDependencySelector::GeoKeys(changed_keys),
                    FlowRuntimeRefreshKind::Full,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn refresh_flow_with_rules(
        &self,
        flow_id: u32,
        rules: Vec<landscape_common::dns::rule::DNSRuleConfig>,
        kind: FlowRuntimeRefreshKind,
    ) -> Result<(), DnsConfigError> {
        tracing::info!("refresh dns rule: flow_id: {flow_id}");
        let time = Instant::now();
        let bundle = self.source.flow_bundle(flow_id, rules).await?;
        let (redirect_engine, resolve_engine, dependencies) = self
            .builder
            .build_flow(
                flow_id,
                bundle.rules,
                bundle.redirects,
                bundle.dynamic_redirects,
                bundle.upstreams,
            )
            .await;

        self.server
            .refresh_flow_runtime_kind(flow_id, redirect_engine, resolve_engine, dependencies, kind)
            .await;
        tracing::info!(
            "[flow_id: {flow_id}] build and refresh DNS runtime: {:?}ms",
            time.elapsed().as_millis()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use landscape_common::{
        config::DnsRuntimeConfig,
        dns::{CacheRuntimeConfig, rule::DNSRuleConfig},
        flow::{NoopDnsResultSink, NoopFlowSocketRegistrar},
        sys_service::lan_hostname::LanHostnameConfig,
    };
    use landscape_core::{
        geo_cache::{GeoCacheDatabase, SiteCacheRepository, SiteMatcherRegistry},
        lan_device::LanDeviceDirectory,
    };

    use super::{DnsConfigError, DnsConfigSource, DnsCoordinator, FlowConfigBundle};
    use crate::server::{DnsServiceDeps, FlowRuntimeRefreshKind, LandscapeDnsServer};

    struct FakeSource {
        flow_rules: HashMap<u32, Vec<DNSRuleConfig>>,
    }

    #[async_trait]
    impl DnsConfigSource for FakeSource {
        async fn all_flow_rules(&self) -> Result<HashMap<u32, Vec<DNSRuleConfig>>, DnsConfigError> {
            Ok(self.flow_rules.clone())
        }

        async fn flow_rules(&self, flow_id: u32) -> Result<Vec<DNSRuleConfig>, DnsConfigError> {
            Ok(self.flow_rules.get(&flow_id).cloned().unwrap_or_default())
        }

        async fn flow_bundle(
            &self,
            _flow_id: u32,
            rules: Vec<DNSRuleConfig>,
        ) -> Result<FlowConfigBundle, DnsConfigError> {
            Ok(FlowConfigBundle {
                rules,
                redirects: Vec::new(),
                dynamic_redirects: Vec::new(),
                upstreams: Vec::new(),
            })
        }

        async fn redirect_flow_ids(&self) -> Result<HashSet<u32>, DnsConfigError> {
            Ok(HashSet::new())
        }

        async fn dynamic_redirect_flow_ids(&self) -> Result<HashSet<u32>, DnsConfigError> {
            Ok(HashSet::new())
        }
    }

    fn run_async_test(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test);
    }

    async fn test_coordinator(source: Arc<dyn DnsConfigSource>) -> Arc<DnsCoordinator> {
        let server = LandscapeDnsServer::new(DnsServiceDeps {
            listen_port: 0,
            msg_tx: None,
            cache_runtime: CacheRuntimeConfig::default(),
            doh: None,
            local_answer_provider: None,
            doh_advertise_provider: None,
            lan_device_directory: LanDeviceDirectory::new_for_test(),
            lan_hostname_config: Arc::new(ArcSwap::from_pointee(LanHostnameConfig::default())),
            result_sink: Arc::new(NoopDnsResultSink),
            socket_registrar: Arc::new(NoopFlowSocketRegistrar),
        });
        let registry = Arc::new(SiteMatcherRegistry::new(SiteCacheRepository::new(
            GeoCacheDatabase::site_mem().await,
        )));
        Arc::new(DnsCoordinator::new(server, registry, source))
    }

    #[test]
    fn apply_runtime_config_updates_cache_settings() {
        run_async_test(async {
            let source = Arc::new(FakeSource { flow_rules: HashMap::new() });
            let coordinator = test_coordinator(source).await;

            coordinator
                .apply_runtime_config(DnsRuntimeConfig {
                    cache_capacity: 32,
                    cache_ttl: 90,
                    negative_cache_ttl: 15,
                    doh_listen_port: 443,
                    doh_http_endpoint: "/dns-query".to_string(),
                })
                .await;

            let (cache, _) = coordinator.server().current_live_runtime_config();
            assert_eq!(cache.cache_capacity, 32);
            assert_eq!(cache.cache_ttl, 90);
            assert_eq!(cache.negative_cache_ttl, 15);
        });
    }

    #[test]
    fn refresh_all_loads_configs_and_tracks_flows() {
        run_async_test(async {
            let source = Arc::new(FakeSource { flow_rules: HashMap::from([(1, Vec::new())]) });
            let coordinator = test_coordinator(source).await;

            let count = coordinator.refresh_all(FlowRuntimeRefreshKind::Full).await.unwrap();

            assert_eq!(count, 1);
            assert_eq!(coordinator.server().tracked_flow_ids().await, HashSet::from([1]));
        });
    }
}

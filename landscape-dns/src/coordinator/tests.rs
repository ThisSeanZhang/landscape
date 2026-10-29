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

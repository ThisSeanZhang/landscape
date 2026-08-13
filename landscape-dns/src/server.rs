use std::{
    collections::HashMap,
    net::IpAddr,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use arc_swap::{ArcSwap, ArcSwapOption};
use landscape_common::dns::error::DnsError;
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_common::{event::DnsMetricMessage, service::WatchService};
use landscape_core::lan_hostname::LanHostnameRegistry;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::{
    convert_record_type,
    domain::ParsedDomain,
    listener::{start_flow_dns_listener, DohListenerState},
    mdns::MdnsService,
    server::{
        engine::{RedirectEngine, ResolveEngine},
        handler::DnsRequestHandler,
        local::LocalResolver,
    },
    CheckChainDnsResult, CheckDnsReq,
};

pub mod builder;
pub mod engine;
pub(crate) mod handler;
pub(crate) mod local;
pub(crate) mod matcher;
pub(crate) mod rule;

pub use builder::MatcherBuilder;

pub use crate::listener::{DohTimeouts, EffectiveDohListenerConfig};
pub use landscape_common::dns::{CacheRuntimeConfig, DohRuntimeConfig};

pub(crate) type MetricSenderState = Arc<ArcSwapOption<mpsc::Sender<DnsMetricMessage>>>;

pub trait LocalDnsAnswerProvider: Send + Sync {
    fn load_local_answer_addrs(
        &self,
        query_type: hickory_proto::rr::RecordType,
    ) -> Arc<Vec<IpAddr>>;

    fn load_local_answer_addrs_for_ifindex(
        &self,
        query_type: hickory_proto::rr::RecordType,
        ifindex: u32,
    ) -> Arc<Vec<IpAddr>> {
        let _ = query_type;
        let _ = ifindex;
        Arc::new(Vec::new())
    }
}

pub trait DohAdvertiseProvider: Send + Sync {
    fn advertise_domains(&self) -> Vec<String>;
}

// system DNS service
#[derive(Clone)]
pub struct LandscapeDnsServer {
    // service status
    pub status: WatchService,
    // internal handlers
    flow_dns_server: Arc<Mutex<HashMap<u32, Arc<FlowServerEntry>>>>,
    // local answers (localhost / LAN hostname zone / PTR / DDR) shared by all flows
    pub local_resolver: Arc<LocalResolver>,
    pub lan_hostname_registry: Arc<LanHostnameRegistry>,
    // DNS events
    pub msg_tx: MetricSenderState,
    // bound UDP DNS listen address
    pub udp_listener_addr: SocketAddr,
    cache_live_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    doh_listener: Option<DohListenerState>,
    _mdns_service: Option<Arc<MdnsService>>,
}

struct FlowServerRuntime {
    handler: DnsRequestHandler,
    _token: CancellationToken,
}

struct FlowServerEntry {
    refresh_lock: Mutex<()>,
    runtime: Arc<ArcSwapOption<FlowServerRuntime>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowRuntimeRefreshKind {
    Full,
    ResolveOnly,
    RedirectOnly,
}

impl FlowServerEntry {
    fn new() -> Self {
        Self {
            refresh_lock: Mutex::new(()),
            runtime: Arc::new(ArcSwapOption::new(None)),
        }
    }
}

impl LandscapeDnsServer {
    pub fn new(
        listen_port: u16,
        msg_tx: Option<mpsc::Sender<DnsMetricMessage>>,
        cache_runtime: CacheRuntimeConfig,
        doh: Option<EffectiveDohListenerConfig>,
        local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
        lan_hostname_registry: Arc<LanHostnameRegistry>,
    ) -> Self {
        let status = WatchService::new();
        let mdns_service = if local_answer_provider.is_some() {
            MdnsService::spawn(local_answer_provider.clone())
        } else {
            None
        };
        let doh_listener = doh.map(DohListenerState::from_effective_config);
        let doh_runtime = doh_listener.as_ref().map(|doh_listener| doh_listener.runtime_config());
        let local_resolver = Arc::new(LocalResolver::new(
            lan_hostname_registry.clone(),
            local_answer_provider,
            doh_advertise_provider,
            doh_runtime,
        ));

        Self {
            status,
            flow_dns_server: Arc::new(Mutex::new(HashMap::new())),
            udp_listener_addr: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                listen_port,
                0,
                0,
            )),
            msg_tx: Arc::new(ArcSwapOption::new(msg_tx.map(Arc::new))),
            cache_live_config: Arc::new(ArcSwap::from_pointee(cache_runtime)),
            doh_listener,
            _mdns_service: mdns_service,
            lan_hostname_registry,
            local_resolver,
        }
    }

    pub fn get_status(&self) -> &WatchService {
        &self.status
    }

    /// Returns whether at least one flow listener runtime is still serving.
    /// On socket bind failure `build_flow_runtime` does not store a runtime;
    /// the cancel token is cancelled when the listener exits.
    pub async fn has_live_flow_runtime(&self) -> bool {
        let flow_server = self.flow_dns_server.lock().await;
        flow_server.values().any(|entry| {
            entry.runtime.load_full().is_some_and(|runtime| !runtime._token.is_cancelled())
        })
    }

    pub fn update_runtime_config(&self, cache_runtime: CacheRuntimeConfig) {
        self.cache_live_config.store(Arc::new(cache_runtime));
    }

    pub async fn renew_runtime_config(&self, rebuild_cache: bool) {
        let entries = {
            let flow_server = self.flow_dns_server.lock().await;
            flow_server.values().cloned().collect::<Vec<_>>()
        };

        for entry in entries {
            let _refresh_guard = entry.refresh_lock.lock().await;
            if let Some(runtime) = entry.runtime.load_full() {
                runtime.handler.renew_runtime_config(rebuild_cache).await;
            }
        }
    }

    pub fn update_metric_sender(&self, msg_tx: Option<mpsc::Sender<DnsMetricMessage>>) {
        self.msg_tx.store(msg_tx.map(Arc::new));
    }

    pub fn update_lan_hostname_config(&self, config: LanHostnameConfig) {
        self.lan_hostname_registry.update_config(config);
    }

    pub fn current_live_runtime_config(&self) -> (CacheRuntimeConfig, Option<DohRuntimeConfig>) {
        let cache_runtime = self.cache_live_config.load();
        let doh_runtime =
            self.doh_listener.as_ref().map(|doh_listener| doh_listener.runtime_config());

        (cache_runtime.as_ref().clone(), doh_runtime)
    }

    pub async fn refresh_flow_runtime(
        &self,
        flow_id: u32,
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
    ) {
        self.refresh_flow_runtime_kind(
            flow_id,
            redirect_engine,
            resolve_engine,
            FlowRuntimeRefreshKind::Full,
        )
        .await;
    }

    pub async fn refresh_flow_runtime_kind(
        &self,
        flow_id: u32,
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
        kind: FlowRuntimeRefreshKind,
    ) {
        let entry = self.get_or_create_entry(flow_id).await;

        let _refresh_guard = entry.refresh_lock.lock().await;
        if let Some(runtime) = entry.runtime.load_full() {
            match kind {
                FlowRuntimeRefreshKind::Full => {
                    runtime.handler.renew_engines(redirect_engine, resolve_engine).await;
                }
                FlowRuntimeRefreshKind::ResolveOnly => {
                    runtime.handler.renew_dns_rules(resolve_engine).await;
                }
                FlowRuntimeRefreshKind::RedirectOnly => {
                    runtime.handler.renew_redirect_rules(redirect_engine).await;
                }
            }
            return;
        }

        let handler = DnsRequestHandler::from_engines(
            redirect_engine,
            resolve_engine,
            self.cache_live_config.clone(),
            flow_id,
            self.msg_tx.clone(),
            self.local_resolver.clone(),
        );
        let Some(runtime) = self.build_flow_runtime(flow_id, handler).await else {
            tracing::error!("[flow: {flow_id}]: DNS server start failed, runtime not registered");
            return;
        };

        entry.runtime.store(Some(Arc::new(runtime)));
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckChainDnsResult {
        let entry = self.get_entry(req.flow_id).await;

        let handler = entry
            .and_then(|entry| entry.runtime.load_full().map(|runtime| runtime.handler.clone()));
        if let Some(handler) = handler {
            let Ok(domain) = req.get_domain() else {
                return CheckChainDnsResult::default();
            };
            let Ok(pd) = ParsedDomain::new(&domain) else {
                return CheckChainDnsResult::default();
            };
            handler.check_domain(&pd, convert_record_type(req.record_type), req.apply_filter).await
        } else {
            CheckChainDnsResult::default()
        }
    }

    pub async fn invalidate_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsError> {
        let domain = req.get_domain()?;
        let query_type = convert_record_type(req.record_type);
        let entry = self.get_entry(req.flow_id).await.ok_or(DnsError::FlowNotFound(req.flow_id))?;

        let _refresh_guard = entry.refresh_lock.lock().await;
        let runtime = entry.runtime.load_full().ok_or(DnsError::FlowNotFound(req.flow_id))?;

        let pd = ParsedDomain::new(&domain)?;
        runtime.handler.invalidate_cache_entry(&pd, query_type).await;
        Ok(runtime.handler.check_domain(&pd, query_type, req.apply_filter).await)
    }

    pub async fn refresh_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsError> {
        let domain = req.get_domain()?;
        let query_type = convert_record_type(req.record_type);
        let entry = self.get_entry(req.flow_id).await.ok_or(DnsError::FlowNotFound(req.flow_id))?;

        let _refresh_guard = entry.refresh_lock.lock().await;
        let runtime = entry.runtime.load_full().ok_or(DnsError::FlowNotFound(req.flow_id))?;

        let pd = ParsedDomain::new(&domain)?;
        runtime.handler.refresh_cache_entry(&pd, query_type, req.apply_filter).await
    }

    async fn get_entry(&self, flow_id: u32) -> Option<Arc<FlowServerEntry>> {
        let flow_server = self.flow_dns_server.lock().await;
        flow_server.get(&flow_id).cloned()
    }

    async fn get_or_create_entry(&self, flow_id: u32) -> Arc<FlowServerEntry> {
        let mut lock = self.flow_dns_server.lock().await;
        lock.entry(flow_id).or_insert_with(|| Arc::new(FlowServerEntry::new())).clone()
    }

    async fn build_flow_runtime(
        &self,
        flow_id: u32,
        handler: DnsRequestHandler,
    ) -> Option<FlowServerRuntime> {
        let token = self.start_runtime_listener(flow_id, handler.clone()).await;
        if token.is_cancelled() {
            return None;
        }

        Some(FlowServerRuntime { handler, _token: token })
    }

    async fn start_runtime_listener(
        &self,
        flow_id: u32,
        handler: DnsRequestHandler,
    ) -> CancellationToken {
        start_flow_dns_listener(
            flow_id,
            self.udp_listener_addr,
            self.build_effective_doh_listener_config(),
            handler,
        )
        .await
    }

    fn build_effective_doh_listener_config(&self) -> Option<EffectiveDohListenerConfig> {
        self.doh_listener.as_ref().map(|doh_listener| doh_listener.build_effective_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use landscape_common::dns::CacheRuntimeConfig;
    use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
    use landscape_core::lan_hostname::LanHostnameRegistry;

    fn run_async_test(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test);
    }

    fn test_cache_runtime_config() -> CacheRuntimeConfig {
        CacheRuntimeConfig {
            cache_capacity: 16,
            cache_ttl: 60,
            negative_cache_ttl: 10,
        }
    }

    fn test_lan_hostname_registry() -> Arc<LanHostnameRegistry> {
        LanHostnameRegistry::new_for_test(LanHostnameConfig::default())
    }

    #[test]
    fn flow_server_entry_runtime_reads_do_not_wait_on_refresh_lock() {
        run_async_test(async {
            let entry = FlowServerEntry::new();
            let handler = DnsRequestHandler::from_engines(
                RedirectEngine::default(),
                ResolveEngine::default(),
                Arc::new(ArcSwap::from_pointee(test_cache_runtime_config())),
                7,
                Arc::new(ArcSwapOption::new(None)),
                Arc::new(LocalResolver::new(test_lan_hostname_registry(), None, None, None)),
            );
            entry.runtime.store(Some(Arc::new(FlowServerRuntime {
                handler,
                _token: CancellationToken::new(),
            })));

            let _guard = entry.refresh_lock.lock().await;
            let runtime = entry.runtime.load_full();

            assert!(runtime.is_some());
            assert_eq!(runtime.unwrap().handler.flow_id, 7);
        });
    }

    #[test]
    fn flow_server_entry_allows_empty_runtime_while_refreshing() {
        run_async_test(async {
            let entry = FlowServerEntry::new();
            let _guard = entry.refresh_lock.lock().await;

            assert!(entry.runtime.load_full().is_none());
        });
    }
}

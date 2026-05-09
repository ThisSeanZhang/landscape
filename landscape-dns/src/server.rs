use std::{
    collections::HashMap,
    net::IpAddr,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use arc_swap::{ArcSwap, ArcSwapOption};
use landscape_common::dns::check::DnsCheckError;
use landscape_common::{dns::FlowDnsDesiredState, event::DnsMetricMessage, service::WatchService};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::{
    convert_record_type,
    listener::{start_flow_dns_listener, DohListenerState},
    server::{
        handler::DnsRequestHandler,
        planner::{DnsRefreshPlan, DnsRefreshPlanner, FlowDnsAppliedState, HandlerRefreshPlan},
    },
    CheckChainDnsResult, CheckDnsReq,
};

pub(crate) mod handler;
pub(crate) mod matcher;
pub(crate) mod planner;
pub(crate) mod rule;

pub use crate::listener::{DohTimeouts, EffectiveDohListenerConfig};
pub use landscape_common::dns::{CacheRuntimeConfig, DohRuntimeConfig};

pub(crate) type MetricSenderState = Arc<ArcSwapOption<mpsc::Sender<DnsMetricMessage>>>;

pub trait LocalDnsAnswerProvider: Send + Sync {
    fn load_local_answer_addrs(
        &self,
        query_type: hickory_proto::rr::RecordType,
    ) -> Arc<Vec<IpAddr>>;
}

pub trait DohAdvertiseProvider: Send + Sync {
    fn advertise_domains(&self) -> Vec<String>;
}

// 系统 DNS 服务
#[derive(Clone)]
pub struct LandscapeDnsServer {
    // 服务状态
    pub status: WatchService,
    // 内部处理
    flow_dns_server: Arc<Mutex<HashMap<u32, Arc<FlowServerEntry>>>>,
    // 用于重定向的动态更新
    pub local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
    pub doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
    // DNS 事件
    pub msg_tx: MetricSenderState,
    // 监听 UDP DNS 地址
    pub udp_listener_addr: SocketAddr,
    cache_live_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    doh_listener: Option<DohListenerState>,
}

struct FlowServerRuntime {
    handler: DnsRequestHandler,
    token: CancellationToken,
}

struct FlowServerEntry {
    refresh_lock: Mutex<()>,
    runtime: Arc<ArcSwapOption<FlowServerRuntime>>,
    applied_state: Arc<ArcSwapOption<FlowDnsAppliedState>>,
}

impl FlowServerEntry {
    fn new() -> Self {
        Self {
            refresh_lock: Mutex::new(()),
            runtime: Arc::new(ArcSwapOption::new(None)),
            applied_state: Arc::new(ArcSwapOption::new(None)),
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
    ) -> Self {
        let status = WatchService::new();
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
            doh_listener: doh.map(DohListenerState::from_effective_config),
            local_answer_provider,
            doh_advertise_provider,
        }
    }

    pub fn get_status(&self) -> &WatchService {
        &self.status
    }

    pub fn update_runtime_config(&self, cache_runtime: CacheRuntimeConfig) {
        self.cache_live_config.store(Arc::new(cache_runtime));
    }

    pub fn update_metric_sender(&self, msg_tx: Option<mpsc::Sender<DnsMetricMessage>>) {
        self.msg_tx.store(msg_tx.map(Arc::new));
    }

    pub fn current_live_runtime_config(&self) -> (CacheRuntimeConfig, Option<DohRuntimeConfig>) {
        let cache_runtime = self.cache_live_config.load();
        let doh_runtime =
            self.doh_listener.as_ref().map(|doh_listener| doh_listener.runtime_config());

        (cache_runtime.as_ref().clone(), doh_runtime)
    }

    pub async fn refresh_flow_server(&self, desired_state: FlowDnsDesiredState) {
        let flow_id = desired_state.flow_id;
        let entry = self.get_or_create_entry(flow_id).await;

        let _refresh_guard = entry.refresh_lock.lock().await;
        if let Some(runtime) = entry.runtime.load_full() {
            let previous_state = entry.applied_state.load_full();
            let plan = DnsRefreshPlanner::build(previous_state.as_deref(), &desired_state);
            if matches!(plan, DnsRefreshPlan::Noop) {
                return;
            }

            self.apply_handler_plan(runtime.handler.clone(), &desired_state, &plan).await;

            if matches!(plan, DnsRefreshPlan::RestartListener { .. }) {
                let token = self.start_runtime_listener(flow_id, runtime.handler.clone()).await;

                if token.is_cancelled() {
                    tracing::error!(
                        "[flow: {flow_id}]: DNS server restart failed, keep current listener"
                    );
                    if let Some(applied_state) = DnsRefreshPlanner::applied_after_failure(
                        previous_state.as_deref(),
                        &desired_state,
                        &plan,
                    ) {
                        entry.applied_state.store(Some(Arc::new(applied_state)));
                    }
                    return;
                }

                runtime.token.cancel();
                entry.runtime.store(Some(Arc::new(FlowServerRuntime {
                    handler: runtime.handler.clone(),
                    token,
                })));
            }

            entry
                .applied_state
                .store(Some(Arc::new(FlowDnsAppliedState::from_desired_state(&desired_state))));
            return;
        }

        let handler = DnsRequestHandler::new(
            desired_state.clone(),
            self.cache_live_config.clone(),
            flow_id,
            self.msg_tx.clone(),
            self.local_answer_provider.clone(),
            self.doh_advertise_provider.clone(),
            desired_state.doh_runtime.clone(),
        );
        let Some(runtime) = self.build_flow_runtime(flow_id, handler).await else {
            tracing::error!("[flow: {flow_id}]: DNS server start failed, runtime not registered");
            return;
        };

        entry.runtime.store(Some(Arc::new(runtime)));
        entry
            .applied_state
            .store(Some(Arc::new(FlowDnsAppliedState::from_desired_state(&desired_state))));
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckChainDnsResult {
        let entry = self.get_entry(req.flow_id).await;

        let handler = entry
            .and_then(|entry| entry.runtime.load_full().map(|runtime| runtime.handler.clone()));
        if let Some(handler) = handler {
            handler
                .check_domain(
                    &req.get_domain(),
                    convert_record_type(req.record_type),
                    req.apply_filter,
                )
                .await
        } else {
            CheckChainDnsResult::default()
        }
    }

    pub async fn invalidate_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsCheckError> {
        let domain = req.get_domain();
        let query_type = convert_record_type(req.record_type);
        let entry =
            self.get_entry(req.flow_id).await.ok_or(DnsCheckError::FlowNotFound(req.flow_id))?;

        let _refresh_guard = entry.refresh_lock.lock().await;
        let runtime = entry.runtime.load_full().ok_or(DnsCheckError::FlowNotFound(req.flow_id))?;

        runtime.handler.invalidate_cache_entry(&domain, query_type).await;
        Ok(runtime.handler.check_domain(&domain, query_type, req.apply_filter).await)
    }

    pub async fn refresh_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsCheckError> {
        let domain = req.get_domain();
        let query_type = convert_record_type(req.record_type);
        let entry =
            self.get_entry(req.flow_id).await.ok_or(DnsCheckError::FlowNotFound(req.flow_id))?;

        let _refresh_guard = entry.refresh_lock.lock().await;
        let runtime = entry.runtime.load_full().ok_or(DnsCheckError::FlowNotFound(req.flow_id))?;

        runtime.handler.refresh_cache_entry(&domain, query_type, req.apply_filter).await
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

        Some(FlowServerRuntime { handler, token })
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

    async fn apply_handler_plan(
        &self,
        handler: DnsRequestHandler,
        desired_state: &FlowDnsDesiredState,
        plan: &DnsRefreshPlan,
    ) {
        let Some(handler_plan) = (match plan {
            DnsRefreshPlan::ApplyHandler(handler_plan) => Some(handler_plan),
            DnsRefreshPlan::RestartListener { handler_plan } => handler_plan.as_ref(),
            DnsRefreshPlan::Noop => None,
        }) else {
            return;
        };

        match handler_plan {
            HandlerRefreshPlan::ReplaceRules { include_redirects } => {
                handler.renew_dns_rules(desired_state.dns_rules.clone()).await;
                if *include_redirects {
                    handler.renew_redirect_rules(desired_state.redirect_rules.clone()).await;
                }
            }
            HandlerRefreshPlan::ReplaceRedirects => {
                handler.renew_redirect_rules(desired_state.redirect_rules.clone()).await;
            }
            HandlerRefreshPlan::ApplyCacheRuntime { rebuild_cache } => {
                handler.renew_runtime_config(*rebuild_cache).await;
            }
        }
    }

    fn build_effective_doh_listener_config(&self) -> Option<EffectiveDohListenerConfig> {
        self.doh_listener.as_ref().map(|doh_listener| doh_listener.build_effective_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use landscape_common::dns::{CacheRuntimeConfig, FlowDnsDesiredState};

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

    #[test]
    fn flow_server_entry_runtime_reads_do_not_wait_on_refresh_lock() {
        run_async_test(async {
            let entry = FlowServerEntry::new();
            let handler = DnsRequestHandler::new(
                FlowDnsDesiredState::default(),
                Arc::new(ArcSwap::from_pointee(test_cache_runtime_config())),
                7,
                Arc::new(ArcSwapOption::new(None)),
                None,
                None,
                None,
            );
            entry.runtime.store(Some(Arc::new(FlowServerRuntime {
                handler,
                token: CancellationToken::new(),
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
            assert!(entry.applied_state.load_full().is_none());
        });
    }
}

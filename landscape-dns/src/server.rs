use std::{
    collections::HashMap,
    net::IpAddr,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use arc_swap::{ArcSwap, ArcSwapOption};
use landscape_common::dns::error::DnsServiceError;
use landscape_common::event::DnsMetricMessage;
use landscape_common::flow::{DnsResultSink, FlowSocketRegistrar};
use landscape_common::service::ServiceStatus;
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_core::lan_device::LanDeviceDirectory;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::{
    CheckChainDnsResult, CheckDnsReq, convert_record_type,
    domain::ParsedDomain,
    listener::{DohListenerState, start_flow_dns_listener},
    mdns::MdnsService,
    server::{
        handler::DnsRequestHandler, local::LocalResolver, redirect_engine::RedirectEngine,
        resolve_engine::ResolveEngine,
    },
};

pub(crate) mod answer;
pub mod builder;
pub(crate) mod cache;
pub(crate) mod chain;
pub(crate) mod handler;
pub(crate) mod local;
pub(crate) mod matcher;
pub mod redirect_engine;
pub(crate) mod resolve_engine;
pub(crate) mod rule;
pub(crate) mod snapshot;

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

impl DohAdvertiseProvider for landscape_core::cert::SharedSniResolver {
    fn advertise_domains(&self) -> Vec<String> {
        self.advertised_domains()
    }
}

/// DNS 服务的一次运行:父取消信号 + 任务追踪器。
///
/// token 为所有 per-flow 监听 token 的父:服务停止时取消一次,全体 flow
/// 监听(UDP + DoH)一并终止;tracker 注册全部监听任务,供停止侧确定性
/// 等待。每次 start 创建新运行,跨 start/stop 周期不复用。
#[derive(Clone)]
struct DnsServiceRun {
    token: CancellationToken,
    tracker: TaskTracker,
}

// system DNS service
#[derive(Clone)]
pub struct LandscapeDnsServer {
    /// 当前运行(None = 已停止):flow 监听任务据此决定是否可以建立
    run: Arc<ArcSwapOption<DnsServiceRun>>,
    // internal handlers
    flow_dns_server: Arc<Mutex<HashMap<u32, Arc<FlowServerEntry>>>>,
    // local answers (localhost / LAN hostname zone / PTR / DDR) shared by all flows
    pub local_resolver: Arc<LocalResolver>,
    // shared LAN hostname config (DNS zone + DHCPv4 options 15/119)
    lan_hostname_config: Arc<ArcSwap<LanHostnameConfig>>,
    // DNS events
    pub msg_tx: MetricSenderState,
    // bound UDP DNS listen address
    pub udp_listener_addr: SocketAddr,
    cache_live_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    doh_listener: Option<DohListenerState>,
    _mdns_service: Option<Arc<MdnsService>>,
    result_sink: Arc<dyn DnsResultSink>,
    socket_registrar: Arc<dyn FlowSocketRegistrar>,
}

struct FlowServerRuntime {
    handler: DnsRequestHandler,
    /// 本 flow 的监听 token(服务运行 token 的 child):bind 失败自我取消,
    /// 服务停止随父取消;`has_live_flow_runtime`/`status_summary` 以其判活
    token: CancellationToken,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listen_port: u16,
        msg_tx: Option<mpsc::Sender<DnsMetricMessage>>,
        cache_runtime: CacheRuntimeConfig,
        doh: Option<EffectiveDohListenerConfig>,
        local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        doh_advertise_provider: Option<Arc<dyn DohAdvertiseProvider>>,
        lan_device_directory: Arc<LanDeviceDirectory>,
        lan_hostname_config: Arc<ArcSwap<LanHostnameConfig>>,
        result_sink: Arc<dyn DnsResultSink>,
        socket_registrar: Arc<dyn FlowSocketRegistrar>,
    ) -> Self {
        let mdns_service = if local_answer_provider.is_some() {
            MdnsService::spawn(local_answer_provider.clone())
        } else {
            None
        };
        let doh_listener = doh.map(DohListenerState::from_effective_config);
        let doh_runtime = doh_listener.as_ref().map(|doh_listener| doh_listener.runtime_config());
        let local_resolver = Arc::new(LocalResolver::new(
            lan_device_directory,
            lan_hostname_config.clone(),
            local_answer_provider,
            doh_advertise_provider,
            doh_runtime,
        ));

        Self {
            run: Arc::new(ArcSwapOption::from(Some(Arc::new(DnsServiceRun {
                token: CancellationToken::new(),
                tracker: TaskTracker::new(),
            })))),
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
            lan_hostname_config,
            local_resolver,
            result_sink,
            socket_registrar,
        }
    }

    /// 当前运行快照(None = 服务已停止)
    fn current_run(&self) -> Option<Arc<DnsServiceRun>> {
        self.run.load_full()
    }

    /// 开始一次新的服务运行:创建全新的父 token 与 tracker。
    /// 此后须由上层重新 refresh 各 flow(停止时已清空的 runtime 会重建)。
    pub fn start_service(&self) {
        self.run.store(Some(Arc::new(DnsServiceRun {
            token: CancellationToken::new(),
            tracker: TaskTracker::new(),
        })));
    }

    /// 真停:取消父 token(全体 flow 监听一并终止)→ 确定性等待全部被
    /// 追踪任务结束 → 清空各 flow 的已死 runtime,供下一轮 refresh 重建。
    pub async fn stop_service(&self) {
        let Some(run) = self.run.swap(None) else {
            tracing::debug!("dns service not running, nothing to stop");
            return;
        };
        run.token.cancel();
        run.tracker.close();
        run.tracker.wait().await;
        let flow_server = self.flow_dns_server.lock().await;
        for entry in flow_server.values() {
            // 持 refresh_lock 清扫:与 refresh 的"检查 + store"临界区互斥,
            // 消除"清扫完成后再落入死 runtime"的残留竞态
            //(锁序 map → refresh;refresh 临界区内不取 map 锁,无死锁)
            let _refresh_guard = entry.refresh_lock.lock().await;
            entry.runtime.store(None);
        }
    }

    /// 服务状态投影(无独立状态持有者,由运行资源派生):
    /// - 无运行(未启动/已停止)或没有任何 flow → Stop
    /// - 存在存活 flow 监听 → Running
    /// - 配置过 flow 但全部死亡(bind 失败/监听退出)→ Failed
    pub async fn status_summary(&self) -> ServiceStatus {
        if self.current_run().is_none() {
            return ServiceStatus::Stop;
        }
        let flow_server = self.flow_dns_server.lock().await;
        if flow_server.is_empty() {
            return ServiceStatus::Stop;
        }
        let live = flow_server.values().any(|entry| {
            entry.runtime.load_full().is_some_and(|runtime| !runtime.token.is_cancelled())
        });
        if live { ServiceStatus::Running } else { ServiceStatus::Failed }
    }

    /// Returns whether at least one flow listener runtime is still serving.
    /// On socket bind failure `build_flow_runtime` does not store a runtime;
    /// the cancel token is cancelled when the listener exits.
    pub async fn has_live_flow_runtime(&self) -> bool {
        let flow_server = self.flow_dns_server.lock().await;
        flow_server.values().any(|entry| {
            entry.runtime.load_full().is_some_and(|runtime| !runtime.token.is_cancelled())
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
        self.lan_hostname_config.store(Arc::new(config));
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
        // 仅存活 runtime 走就地更新;死 runtime(bind 失败/监听中途退出/
        // 停止清扫残留)视同不存在,落入下方重建路径整体替换
        if let Some(runtime) = entry.runtime.load_full()
            && !runtime.token.is_cancelled()
        {
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
            self.result_sink.clone(),
        );
        let Some(run) = self.current_run() else {
            tracing::debug!("[flow: {flow_id}]: dns service not running, skip listener build");
            return;
        };
        let Some(runtime) = self.build_flow_runtime(flow_id, handler, &run).await else {
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
    ) -> Result<CheckChainDnsResult, DnsServiceError> {
        let domain = req.get_domain()?;
        let query_type = convert_record_type(req.record_type);
        let entry =
            self.get_entry(req.flow_id).await.ok_or(DnsServiceError::FlowNotFound(req.flow_id))?;

        let _refresh_guard = entry.refresh_lock.lock().await;
        let runtime =
            entry.runtime.load_full().ok_or(DnsServiceError::FlowNotFound(req.flow_id))?;

        let pd = ParsedDomain::new(&domain)?;
        runtime.handler.invalidate_cache_entry(&pd, query_type).await;
        Ok(runtime.handler.check_domain(&pd, query_type, req.apply_filter).await)
    }

    pub async fn refresh_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsServiceError> {
        let domain = req.get_domain()?;
        let query_type = convert_record_type(req.record_type);
        let entry =
            self.get_entry(req.flow_id).await.ok_or(DnsServiceError::FlowNotFound(req.flow_id))?;

        let _refresh_guard = entry.refresh_lock.lock().await;
        let runtime =
            entry.runtime.load_full().ok_or(DnsServiceError::FlowNotFound(req.flow_id))?;

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
        run: &DnsServiceRun,
    ) -> Option<FlowServerRuntime> {
        let token = run.token.child_token();
        let started = self
            .start_runtime_listener(flow_id, handler.clone(), &token, run.tracker.clone())
            .await;
        if started.is_cancelled() {
            return None;
        }

        Some(FlowServerRuntime { handler, token })
    }

    async fn start_runtime_listener(
        &self,
        flow_id: u32,
        handler: DnsRequestHandler,
        token: &CancellationToken,
        tracker: TaskTracker,
    ) -> CancellationToken {
        start_flow_dns_listener(
            flow_id,
            self.udp_listener_addr,
            self.build_effective_doh_listener_config(),
            handler,
            self.socket_registrar.clone(),
            token.clone(),
            tracker,
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
    use landscape_common::flow::{NoopDnsResultSink, NoopFlowSocketRegistrar};
    use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
    use landscape_core::lan_device::LanDeviceDirectory;

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

    fn test_local_resolver() -> Arc<LocalResolver> {
        Arc::new(LocalResolver::new(
            LanDeviceDirectory::new_for_test(),
            test_lan_hostname_config(),
            None,
            None,
            None,
        ))
    }

    fn test_lan_hostname_config() -> Arc<ArcSwap<LanHostnameConfig>> {
        Arc::new(ArcSwap::from_pointee(LanHostnameConfig::default()))
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
                test_local_resolver(),
                Arc::new(NoopDnsResultSink),
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
        });
    }

    fn test_dns_server() -> LandscapeDnsServer {
        let mut server = LandscapeDnsServer::new(
            53,
            None,
            test_cache_runtime_config(),
            None,
            None,
            None,
            LanDeviceDirectory::new_for_test(),
            test_lan_hostname_config(),
            Arc::new(NoopDnsResultSink),
            Arc::new(NoopFlowSocketRegistrar),
        );
        // 避免测试环境绑定特权端口 53:改用内核分配的临时端口
        server.udp_listener_addr = "[::]:0".parse().unwrap();
        server
    }

    async fn refresh_full(server: &LandscapeDnsServer, flow_id: u32) {
        server
            .refresh_flow_runtime_kind(
                flow_id,
                RedirectEngine::default(),
                ResolveEngine::default(),
                FlowRuntimeRefreshKind::Full,
            )
            .await;
    }

    #[test]
    fn refresh_rebuilds_dead_runtime() {
        run_async_test(async {
            let server = test_dns_server();
            refresh_full(&server, 1).await;
            let entry = server.get_entry(1).await.unwrap();
            assert!(!entry.runtime.load_full().unwrap().token.is_cancelled());

            // listener 死亡后,refresh 必须整体重建(新 token 存活)而非就地 renew
            entry.runtime.load_full().unwrap().token.cancel();
            assert!(!server.has_live_flow_runtime().await);

            server
                .refresh_flow_runtime_kind(
                    1,
                    RedirectEngine::default(),
                    ResolveEngine::default(),
                    FlowRuntimeRefreshKind::ResolveOnly,
                )
                .await;
            let runtime = entry.runtime.load_full().unwrap();
            assert!(!runtime.token.is_cancelled());
            assert!(server.has_live_flow_runtime().await);
        });
    }

    #[test]
    fn status_summary_projection_phases() {
        run_async_test(async {
            let server = test_dns_server();

            // 无任何 flow 条目 → Stop
            assert_eq!(server.status_summary().await, ServiceStatus::Stop);

            // 配置过 flow 但无存活 runtime → Failed
            server.get_or_create_entry(1).await;
            assert_eq!(server.status_summary().await, ServiceStatus::Failed);

            // 建立成功 → Running;listener 死亡 → Failed
            refresh_full(&server, 1).await;
            assert_eq!(server.status_summary().await, ServiceStatus::Running);
            server.get_entry(1).await.unwrap().runtime.load_full().unwrap().token.cancel();
            assert_eq!(server.status_summary().await, ServiceStatus::Failed);

            // 停止 → Stop
            server.stop_service().await;
            assert_eq!(server.status_summary().await, ServiceStatus::Stop);
        });
    }

    #[test]
    fn stop_then_start_rebuilds_listeners() {
        run_async_test(async {
            let server = test_dns_server();
            refresh_full(&server, 1).await;
            assert_eq!(server.status_summary().await, ServiceStatus::Running);

            // 停止:runtime 被确定性清空
            server.stop_service().await;
            assert!(server.get_entry(1).await.unwrap().runtime.load_full().is_none());
            assert_eq!(server.status_summary().await, ServiceStatus::Stop);

            // 重启:refresh 重建 listener 后恢复 Running
            server.start_service();
            refresh_full(&server, 1).await;
            assert_eq!(server.status_summary().await, ServiceStatus::Running);
            assert!(server.has_live_flow_runtime().await);
        });
    }
}

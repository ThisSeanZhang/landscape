use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::rr::RecordType;
use landscape_common::sys_config::LanHostnameRuntimeConfig;
use landscape_common::{
    dns::error::DnsServiceError,
    dns::{DnsServiceStatus, FlowDnsStatus},
    event::dns::DnsEvent,
    flow::{DnsResultSink, FlowSocketRegistrar},
    metric::dns::DnsMetricReporter,
    sys_config::{CacheRuntimeConfig, DohRuntimeConfig},
};
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_dns::{
    CheckChainDnsResult, CheckDnsReq,
    coordinator::DnsCoordinator,
    listener::DohSettings,
    prepare_system_dns,
    resolve::LocalDnsAnswerProvider,
    server::{DnsServiceDeps, FlowRuntimeRefreshKind, LandscapeDnsServer},
};
use tokio::sync::{Mutex, mpsc, watch};

use crate::dns::{
    config_source::DbDnsConfigSource, redirect_service::DNSRedirectService,
    rule_service::DNSRuleService, upstream_service::DnsUpstreamService,
};
use crate::{
    cert::order_service::CertService,
    geo::site_service::GeoSiteService,
    sys_service::route::{IpRouteService, LocalAddrView},
};

/// Bridges the route service's shared address snapshots into the DNS local
/// answer provider port. Keeps the route service free of any DNS crate
/// dependency: it only ever sees [`LocalAddrView`].
struct RouteLocalAnswerProvider {
    view: LocalAddrView,
}

impl LocalDnsAnswerProvider for RouteLocalAnswerProvider {
    fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
        match query_type {
            RecordType::A => self.view.load_ipv4_addrs(),
            RecordType::AAAA => self.view.load_ipv6_addrs(),
            _ => Arc::new(Vec::new()),
        }
    }

    fn load_local_answer_addrs_for_ifindex(
        &self,
        query_type: RecordType,
        ifindex: u32,
    ) -> Arc<Vec<IpAddr>> {
        if ifindex == 0 {
            return self.load_local_answer_addrs(query_type);
        }

        match query_type {
            RecordType::A => self.view.load_ipv4_addrs_for_ifindex(ifindex),
            RecordType::AAAA => self.view.load_ipv6_addrs_for_ifindex(ifindex),
            _ => Arc::new(Vec::new()),
        }
    }
}

#[derive(Clone)]
pub struct LandscapeDnsService {
    coordinator: Arc<DnsCoordinator>,
    lifecycle: Arc<Mutex<()>>,
}

impl LandscapeDnsService {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        receiver: mpsc::Receiver<DnsEvent>,
        dns_rule_service: DNSRuleService,
        dns_redirect_rule_service: DNSRedirectService,
        geo_site_service: GeoSiteService,
        dns_upstream_service: DnsUpstreamService,
        route_service: IpRouteService,
        mut cache_config: watch::Receiver<CacheRuntimeConfig>,
        doh_config: watch::Receiver<DohRuntimeConfig>,
        cert_service: CertService,
        metric_reporter: DnsMetricReporter,
        lan_device_directory: Arc<LanDeviceDirectory>,
        lan_hostname_config: Arc<ArcSwap<LanHostnameRuntimeConfig>>,
        dns_result_sink: Arc<dyn DnsResultSink>,
        flow_socket_registrar: Arc<dyn FlowSocketRegistrar>,
    ) -> Self {
        let cache_runtime = cache_config.borrow_and_update().clone();
        if prepare_system_dns() {
            tracing::info!("system DNS redirected to local DNS service");
        } else {
            tracing::error!("failed to redirect system DNS to local DNS service");
        }
        let api_tls_resolver = cert_service.api_tls_resolver();
        let doh = Some(DohSettings {
            config: doh_config,
            cert_resolver: Arc::new(api_tls_resolver.clone()),
        });
        let server = LandscapeDnsServer::new(DnsServiceDeps {
            listen_port: landscape_common::DNS_LISTEN_PORT,
            metric_reporter,
            cache_runtime,
            doh,
            local_answer_provider: Some(Arc::new(RouteLocalAnswerProvider {
                view: route_service.local_addr_view(),
            }) as Arc<dyn LocalDnsAnswerProvider>),
            doh_advertise_provider: Some(
                Arc::new(api_tls_resolver) as Arc<dyn landscape_dns::resolve::DohAdvertiseProvider>
            ),
            lan_device_directory,
            lan_hostname_config,
            result_sink: dns_result_sink,
            socket_registrar: flow_socket_registrar,
        });
        let source = Arc::new(DbDnsConfigSource::new(
            dns_rule_service,
            dns_redirect_rule_service,
            dns_upstream_service,
        ));
        let coordinator =
            Arc::new(DnsCoordinator::new(server, geo_site_service.matcher_registry(), source));

        // 创建即视为进入运行状态(server::new 已初始化运行):直接刷新各
        // flow 监听;状态由 `status_summary` 从运行资源投影,无需另行汇报
        match coordinator.refresh_all(FlowRuntimeRefreshKind::Full).await {
            Ok(flow_count) => {
                let live = coordinator.server().has_live_flow_runtime().await;
                tracing::info!(
                    "DNS service started: flow_count: {flow_count}, live_runtime: {live}"
                );
            }
            Err(error) => {
                tracing::error!(%error, "DNS service initial refresh failed");
            }
        }
        coordinator.spawn_event_loop(receiver);

        let observer = coordinator.clone();
        landscape_common::concurrency::spawn_task(
            landscape_common::concurrency::task_label::task::DNS_SERVICE_OBSERVER,
            async move {
                while cache_config.changed().await.is_ok() {
                    let cache = cache_config.borrow_and_update().clone();
                    observer.apply_cache_config(cache).await;
                }
            },
        );
        Self { coordinator, lifecycle: Default::default() }
    }

    pub async fn get_status(&self) -> DnsServiceStatus {
        self.coordinator.server().service_status().await
    }

    pub async fn flow_statuses(&self) -> Vec<FlowDnsStatus> {
        self.coordinator.server().flow_statuses().await
    }

    pub async fn flow_status(&self, flow_id: u32) -> Option<FlowDnsStatus> {
        self.coordinator.server().flow_status(flow_id).await
    }

    /// 真启动:开启新的服务运行 → 重建各 flow 监听(停止时清空的
    /// runtime 会重新建立)→ 恢复系统解析器劫持。
    pub async fn start_dns_service(&self) -> Result<(), DnsServiceError> {
        let _guard = self.lifecycle.lock().await;
        tracing::info!("starting DNS service");
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.coordinator.server().start_service(),
        )
        .await
        .map_err(|_| {
            DnsServiceError::Internal("Previous DNS listeners are still stopping".into())
        })?;

        match self.coordinator.refresh_all(FlowRuntimeRefreshKind::Full).await {
            Ok(flow_count) => {
                tracing::info!("DNS service run started: flow_count: {flow_count}");
            }
            Err(error) => {
                tracing::error!(%error, "DNS service refresh failed on start");
            }
        }

        if prepare_system_dns() {
            tracing::info!("system DNS redirected to local DNS service");
        } else {
            tracing::error!("failed to redirect system DNS to local DNS service");
        }
        Ok(())
    }

    /// 真停:先恢复系统解析器,再取消全部 flow 监听并确定性等待其结束。
    /// 语义变更:此前 stop 仅恢复 resolv.conf,flow 监听继续运行。
    pub async fn stop(&self) -> Result<(), DnsServiceError> {
        let _guard = self.lifecycle.lock().await;
        tracing::info!("stopping DNS service");
        landscape_dns::restore_resolver_conf();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.coordinator.server().stop_service(),
        )
        .await
        .map_err(|_| DnsServiceError::Internal("DNS listener shutdown timed out".into()))?;
        tracing::info!("DNS service stopped");
        Ok(())
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckChainDnsResult {
        self.coordinator.server().check_domain(req).await
    }

    pub async fn invalidate_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsServiceError> {
        self.coordinator.server().invalidate_domain_cache(req).await
    }

    pub async fn refresh_domain_cache(
        &self,
        req: CheckDnsReq,
    ) -> Result<CheckChainDnsResult, DnsServiceError> {
        self.coordinator.server().refresh_domain_cache(req).await
    }

    pub fn advertised_doh(&self) -> Arc<arc_swap::ArcSwapOption<DohRuntimeConfig>> {
        self.coordinator.server().advertised_doh()
    }
}

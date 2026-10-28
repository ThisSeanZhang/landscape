use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::rr::RecordType;
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_common::{
    config::DnsRuntimeConfig,
    dns::error::DnsServiceError,
    event::dns::DnsEvent,
    flow::{DnsResultSink, FlowSocketRegistrar},
    metric::dns::DnsMetricEvent,
    service::ServiceStatus,
};
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_dns::{
    CheckChainDnsResult, CheckDnsReq,
    coordinator::DnsCoordinator,
    listener::{DohTimeouts, EffectiveDohListenerConfig},
    prepare_system_dns,
    resolve::LocalDnsAnswerProvider,
    server::{DnsServiceDeps, FlowRuntimeRefreshKind, LandscapeDnsServer},
};
use rustls::server::ResolvesServerCert;
use tokio::sync::mpsc;

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
        dns_config: DnsRuntimeConfig,
        cert_service: CertService,
        msg_tx: Option<mpsc::Sender<DnsMetricEvent>>,
        lan_device_directory: Arc<LanDeviceDirectory>,
        lan_hostname_config: Arc<ArcSwap<LanHostnameConfig>>,
        dns_result_sink: Arc<dyn DnsResultSink>,
        flow_socket_registrar: Arc<dyn FlowSocketRegistrar>,
    ) -> Self {
        let cache_runtime = dns_config.cache_runtime();
        let doh_runtime = dns_config.doh_runtime();
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
        let server = LandscapeDnsServer::new(DnsServiceDeps {
            listen_port: 53,
            msg_tx,
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

        Self { coordinator }
    }

    pub async fn get_status(&self) -> ServiceStatus {
        self.coordinator.server().status_summary().await
    }

    /// 真启动:开启新的服务运行 → 重建各 flow 监听(停止时清空的
    /// runtime 会重新建立)→ 恢复系统解析器劫持。
    pub async fn start_dns_service(&self) {
        tracing::info!("starting DNS service");
        self.coordinator.server().start_service();

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
    }

    /// 真停:先恢复系统解析器,再取消全部 flow 监听并确定性等待其结束。
    /// 语义变更:此前 stop 仅恢复 resolv.conf,flow 监听继续运行。
    pub async fn stop(&self) {
        tracing::info!("stopping DNS service");
        landscape_dns::restore_resolver_conf();
        self.coordinator.server().stop_service().await;
        tracing::info!("DNS service stopped");
    }

    pub fn update_metric_sender(&self, msg_tx: Option<mpsc::Sender<DnsMetricEvent>>) {
        self.coordinator.server().update_metric_sender(msg_tx);
    }

    pub fn update_lan_hostname_config(&self, config: LanHostnameConfig) {
        self.coordinator.server().update_lan_hostname_config(config);
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

    pub async fn apply_runtime_config(&self, dns_config: DnsRuntimeConfig) {
        self.coordinator.apply_runtime_config(dns_config).await;
    }
}

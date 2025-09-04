use std::time::Instant;

use landscape_common::{
    event::dns::DnsEvent,
    service::{controller_service_v2::FlowConfigController, DefaultWatchServiceStatus},
};
use landscape_dns::{
    reuseport_chain_server::LandscapeReusePortChainDnsServer, CheckChainDnsResult, CheckDnsReq,
};
use tokio::sync::mpsc;

use crate::config_service::{
    dns::{redirect::DNSRedirectService, upstream::DnsUpstreamService},
    dns_rule::DNSRuleService,
    geo_site_service::GeoSiteService,
};

#[derive(Clone)]
#[allow(dead_code)]
pub struct LandscapeDnsService {
    dns_service: LandscapeReusePortChainDnsServer,
    dns_rule_service: DNSRuleService,
    dns_redirect_rule_service: DNSRedirectService,
    geo_site_service: GeoSiteService,
    dns_upstream_service: DnsUpstreamService,
}

impl LandscapeDnsService {
    pub async fn new(
        mut receiver: mpsc::Receiver<DnsEvent>,
        dns_rule_service: DNSRuleService,
        dns_redirect_rule_service: DNSRedirectService,
        geo_site_service: GeoSiteService,
        dns_upstream_service: DnsUpstreamService,
    ) -> Self {
        let dns_service = LandscapeReusePortChainDnsServer::new(53);

        // dns_service.restart(53).await;
        // dns_service.update_flow_map(&flow_rule_service.list().await).await;

        let dns_service = Self {
            dns_service,
            dns_rule_service,
            dns_redirect_rule_service,
            geo_site_service,
            dns_upstream_service,
        };
        dns_service.reflush_dns(None).await;
        let dns_service_clone = dns_service.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    DnsEvent::RuleUpdated { flow_id: None } | DnsEvent::GeositeUpdated => {
                        dns_service_clone.reflush_dns(None).await;
                    }
                    DnsEvent::RuleUpdated { flow_id: Some(flow_id) } => {
                        dns_service_clone.reflush_dns(Some(flow_id)).await;
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

    pub async fn get_status(&self) -> DefaultWatchServiceStatus {
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
        // self.dns_service.stop();
    }

    pub async fn check_domain(&self, req: CheckDnsReq) -> CheckChainDnsResult {
        self.dns_service.check_domain(req).await
    }

    async fn reflush_dns(&self, flow_id: Option<u32>) {
        if let Some(flow_id) = flow_id {
            tracing::info!("refresh dns rule: flow_id: {flow_id}");
            let time = Instant::now();
            let flow_dns_rules = self.dns_rule_service.list_flow_configs(flow_id).await;
            tracing::info!("load rule: {:?}ms", time.elapsed().as_millis());

            let dns_redirect_rules =
                self.dns_redirect_rule_service.list_flow_configs(flow_id).await;
            let dns_rules = self
                .geo_site_service
                .convert_to_chain_init_config(flow_dns_rules, dns_redirect_rules)
                .await;

            tracing::info!("convert rule: {:?}ms", time.elapsed().as_millis());
            self.dns_service.refresh_flow_server(flow_id, dns_rules).await;
            tracing::info!(
                "[flow_id: {flow_id}] init all DNS rule: {:?}ms",
                time.elapsed().as_millis()
            );
        } else {
            let dns_rules = self.dns_rule_service.get_flow_hashmap().await;

            for (flow_id, value) in dns_rules {
                // let dns_rules = geo_site_service.convert_config_to_runtime_rule(value).await;
                // let info = geo_site_service.convert_config_to_init_info(value).await;
                let dns_redirect_rules =
                    self.dns_redirect_rule_service.list_flow_configs(flow_id).await;
                let dns_rules = self
                    .geo_site_service
                    .convert_to_chain_init_config(value, dns_redirect_rules)
                    .await;
                self.dns_service.refresh_flow_server(flow_id, dns_rules).await;
            }
        }
    }
}

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use landscape_common::dns::{redirect::DynamicDnsRedirectScope, rule::DNSRuleConfig};
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreFlowController};
use landscape_dns::coordinator::{DnsConfigError, DnsConfigSource, FlowConfigBundle};

use crate::dns::{
    redirect_service::DNSRedirectService, rule_service::DNSRuleService,
    upstream_service::DnsUpstreamService,
};

/// Database-backed implementation of the DNS runtime's config source port.
#[derive(Clone)]
pub struct DbDnsConfigSource {
    rules: DNSRuleService,
    redirects: DNSRedirectService,
    upstreams: DnsUpstreamService,
    routes: crate::sys_service::route::IpRouteService,
}

impl DbDnsConfigSource {
    pub fn new(
        rules: DNSRuleService,
        redirects: DNSRedirectService,
        upstreams: DnsUpstreamService,
        routes: crate::sys_service::route::IpRouteService,
    ) -> Self {
        Self { rules, redirects, upstreams, routes }
    }
}

fn config_error(context: &str, error: impl std::fmt::Display) -> DnsConfigError {
    DnsConfigError::new(format!("{context}: {error}"))
}

#[async_trait]
impl DnsConfigSource for DbDnsConfigSource {
    async fn all_flow_rules(&self) -> Result<HashMap<u32, Vec<DNSRuleConfig>>, DnsConfigError> {
        self.rules
            .get_flow_hashmap()
            .await
            .map_err(|error| config_error("failed to load DNS rules", error))
    }

    async fn flow_rules(&self, flow_id: u32) -> Result<Vec<DNSRuleConfig>, DnsConfigError> {
        self.rules
            .list_flow_configs(flow_id)
            .await
            .map_err(|error| config_error("failed to load flow DNS rules", error))
    }

    async fn flow_bundle(
        &self,
        flow_id: u32,
        mut rules: Vec<DNSRuleConfig>,
    ) -> Result<FlowConfigBundle, DnsConfigError> {
        let upstream_ids = rules
            .iter()
            .flat_map(|rule| {
                std::iter::once(rule.upstream_id)
                    .chain(rule.wan_upstreams.iter().map(|mapping| mapping.upstream_id))
            })
            .collect();
        if rules.iter().any(|rule| !rule.wan_upstreams.is_empty()) {
            let binding = self.routes.dns_wan_binding(flow_id).await;
            for rule in &mut rules {
                if !rule.wan_upstreams.is_empty() {
                    rule.resolved_wan = Some(binding.clone());
                }
            }
        }
        let mut upstreams = self
            .upstreams
            .find_ids(upstream_ids)
            .await
            .map_err(|error| config_error("failed to load DNS upstreams", error))?;
        for upstream in &mut upstreams {
            if let Some(flow) = upstream.bind_config.follow_flow {
                upstream.bind_config.resolved_wan = Some(self.routes.dns_wan_binding(flow).await);
            }
        }
        let redirects = self
            .redirects
            .list_flow_configs(flow_id)
            .await
            .map_err(|error| config_error("failed to load DNS redirects", error))?;
        let dynamic_redirects = self.redirects.list_flow_dynamic_batches(flow_id).await;

        Ok(FlowConfigBundle { rules, redirects, dynamic_redirects, upstreams })
    }

    async fn redirect_flow_ids(&self) -> Result<HashSet<u32>, DnsConfigError> {
        let redirects = self
            .redirects
            .list()
            .await
            .map_err(|error| config_error("failed to list DNS redirects", error))?;
        Ok(redirects.into_iter().flat_map(|rule| rule.apply_flows).collect())
    }

    async fn dynamic_redirect_flow_ids(&self) -> Result<HashSet<u32>, DnsConfigError> {
        Ok(self
            .redirects
            .list_dynamic_batches()
            .await
            .into_iter()
            .filter_map(|batch| match batch.scope {
                DynamicDnsRedirectScope::Flow(flow_id) => Some(flow_id),
                DynamicDnsRedirectScope::Global => None,
            })
            .collect())
    }
}

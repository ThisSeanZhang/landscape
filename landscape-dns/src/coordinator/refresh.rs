use std::{collections::HashSet, time::Instant};

use landscape_common::dns::rule::DNSRuleConfig;

use super::{DnsConfigError, DnsCoordinator};
use crate::server::{FlowDependencySelector, FlowRuntimeRefreshKind};

impl DnsCoordinator {
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

    async fn refresh_flow_with_rules(
        &self,
        flow_id: u32,
        rules: Vec<DNSRuleConfig>,
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

use std::{collections::HashSet, sync::Arc};

use landscape_common::{
    concurrency::{spawn_task, task_label},
    event::dns::DnsEvent,
};
use tokio::sync::mpsc;

use super::{DnsConfigError, DnsCoordinator};
use crate::server::{FlowDependencySelector, FlowRuntimeRefreshKind};

impl DnsCoordinator {
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
}

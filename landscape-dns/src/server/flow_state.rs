use std::{collections::HashSet, sync::Arc};

use arc_swap::ArcSwap;
use landscape_common::{config_service::geo::GeoFileCacheKey, dns::FlowDnsDependencies};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::server::handler::DnsRequestHandler;

/// Coarse lifecycle of one flow's DNS runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowDnsPhase {
    /// The whole DNS service is stopped.
    Stopped,
    /// The service is running, but this flow has no listener yet.
    Idle,
    /// A listener is being built for this flow.
    Starting,
    /// The flow has a live listener runtime.
    Running,
    /// The last listener build attempt failed.
    Failed,
}

/// The live part of one flow's DNS runtime: the query handler plus the token
/// that owns its UDP/DoH listener tasks.
#[derive(Clone)]
pub(crate) struct FlowDnsRuntime {
    pub(crate) handler: DnsRequestHandler,
    /// Child of the service run token. Cancelled on bind failure or service stop.
    pub(crate) token: CancellationToken,
}

/// Immutable snapshot of one flow's DNS state. Refreshes replace the whole
/// snapshot atomically so readers never observe a partially updated flow.
#[derive(Clone)]
pub(crate) struct FlowDnsSnapshot {
    pub(crate) flow_id: u32,
    pub(crate) phase: FlowDnsPhase,
    pub(crate) dependencies: FlowDnsDependencies,
    pub(crate) runtime: Option<Arc<FlowDnsRuntime>>,
    pub(crate) last_error: Option<String>,
    pub(crate) revision: u64,
}

impl FlowDnsSnapshot {
    pub(crate) fn idle(flow_id: u32) -> Self {
        Self {
            flow_id,
            phase: FlowDnsPhase::Idle,
            dependencies: FlowDnsDependencies::default(),
            runtime: None,
            last_error: None,
            revision: 0,
        }
    }

    pub(crate) fn transition(
        &self,
        phase: FlowDnsPhase,
        dependencies: FlowDnsDependencies,
        runtime: Option<Arc<FlowDnsRuntime>>,
        last_error: Option<String>,
    ) -> Self {
        Self {
            flow_id: self.flow_id,
            phase,
            dependencies,
            runtime,
            last_error,
            revision: self.revision.wrapping_add(1),
        }
    }
}

/// Selects the flows whose last applied configuration references a changed
/// resource.
#[derive(Debug, Clone)]
pub enum FlowDependencySelector {
    GeoKeys(HashSet<GeoFileCacheKey>),
    Upstreams(HashSet<Uuid>),
    DynamicRedirectSource(String),
}

impl FlowDependencySelector {
    pub(crate) fn matches(&self, dependencies: &FlowDnsDependencies) -> bool {
        match self {
            Self::GeoKeys(changed_keys) => {
                dependencies.geo_keys.iter().any(|key| changed_keys.contains(key))
            }
            Self::Upstreams(changed_ids) => {
                dependencies.upstream_ids.iter().any(|id| changed_ids.contains(id))
            }
            Self::DynamicRedirectSource(source_id) => {
                dependencies.dynamic_redirect_sources.contains(source_id)
            }
        }
    }
}

/// Per-flow state slot. Writers serialize through `refresh_lock`; readers use
/// the lock-free `ArcSwap` snapshot.
pub(crate) struct FlowDnsEntry {
    pub(crate) refresh_lock: Mutex<()>,
    state: ArcSwap<FlowDnsSnapshot>,
}

impl FlowDnsEntry {
    pub(crate) fn new(flow_id: u32) -> Self {
        Self {
            refresh_lock: Mutex::new(()),
            state: ArcSwap::from_pointee(FlowDnsSnapshot::idle(flow_id)),
        }
    }

    pub(crate) fn snapshot(&self) -> Arc<FlowDnsSnapshot> {
        self.state.load_full()
    }

    pub(crate) fn store(&self, snapshot: FlowDnsSnapshot) {
        self.state.store(Arc::new(snapshot));
    }
}

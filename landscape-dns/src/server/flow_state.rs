use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

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
    pub(crate) runtime: Option<Arc<FlowDnsRuntime>>,
    pub(crate) last_error: Option<String>,
    pub(crate) revision: u64,
}

impl FlowDnsSnapshot {
    pub(crate) fn idle(flow_id: u32) -> Self {
        Self {
            flow_id,
            phase: FlowDnsPhase::Idle,
            runtime: None,
            last_error: None,
            revision: 0,
        }
    }

    pub(crate) fn transition(
        &self,
        phase: FlowDnsPhase,
        runtime: Option<Arc<FlowDnsRuntime>>,
        last_error: Option<String>,
    ) -> Self {
        Self {
            flow_id: self.flow_id,
            phase,
            runtime,
            last_error,
            revision: self.revision.wrapping_add(1),
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

//! Flow rule sync: push flow-match rules and per-flow destination-IP
//! marks into the eBPF maps and invalidate the verdict cache.

use crate::flow::RuntimeFlowConfig;
use crate::flow::ip_mark::{IpMarkInfo, PortMarkInfo};

/// eBPF capability for the flow rule services.
pub trait FlowRuleDataplane: Send + Sync {
    /// Reconcile the flow-match map to `configs` (also invalidates the
    /// LAN verdict cache on change).
    fn sync_flow_matches(&self, configs: &[RuntimeFlowConfig]);

    /// Create or update the per-flow destination-IP LPM marks of
    /// `flow_id`.
    fn set_dst_ip_marks(&self, flow_id: u32, ips: Vec<IpMarkInfo>);

    /// Create or update the per-flow destination L4 protocol/port-range
    /// marks of `flow_id`.
    fn set_dst_port_marks(&self, flow_id: u32, ports: Vec<PortMarkInfo>) {
        let _ = (flow_id, ports);
    }

    /// Recreate the LAN verdict-cache inner maps (invalidate all cached
    /// verdicts).
    fn invalidate_lan_cache(&self);
}

/// No-op implementation for tests.
pub struct NoopFlowRuleDataplane;

impl FlowRuleDataplane for NoopFlowRuleDataplane {
    fn sync_flow_matches(&self, _configs: &[RuntimeFlowConfig]) {}

    fn set_dst_ip_marks(&self, _flow_id: u32, _ips: Vec<IpMarkInfo>) {}

    fn invalidate_lan_cache(&self) {}
}

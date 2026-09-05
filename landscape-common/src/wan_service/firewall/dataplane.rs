//! Firewall dataplane: attach the TC/XDP firewall stage and keep the
//! blacklist LPM maps in sync with the resolved configuration.

use crate::ebpf::DataplaneGuard;
use crate::flow::ip_mark::IpConfig;

/// eBPF capability for the firewall service.
pub trait FirewallDataplane: Send + Sync {
    /// Attach the firewall stage (TC ingress/egress + XDP LAN/WAN) for
    /// `ifindex`.  Dropping the returned guard removes the stage from
    /// the chains.
    fn attach(&self, ifindex: u32, has_mac: bool) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Reconcile the blacklist maps from `old_ips` to `new_ips`.
    fn sync_blacklist(&self, new_ips: Vec<IpConfig>, old_ips: Vec<IpConfig>);
}

/// No-op implementation for tests.
pub struct NoopFirewallDataplane;

impl FirewallDataplane for NoopFirewallDataplane {
    fn attach(&self, _ifindex: u32, _has_mac: bool) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn sync_blacklist(&self, _new_ips: Vec<IpConfig>, _old_ips: Vec<IpConfig>) {}
}

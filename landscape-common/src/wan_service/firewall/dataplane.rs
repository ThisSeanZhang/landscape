//! Firewall dataplane: reconcile the blacklist LPM maps with the
//! resolved configuration.  The firewall *stage* attach itself is owned
//! by the wan link via [`crate::wan_service::wan_chain`].

use crate::flow::ip_mark::IpConfig;

/// eBPF capability for the firewall blacklist maps.
pub trait FirewallDataplane: Send + Sync {
    /// Reconcile the blacklist maps from `old_ips` to `new_ips`.
    fn sync_blacklist(&self, new_ips: Vec<IpConfig>, old_ips: Vec<IpConfig>);
}

/// No-op implementation for tests.
pub struct NoopFirewallDataplane;

impl FirewallDataplane for NoopFirewallDataplane {
    fn sync_blacklist(&self, _new_ips: Vec<IpConfig>, _old_ips: Vec<IpConfig>) {}
}

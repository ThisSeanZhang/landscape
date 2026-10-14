//! NAT dataplane: reconcile the static NAT mapping maps with the
//! resolved configuration.  The NAT *stage* attach itself is owned by
//! the wan link via [`crate::wan_service::wan_chain`].

use crate::config_service::static_nat::config4::RuntimeStaticNatMappingV4Config;
use crate::config_service::static_nat::config6::RuntimeStaticNatMappingV6Config;

/// eBPF capability for the static NAT mapping maps.
pub trait NatDataplane: Send + Sync {
    /// Reconcile the IPv4 static NAT map to `configs`.
    fn sync_static_nat4(&self, configs: &[RuntimeStaticNatMappingV4Config]);

    /// Reconcile the IPv6 static NAT map to `configs`.
    fn sync_static_nat6(&self, configs: &[RuntimeStaticNatMappingV6Config]);
}

/// No-op implementation for tests.
pub struct NoopNatDataplane;

impl NatDataplane for NoopNatDataplane {
    fn sync_static_nat4(&self, _configs: &[RuntimeStaticNatMappingV4Config]) {}

    fn sync_static_nat6(&self, _configs: &[RuntimeStaticNatMappingV6Config]) {}
}

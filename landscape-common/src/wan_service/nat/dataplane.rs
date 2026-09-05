//! NAT dataplane: attach the unified TC+XDP NAT stage and keep the
//! static NAT mapping maps in sync with the resolved configuration.

use crate::config_service::static_nat::config4::RuntimeStaticNatMappingV4Config;
use crate::config_service::static_nat::config6::RuntimeStaticNatMappingV6Config;
use crate::ebpf::DataplaneGuard;

use super::config::NatConfig;

/// eBPF capability for the NAT service.
pub trait NatDataplane: Send + Sync {
    /// Attach the NAT stage (TC ingress/egress + XDP with shared
    /// runtime maps) for `ifindex`.  Dropping the returned guard
    /// removes the stage from the chains.
    fn attach(
        &self,
        ifindex: u32,
        has_mac: bool,
        config: &NatConfig,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Reconcile the IPv4 static NAT map to `configs`.
    fn sync_static_nat4(&self, configs: &[RuntimeStaticNatMappingV4Config]);

    /// Reconcile the IPv6 static NAT map to `configs`.
    fn sync_static_nat6(&self, configs: &[RuntimeStaticNatMappingV6Config]);
}

/// No-op implementation for tests.
pub struct NoopNatDataplane;

impl NatDataplane for NoopNatDataplane {
    fn attach(
        &self,
        _ifindex: u32,
        _has_mac: bool,
        _config: &NatConfig,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn sync_static_nat4(&self, _configs: &[RuntimeStaticNatMappingV4Config]) {}

    fn sync_static_nat6(&self, _configs: &[RuntimeStaticNatMappingV6Config]) {}
}

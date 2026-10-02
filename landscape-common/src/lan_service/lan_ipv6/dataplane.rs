//! Standalone DAD-NS observer filter for the LAN IPv6 service.

use crate::ebpf::DataplaneGuard;

/// Attaches the standalone DAD-NS observer (`tc_lan_dao`) as an ingress TC
/// filter on a LAN interface. The LAN IPv6 service installs it before its
/// first Router Advertisement so early DAD NS from clients are observed.
pub trait Ip6DaoFilterDataplane: Send + Sync {
    fn install_tc_dao(&self, ifindex: u32) -> Result<Box<dyn DataplaneGuard>, String>;
}

/// No-op implementation for tests.
pub struct NoopIp6DaoFilterDataplane;

impl Ip6DaoFilterDataplane for NoopIp6DaoFilterDataplane {
    fn install_tc_dao(&self, _ifindex: u32) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }
}

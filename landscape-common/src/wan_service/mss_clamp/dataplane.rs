//! MSS clamp dataplane: attach the TC/XDP MSS-clamp stage.

use crate::ebpf::DataplaneGuard;

/// eBPF capability for the MSS clamp service.
pub trait MssClampDataplane: Send + Sync {
    /// Attach the MSS-clamp stage (TC ingress/egress + XDP LAN/WAN) for
    /// `ifindex`, advertising `mtu` sized segments.  Dropping the
    /// returned guard removes the stage from the chains.
    fn attach(
        &self,
        ifindex: u32,
        mtu: u16,
        has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;
}

/// No-op implementation for tests.
pub struct NoopMssClampDataplane;

impl MssClampDataplane for NoopMssClampDataplane {
    fn attach(
        &self,
        _ifindex: u32,
        _mtu: u16,
        _has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }
}

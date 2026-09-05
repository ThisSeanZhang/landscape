//! WAN-side route chains: install the per-interface XDP/TC datapath
//! and manage the XDP redirect-able flag.

use crate::ebpf::DataplaneGuard;

/// eBPF capability for the WAN route service.
pub trait WanRouteDataplane: Send + Sync {
    /// Attach the XDP WAN-route program (native with SKB fallback).
    /// Dropping the returned guard detaches it.
    fn install_xdp_route(
        &self,
        ifindex: u32,
        has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Attach the TC ingress/egress WAN-route intro programs.  Dropping
    /// the returned guard detaches them.
    fn install_tc_route(
        &self,
        ifindex: u32,
        has_mac: bool,
        xdp_handoff_enabled: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Remove this interface's entries from the XDP root prog-arrays
    /// (used when switching away from XDP mode).
    fn remove_xdp_roots(&self, ifindex: u32);

    /// Mark `ifindex` as XDP-redirect-able (or not).
    fn set_redirect_able(&self, ifindex: u32, able: bool);

    /// Forget the XDP redirect-able state of `ifindex`.
    fn del_redirect_able(&self, ifindex: u32);
}

/// No-op implementation for tests.
pub struct NoopWanRouteDataplane;

impl WanRouteDataplane for NoopWanRouteDataplane {
    fn install_xdp_route(
        &self,
        _ifindex: u32,
        _has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn install_tc_route(
        &self,
        _ifindex: u32,
        _has_mac: bool,
        _xdp_handoff_enabled: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn remove_xdp_roots(&self, _ifindex: u32) {}

    fn set_redirect_able(&self, _ifindex: u32, _able: bool) {}

    fn del_redirect_able(&self, _ifindex: u32) {}
}

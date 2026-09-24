//! WAN link stage-chain root capability.
//!
//! The `xdp_wan_chain_root` / `xdp_lan_chain_root` are the entry of a WAN
//! link's stage chain (mss -> firewall -> nat -> route exit), so their
//! creation and registration belong to the link, not to the WAN route service.

use crate::ebpf::DataplaneGuard;

/// eBPF capability owning a WAN link's stage-chain entry.
pub trait WanLinkChainDataplane: Send + Sync {
    /// Create/register the link's stage-chain root on `ifindex`, tagged with
    /// the link's stable `link_chain_id`. The returned guard removes the root
    /// registration when dropped.
    fn open(
        &self,
        ifindex: u32,
        has_mac: bool,
        link_chain_id: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String>;
}

/// No-op implementation for tests.
pub struct NoopWanLinkChainDataplane;

impl WanLinkChainDataplane for NoopWanLinkChainDataplane {
    fn open(
        &self,
        _ifindex: u32,
        _has_mac: bool,
        _link_chain_id: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }
}

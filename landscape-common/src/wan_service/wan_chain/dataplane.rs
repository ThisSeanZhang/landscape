//! WAN chain dataplane: the single eBPF control surface for wan-link
//! owned dataplane state, keyed by the link's immutable `link_chain_id`.
//!
//! The chain managers below this trait stay keyed by ifindex (they are
//! shared with the independent per-iface route services); this trait adds
//! the chain-level registry on top: stage attaches and WAN address
//! bindings are recorded per chain, so later phases (NAT rodata,
//! chain-keyed dispatch) have a stable per-link identity to build on.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ebpf::DataplaneGuard;
use crate::net::MacAddr;
use crate::wan_service::nat::config::NatConfig;

/// PPPoE egress header template handed to the dataplane for the
/// TC-encap program.  Wire layout mirrors `struct pppoe_egress_tmpl` in
/// the eBPF skeleton (all multi-byte fields in network byte order).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PppoeEgressTmpl {
    pub dmac: [u8; 6],
    pub smac: [u8; 6],
    pub eth_proto: u16,
    pub ver_type: u8,
    pub code: u8,
    pub session_id: u16,
    pub length: u16,
    pub protocol: u16,
}

/// eBPF capability for everything a wan link controls on the dataplane:
/// stage lifecycle (MSS / NAT / firewall / PPPoE encap) and WAN address
/// bindings, all identified by the link's `link_chain_id`.
///
/// `ifindex` stays a parameter (hook attachment and the `wan_ip_binding`
/// map are still ifindex-scoped), but the chain registry records the
/// chain ↔ ifindex pairing, and unbinds address a chain by its recorded
/// binding — surviving ifindex churn such as a PPP re-dial.
pub trait WanChainDataplane: Send + Sync {
    /// Attach the MSS-clamp stage (TC ingress/egress + XDP LAN/WAN) for
    /// `chain` on `ifindex`, advertising `mtu` sized segments.  Dropping
    /// the returned guard removes the stage from the chains.
    fn attach_mss(
        &self,
        chain: u16,
        ifindex: u32,
        mtu: u16,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Attach the v4 NAT stage (TC ingress/egress + XDP with shared
    /// runtime maps) for `chain` on `ifindex`.  Dropping the returned
    /// guard removes the stage from the chains.
    fn attach_nat4(
        &self,
        chain: u16,
        ifindex: u32,
        has_eth_header: bool,
        config: &NatConfig,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Attach the v6 NAT stage (TC ingress/egress + XDP with a shared
    /// conntrack timer map) for `chain` on `ifindex`.  Dropping the
    /// returned guard removes the stage from the chains.
    fn attach_nat6(
        &self,
        chain: u16,
        ifindex: u32,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Attach the firewall stage (TC ingress/egress + XDP LAN/WAN) for
    /// `chain` on `ifindex`.  Dropping the returned guard removes the
    /// stage from the chains.
    fn attach_firewall(
        &self,
        chain: u16,
        ifindex: u32,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Attach the PPPoE session dataplane (TC egress encap + XDP decap)
    /// for `chain` on `ifindex`.  Dropping the returned guard detaches
    /// it and recycles the SKB fallback state.
    fn attach_pppoe_session(
        &self,
        chain: u16,
        ifindex: u32,
        tmpl: PppoeEgressTmpl,
        mtu: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Bind `addr` as the WAN IPv4 address of the chain (peer/gateway,
    /// prefix length and device MAC included).
    fn bind_wan_ipv4(
        &self,
        chain: u16,
        ifindex: u32,
        addr: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    );

    /// Remove the chain's recorded WAN IPv4 binding (deleting the map
    /// entry at the ifindex it was bound to, even after a re-dial).
    fn unbind_wan_ipv4(&self, chain: u16);

    /// Bind `addr` as the WAN IPv6 prefix of the chain.
    fn bind_wan_ipv6(
        &self,
        chain: u16,
        ifindex: u32,
        addr: Ipv6Addr,
        gateway: Option<Ipv6Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    );

    /// Remove the chain's recorded WAN IPv6 binding.
    fn unbind_wan_ipv6(&self, chain: u16);
}

/// No-op implementation for tests.
pub struct NoopWanChainDataplane;

impl WanChainDataplane for NoopWanChainDataplane {
    fn attach_mss(
        &self,
        _chain: u16,
        _ifindex: u32,
        _mtu: u16,
        _has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn attach_nat4(
        &self,
        _chain: u16,
        _ifindex: u32,
        _has_eth_header: bool,
        _config: &NatConfig,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn attach_nat6(
        &self,
        _chain: u16,
        _ifindex: u32,
        _has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn attach_firewall(
        &self,
        _chain: u16,
        _ifindex: u32,
        _has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn attach_pppoe_session(
        &self,
        _chain: u16,
        _ifindex: u32,
        _tmpl: PppoeEgressTmpl,
        _mtu: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn bind_wan_ipv4(
        &self,
        _chain: u16,
        _ifindex: u32,
        _addr: Ipv4Addr,
        _gateway: Option<Ipv4Addr>,
        _mask: u8,
        _mac: Option<MacAddr>,
    ) {
    }

    fn unbind_wan_ipv4(&self, _chain: u16) {}

    fn bind_wan_ipv6(
        &self,
        _chain: u16,
        _ifindex: u32,
        _addr: Ipv6Addr,
        _gateway: Option<Ipv6Addr>,
        _mask: u8,
        _mac: Option<MacAddr>,
    ) {
    }

    fn unbind_wan_ipv6(&self, _chain: u16) {}
}

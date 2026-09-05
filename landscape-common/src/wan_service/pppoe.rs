//! PPPoE session dataplane: the eBPF capability consumed by the
//! PPPoE client service.

use std::net::Ipv4Addr;

use crate::ebpf::DataplaneGuard;
use crate::net::MacAddr;

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

/// eBPF capability for one PPPoE session: attach the encap/decap
/// dataplane and keep the session's WAN IP binding in sync.
pub trait PppoeDataplane: Send + Sync {
    /// Attach the PPPoE TC/XDP dataplane for `ifindex`.  Dropping the
    /// returned guard detaches it and recycles the SKB fallback state.
    fn attach_session(
        &self,
        ifindex: u32,
        tmpl: PppoeEgressTmpl,
        mtu: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String>;

    /// Bind `addr` as the WAN IPv4 address of `ifindex` (peer/gateway,
    /// prefix length and device MAC included).
    fn bind_wan_ipv4(
        &self,
        ifindex: u32,
        addr: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    );

    /// Remove the WAN IPv4 binding of `ifindex`.
    fn unbind_wan_ipv4(&self, ifindex: u32);
}

/// No-op implementation for tests.
pub struct NoopPppoeDataplane;

impl PppoeDataplane for NoopPppoeDataplane {
    fn attach_session(
        &self,
        _ifindex: u32,
        _tmpl: PppoeEgressTmpl,
        _mtu: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn bind_wan_ipv4(
        &self,
        _ifindex: u32,
        _addr: Ipv4Addr,
        _gateway: Option<Ipv4Addr>,
        _mask: u8,
        _mac: Option<MacAddr>,
    ) {
    }

    fn unbind_wan_ipv4(&self, _ifindex: u32) {}
}

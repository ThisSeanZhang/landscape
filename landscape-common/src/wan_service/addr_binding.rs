//! WAN address binding: write the WAN interface address/gateway/MAC
//! into the eBPF `wan_ip_binding` map so the datapath picks the right
//! egress interface.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::net::MacAddr;

/// eBPF capability for managing WAN IP bindings.
pub trait WanAddrBinding: Send + Sync {
    fn bind_ipv4(
        &self,
        ifindex: u32,
        addr: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    );

    fn unbind_ipv4(&self, ifindex: u32);

    fn bind_ipv6(
        &self,
        ifindex: u32,
        addr: Ipv6Addr,
        gateway: Option<Ipv6Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    );

    fn unbind_ipv6(&self, ifindex: u32);
}

/// No-op implementation for tests.
pub struct NoopWanAddrBinding;

impl WanAddrBinding for NoopWanAddrBinding {
    fn bind_ipv4(
        &self,
        _ifindex: u32,
        _addr: Ipv4Addr,
        _gateway: Option<Ipv4Addr>,
        _mask: u8,
        _mac: Option<MacAddr>,
    ) {
    }

    fn unbind_ipv4(&self, _ifindex: u32) {}

    fn bind_ipv6(
        &self,
        _ifindex: u32,
        _addr: Ipv6Addr,
        _gateway: Option<Ipv6Addr>,
        _mask: u8,
        _mac: Option<MacAddr>,
    ) {
    }

    fn unbind_ipv6(&self, _ifindex: u32) {}
}

//! Neighbor MAC learning: record IP→MAC bindings learned from DHCP
//! and IPv6 ND/DHCP traffic so the datapath can fill in L2 headers.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::net::MacAddr;

/// eBPF capability for learning neighbor MAC bindings.
pub trait MacBindingDataplane: Send + Sync {
    /// Upsert the IPv4 `ip` → `mac` binding for `ifindex` (`dev_mac` is
    /// the interface's own MAC used for egress rewriting).
    fn learn_ipv4(&self, ifindex: u32, ip: Ipv4Addr, mac: MacAddr, dev_mac: MacAddr);

    /// Upsert the IPv6 `ip` → `mac` binding for `ifindex`.
    fn learn_ipv6(&self, ifindex: u32, ip: Ipv6Addr, mac: MacAddr, dev_mac: MacAddr);
}

/// No-op implementation for tests.
pub struct NoopMacBindingDataplane;

impl MacBindingDataplane for NoopMacBindingDataplane {
    fn learn_ipv4(&self, _ifindex: u32, _ip: Ipv4Addr, _mac: MacAddr, _dev_mac: MacAddr) {}

    fn learn_ipv6(&self, _ifindex: u32, _ip: Ipv6Addr, _mac: MacAddr, _dev_mac: MacAddr) {}
}

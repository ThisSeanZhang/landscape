use std::net::Ipv6Addr;

use landscape_common::net::MacAddr;

#[derive(Debug)]
pub struct DHCPv6NACache {
    pub suffix: u64,
    pub hostname: Option<String>,
    pub mac: Option<MacAddr>,
    pub duid_hex: String,
    pub relative_offer_time: u64,
    pub valid_time: u32,
    pub preferred_time: u32,
    pub is_static: bool,
}

#[derive(Debug)]
pub struct DHCPv6PDCache {
    /// Index into `PdDelegationParent` pool (`get_qualifying_pd_prefixes` result).
    /// Identifies which pre-computed delegation block this client received.
    pub sub_index: u32,
    pub duid_hex: String,
    pub relative_offer_time: u64,
    pub valid_time: u32,
    pub preferred_time: u32,
    /// Client's link-local address (from DHCPv6 message source), used as route gateway
    pub client_addr: Ipv6Addr,
    /// Routes currently installed for this delegation: (prefix, prefix_len)
    pub active_routes: Vec<(Ipv6Addr, u8)>,
}

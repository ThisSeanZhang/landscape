use std::{collections::HashMap, net::Ipv6Addr};

pub mod connection;
pub mod dhcpv6;
pub mod icmpv6;
pub mod server;

pub struct Ip6AssignInfo {}

pub enum AssignId {
    Duid,
    Mac,
}

pub struct Ipv6ServerStatus {
    assign_ip_map: HashMap<Ipv6Addr, Ip6AssignInfo>,
    assign_suffix_duid_map: HashMap<AssignId, Ipv6Addr>,
    // pd info
}
impl Ipv6ServerStatus {
    pub fn new() -> Self {
        Ipv6ServerStatus {
            assign_ip_map: todo!(),
            assign_suffix_duid_map: todo!(),
        }
    }
    pub fn assign_ipv6() {}
    pub fn assign_ipv6_pd() {}
    pub fn get_ra_prefixs() {}
    pub fn get_ra_onlink_prefixs() {}
    pub fn upate_prefix(//prefix info,
        // sender
    ) {
    }

    pub fn upate_device(// ...
    ) {
    }
}

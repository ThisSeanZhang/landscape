use landscape_common::lan_service::lan_ipv6::mark_wan_iid;

/// Stable WAN interface identifier shared by the IPv6 PD client instances.
pub fn generate_wan_iid() -> u64 {
    mark_wan_iid(rand::random::<u64>())
}

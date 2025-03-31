use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::{
    net::MacAddr, LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START, LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP,
    LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK, LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME,
};

/// 持有的数据
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DHCPv4OfferInfo {
    pub relative_boot_time: u64,
    pub offered_ips: Vec<DHCPv4OfferInfoItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DHCPv4OfferInfoItem {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub relative_active_time: u64,
    pub expire_time: u32,
}

/// DHCP Server IPv4 Config
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DHCPv4ServerConfig {
    /// dhcp options
    // #[serde(default)]
    // options: Vec<DhcpOptions>,
    /// range start
    pub ip_range_start: Ipv4Addr,
    /// range end [not include]
    #[serde(default)]
    pub ip_range_end: Option<Ipv4Addr>,

    /// DHCP Server Addr e.g. 192.168.1.1
    pub server_ip_addr: Ipv4Addr,
    /// network mask e.g. 255.255.255.0 = 24
    pub network_mask: u8,

    #[serde(default)]
    pub address_lease_time: Option<u32>,

    #[serde(default)]
    /// Static MAC --> IP address binding
    pub mac_binding_records: Vec<MacBindingRecord>,
}

impl Default for DHCPv4ServerConfig {
    fn default() -> Self {
        Self {
            ip_range_start: LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START,
            ip_range_end: None,
            server_ip_addr: LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP,
            network_mask: LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK,
            address_lease_time: Some(LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME),
            mac_binding_records: vec![],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MacBindingRecord {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub expire_time: u32,
}

use cidr::Ipv4Inet;
use landscape_common::{
    LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START, LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP,
    LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK, LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::dump::udp_packet::dhcp::options::DhcpOptions;

pub mod dhcp_server;

/// DHCP Server IPv4 Config
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpServerIpv4Config {
    /// dhcp options
    #[serde(default)]
    options: Vec<DhcpOptions>,
    /// range start
    pub ip_range_start: Ipv4Addr,
    /// range end
    #[serde(default)]
    pub ip_range_end: Option<Ipv4Addr>,

    /// DHCP Server Addr e.g. 192.168.1.1
    pub server_ip_addr: Ipv4Addr,
    /// network mask e.g. 255.255.255.0 = 24
    pub network_mask: u8,
}

impl DhcpServerIpv4Config {
    // pub fn new(
    //     server_ip_addr: Ipv4Addr,
    //     network_mask: u8,
    //     ip_range_start: Ipv4Addr,
    //     ip_range_end: Option<Ipv4Addr>,
    //     mut options: Vec<DhcpOptions>,
    // ) -> Self {
    //     // 如果 ip_range_end 为 None，则使用默认值

    //     DhcpServerIpv4Config {
    //         options,
    //         ip_range_start,
    //         ip_range_end,
    //         server_ip_addr,
    //         network_mask,
    //     }
    // }

    pub fn get_range_capacity(&self) -> u32 {
        let ip_range_end = self.ip_range_end.unwrap_or_else(|| {
            // 假设默认的结束地址是网络地址加上 2^（32 - network_mask） - 1
            let network_size = 2u32.pow(32 - self.network_mask as u32) - 1;
            let start_u32 = u32::from(self.ip_range_start);
            Ipv4Addr::from(start_u32 + network_size)
        });

        let range_capacity = u32::from(ip_range_end) - u32::from(self.ip_range_start) + 1;
        range_capacity
    }

    pub fn get_ipv4_inet_start(&self) -> Option<Ipv4Inet> {
        Some(Ipv4Inet::new(self.ip_range_start, self.network_mask).unwrap())
    }

    pub fn get_server_options(&self) -> Vec<DhcpOptions> {
        let mut options = self.options.clone();
        let server_ip_addr = self.server_ip_addr;
        let network_mask = self.network_mask;

        let ipv4 = Ipv4Inet::new(server_ip_addr, network_mask).unwrap();

        let cidr = ipv4.network();
        // println!("{:?}", ipv4.network());
        // println!("{:?}", ipv4.first());
        // println!("{:?}", ipv4.last());
        // println!("{:?}", ipv4.is_host_address());
        // println!("first: {:?}", ipv4.first().overflowing_add_u32(3).0.address());
        // println!("size: {:?}", 1 << (32 - ipv4.network_length()));
        // println!("mask: {:?}", ipv4.mask());
        // println!("{:?}", cidr.network_length());
        // println!("{:?}", cidr.first_address());
        // println!("{:?}", cidr.is_host_address());
        // println!("{:?}", cidr.last_address());

        options.push(DhcpOptions::SubnetMask(cidr.mask()));
        options.push(DhcpOptions::Router(server_ip_addr));
        options.push(DhcpOptions::ServerIdentifier(server_ip_addr));
        options.push(DhcpOptions::DomainNameServer(vec![server_ip_addr]));

        // options.push(DhcpOptions::AddressLeaseTime(LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME));
        options
    }
}

impl Default for DhcpServerIpv4Config {
    fn default() -> Self {
        DhcpServerIpv4Config {
            options: vec![],
            ip_range_start: LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START,
            ip_range_end: None,
            server_ip_addr: LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP,
            network_mask: LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DhcpServerIpv4Config;

    #[test]
    pub fn test_addr() {
        let data = DhcpServerIpv4Config::default();
        print!("{:?}", data);
    }
}

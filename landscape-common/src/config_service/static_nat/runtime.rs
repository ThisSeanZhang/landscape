use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use super::config::StaticMapPair;
use super::config6::StaticNatV6PortConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingConfig {
    pub mapping_pair_ports: Vec<StaticMapPair>,
    pub lan_ipv4: Option<Ipv4Addr>,
    pub lan_ipv6: Option<Ipv6Addr>,
    pub ipv4_l4_protocol: Vec<u8>,
    pub ipv6_l4_protocol: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct StaticNatMappingItem {
    pub wan_port: u16,
    pub lan_port: u16,
    pub lan_ip: IpAddr,
    pub l4_protocol: u8,
}

impl RuntimeStaticNatMappingConfig {
    pub fn convert_to_item(&self) -> Vec<StaticNatMappingItem> {
        let mut result = Vec::with_capacity(4);
        for l4_protocol in &self.ipv4_l4_protocol {
            if let Some(ipv4) = self.lan_ipv4 {
                let items = self.mapping_pair_ports.iter().map(|pair_port| StaticNatMappingItem {
                    wan_port: pair_port.wan_port,
                    lan_port: pair_port.lan_port,
                    lan_ip: IpAddr::V4(ipv4),
                    l4_protocol: *l4_protocol,
                });
                result.extend(items);
            }
        }

        for l4_protocol in &self.ipv6_l4_protocol {
            if let Some(ipv6) = self.lan_ipv6 {
                let items = self.mapping_pair_ports.iter().map(|pair_port| StaticNatMappingItem {
                    wan_port: pair_port.wan_port,
                    lan_port: pair_port.lan_port,
                    lan_ip: IpAddr::V6(ipv6),
                    l4_protocol: *l4_protocol,
                });

                result.extend(items);
            }
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingV4Config {
    pub mapping_pair_ports: Vec<StaticMapPair>,
    pub lan_ipv4: Ipv4Addr,
    pub l4_protocols: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingV6Config {
    pub port_config: StaticNatV6PortConfig,
    pub lan_ipv6: Ipv6Addr,
    pub l4_protocols: Vec<u8>,
}

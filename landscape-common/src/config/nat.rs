use core::ops::Range;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ts_rs::TS;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::store::storev2::LandscapeStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "common/nat.d.ts")]
pub struct NatServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default)]
    pub nat_config: NatConfig,
    #[serde(default = "get_f64_timestamp")]
    pub update_at: f64,
}

impl LandscapeStore for NatServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for NatServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "common/nat.d.ts")]
pub struct NatConfig {
    pub tcp_range: Range<u16>,
    pub udp_range: Range<u16>,
    pub icmp_in_range: Range<u16>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            tcp_range: 32768..65535,
            udp_range: 32768..65535,
            icmp_in_range: 32768..65535,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "common/nat.d.ts")]
pub struct StaticNatMappingConfig {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    pub id: Uuid,
    pub enable: bool,
    pub remark: String,
    pub wan_port: u16,
    pub wan_iface_name: Option<String>,
    pub lan_port: u16,
    /// If set to `UNSPECIFIED` (e.g., 0.0.0.0 or ::), the mapping targets
    /// the router's own address instead of an internal host.
    pub lan_ipv4: Option<Ipv4Addr>,
    pub lan_ipv6: Option<Ipv6Addr>,
    /// TCP / UDP
    pub ipv4_l4_protocol: Vec<u8>,
    pub ipv6_l4_protocol: Vec<u8>,
    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    pub update_at: f64,
}

impl StaticNatMappingConfig {
    pub fn convert_to_item(&self) -> Vec<StaticNatMappingItem> {
        let mut result = Vec::with_capacity(4);
        for l4_protocol in self.ipv4_l4_protocol.iter() {
            if let Some(ipv4) = self.lan_ipv4 {
                result.push(StaticNatMappingItem {
                    wan_port: self.wan_port,
                    wan_iface_name: self.wan_iface_name.clone(),
                    lan_port: self.lan_port,
                    lan_ip: IpAddr::V4(ipv4),
                    l4_protocol: *l4_protocol,
                });
            }
        }

        for l4_protocol in self.ipv6_l4_protocol.iter() {
            if let Some(ipv6) = self.lan_ipv6 {
                result.push(StaticNatMappingItem {
                    wan_port: self.wan_port,
                    wan_iface_name: self.wan_iface_name.clone(),
                    lan_port: self.lan_port,
                    lan_ip: IpAddr::V6(ipv6),
                    l4_protocol: *l4_protocol,
                });
            }
        }
        result
    }
}

impl LandscapeDBStore<Uuid> for StaticNatMappingConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct StaticNatMappingItem {
    pub wan_port: u16,
    pub wan_iface_name: Option<String>,
    pub lan_port: u16,
    pub lan_ip: IpAddr,
    pub l4_protocol: u8,
}

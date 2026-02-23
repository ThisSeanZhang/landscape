use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::database::repository::LandscapeDBStore;
use crate::net::MacAddr;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;
use crate::LANDSCAPE_DEFAULT_LAN_NAME;

use crate::{
    LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START, LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP,
    LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK, LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME,
};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/dhcp_v4_server.d.ts")]
pub struct DHCPv4ServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub config: DHCPv4ServerConfig,
    /// 最近一次编译时间
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

impl Default for DHCPv4ServiceConfig {
    fn default() -> Self {
        Self {
            iface_name: LANDSCAPE_DEFAULT_LAN_NAME.into(),
            enable: true,
            config: DHCPv4ServerConfig::default(),
            update_at: get_f64_timestamp(),
        }
    }
}

impl LandscapeStore for DHCPv4ServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for DHCPv4ServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}

/// DHCP Server IPv4 Config
#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/dhcp_v4_server.d.ts")]
pub struct DHCPv4ServerConfig {
    /// dhcp options
    // #[serde(default)]
    // options: Vec<DhcpOptions>,
    /// range start
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip_range_start: Ipv4Addr,
    /// range end [not include]
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true, value_type = Option<String>))]
    pub ip_range_end: Option<Ipv4Addr>,

    /// DHCP Server Addr e.g. 192.168.1.1
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub server_ip_addr: Ipv4Addr,
    /// network mask e.g. 255.255.255.0 = 24
    pub network_mask: u8,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub address_lease_time: Option<u32>,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    /// Static MAC --> IP address binding
    pub mac_binding_records: Vec<MacBindingRecord>,
}

impl DHCPv4ServerConfig {
    /// 获取IP范围的起始和结束地址
    pub fn get_ip_range(&self) -> (Ipv4Addr, Ipv4Addr) {
        let start = self.ip_range_start;
        let end = self.ip_range_end.unwrap_or_else(|| {
            // 如果没有指定结束地址，根据网络掩码计算
            let network = u32::from(start) & (0xFFFFFFFFu32 << (32 - self.network_mask));
            let broadcast = network | (0xFFFFFFFFu32 >> self.network_mask);
            Ipv4Addr::from(broadcast - 1) // 广播地址前一个
        });
        (start, end)
    }

    /// 检查两个IP范围是否有重叠
    pub fn has_ip_range_overlap(&self, other: &DHCPv4ServerConfig) -> bool {
        let (start1, end1) = self.get_ip_range();
        let (start2, end2) = other.get_ip_range();

        let start1_u32 = u32::from(start1);
        let end1_u32 = u32::from(end1);
        let start2_u32 = u32::from(start2);
        let end2_u32 = u32::from(end2);

        // 检查是否有重叠：A的开始 <= B的结束 && B的开始 <= A的结束
        start1_u32 <= end2_u32 && start2_u32 <= end1_u32
    }
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

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/dhcp_v4_server.d.ts")]
pub struct MacBindingRecord {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub mac: MacAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: Ipv4Addr,
    #[serde(default = "default_binding_record")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub expire_time: u32,
}

const fn default_binding_record() -> u32 {
    // 24 小时
    86400
}

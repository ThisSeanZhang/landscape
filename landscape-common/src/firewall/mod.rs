pub mod blacklist;

use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ts_rs::TS;
use uuid::Uuid;

use crate::config::ConfigId;
use crate::flow::mark::FlowMark;
use crate::{
    network::LandscapeIpProtocolCode, store::storev2::LandscapeStore,
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum FirewallRuleError {
    #[error("Firewall rule '{0}' not found")]
    #[api_error(id = "firewall_rule.not_found", status = 404)]
    NotFound(ConfigId),
}

use crate::database::repository::LandscapeDBStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/firewall.d.ts")]
pub struct FirewallRuleConfig {
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub id: Option<Uuid>,
    // 优先级
    pub index: u32,
    pub enable: bool,

    pub remark: String,
    pub items: Vec<FirewallRuleConfigItem>,
    /// 流量标记
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mark: FlowMark,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

impl LandscapeStore for FirewallRuleConfig {
    fn get_store_key(&self) -> String {
        self.index.to_string()
    }
}

impl LandscapeDBStore<Uuid> for FirewallRuleConfig {
    fn get_id(&self) -> Uuid {
        self.id.unwrap_or(Uuid::new_v4())
    }
}

/// 配置的小项
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/firewall.d.ts")]
pub struct FirewallRuleConfigItem {
    // IP 承载的协议
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub ip_protocol: Option<LandscapeIpProtocolCode>,
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub local_port: Option<String>,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: IpAddr,
    pub ip_prefixlen: u8,
}

/// 存入 bpf map 中的遍历项
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirewallRuleItem {
    pub ip_protocol: Option<LandscapeIpProtocolCode>,
    pub local_port: Option<u16>,
    pub address: IpAddr,
    pub ip_prefixlen: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LandscapeIpType {
    Ipv4 = 0,
    Ipv6 = 1,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirewallRuleMark {
    pub item: FirewallRuleItem,
    pub mark: FlowMark,
}

pub fn insert_default_firewall_rule() -> Option<FirewallRuleConfig> {
    let mut items = vec![];
    #[cfg(debug_assertions)]
    {
        items.push(FirewallRuleConfigItem {
            ip_protocol: Some(LandscapeIpProtocolCode::TCP),
            local_port: Some("22".to_string()),
            address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ip_prefixlen: 0,
        });
        items.push(FirewallRuleConfigItem {
            ip_protocol: Some(LandscapeIpProtocolCode::TCP),
            local_port: Some("22".to_string()),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_prefixlen: 0,
        });

        items.push(FirewallRuleConfigItem {
            ip_protocol: Some(LandscapeIpProtocolCode::TCP),
            local_port: Some("5173".to_string()),
            address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ip_prefixlen: 0,
        });
        items.push(FirewallRuleConfigItem {
            ip_protocol: Some(LandscapeIpProtocolCode::TCP),
            local_port: Some("5173".to_string()),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_prefixlen: 0,
        });

        items.push(FirewallRuleConfigItem {
            ip_protocol: Some(LandscapeIpProtocolCode::TCP),
            local_port: Some("5800".to_string()),
            address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ip_prefixlen: 0,
        });
        items.push(FirewallRuleConfigItem {
            ip_protocol: Some(LandscapeIpProtocolCode::TCP),
            local_port: Some("5800".to_string()),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_prefixlen: 0,
        });
    }
    #[cfg(not(debug_assertions))]
    {}

    // DHCPv4 Client
    items.push(FirewallRuleConfigItem {
        ip_protocol: Some(LandscapeIpProtocolCode::UDP),
        local_port: Some("68".to_string()),
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ip_prefixlen: 0,
    });

    // DHCPv6 PD Client
    items.push(FirewallRuleConfigItem {
        ip_protocol: Some(LandscapeIpProtocolCode::UDP),
        local_port: Some(format!("{}", LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT)),
        address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ip_prefixlen: 0,
    });

    // TODO:
    // if LAND_ARGS.export_manager {
    //     items.push(FirewallRuleConfigItem {
    //         ip_protocol: Some(LandscapeIpProtocolCode::TCP),
    //         local_port: Some(format!("{}", LAND_ARGS.port)),
    //         address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    //         ip_prefixlen: 0,
    //     });
    //     items.push(FirewallRuleConfigItem {
    //         ip_protocol: Some(LandscapeIpProtocolCode::TCP),
    //         local_port: Some(format!("{}", LAND_ARGS.port)),
    //         address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    //         ip_prefixlen: 0,
    //     });
    // }

    if items.is_empty() {
        None
    } else {
        Some(FirewallRuleConfig {
            id: None,
            index: 1,
            enable: true,
            remark: "Landscape Router Default Firewall Rule".to_string(),
            items,
            mark: FlowMark::default(),
            update_at: get_f64_timestamp(),
        })
    }
}

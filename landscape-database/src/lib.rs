use sea_orm::prelude::Uuid;

pub mod dhcp_v4_server;
pub mod dhcp_v6_client;
pub mod error;
pub mod firewall;
pub mod flow_wan;
pub mod iface;
pub mod iface_ip;
pub mod mss_clamp;
pub mod pppd;
pub mod provider;
pub mod ra;
pub mod wifi;

pub mod dst_ip_rule;
pub mod firewall_rule;
pub mod flow_rule;

pub mod geo_ip;
pub mod geo_site;

pub mod route_lan;
pub mod route_wan;

pub mod nat;
pub mod static_nat_mapping;

pub mod dns_redirect;
pub mod dns_rule;

/// 定义 ID 类型
pub(crate) type DBId = Uuid;
/// 定义 JSON
pub(crate) type DBJson = serde_json::Value;
/// 定义通用时间戳存储, 用于乐观锁判断
pub(crate) type DBTimestamp = f64;

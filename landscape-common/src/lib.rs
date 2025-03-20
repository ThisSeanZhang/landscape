use std::net::Ipv4Addr;

pub mod args;
pub mod dns;
pub mod error;
pub mod firewall;
pub mod global_const;
pub mod info;
pub mod ip_mark;
pub mod mark;
pub mod observer;
pub mod service;
pub mod store;
pub mod sys_config;
pub mod util;
pub mod utils;

/// Config file
pub const LAND_CONFIG: &'static str = "landscape.toml";

/// Home Path
pub const LANDSCAPE_CONFIG_DIR_NAME: &'static str = ".landscape-router";
/// LOG Path
pub const LANDSCAPE_LOG_DIR_NAME: &'static str = "logs";
/// web resource
pub const LANDSCAPE_WEBROOT_DIR_NAME: &'static str = "static";
/// init file name
pub const INIT_FILE_NAME: &'static str = "landscape_init.toml";
/// init lock file name
pub const INIT_LOCK_FILE_NAME: &'static str = "landscape_init.lock";
/// sys token
pub const LANDSCAPE_SYS_TOKEN_FILE_ANME: &'static str = "landscape_api_token";

pub const GEO_SITE_FILE_NAME: &'static str = "geosite.dat";
pub const GEO_IP_FILE_NAME: &'static str = "geoip.dat";

/// Landscape default lan bridge name
pub const LANDSCAPE_DEFAULT_LAN_NAME: &'static str = "br_lan";

pub const LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 1);
pub const LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK: u8 = 24_u8;
pub const LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 100);

pub const LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT: u16 = 546;
pub const LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT: u16 = 547;

#[cfg(debug_assertions)]
pub const LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME: u32 = 40;

#[cfg(not(debug_assertions))]
pub const LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME: u32 = 60 * 60 * 12;

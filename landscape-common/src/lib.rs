use std::net::Ipv4Addr;

pub mod args;
pub mod dns;
pub mod error;
pub mod info;
pub mod ip_mark;
pub mod mark;
pub mod observer;
pub mod service;
pub mod store;
pub mod sys_config;
pub mod util;

/// Config file
pub const LAND_CONFIG: &'static str = "landscape.toml";

/// Home Path
pub const LANDSCAPE_CONFIG_DIR_NAME: &'static str = ".landscape-router";

pub const GEO_SITE_FILE_NAME: &'static str = "geosite.dat";
pub const GEO_IP_FILE_NAME: &'static str = "geoip.dat";

/// Landscape default lan bridge name
pub const LANDSCAPE_DEFAULT_LAN_NAME: &'static str = "br_lan";

pub const LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 1);
pub const LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK: u8 = 24_u8;
pub const LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 100);

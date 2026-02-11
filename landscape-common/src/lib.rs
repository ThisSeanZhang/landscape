use std::net::Ipv4Addr;

pub mod api_response;
pub mod args;
pub mod sys_config;

pub mod lan_services;

pub mod config;
pub mod database;
pub mod dev;
pub mod dhcp;
pub mod docker;
pub mod error;
pub mod event;
pub mod firewall;
pub mod flow;
pub mod global_const;
pub mod iface;
pub mod info;
pub mod ip_mark;
pub mod ipv6_pd;
pub mod metric;
pub mod net;
pub mod net_proto;
pub mod network;
pub mod observer;
pub mod route;
pub mod service;
pub mod store;
pub mod test;
pub mod utils;

pub mod auth;

pub mod pty;

pub mod dns;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Home Path
pub const LANDSCAPE_CONFIG_DIR_NAME: &str = ".landscape-router";

/// sys token
pub const LANDSCAPE_SYS_TOKEN_FILE_ANME: &str = "landscape_api_token";

/// Config file
pub const LAND_CONFIG: &str = "landscape.toml";
/// init lock file name
pub const INIT_LOCK_FILE_NAME: &str = "landscape_init.lock";
/// init file name
pub const INIT_FILE_NAME: &str = "landscape_init.toml";

pub const TLS_DEFAULT_CERT: &str = "cert.pem";
pub const TLS_DEFAULT_KEY: &str = "key.pem";

/// NAMESPACE SOCK
pub const NAMESPACE_REGISTER_SOCK_PATH: &str = "unix_link";
pub const NAMESPACE_REGISTER_SOCK_PATH_IN_DOCKER: &str = "ld_unix_link";
pub const NAMESPACE_REGISTER_SOCK: &str = "register.sock";

/// LOG Path
pub const LANDSCAPE_LOG_DIR_NAME: &str = "logs";
/// web resource
pub const LANDSCAPE_WEBROOT_DIR_NAME: &str = "static";
// --- Metric Settings ---
pub const LANDSCAPE_METRIC_DIR_NAME: &str = "metric";
pub const LANDSCAPE_METRIC_DB_VERSION: u32 = 3;

// Metric Retention Defaults
pub const DEFAULT_CONN_METRIC_RETENTION_MINS: u64 = 5;
pub const DEFAULT_CONN_METRIC_RETENTION_DAYS_1M: u64 = 1;
pub const DEFAULT_CONN_METRIC_RETENTION_DAYS_1H: u64 = 7;
pub const DEFAULT_CONN_METRIC_RETENTION_DAYS_1D: u64 = 30;
pub const DEFAULT_DNS_METRIC_RETENTION_DAYS: u64 = 7;

// Metric Performance & Storage Defaults
pub const DEFAULT_METRIC_BATCH_SIZE: usize = 5000;
pub const DEFAULT_METRIC_FLUSH_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_METRIC_MAX_MEMORY: usize = 256;
pub const DEFAULT_METRIC_MAX_THREADS: usize = 4;

// --- DNS Settings ---
pub const DEFAULT_DNS_CACHE_CAPACITY: u32 = 4096;
pub const DEFAULT_DNS_CACHE_TTL: u32 = 24 * 60 * 60;
pub const DEFAULT_DNS_NEGATIVE_CACHE_TTL: u32 = 120;

#[cfg(debug_assertions)]
pub const DEFAULT_METRIC_CLEANUP_INTERVAL_SECS: u64 = 60;
#[cfg(not(debug_assertions))]
pub const DEFAULT_METRIC_CLEANUP_INTERVAL_SECS: u64 = 300;

/// default sqlite path
pub const LANDSCAPE_DB_SQLITE_NAME: &str = "landscape_db.sqlite";
/// LOG Path
pub const LANDSCAPE_HOSTAPD_TMP_DIR: &str = "hostapd_tmp";
/// GEO_CACHE Path
pub const LANDSCAPE_GEO_CACHE_TMP_DIR: &str = "geo_tmp";

pub const GEO_SITE_FILE_NAME: &str = "geosite.dat";
pub const GEO_IP_FILE_NAME: &str = "geoip.dat";

/// Landscape default lan bridge name
pub const LANDSCAPE_DEFAULT_LAN_NAME: &str = "br_lan";

pub const LANDSCAPE_DEFAULE_LAN_DHCP_SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 1);
pub const LANDSCAPE_DEFAULT_LAN_DHCP_SERVER_NETMASK: u8 = 24_u8;
pub const LANDSCAPE_DEFAULE_LAN_DHCP_RANGE_START: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 100);

pub const LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT: u16 = 68;
pub const LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT: u16 = 67;

pub const LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT: u16 = 546;
pub const LANDSCAPE_DEFAULE_DHCP_V6_SERVER_PORT: u16 = 547;

#[cfg(debug_assertions)]
pub const LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME: u32 = 40;

#[cfg(not(debug_assertions))]
pub const LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME: u32 = 60 * 60 * 12;

pub const SYSCTL_IPV6_RA_ACCEPT_PATTERN: &str = "net.ipv6.conf.{}.accept_ra";
pub const SYSCTL_IPV4_RP_FILTER_PATTERN: &str = "net.ipv4.conf.{}.rp_filter";

// 1
pub const SYSCTL_IPV4_ARP_IGNORE_PATTERN: &str = "net.ipv4.conf.{}.arp_ignore";
// 2
pub const SYSCTL_IPV4_ARP_ANNOUNCE_PATTERN: &str = "net.ipv4.conf.{}.arp_announce";

pub const LAND_ARP_INFO_SIZE: usize = 24;

#[cfg(debug_assertions)]
pub const LAND_ARP_SCAN_INTERVAL: u64 = 1000 * 60 * 5;

#[cfg(not(debug_assertions))]
pub const LAND_ARP_SCAN_INTERVAL: u64 = 1000 * 60 * 60;

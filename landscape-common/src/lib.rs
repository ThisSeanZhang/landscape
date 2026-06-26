use std::net::Ipv4Addr;

use crate::config::MetricMode;
pub use landscape_macro::LdApiError;

pub mod api_response;
pub mod args;
pub mod sys_config;

pub mod lan_services;

pub mod concurrency;
pub mod config;
pub mod ddns;
pub mod dev;
pub mod dhcp;
pub mod docker;
pub mod error;
pub mod event;
pub mod firewall;
pub mod flow;
pub mod gateway;
pub mod geo;
pub mod global_const;
pub mod iface;
pub mod info;
pub mod ip_mark;
pub mod ipv6;
pub mod ipv6_pd;
pub mod metric;
pub mod network;
pub mod route;
pub mod service;

pub mod auth;
pub mod cert;
pub mod client;
pub mod dns;
pub mod enrolled_device;

pub mod database;
pub mod net_proto;
pub mod observer;
pub mod pty;
pub mod store;

pub mod net;
pub mod test;
pub mod utils;

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
pub const LANDSCAPE_METRIC_DB_VERSION: u32 = 14;

// Metric Retention Defaults
pub const DEFAULT_METRIC_MODE: MetricMode = MetricMode::Duckdb;
pub const DEFAULT_METRIC_CONNECT_1M_RETENTION_DAYS: u64 = 1;
pub const DEFAULT_METRIC_CONNECT_1H_RETENTION_DAYS: u64 = 7;
pub const DEFAULT_METRIC_CONNECT_1D_RETENTION_DAYS: u64 = 30;
pub const DEFAULT_DNS_METRIC_RETENTION_DAYS: u64 = 7;
pub const DEFAULT_METRIC_CONNECT_SECOND_WINDOW_MINUTES: u64 = 5;

// Metric Performance & Storage Defaults
pub const DEFAULT_METRIC_WRITE_BATCH_SIZE: usize = 20_000;
pub const DEFAULT_METRIC_WRITE_FLUSH_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_METRIC_DB_MAX_MEMORY_MB: usize = 256;
pub const DEFAULT_METRIC_DB_MAX_THREADS: usize = 4;
pub const DEFAULT_METRIC_CLEANUP_TIME_BUDGET_MS: u64 = 2_000;
pub const DEFAULT_METRIC_CLEANUP_SLICE_WINDOW_SECS: u64 = 300;

// --- DNS Settings ---
pub const DEFAULT_DNS_CACHE_CAPACITY: u32 = 4096;
pub const DEFAULT_DNS_CACHE_TTL: u32 = 24 * 60 * 60;
pub const DEFAULT_DNS_NEGATIVE_CACHE_TTL: u32 = 120;
pub const DEFAULT_DNS_DOH_LISTEN_PORT: u16 = 6053;
pub const DEFAULT_DNS_LAN_SUFFIX: &str = "lan";

// --- Time Settings ---
pub const DEFAULT_TIME_ENABLE: bool = false;
pub const DEFAULT_TIME_SERVERS: &[&str] =
    &["ntp.aliyun.com:123", "time.cloudflare.com:123", "pool.ntp.org:123"];
pub const DEFAULT_TIME_FALLBACK_SERVER: &str = "pool.ntp.org:123";
pub const DEFAULT_TIME_SYNC_INTERVAL_SECS: u64 = 3600;
pub const DEFAULT_TIME_TIMEOUT_SECS: u64 = 3;
pub const DEFAULT_TIME_STEP_THRESHOLD_MS: u64 = 500;
pub const DEFAULT_TIME_SAMPLES_PER_SERVER: u8 = 3;

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

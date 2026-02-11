pub mod dns;
pub mod firewall;
pub mod flow;
pub mod geo;
pub mod iface;
pub mod iface_ip;
pub mod mss_clamp;
pub mod nat;
pub mod ppp;
pub mod ra;
pub mod wifi;

pub mod route_lan;
pub mod route_wan;

use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
};

use crate::dhcp::v4_server::config::DHCPv4ServiceConfig;
use crate::dhcp::v6_client::config::IPV6PDServiceConfig;
use dns::DNSRuleConfig;
use firewall::FirewallServiceConfig;
use flow::FlowWanServiceConfig;
use iface::NetworkIfaceConfig;
use iface_ip::IfaceIpServiceConfig;
use mss_clamp::MSSClampServiceConfig;
use nat::NatServiceConfig;
use ppp::PPPDServiceConfig;
use ra::IPV6RAServiceConfig;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;
use wifi::WifiServiceConfig;

use crate::{
    args::WebCommArgs,
    config::{
        geo::{GeoIpSourceConfig, GeoSiteSourceConfig},
        nat::StaticNatMappingConfig,
        route_lan::RouteLanServiceConfig,
        route_wan::RouteWanServiceConfig,
    },
    dns::{config::DnsUpstreamConfig, redirect::DNSRedirectRule},
    firewall::FirewallRuleConfig,
    flow::config::FlowConfig,
    ip_mark::WanIpRuleConfig,
    LANDSCAPE_CONFIG_DIR_NAME, LANDSCAPE_DB_SQLITE_NAME, LANDSCAPE_LOG_DIR_NAME,
    LANDSCAPE_WEBROOT_DIR_NAME, LAND_CONFIG,
};

pub type FlowId = u32;
pub type ConfigId = Uuid;

/// 初始化配置结构体
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct InitConfig {
    /// config file
    pub config: LandscapeConfig,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ifaces: Vec<NetworkIfaceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ipconfigs: Vec<IfaceIpServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nats: Vec<NatServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub marks: Vec<FlowWanServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pppds: Vec<PPPDServiceConfig>,

    pub flow_rules: Vec<FlowConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_rules: Vec<DNSRuleConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_ip_mark: Vec<WanIpRuleConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dhcpv6pds: Vec<IPV6PDServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub icmpras: Vec<IPV6RAServiceConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub firewalls: Vec<FirewallServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub firewall_rules: Vec<FirewallRuleConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wifi_configs: Vec<WifiServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dhcpv4_services: Vec<DHCPv4ServiceConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mss_clamps: Vec<MSSClampServiceConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub geo_ips: Vec<GeoIpSourceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub geo_sites: Vec<GeoSiteSourceConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub route_lans: Vec<RouteLanServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub route_wans: Vec<RouteWanServiceConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub static_nat_mappings: Vec<StaticNatMappingConfig>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_redirects: Vec<DNSRedirectRule>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_upstream_configs: Vec<DnsUpstreamConfig>,
}

/// auth realte config
#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeAuthConfig {
    /// login user
    pub admin_user: Option<String>,

    /// login pass
    pub admin_pass: Option<String>,
}

/// web realte config
#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeWebConfig {
    /// Web Root
    pub web_root: Option<PathBuf>,

    /// Listen HTTP port
    pub port: Option<u16>,

    /// Listen HTTPS port
    pub https_port: Option<u16>,

    /// Listen address
    pub address: Option<IpAddr>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeLogConfig {
    pub log_path: Option<PathBuf>,
    pub debug: Option<bool>,
    pub log_output_in_terminal: Option<bool>,
    pub max_log_files: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeStoreConfig {
    pub database_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeMetricConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub conn_retention_mins: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub conn_retention_minute_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub conn_retention_hour_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub conn_retention_day_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub dns_retention_days: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub batch_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub flush_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub max_memory: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub max_threads: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeDnsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub cache_capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub cache_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub negative_cache_ttl: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeUIConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub theme: Option<String>,
}

#[derive(Serialize, TS, Debug, Clone)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct GetUIConfigResponse {
    pub ui: LandscapeUIConfig,
    pub hash: String,
}

#[derive(Deserialize, TS, Debug, Clone)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct UpdateUIConfigRequest {
    pub new_ui: LandscapeUIConfig,
    pub expected_hash: String,
}

#[derive(Serialize, TS, Debug, Clone)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct GetMetricConfigResponse {
    pub metric: LandscapeMetricConfig,
    pub hash: String,
}

#[derive(Deserialize, TS, Debug, Clone)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct UpdateMetricConfigRequest {
    pub new_metric: LandscapeMetricConfig,
    pub expected_hash: String,
}

#[derive(Serialize, TS, Debug, Clone)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct GetDnsConfigResponse {
    pub dns: LandscapeDnsConfig,
    pub hash: String,
}

#[derive(Deserialize, TS, Debug, Clone)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct UpdateDnsConfigRequest {
    pub new_dns: LandscapeDnsConfig,
    pub expected_hash: String,
}

/// Read & Write <CONFIG_PATH>/landscape.toml
#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/config.d.ts")]
pub struct LandscapeConfig {
    #[serde(default)]
    pub auth: LandscapeAuthConfig,
    #[serde(default)]
    pub web: LandscapeWebConfig,
    #[serde(default)]
    pub log: LandscapeLogConfig,
    #[serde(default)]
    pub store: LandscapeStoreConfig,
    #[serde(default)]
    pub metric: LandscapeMetricConfig,
    #[serde(default)]
    pub dns: LandscapeDnsConfig,
    #[serde(default)]
    pub ui: LandscapeUIConfig,
}

///
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub home_path: PathBuf,
    /// File Config
    pub file_config: LandscapeConfig,

    pub auth: AuthRuntimeConfig,
    pub log: LogRuntimeConfig,
    pub web: WebRuntimeConfig,
    pub store: StoreRuntimeConfig,
    pub metric: MetricRuntimeConfig,
    pub dns: DnsRuntimeConfig,
    pub ui: LandscapeUIConfig,
    pub auto: bool,
}

fn default_home_path() -> PathBuf {
    let Some(path) = homedir::my_home().unwrap() else {
        panic!("can not get home path");
    };
    path.join(LANDSCAPE_CONFIG_DIR_NAME)
}

const fn default_debug_mode() -> bool {
    #[cfg(debug_assertions)]
    {
        true
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

fn read_home_config_file(home_path: PathBuf) -> LandscapeConfig {
    let config_path = home_path.join(LAND_CONFIG);
    if config_path.exists() && config_path.is_file() {
        let config_raw = std::fs::read_to_string(config_path).unwrap();
        toml::from_str(&config_raw).unwrap()
    } else {
        LandscapeConfig::default()
    }
}

impl RuntimeConfig {
    pub fn new(args: WebCommArgs) -> Self {
        fn read_value<T: Clone>(a: &Option<T>, b: &Option<T>, default: T) -> T {
            a.clone().or_else(|| b.clone()).unwrap_or(default)
        }

        let mut home_path = args.config_dir.unwrap_or(default_home_path());

        if home_path.is_relative() {
            home_path = std::env::current_dir().unwrap().join(home_path);
            home_path = home_path.components().collect();
        }

        let config = read_home_config_file(home_path.clone());

        let auth = AuthRuntimeConfig {
            admin_user: read_value(&args.admin_user, &config.auth.admin_user, "root".to_string()),
            admin_pass: read_value(&args.admin_pass, &config.auth.admin_pass, "root".to_string()),
        };

        let default_log_path = home_path.join(LANDSCAPE_LOG_DIR_NAME);
        let log = LogRuntimeConfig {
            log_path: read_value(&args.log_path, &config.log.log_path, default_log_path),
            debug: read_value(&args.debug, &config.log.debug, default_debug_mode()),
            log_output_in_terminal: read_value(
                &args.log_output_in_terminal,
                &config.log.log_output_in_terminal,
                default_debug_mode(),
            ),
            max_log_files: read_value(&args.max_log_files, &config.log.max_log_files, 7),
        };

        let default_web_path = home_path.join(LANDSCAPE_WEBROOT_DIR_NAME);
        let web = WebRuntimeConfig {
            web_root: read_value(&args.web, &config.web.web_root, default_web_path),
            port: read_value(&args.port, &config.web.port, 6300),
            https_port: read_value(&args.https_port, &config.web.https_port, 6443),
            address: read_value(
                &args.address,
                &config.web.address,
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ),
        };

        let store = StoreRuntimeConfig {
            database_path: read_value(
                &args.database_path,
                &config.store.database_path,
                StoreRuntimeConfig::create_default_db_store(&home_path),
            ),
        };

        let metric = MetricRuntimeConfig {
            conn_retention_mins: config
                .metric
                .conn_retention_mins
                .unwrap_or(crate::DEFAULT_CONN_METRIC_RETENTION_MINS),
            conn_retention_minute_days: config
                .metric
                .conn_retention_minute_days
                .unwrap_or(crate::DEFAULT_CONN_METRIC_RETENTION_DAYS_1M),
            conn_retention_hour_days: config
                .metric
                .conn_retention_hour_days
                .unwrap_or(crate::DEFAULT_CONN_METRIC_RETENTION_DAYS_1H),
            conn_retention_day_days: config
                .metric
                .conn_retention_day_days
                .unwrap_or(crate::DEFAULT_CONN_METRIC_RETENTION_DAYS_1D),
            dns_retention_days: config
                .metric
                .dns_retention_days
                .unwrap_or(crate::DEFAULT_DNS_METRIC_RETENTION_DAYS),
            batch_size: config.metric.batch_size.unwrap_or(crate::DEFAULT_METRIC_BATCH_SIZE),
            flush_interval_secs: config
                .metric
                .flush_interval_secs
                .unwrap_or(crate::DEFAULT_METRIC_FLUSH_INTERVAL_SECS),
            max_memory: config.metric.max_memory.unwrap_or(crate::DEFAULT_METRIC_MAX_MEMORY),
            max_threads: config.metric.max_threads.unwrap_or(crate::DEFAULT_METRIC_MAX_THREADS),
        };
        let dns = DnsRuntimeConfig {
            cache_capacity: config.dns.cache_capacity.unwrap_or(crate::DEFAULT_DNS_CACHE_CAPACITY),
            cache_ttl: config.dns.cache_ttl.unwrap_or(crate::DEFAULT_DNS_CACHE_TTL),
            negative_cache_ttl: config
                .dns
                .negative_cache_ttl
                .unwrap_or(crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL),
        };

        let runtime_config = RuntimeConfig {
            home_path,
            auth,
            log,
            web,
            store,
            metric,
            dns,
            ui: config.ui.clone(),
            file_config: config,
            auto: args.auto,
        };

        runtime_config
    }

    pub fn to_string_summary(&self) -> String {
        let address_http_str = match self.web.address {
            std::net::IpAddr::V4(addr) => format!("{}:{}", addr, self.web.port),
            std::net::IpAddr::V6(addr) => format!("[{}]:{}", addr, self.web.port),
        };
        let address_https_str = match self.web.address {
            std::net::IpAddr::V4(addr) => format!("{}:{}", addr, self.web.https_port),
            std::net::IpAddr::V6(addr) => format!("[{}]:{}", addr, self.web.https_port),
        };
        format!(
            "\n\
         Landscape Home Path: {}\n\
         \n\
         [Auth]\n\
         Admin User: {}\n\
         Admin Pass: {}\n\
         \n\
         [Log]\n\
         Log Path: {}\n\
         Debug: {}\n\
         Log Output In Terminal: {}\n\
         Max Log Files: {}\n\
         \n\
         [Web]\n\
         Web Root Path: {}\n\
         Listen HTTP on: http://{}\n\
         Listen HTTPS on: https://{}\n\
         \n\
         [Store]\n\
         Database Connect: {}\n\
         \n\
          [Metric]\n\
         Retention Mins (Raw): {} mins\n\
         Retention Days (1m): {} days\n\
         Retention Days (1h): {} days\n\
         Retention Days (1d): {} days\n\
         Retention Days (DNS): {} days\n\
         Batch Size: {}\n\
         Flush Interval: {}s\n\
         Max Memory: {}MB\n\
         Max Threads: {}\n",
            self.home_path.display(),
            self.auth.admin_user,
            self.auth.admin_pass,
            self.log.log_path.display(),
            self.log.debug,
            self.log.log_output_in_terminal,
            self.log.max_log_files,
            self.web.web_root.display(),
            address_http_str,
            address_https_str,
            self.store.database_path,
            self.metric.conn_retention_mins,
            self.metric.conn_retention_minute_days,
            self.metric.conn_retention_hour_days,
            self.metric.conn_retention_day_days,
            self.metric.dns_retention_days,
            self.metric.batch_size,
            self.metric.flush_interval_secs,
            self.metric.max_memory,
            self.metric.max_threads,
        )
    }
}

#[derive(Clone, Debug)]
pub struct AuthRuntimeConfig {
    /// login user
    pub admin_user: String,

    /// login pass
    pub admin_pass: String,
}

#[derive(Clone, Debug)]
pub struct LogRuntimeConfig {
    pub log_path: PathBuf,
    pub debug: bool,
    pub log_output_in_terminal: bool,
    pub max_log_files: usize,
}

#[derive(Clone, Debug)]
pub struct WebRuntimeConfig {
    /// Web Root
    pub web_root: PathBuf,

    /// Listen HTTP port
    pub port: u16,

    /// Listen HTTPS port
    pub https_port: u16,

    /// Listen address
    pub address: IpAddr,
}

#[derive(Clone, Debug)]
pub struct StoreRuntimeConfig {
    pub database_path: String,
}

#[derive(Clone, Debug)]
pub struct MetricRuntimeConfig {
    pub conn_retention_mins: u64,
    pub conn_retention_minute_days: u64,
    pub conn_retention_hour_days: u64,
    pub conn_retention_day_days: u64,
    pub dns_retention_days: u64,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
    pub max_memory: usize,
    pub max_threads: usize,
}

#[derive(Clone, Debug, Default)]
pub struct DnsRuntimeConfig {
    pub cache_capacity: u32,
    pub cache_ttl: u32,
    pub negative_cache_ttl: u32,
}

impl MetricRuntimeConfig {
    pub fn update_from_file_config(&mut self, config: &LandscapeMetricConfig) {
        if let Some(v) = config.conn_retention_mins {
            self.conn_retention_mins = v;
        }
        if let Some(v) = config.conn_retention_minute_days {
            self.conn_retention_minute_days = v;
        }
        if let Some(v) = config.conn_retention_hour_days {
            self.conn_retention_hour_days = v;
        }
        if let Some(v) = config.conn_retention_day_days {
            self.conn_retention_day_days = v;
        }
        if let Some(v) = config.dns_retention_days {
            self.dns_retention_days = v;
        }
        if let Some(v) = config.batch_size {
            self.batch_size = v;
        }
        if let Some(v) = config.flush_interval_secs {
            self.flush_interval_secs = v;
        }
        if let Some(v) = config.max_memory {
            self.max_memory = v;
        }
        if let Some(v) = config.max_threads {
            self.max_threads = v;
        }
    }
}

impl DnsRuntimeConfig {
    pub fn update_from_file_config(&mut self, config: &LandscapeDnsConfig) {
        if let Some(v) = config.cache_capacity {
            self.cache_capacity = v;
        }
        if let Some(v) = config.cache_ttl {
            self.cache_ttl = v;
        }
        if let Some(v) = config.negative_cache_ttl {
            self.negative_cache_ttl = v;
        }
    }
}

impl StoreRuntimeConfig {
    pub fn create_default_db_store(home_path: &PathBuf) -> String {
        let path = home_path.join(LANDSCAPE_DB_SQLITE_NAME);
        // 检查路径是否存在
        if path.exists() {
            if path.is_dir() {
                panic!(
                    "Expected a file path for database, but found a directory: {}",
                    path.display()
                );
            }
        } else {
            // 确保目录存在
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent).expect("Failed to create database directory");
                }
            }
            std::fs::File::create(&path).expect("Failed to create database file");
        }
        format!("sqlite://{}?mode=rwc", path.display())
    }
}

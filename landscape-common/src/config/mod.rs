pub mod dhcp_v4_server;
pub mod dhcp_v6_client;
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

use dhcp_v4_server::DHCPv4ServiceConfig;
use dhcp_v6_client::IPV6PDServiceConfig;
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
    dns::redirect::DNSRedirectRule,
    firewall::FirewallRuleConfig,
    flow::FlowConfig,
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

/// Read & Write <CONFIG_PATH>/config.toml
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

        let home_path = args.config_dir.unwrap_or(default_home_path());
        let config = read_home_config_file(home_path.clone());

        let auth = AuthRuntimeConfig {
            admin_user: read_value(&args.admin_user, &config.auth.admin_user, "root".to_string()),
            admin_pass: read_value(&args.admin_pass, &config.auth.admin_pass, "root".to_string()),
        };

        let log = LogRuntimeConfig {
            log_path: home_path.join(LANDSCAPE_LOG_DIR_NAME),
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
            https_port: read_value(&args.port, &config.web.port, 6443),
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
        let runtime_config = RuntimeConfig {
            home_path,
            auth,
            log,
            web,
            store,
            file_config: config,
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
         Database Connect: {}\n",
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

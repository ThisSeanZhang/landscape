use std::{net::IpAddr, path::PathBuf};

use crate::config::settings::{
    LandscapeConfig, LandscapeDnsConfig, LandscapeMetricConfig, LandscapeTimeConfig,
    LandscapeUIConfig, MetricMode,
};
use crate::gateway::settings::GatewayRuntimeConfig;
use crate::{
    DEFAULT_TIME_ENABLE, DEFAULT_TIME_SAMPLES_PER_SERVER, DEFAULT_TIME_SERVERS,
    DEFAULT_TIME_STEP_THRESHOLD_MS, DEFAULT_TIME_SYNC_INTERVAL_SECS, DEFAULT_TIME_TIMEOUT_SECS,
    LANDSCAPE_DB_SQLITE_NAME,
};

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub home_path: PathBuf,
    pub file_config: LandscapeConfig,
    pub auth: AuthRuntimeConfig,
    pub log: LogRuntimeConfig,
    pub web: WebRuntimeConfig,
    pub store: StoreRuntimeConfig,
    pub metric: MetricRuntimeConfig,
    pub dns: DnsRuntimeConfig,
    pub ui: LandscapeUIConfig,
    pub time: TimeRuntimeConfig,
    pub gateway: GatewayRuntimeConfig,
    pub auto: bool,
}

#[derive(Clone, Debug)]
pub struct AuthRuntimeConfig {
    pub admin_user: String,
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
    pub web_root: PathBuf,
    pub port: u16,
    pub https_port: u16,
    pub address: IpAddr,
}

#[derive(Clone, Debug)]
pub struct StoreRuntimeConfig {
    pub database_path: String,
}

#[derive(Clone, Debug)]
pub struct MetricRuntimeConfig {
    pub mode: MetricMode,
    pub connect_second_window_minutes: u64,
    pub connect_1m_retention_days: u64,
    pub connect_1h_retention_days: u64,
    pub connect_1d_retention_days: u64,
    pub dns_retention_days: u64,
    pub write_batch_size: usize,
    pub write_flush_interval_secs: u64,
    pub db_max_memory_mb: usize,
    pub db_max_threads: usize,
    pub cleanup_interval_secs: u64,
    pub cleanup_time_budget_ms: u64,
    pub cleanup_slice_window_secs: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsRuntimeConfig {
    pub cache_capacity: u32,
    pub cache_ttl: u32,
    pub negative_cache_ttl: u32,
    pub doh_listen_port: u16,
    pub doh_http_endpoint: String,
}

#[derive(Clone, Debug)]
pub struct TimeRuntimeConfig {
    pub enabled: bool,
    pub servers: Vec<String>,
    pub sync_interval_secs: u64,
    pub timeout_secs: u64,
    pub step_threshold_ms: u64,
    pub samples_per_server: u8,
}

impl Default for TimeRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_TIME_ENABLE,
            servers: DEFAULT_TIME_SERVERS.iter().map(|server| (*server).to_string()).collect(),
            sync_interval_secs: DEFAULT_TIME_SYNC_INTERVAL_SECS,
            timeout_secs: DEFAULT_TIME_TIMEOUT_SECS,
            step_threshold_ms: DEFAULT_TIME_STEP_THRESHOLD_MS,
            samples_per_server: DEFAULT_TIME_SAMPLES_PER_SERVER,
        }
    }
}

impl RuntimeConfig {
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
         Mode: {:?}\n\
         Connect Second Window: {} mins\n\
         Connect 1m Retention: {} days\n\
         Connect 1h Retention: {} days\n\
         Connect 1d Retention: {} days\n\
         DNS Retention: {} days\n\
         Write Batch Size: {}\n\
         Write Flush Interval: {}s\n\
         DB Max Memory: {}MB\n\
         DB Max Threads: {}\n\
         Cleanup Interval: {}s\n\
         Cleanup Budget: {}ms\n\
          Cleanup Slice Window: {}s\n\
          \n\
          [Time]\n\
          Enabled: {}\n\
          NTP Servers: {}\n\
          Sync Interval: {}s\n\
          Timeout: {}s\n\
          Step Threshold: {}ms\n\
          Samples Per Server: {}\n",
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
            self.metric.mode,
            self.metric.connect_second_window_minutes,
            self.metric.connect_1m_retention_days,
            self.metric.connect_1h_retention_days,
            self.metric.connect_1d_retention_days,
            self.metric.dns_retention_days,
            self.metric.write_batch_size,
            self.metric.write_flush_interval_secs,
            self.metric.db_max_memory_mb,
            self.metric.db_max_threads,
            self.metric.cleanup_interval_secs,
            self.metric.cleanup_time_budget_ms,
            self.metric.cleanup_slice_window_secs,
            self.time.enabled,
            self.time.servers.join(", "),
            self.time.sync_interval_secs,
            self.time.timeout_secs,
            self.time.step_threshold_ms,
            self.time.samples_per_server,
        )
    }
}

impl MetricRuntimeConfig {
    pub fn update_from_file_config(&mut self, config: &LandscapeMetricConfig) {
        if let Some(v) = &config.mode {
            self.mode = v.clone();
        }
        if let Some(v) = config.connect_second_window_minutes {
            self.connect_second_window_minutes = v;
        }
        if let Some(v) = config.connect_1m_retention_days {
            self.connect_1m_retention_days = v;
        }
        if let Some(v) = config.connect_1h_retention_days {
            self.connect_1h_retention_days = v;
        }
        if let Some(v) = config.connect_1d_retention_days {
            self.connect_1d_retention_days = v;
        }
        if let Some(v) = config.dns_retention_days {
            self.dns_retention_days = v;
        }
        if let Some(v) = config.write_batch_size {
            self.write_batch_size = v;
        }
        if let Some(v) = config.write_flush_interval_secs {
            self.write_flush_interval_secs = v;
        }
        if let Some(v) = config.db_max_memory_mb {
            self.db_max_memory_mb = v;
        }
        if let Some(v) = config.db_max_threads {
            self.db_max_threads = v;
        }
        if let Some(v) = config.cleanup_interval_secs {
            self.cleanup_interval_secs = v;
        }
        if let Some(v) = config.cleanup_time_budget_ms {
            self.cleanup_time_budget_ms = v;
        }
        if let Some(v) = config.cleanup_slice_window_secs {
            self.cleanup_slice_window_secs = v;
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
        if let Some(v) = config.doh_listen_port {
            self.doh_listen_port = v;
        }
        if let Some(v) = &config.doh_http_endpoint {
            self.doh_http_endpoint = v.clone();
        }
    }
}

impl TimeRuntimeConfig {
    pub fn update_from_file_config(&mut self, config: &LandscapeTimeConfig) {
        if let Some(v) = config.enabled {
            self.enabled = v;
        }
        if let Some(v) = &config.servers {
            self.servers = v.clone();
        }
        if let Some(v) = config.sync_interval_secs {
            self.sync_interval_secs = v;
        }
        if let Some(v) = config.timeout_secs {
            self.timeout_secs = v;
        }
        if let Some(v) = config.step_threshold_ms {
            self.step_threshold_ms = v;
        }
        if let Some(v) = config.samples_per_server {
            self.samples_per_server = v;
        }
    }
}

impl StoreRuntimeConfig {
    pub fn create_default_db_store(home_path: &PathBuf) -> String {
        let path = home_path.join(LANDSCAPE_DB_SQLITE_NAME);
        if path.exists() {
            if path.is_dir() {
                panic!(
                    "Expected a file path for database, but found a directory: {}",
                    path.display()
                );
            }
        } else {
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

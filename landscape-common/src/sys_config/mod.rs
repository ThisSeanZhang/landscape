pub mod error;
pub use error::ConfigUpdateError;
pub mod auth;
pub mod dns;
pub mod gateway;
pub mod loader;
pub mod runtime;
pub use runtime::RuntimeConfigSource;
pub mod log;
pub mod metric;
pub mod store;
pub mod time;
pub mod ui;
pub mod web;

pub mod lan_hostname;

pub use auth::{AuthRuntimeConfig, ChangePasswordRequest, LandscapeAuthConfig};
pub use dns::{
    CacheRuntimeConfig, DnsRuntimeConfig, DohRuntimeConfig, GetDnsConfigResponse,
    LandscapeDnsConfig, UpdateDnsConfigRequest,
};
pub use gateway::{
    GatewayRuntimeConfig, GetGatewayConfigResponse, LandscapeGatewayConfig,
    UpdateGatewayConfigRequest,
};
pub use lan_hostname::{
    GetLanHostnameConfigResponse, LanHostnameError, LanHostnameRuntimeConfig,
    LandscapeLanHostnameConfig, UpdateLanHostnameConfigRequest,
};
pub use log::{LandscapeLogConfig, LogRuntimeConfig};
pub use metric::{
    GetMetricConfigResponse, LandscapeMetricConfig, MetricMode, MetricRuntimeConfig,
    UpdateMetricConfigRequest,
};
pub use store::{LandscapeStoreConfig, StoreRuntimeConfig};
pub use time::{
    GetTimeConfigResponse, LandscapeTimeConfig, TimeRuntimeConfig, UpdateTimeConfigRequest,
};
pub use ui::{
    GetUiConfigResponse, LandscapeThemeStyleConfig, LandscapeUiConfig, UpdateUiConfigRequest,
};
pub use web::{LandscapeWebConfig, WebRuntimeConfig};

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeConfig {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub auth: LandscapeAuthConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub web: LandscapeWebConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub log: LandscapeLogConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub store: LandscapeStoreConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub metric: LandscapeMetricConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub dns: LandscapeDnsConfig,
    #[serde(default, alias = "hostname_registry")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub lan_hostname: LandscapeLanHostnameConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub ui: LandscapeUiConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub time: LandscapeTimeConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub gateway: LandscapeGatewayConfig,
}

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
    pub lan_hostname: LanHostnameRuntimeConfig,
    pub ui: LandscapeUiConfig,
    pub time: TimeRuntimeConfig,
    pub gateway: GatewayRuntimeConfig,
    pub auto: bool,
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
         Admin Pass: ******\n\
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
         Connect Summary Retention: {} days\n\
         Connect Summary Max Rows: {}\n\
         Connect Database Max Size: {} bytes\n\
         DNS Retention: {} days\n\
         DNS 1m Retention: {} days\n\
         DNS Database Max Size: {} bytes\n\
             Write Batch Size: {}\n\
         Write Flush Interval: {}s\n\
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
            self.metric.connect_summary_retention_days,
            self.metric.connect_summary_max_rows,
            self.metric.connect_db_max_bytes,
            self.metric.dns_retention_days,
            self.metric.dns_1m_retention_days,
            self.metric.dns_db_max_bytes,
            self.metric.write_batch_size,
            self.metric.write_flush_interval_secs,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::WebCommArgs;

    #[test]
    fn to_string_summary_redacts_admin_pass() {
        let temp_dir = tempfile::tempdir().unwrap();
        let args = WebCommArgs {
            config_dir: Some(temp_dir.path().to_path_buf()),
            admin_user: Some("root".to_string()),
            admin_pass: Some("super-secret-passphrase".to_string()),
            ..Default::default()
        };
        let config = RuntimeConfig::new(args);

        let summary = config.to_string_summary();

        assert!(!summary.contains("super-secret-passphrase"));
        assert!(summary.contains("Admin Pass: ******"));
        assert!(summary.contains("Admin User: root"));
    }
}

pub mod api;
pub mod cli;
pub mod error;
pub mod init;
pub mod loader;
pub mod runtime;
pub mod settings;

pub use crate::sys_service::gateway::settings::LandscapeGatewayConfig;
pub use crate::sys_service::lan_hostname::LandscapeLanHostnameConfig;
pub use api::{
    GetDnsConfigResponse, GetGatewayConfigResponse, GetMetricConfigResponse, GetTimeConfigResponse,
    GetUIConfigResponse, UpdateDnsConfigRequest, UpdateGatewayConfigRequest,
    UpdateMetricConfigRequest, UpdateTimeConfigRequest, UpdateUIConfigRequest,
};
pub use cli::{ConfigCliArgs, ConfigCliError, ConfigOutput};
pub use error::InitConfigError;
pub use init::InitConfig;
pub use runtime::{
    AuthRuntimeConfig, DnsRuntimeConfig, LogRuntimeConfig, MetricRuntimeConfig, RuntimeConfig,
    StoreRuntimeConfig, TimeRuntimeConfig, WebRuntimeConfig,
};
pub use settings::{
    LandscapeAuthConfig, LandscapeConfig, LandscapeDnsConfig, LandscapeLogConfig,
    LandscapeMetricConfig, LandscapeStoreConfig, LandscapeThemeStyleConfig, LandscapeTimeConfig,
    LandscapeUIConfig, LandscapeWebConfig, MetricMode,
};

use uuid::Uuid;

pub type FlowId = u32;
pub type ConfigId = Uuid;

pub fn metric_db_max_mb_to_bytes(mb: u64) -> u64 {
    if mb == 0 {
        return 0;
    }
    mb.max(crate::MIN_METRIC_DB_MAX_MB).saturating_mul(1024 * 1024)
}

pub fn cleanup_budget_secs_to_ms(secs: u64) -> u64 {
    secs.max(1).saturating_mul(1000)
}

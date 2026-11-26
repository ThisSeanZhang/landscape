use super::config::{ConnectMetricConfig, DnsMetricConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetConnectMetricConfigResponse {
    pub config: ConnectMetricConfig,
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateConnectMetricConfigRequest {
    pub config: ConnectMetricConfig,
    pub expected_hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDnsMetricConfigResponse {
    pub config: DnsMetricConfig,
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDnsMetricConfigRequest {
    pub config: DnsMetricConfig,
    pub expected_hash: String,
}

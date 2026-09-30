use serde::{Deserialize, Serialize};

use crate::cert::order::DnsProviderConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsProviderCredentialCheckRequest {
    #[serde(default)]
    pub provider_config: DnsProviderConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsProviderCredentialCheckResult {
    pub message: String,
}

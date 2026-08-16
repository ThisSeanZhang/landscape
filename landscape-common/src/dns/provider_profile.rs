use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cert::order::DnsProviderConfig;
use crate::database::error::DbError;
use crate::database::repository::LandscapeDBStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsProviderProfileError {
    #[error("Invalid DNS provider profile: {0}")]
    #[api_error(id = "dns_provider_profile.invalid", status = 422)]
    Invalid(String),

    #[error("DNS provider profile name '{0}' already exists")]
    #[api_error(id = "dns_provider_profile.name_conflict", status = 409)]
    NameConflict(String),

    #[error("Manual DNS provider cannot be used as a reusable DNS provider profile")]
    #[api_error(id = "dns_provider_profile.manual_not_allowed", status = 422)]
    ManualNotAllowed,

    #[error("DNS provider profile is still used by DDNS jobs: {0}")]
    #[api_error(id = "dns_provider_profile.in_use_by_ddns", status = 409)]
    InUseByDdns(String),

    #[error("DNS provider profile is still used by certificates: {0}")]
    #[api_error(id = "dns_provider_profile.in_use_by_certs", status = 409)]
    InUseByCerts(String),

    #[error("Provider credential validation failed: {0}")]
    #[api_error(id = "dns_provider_profile.credential_error", status = 422)]
    CredentialError(String),

    #[error(transparent)]
    #[api_error(id = "dns_provider_profile.internal", status = 500)]
    Internal(#[from] DbError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsProviderProfile {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub provider_config: DnsProviderConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub remark: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub ddns_default_ttl: Option<u32>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl DnsProviderProfile {
    /// Preferred TTL (seconds) for DNS records created by this profile, covering
    /// both DDNS records and ACME DNS challenge records. Returns `None` to let the
    /// provider fall back to its own default.
    pub fn default_record_ttl(&self) -> Option<u32> {
        self.ddns_default_ttl
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("DNS provider profile name must not be empty".to_string());
        }
        if matches!(self.ddns_default_ttl, Some(0)) {
            return Err("ddns_default_ttl must be greater than 0 when provided".to_string());
        }
        Ok(())
    }
}

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

impl LandscapeDBStore<Uuid> for DnsProviderProfile {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_update_at(&self) -> f64 {
        self.update_at
    }

    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProviderConfig {
    LetsEncrypt,
    ZeroSsl { eab_kid: String, eab_hmac_key: String },
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self::LetsEncrypt
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    #[default]
    Unregistered,
    Registering,
    Registered,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertAccountConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub provider_config: ProviderConfig,
    pub email: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub account_private_key: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub acme_account_url: Option<String>,
    #[serde(default)]
    pub use_staging: bool,
    #[serde(default)]
    pub terms_agreed: bool,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub status: AccountStatus,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub status_message: Option<String>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for CertAccountConfig {
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

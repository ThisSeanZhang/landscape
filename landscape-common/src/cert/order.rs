use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

fn default_http_port() -> u16 {
    80
}

fn default_renew_before_days() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    Http {
        #[serde(default = "default_http_port")]
        port: u16,
    },
    Dns {
        #[serde(default)]
        dns_provider: DnsProviderConfig,
    },
}

impl Default for ChallengeType {
    fn default() -> Self {
        Self::Http { port: default_http_port() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DnsProviderConfig {
    #[default]
    Manual,
    Cloudflare {
        api_token: String,
    },
    Aliyun {
        access_key_id: String,
        access_key_secret: String,
    },
    Tencent {
        secret_id: String,
        secret_key: String,
    },
    Aws {
        access_key_id: String,
        secret_access_key: String,
        region: String,
    },
    Google {
        service_account_json: String,
    },
    Custom {
        script_path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    #[default]
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    #[default]
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa4096,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum CertType {
    Acme(AcmeCertConfig),
    Manual,
}

impl Default for CertType {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AcmeCertConfig {
    pub account_id: Uuid,
    #[serde(default)]
    pub challenge_type: ChallengeType,
    #[serde(default)]
    pub key_type: KeyType,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub acme_order_url: Option<String>,
    #[serde(default)]
    pub auto_renew: bool,
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub status: CertStatus,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub private_key: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub certificate: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub certificate_chain: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub expires_at: Option<f64>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub issued_at: Option<f64>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub status_message: Option<String>,
    #[serde(default)]
    pub cert_type: CertType,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for CertConfig {
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

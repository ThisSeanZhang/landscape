use std::collections::HashSet;

use landscape_macro::LdApiError;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::config::ConfigId;
use crate::database::repository::LandscapeDBStore;
use crate::dns::rule::{DomainConfig, DomainMatchType};
use crate::flow::ip_mark::IpConfig;
use crate::store::storev4::LandscapeStoreTrait;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum GeoError {
    #[error("Geo site '{0}' not found")]
    #[api_error(id = "geo_site.not_found", status = 404)]
    SiteNotFound(ConfigId),

    #[error("Geo site cache key '{0}' not found")]
    #[api_error(id = "geo_site.cache_not_found", status = 404)]
    SiteCacheNotFound(String),

    #[error("Geo site file not found in upload")]
    #[api_error(id = "geo_site.file_not_found", status = 400)]
    SiteFileNotFound,

    #[error("Geo site file read error")]
    #[api_error(id = "geo_site.file_read_error", status = 400)]
    SiteFileReadError,

    #[error("Geo IP '{0}' not found")]
    #[api_error(id = "geo_ip.not_found", status = 404)]
    IpNotFound(ConfigId),

    #[error("Geo IP cache key '{0}' not found")]
    #[api_error(id = "geo_ip.cache_not_found", status = 404)]
    IpCacheNotFound(String),

    #[error("Geo IP file not found in upload")]
    #[api_error(id = "geo_ip.file_not_found", status = 400)]
    IpFileNotFound,

    #[error("Geo IP file read error")]
    #[api_error(id = "geo_ip.file_read_error", status = 400)]
    IpFileReadError,

    #[error("Geo IP config '{0}' not found")]
    #[api_error(id = "geo_ip.config_not_found", status = 404)]
    IpConfigNotFound(String),

    #[error("Geo IP DAT decode error")]
    #[api_error(id = "geo_ip.dat_decode_error", status = 400)]
    IpDatDecodeError,

    #[error("Geo IP TXT file contains no valid CIDR entries")]
    #[api_error(id = "geo_ip.no_valid_cidr", status = 400)]
    IpNoValidCidrFound,

    #[error("failed to read geo site cache '{name}:{key}'")]
    #[api_error(id = "geo_matcher.read_failed", status = 500)]
    MatcherReadFailed { name: String, key: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GeoIpFileFormat {
    #[default]
    Dat,
    Txt,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoSiteSourceConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
    pub name: String,
    pub enable: bool,
    pub source: GeoSiteSource,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum GeoSiteSource {
    Url {
        url: String,
        next_update_at: f64,
        geo_keys: Vec<String>,
    },
    Direct {
        data: Vec<GeoSiteDirectItem>,
    },
    AdguardHome {
        url: String,
        next_update_at: f64,
        /// Cache key name for parsed domains (default: "ADGUARD")
        #[serde(default = "default_adguard_key", deserialize_with = "deserialize_adguard_key")]
        key: String,
    },
}

pub const DEFAULT_ADGUARD_KEY: &str = "ADGUARD";

fn default_adguard_key() -> String {
    DEFAULT_ADGUARD_KEY.to_string()
}

pub fn normalize_adguard_key(key: &str) -> String {
    let key = key.trim();
    if key.is_empty() { DEFAULT_ADGUARD_KEY } else { key }.to_ascii_uppercase()
}

fn deserialize_adguard_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(|key| normalize_adguard_key(&key))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoSiteDirectItem {
    pub key: String,
    pub values: Vec<GeoSiteFileConfig>,
}

impl LandscapeDBStore<Uuid> for GeoSiteSourceConfig {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoDomainConfig {
    pub name: String,
    pub key: String,
    pub values: Vec<GeoSiteFileConfig>,
}

impl LandscapeStoreTrait for GeoDomainConfig {
    type K = GeoFileCacheKey;
    fn get_store_key(&self) -> GeoFileCacheKey {
        GeoFileCacheKey { name: self.name.clone(), key: self.key.clone() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoSiteFileConfig {
    pub match_type: DomainMatchType,
    pub value: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub attributes: HashSet<String>,
}

impl From<GeoSiteFileConfig> for DomainConfig {
    fn from(value: GeoSiteFileConfig) -> DomainConfig {
        DomainConfig { match_type: value.match_type, value: value.value }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoFileCacheKey {
    pub name: String,
    pub key: String,
}

#[async_trait::async_trait]
pub trait GeoMatcherSource: Send + Sync {
    /// `None` means the key does not exist; an empty vector is a valid empty key.
    async fn load_geo_domains(
        &self,
        key: &GeoFileCacheKey,
    ) -> Result<Option<Vec<GeoSiteFileConfig>>, GeoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoConfigKey {
    pub name: String,
    pub key: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub inverse: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub attribute_key: Option<String>,
}

impl GeoConfigKey {
    pub fn get_file_cache_key(&self) -> GeoFileCacheKey {
        GeoFileCacheKey { name: self.name.clone(), key: self.key.clone() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct QueryGeoKey {
    pub name: Option<String>,
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct QueryGeoDomainConfig {
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoIpSourceConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
    pub name: String,
    pub enable: bool,
    pub source: GeoIpSource,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum GeoIpSource {
    Url {
        url: String,
        next_update_at: f64,
        #[serde(default)]
        format: GeoIpFileFormat,
        #[serde(default)]
        txt_key: Option<String>,
    },
    Direct {
        data: Vec<GeoIpDirectItem>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoIpDirectItem {
    pub key: String,
    pub values: Vec<IpConfig>,
}

impl LandscapeDBStore<Uuid> for GeoIpSourceConfig {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoIpConfig {
    pub name: String,
    pub key: String,
    pub values: Vec<IpConfig>,
}

impl LandscapeStoreTrait for GeoIpConfig {
    type K = GeoFileCacheKey;
    fn get_store_key(&self) -> GeoFileCacheKey {
        GeoFileCacheKey { name: self.name.clone(), key: self.key.clone() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct QueryGeoIpConfig {
    pub name: Option<String>,
}

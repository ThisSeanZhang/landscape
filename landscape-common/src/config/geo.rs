use std::collections::HashSet;

use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::{
    config::dns::{DomainConfig, DomainMatchType},
    config::ConfigId,
    database::repository::LandscapeDBStore,
    ip_mark::IpConfig,
    store::storev4::LandscapeStoreTrait,
};

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum GeoSiteError {
    #[error("Geo site '{0}' not found")]
    #[api_error(id = "geo_site.not_found", status = 404)]
    NotFound(ConfigId),

    #[error("Geo site cache key '{0}' not found")]
    #[api_error(id = "geo_site.cache_not_found", status = 404)]
    CacheNotFound(String),

    #[error("Geo site file not found in upload")]
    #[api_error(id = "geo_site.file_not_found", status = 400)]
    FileNotFound,

    #[error("Geo site file read error")]
    #[api_error(id = "geo_site.file_read_error", status = 400)]
    FileReadError,
}

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum GeoIpError {
    #[error("Geo IP '{0}' not found")]
    #[api_error(id = "geo_ip.not_found", status = 404)]
    NotFound(ConfigId),

    #[error("Geo IP cache key '{0}' not found")]
    #[api_error(id = "geo_ip.cache_not_found", status = 404)]
    CacheNotFound(String),

    #[error("Geo IP file not found in upload")]
    #[api_error(id = "geo_ip.file_not_found", status = 400)]
    FileNotFound,

    #[error("Geo IP file read error")]
    #[api_error(id = "geo_ip.file_read_error", status = 400)]
    FileReadError,
}

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_site.d.ts")]
pub struct GeoSiteSourceConfig {
    /// 用这个 ID 作为文件名称
    pub id: Option<Uuid>,
    /// 记录更新时间
    pub update_at: f64,
    /// 展示名称
    pub name: String,
    /// 启用状态
    pub enable: bool,
    /// 来源配置
    pub source: GeoSiteSource,
}

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
#[ts(export, export_to = "common/geo_site.d.ts")]
pub enum GeoSiteSource {
    Url { url: String, next_update_at: f64, geo_keys: Vec<String> },
    Direct { data: Vec<GeoSiteDirectItem> },
}

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_site.d.ts")]
pub struct GeoSiteDirectItem {
    pub key: String,
    pub values: Vec<GeoSiteFileConfig>,
}

impl LandscapeDBStore<Uuid> for GeoSiteSourceConfig {
    fn get_id(&self) -> Uuid {
        self.id.unwrap_or(Uuid::new_v4())
    }
}

/// 存储在 file cache 中
#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_site.d.ts")]
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

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_site.d.ts")]
pub struct GeoSiteFileConfig {
    pub match_type: DomainMatchType,
    pub value: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub attributes: HashSet<String>,
}

impl Into<DomainConfig> for GeoSiteFileConfig {
    fn into(self) -> DomainConfig {
        DomainConfig { match_type: self.match_type, value: self.value }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo.d.ts")]
pub struct GeoFileCacheKey {
    pub name: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo.d.ts")]
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

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo.d.ts")]
pub struct QueryGeoKey {
    pub name: Option<String>,
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_site.d.ts")]
pub struct QueryGeoDomainConfig {
    pub name: Option<String>,
}

/// Geo IP
#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_ip.d.ts")]
pub struct GeoIpSourceConfig {
    /// 用这个 ID 作为文件名称
    pub id: Option<Uuid>,
    /// 记录更新时间
    pub update_at: f64,
    /// 展示名称
    pub name: String,
    /// 启用状态
    pub enable: bool,
    /// 来源配置
    pub source: GeoIpSource,
}

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
#[ts(export, export_to = "common/geo_ip.d.ts")]
pub enum GeoIpSource {
    Url { url: String, next_update_at: f64 },
    Direct { data: Vec<GeoIpDirectItem> },
}

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_ip.d.ts")]
pub struct GeoIpDirectItem {
    pub key: String,
    pub values: Vec<IpConfig>,
}

impl LandscapeDBStore<Uuid> for GeoIpSourceConfig {
    fn get_id(&self) -> Uuid {
        self.id.unwrap_or(Uuid::new_v4())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_ip.d.ts")]
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

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/geo_ip.d.ts")]
pub struct QueryGeoIpConfig {
    pub name: Option<String>,
}

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::{
    config::dns::{DomainConfig, DomainMatchType},
    database::repository::LandscapeDBStore,
    ip_mark::IpConfig,
    store::storev4::LandscapeStoreTrait,
};

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[ts(export, export_to = "common/geo_site.d.ts")]
pub struct GeoSiteSourceConfig {
    /// 用这个 ID 作为文件名称
    pub id: Option<Uuid>,
    /// 记录更新时间
    pub update_at: f64,
    /// 文件 URL 地址
    pub url: String,
    /// 展示名称
    pub name: String,
    /// 启用状态
    pub enable: bool,
    /// 下次更新时间
    pub next_update_at: f64,
    /// 提取文件中的 key
    pub geo_keys: Vec<String>,
}

impl LandscapeDBStore<Uuid> for GeoSiteSourceConfig {
    fn get_id(&self) -> Uuid {
        self.id.unwrap_or(Uuid::new_v4())
    }
}

/// 存储在 file cache 中
#[derive(Serialize, Deserialize, Debug, Clone, TS)]
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
#[ts(export, export_to = "common/geo_site.d.ts")]
pub struct GeoSiteFileConfig {
    pub match_type: DomainMatchType,
    pub value: String,
    #[serde(default)]
    pub attributes: HashSet<String>,
}

impl Into<DomainConfig> for GeoSiteFileConfig {
    fn into(self) -> DomainConfig {
        DomainConfig { match_type: self.match_type, value: self.value }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[ts(export, export_to = "common/geo.d.ts")]
pub struct GeoFileCacheKey {
    pub name: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/geo.d.ts")]
pub struct GeoConfigKey {
    pub name: String,
    pub key: String,
    #[serde(default)]
    pub inverse: bool,
    #[serde(default)]
    pub attribute_key: Option<String>,
}

impl GeoConfigKey {
    pub fn get_file_cache_key(&self) -> GeoFileCacheKey {
        GeoFileCacheKey { name: self.name.clone(), key: self.key.clone() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[ts(export, export_to = "common/geo.d.ts")]
pub struct QueryGeoKey {
    pub name: Option<String>,
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, TS)]
#[ts(export, export_to = "common/geo_site.d.ts")]
pub struct QueryGeoDomainConfig {
    pub name: Option<String>,
}

/// Geo IP
#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[ts(export, export_to = "common/geo_ip.ts")]
pub struct GeoIpSourceConfig {
    /// 用这个 ID 作为文件名称
    pub id: Option<Uuid>,
    /// 记录更新时间
    pub update_at: f64,
    /// 文件 URL 地址
    pub url: String,
    /// 展示名称
    pub name: String,
    /// 启用状态
    pub enable: bool,
    /// 下次更新时间
    pub next_update_at: f64,
}

impl LandscapeDBStore<Uuid> for GeoIpSourceConfig {
    fn get_id(&self) -> Uuid {
        self.id.unwrap_or(Uuid::new_v4())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/geo_ip.ts")]
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
#[ts(export, export_to = "common/geo_ip.ts")]
pub struct QueryGeoIpConfig {
    pub name: Option<String>,
}

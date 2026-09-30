use landscape_macro::LdApiError;

use crate::config::ConfigId;
use crate::database::error::DbError;

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

    #[error("Geo site DAT decode error")]
    #[api_error(id = "geo_site.dat_decode_error", status = 400)]
    SiteDatDecodeError,

    #[error("Geo raw dat not found, background download started")]
    #[api_error(id = "geo.raw_dat_not_ready", status = 404)]
    RawDatNotReady,

    #[error("Geo raw dat download already running")]
    #[api_error(id = "geo.raw_dat_download_running", status = 409)]
    RawDatDownloadRunning,

    #[error("Geo raw dat read failed: {0}")]
    #[api_error(id = "geo.raw_dat_read_failed", status = 500)]
    RawDatReadFailed(String),

    #[error("invalid GeoSite lookup domain '{0}'")]
    #[api_error(id = "geo_site.invalid_lookup_domain", status = 400)]
    SiteInvalidLookupDomain(String),

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

    #[error("Geo IP source request failed: {0}")]
    #[api_error(id = "geo_ip.source_request_failed", status = 502)]
    IpSourceRequestFailed(String),

    #[error("Geo IP config store failed: {0}")]
    #[api_error(id = "geo_ip.config_store_failed", status = 500)]
    IpConfigStoreFailed(String),

    #[error("Geo IP DAT decode error")]
    #[api_error(id = "geo_ip.dat_decode_error", status = 400)]
    IpDatDecodeError,

    #[error("Geo IP TXT file contains no valid CIDR entries")]
    #[api_error(id = "geo_ip.no_valid_cidr", status = 400)]
    IpNoValidCidrFound,

    #[error("invalid GeoIP lookup address '{0}'")]
    #[api_error(id = "geo_ip.invalid_lookup_address", status = 400)]
    IpInvalidLookupAddress(String),

    #[error("failed to read geo site cache '{name}:{key}'")]
    #[api_error(id = "geo_matcher.read_failed", status = 500)]
    MatcherReadFailed { name: String, key: String },

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
}

pub mod config;
pub mod error;

pub use config::*;
pub use error::GeoError;

#[derive(Debug)]
pub enum RawDatState {
    Ready(Vec<u8>),
    Started,
    Running,
}

#[async_trait::async_trait]
pub trait GeoMatcherSource: Send + Sync {
    /// `None` means the key does not exist; an empty vector is a valid empty key.
    async fn load_geo_domains(
        &self,
        key: &GeoFileCacheKey,
    ) -> Result<Option<Vec<GeoSiteFileConfig>>, GeoError>;
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeStoreConfig {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub database_path: Option<String>,
}

use std::{net::IpAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeWebConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable = false))]
    pub web_root: Option<PathBuf>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub port: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub https_port: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable = false))]
    pub address: Option<IpAddr>,
}

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeLogConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable = false))]
    pub log_path: Option<PathBuf>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub debug: Option<bool>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub log_output_in_terminal: Option<bool>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub max_log_files: Option<usize>,
}

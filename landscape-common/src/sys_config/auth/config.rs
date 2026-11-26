use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeAuthConfig {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub admin_user: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub admin_pass: Option<String>,
}

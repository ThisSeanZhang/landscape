use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LoginInfo {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/auth.d.ts")]
pub struct LoginResult {
    pub success: bool,
    pub token: String,
}

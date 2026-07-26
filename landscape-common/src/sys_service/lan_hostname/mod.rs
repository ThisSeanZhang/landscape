pub mod api;
pub mod config;
pub mod error;

pub use api::{GetLanHostnameConfigResponse, UpdateLanHostnameConfigRequest};
pub use config::{normalize_lan_suffix, LanHostnameConfig, LandscapeLanHostnameConfig};
pub use error::LanHostnameError;

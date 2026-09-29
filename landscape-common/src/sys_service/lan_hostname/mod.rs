pub mod api;
pub mod config;
pub mod error;

pub use api::{GetLanHostnameConfigResponse, UpdateLanHostnameConfigRequest};
pub use config::{LanHostnameConfig, LandscapeLanHostnameConfig, normalize_lan_suffix};
pub use error::LanHostnameError;

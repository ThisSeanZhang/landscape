pub mod api;
pub mod config;
pub mod error;
pub mod runtime;

pub use api::{GetLanHostnameConfigResponse, UpdateLanHostnameConfigRequest};
pub use config::LandscapeLanHostnameConfig;
pub use error::LanHostnameError;
pub use runtime::{LanHostnameRuntimeConfig, normalize_lan_suffix};

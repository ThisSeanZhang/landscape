pub mod dataplane;

use serde::{Deserialize, Serialize};

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MSSClampServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default = "default_clamp_size")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub clamp_size: u16,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeStore for MSSClampServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for MSSClampServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

impl ZoneAwareConfig for MSSClampServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::WanOrPpp
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::MssClamp
    }
}

impl MSSClampServiceConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.clamp_size < 536 || self.clamp_size > 1500 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("clamp_size ({}) must be between 536 and 1500", self.clamp_size),
            });
        }
        Ok(())
    }
}

const fn default_clamp_size() -> u16 {
    1492
}

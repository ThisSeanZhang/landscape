use core::ops::Range;
use serde::{Deserialize, Serialize};

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::service::manager::ServiceKeyProvider;
use crate::utils::time::get_f64_timestamp;
use crate::wan_service::nat::error::NatServiceError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NatServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub nat_config: NatConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl ServiceKeyProvider for NatServiceConfig {
    fn service_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for NatServiceConfig {
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

impl ZoneAwareConfig for NatServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::WanOrPpp
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::NAT
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NatConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = crate::wan_service::nat::PortRange))]
    pub tcp_range: Range<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = crate::wan_service::nat::PortRange))]
    pub udp_range: Range<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = crate::wan_service::nat::PortRange))]
    pub icmp_in_range: Range<u16>,
}

impl NatConfig {
    fn validate_range(name: &str, range: &Range<u16>) -> Result<(), NatServiceError> {
        if range.start == 0 {
            return Err(NatServiceError::PortStartZero { name: name.to_string() });
        }
        if range.start >= range.end {
            return Err(NatServiceError::PortRangeInvalid {
                name: name.to_string(),
                start: range.start,
                end: range.end,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), NatServiceError> {
        Self::validate_range("tcp_range", &self.tcp_range)?;
        Self::validate_range("udp_range", &self.udp_range)?;
        Self::validate_range("icmp_in_range", &self.icmp_in_range)?;
        Ok(())
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            tcp_range: 32768..65535,
            udp_range: 32768..65535,
            icmp_in_range: 32768..65535,
        }
    }
}

impl crate::database::validator::ValidatableConfig for NatServiceConfig {
    fn validate(&self) -> Result<(), crate::service::ServiceConfigError> {
        self.nat_config.validate().map_err(|e| crate::service::ServiceConfigError::InvalidConfig {
            reason: e.to_string(),
        })
    }
}

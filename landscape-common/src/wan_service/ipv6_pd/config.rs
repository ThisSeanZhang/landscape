use crate::{
    database::repository::LandscapeDBStore, store::storev2::LandscapeStore,
    utils::time::get_f64_timestamp,
};
use serde::{Deserialize, Serialize};

use crate::net::MacAddr;
use crate::service::ServiceConfigError;

pub const DEFAULT_EXPECTED_PD_LEN: u8 = 60;

const fn default_expected_pd_len() -> u8 {
    DEFAULT_EXPECTED_PD_LEN
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPV6PDServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub config: IPV6PDConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPV6PDConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub mac: MacAddr,
    #[serde(default = "default_expected_pd_len")]
    #[cfg_attr(
        feature = "openapi",
        schema(required = false, default = 60, minimum = 56, maximum = 64)
    )]
    pub expected_pd_len: u8,
}

impl IPV6PDConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if !(56..=64).contains(&self.expected_pd_len) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "expected_pd_len ({}) must be between 56 and 64",
                    self.expected_pd_len
                ),
            });
        }
        Ok(())
    }
}

impl LandscapeDBStore<String> for IPV6PDServiceConfig {
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

impl LandscapeStore for IPV6PDServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl crate::config_service::iface::ZoneAwareConfig for IPV6PDServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> crate::config_service::iface::ZoneRequirement {
        crate::config_service::iface::ZoneRequirement::WanOrPpp
    }
    fn service_kind() -> crate::config_service::iface::ServiceKind {
        crate::config_service::iface::ServiceKind::Ipv6Pd
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{IPV6PDConfig, DEFAULT_EXPECTED_PD_LEN};

    fn config_with_expected_len(expected_pd_len: u8) -> IPV6PDConfig {
        serde_json::from_value(json!({
            "mac": "02:00:00:00:00:01",
            "expected_pd_len": expected_pd_len,
        }))
        .unwrap()
    }

    #[test]
    fn missing_expected_pd_len_defaults_to_sixty() {
        let config: IPV6PDConfig =
            serde_json::from_value(json!({ "mac": "02:00:00:00:00:01" })).unwrap();

        assert_eq!(config.expected_pd_len, DEFAULT_EXPECTED_PD_LEN);
        assert_eq!(
            serde_json::to_value(config).unwrap()["expected_pd_len"],
            DEFAULT_EXPECTED_PD_LEN
        );
    }

    #[test]
    fn expected_pd_len_accepts_supported_boundaries() {
        for expected_pd_len in [56, 60, 64] {
            assert!(config_with_expected_len(expected_pd_len).validate().is_ok());
        }
    }

    #[test]
    fn expected_pd_len_rejects_values_outside_supported_range() {
        for expected_pd_len in [55, 65] {
            assert!(config_with_expected_len(expected_pd_len).validate().is_err());
        }
    }
}

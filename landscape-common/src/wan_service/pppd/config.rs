use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::service::manager::ServiceKeyProvider;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PPPoEPlugin {
    #[default]
    RpPppoe,
    Pppoe,
}

impl fmt::Display for PPPoEPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PPPoEPlugin::RpPppoe => write!(f, "rp-pppoe.so"),
            PPPoEPlugin::Pppoe => write!(f, "pppoe.so"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PPPDServiceConfig {
    pub attach_iface_name: String,
    pub iface_name: String,
    pub enable: bool,
    pub pppd_config: PPPDConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl ServiceKeyProvider for PPPDServiceConfig {
    fn service_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for PPPDServiceConfig {
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

impl ZoneAwareConfig for PPPDServiceConfig {
    // PPPoE 语义：zone 匹配按物理口(attach)进行，iface_name 是拨号后的 ppp0 虚拟口
    #[allow(clippy::misnamed_getters)]
    fn iface_name(&self) -> &str {
        &self.attach_iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::WanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::PPPoE
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PPPDConfig {
    pub default_route: bool,
    pub peer_id: String,
    pub password: String,
    pub ac: Option<String>,
    #[serde(default)]
    pub plugin: PPPoEPlugin,
}

impl PPPDConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        fn check(field: &str, val: &str, allow_empty: bool) -> Result<(), ServiceConfigError> {
            if !allow_empty && val.is_empty() {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("{field} must not be empty"),
                });
            }
            if val.len() > 256 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("{field} exceeds 256 chars"),
                });
            }
            if val.contains('\n') || val.contains('\r') || val.contains('"') {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("{field} contains forbidden characters"),
                });
            }
            Ok(())
        }
        check("peer_id", &self.peer_id, false)?;
        check("password", &self.password, false)?;
        if let Some(ac) = &self.ac
            && !ac.trim().is_empty()
        {
            check("ac", ac, true)?;
        }
        Ok(())
    }
}

impl crate::database::validator::ValidatableConfig for PPPDServiceConfig {
    fn validate(&self) -> Result<(), ServiceConfigError> {
        super::validate_ppp_iface_name(&self.iface_name)?;
        if self.iface_name == self.attach_iface_name {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "PPPoE interface name cannot be the same as its attached interface"
                    .to_string(),
            });
        }
        self.pppd_config.validate()
    }
}

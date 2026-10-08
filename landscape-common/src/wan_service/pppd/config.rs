use std::fmt;

use serde::{Deserialize, Serialize};

use crate::service::ServiceConfigError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

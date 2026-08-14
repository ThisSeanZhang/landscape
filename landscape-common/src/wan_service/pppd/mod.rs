use std::fmt;
use std::path::PathBuf;
use std::{fs::OpenOptions, io::Write};

use serde::{Deserialize, Serialize};

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

const PPP_IFACE_NAME_MAX_LEN: usize = 15;

pub fn validate_ppp_iface_name(iface_name: &str) -> Result<(), ServiceConfigError> {
    let trimmed = iface_name.trim();
    if trimmed.is_empty() {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "PPPoE interface name must not be empty".to_string(),
        });
    }

    if trimmed != iface_name {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "PPPoE interface name must not have leading or trailing whitespace".to_string(),
        });
    }

    if iface_name.len() > PPP_IFACE_NAME_MAX_LEN {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!(
                "PPPoE interface name must be at most {PPP_IFACE_NAME_MAX_LEN} characters"
            ),
        });
    }

    if !iface_name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')) {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "PPPoE interface name may only contain ASCII letters, digits, '-' and '_'"
                .to_string(),
        });
    }

    Ok(())
}

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

impl LandscapeStore for PPPDServiceConfig {
    fn get_store_key(&self) -> String {
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
        if let Some(ac) = &self.ac {
            if !ac.trim().is_empty() {
                check("ac", ac, true)?;
            }
        }
        Ok(())
    }

    pub fn delete_config(&self, ppp_iface_name: &str) {
        if let Err(e) = validate_ppp_iface_name(ppp_iface_name) {
            tracing::error!("invalid PPP interface name for delete_config: {e}");
            return;
        }

        let _ = std::fs::remove_file(PathBuf::from("/etc/ppp/peers").join(ppp_iface_name));
    }

    #[allow(clippy::result_unit_err)] // 内部 API：调用方只关心成功与否
    pub fn write_config(&self, attach_iface_name: &str, ppp_iface_name: &str) -> Result<(), ()> {
        if let Err(e) = validate_ppp_iface_name(ppp_iface_name) {
            tracing::error!("invalid PPP interface name for write_config: {e}");
            return Err(());
        }

        let path = PathBuf::from("/etc/ppp/peers");
        if !path.exists() {
            tracing::error!("The directory /etc/ppp/peers does not exist, please check whether ppp is installed");
            return Err(());
        }

        let Ok(mut file) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(path.join(ppp_iface_name))
        else {
            tracing::error!("Error opening file handle");
            return Err(());
        };

        let ac_line = self
            .ac
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|ac| format!("pppoe-ac \"{}\"\n", ac))
            .unwrap_or_default();

        let config = format!(
            r#"
# 此文件每次启动 pppd 都会被复写, 所以修改此文件不会有任何效果, 仅作为检查启动配置
# This file is truncated each time pppd is started, so editing this file has no effect.
noipdefault
hide-password
lcp-echo-interval 30
lcp-echo-failure 4
noauth
persist
#mtu 1492
maxfail 1
#holdoff 20
plugin {plugin}
nic-{ifacename}
{ac_line}
user "{user}"
password "{pass}"
ifname {ppp_iface_name}
"#,
            plugin = self.plugin,
            ifacename = attach_iface_name,
            ac_line = ac_line,
            user = self.peer_id,
            pass = self.password,
            ppp_iface_name = ppp_iface_name
        );
        let Ok(_) = file.write_all(config.as_bytes()) else {
            tracing::error!("Error writing configuration file bytes");
            return Err(());
        };

        Ok(())
    }
}

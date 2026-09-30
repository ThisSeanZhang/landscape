use super::config::{LandscapeLanHostnameConfig, normalize_lan_suffix};
use super::error::LanHostnameError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanHostnameConfig {
    pub enable: bool,
    pub lan_suffix: String,
}

impl Default for LanHostnameConfig {
    fn default() -> Self {
        Self {
            enable: crate::DEFAULT_LAN_HOSTNAME_ENABLE,
            lan_suffix: crate::DEFAULT_DNS_LAN_SUFFIX.to_string(),
        }
    }
}

impl LanHostnameConfig {
    pub fn from_file_config(config: &LandscapeLanHostnameConfig) -> Result<Self, LanHostnameError> {
        let mut runtime = Self::default();
        runtime.update_from_file_config(config)?;
        Ok(runtime)
    }

    pub fn update_from_file_config(
        &mut self,
        config: &LandscapeLanHostnameConfig,
    ) -> Result<(), LanHostnameError> {
        self.enable = config.enable.unwrap_or(crate::DEFAULT_LAN_HOSTNAME_ENABLE);
        self.lan_suffix = match &config.lan_suffix {
            Some(value) => {
                let normalized = normalize_lan_suffix(value)?;
                if normalized.is_empty() {
                    crate::DEFAULT_DNS_LAN_SUFFIX.to_string()
                } else {
                    normalized
                }
            }
            None => crate::DEFAULT_DNS_LAN_SUFFIX.to_string(),
        };
        Ok(())
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeLanHostnameConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub lan_suffix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanHostnameConfig {
    pub lan_suffix: String,
}

impl Default for LanHostnameConfig {
    fn default() -> Self {
        Self {
            lan_suffix: crate::DEFAULT_DNS_LAN_SUFFIX.to_string(),
        }
    }
}

impl LanHostnameConfig {
    pub fn update_from_file_config(&mut self, config: &LandscapeLanHostnameConfig) {
        if let Some(v) = &config.lan_suffix {
            self.lan_suffix = v.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::LandscapeConfig;

    use super::{LanHostnameConfig, LandscapeLanHostnameConfig};

    #[test]
    fn legacy_hostname_registry_key_deserializes_as_lan_hostname() {
        let config: LandscapeConfig = toml::from_str(
            r#"
                [hostname_registry]
                lan_suffix = "home"
            "#,
        )
        .unwrap();

        assert_eq!(config.lan_hostname.lan_suffix.as_deref(), Some("home"));
    }

    #[test]
    fn legacy_and_canonical_keys_cannot_be_combined() {
        let config = toml::from_str::<LandscapeConfig>(
            r#"
                [hostname_registry]
                lan_suffix = "legacy"

                [lan_hostname]
                lan_suffix = "canonical"
            "#,
        );

        assert!(config.is_err());
    }

    #[test]
    fn serialization_uses_only_lan_hostname_key() {
        let config = LandscapeConfig {
            lan_hostname: LandscapeLanHostnameConfig { lan_suffix: Some("home".to_string()) },
            ..Default::default()
        };

        let serialized = toml::to_string(&config).unwrap();

        assert!(serialized.contains("[lan_hostname]"));
        assert!(!serialized.contains("[hostname_registry]"));
    }

    #[test]
    fn runtime_config_updates_from_file_config() {
        let mut runtime = LanHostnameConfig::default();

        runtime.update_from_file_config(&LandscapeLanHostnameConfig {
            lan_suffix: Some("home".to_string()),
        });

        assert_eq!(runtime.lan_suffix, "home");
    }
}

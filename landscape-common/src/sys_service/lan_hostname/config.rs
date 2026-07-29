use serde::{Deserialize, Serialize};

use crate::dns::domain::normalize_domain_name;

use super::LanHostnameError;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeLanHostnameConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub enable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub lan_suffix: Option<String>,
}

impl LandscapeLanHostnameConfig {
    pub fn normalized(mut self) -> Result<Self, LanHostnameError> {
        if let Some(suffix) = self.lan_suffix.take() {
            let suffix = normalize_lan_suffix(&suffix)?;
            self.lan_suffix = (!suffix.is_empty()).then_some(suffix);
        }
        Ok(self)
    }
}

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

pub fn normalize_lan_suffix(suffix: &str) -> Result<String, LanHostnameError> {
    let trimmed = suffix.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    // Permit one optional root dot, but reject multi-label input before the
    // shared domain normalizer removes trailing dots.
    if trimmed.strip_suffix('.').unwrap_or(trimmed).contains('.') {
        return Err(LanHostnameError::MultipleLabels { suffix: suffix.to_string() });
    }

    let normalized = normalize_domain_name(trimmed)
        .map_err(|_| LanHostnameError::InvalidIdna { suffix: suffix.to_string() })?;
    if normalized.contains('.') {
        return Err(LanHostnameError::MultipleLabels { suffix: suffix.to_string() });
    }
    if normalized.len() > 63 {
        return Err(LanHostnameError::TooLong { suffix: suffix.to_string() });
    }
    if normalized.starts_with('-') || normalized.ends_with('-') {
        return Err(LanHostnameError::InvalidHyphen { suffix: suffix.to_string() });
    }
    if !normalized.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
        return Err(LanHostnameError::InvalidCharacter { suffix: suffix.to_string() });
    }
    if matches!(normalized.as_str(), "invalid" | "test" | "onion" | "localhost" | "arpa") {
        return Err(LanHostnameError::Reserved { suffix: suffix.to_string() });
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use crate::config::LandscapeConfig;
    use crate::error::LdApiErrorInfo;

    use super::{
        normalize_lan_suffix, LanHostnameConfig, LanHostnameError, LandscapeLanHostnameConfig,
    };

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
            lan_hostname: LandscapeLanHostnameConfig {
                lan_suffix: Some("home".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let serialized = toml::to_string(&config).unwrap();

        assert!(serialized.contains("[lan_hostname]"));
        assert!(!serialized.contains("[hostname_registry]"));
    }

    #[test]
    fn runtime_config_updates_from_file_config() {
        let runtime = LanHostnameConfig::from_file_config(&LandscapeLanHostnameConfig {
            lan_suffix: Some("home".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert!(runtime.enable);
        assert_eq!(runtime.lan_suffix, "home");
    }

    #[test]
    fn runtime_config_uses_default_when_suffix_is_omitted() {
        let runtime =
            LanHostnameConfig::from_file_config(&LandscapeLanHostnameConfig::default()).unwrap();

        assert!(runtime.enable);
        assert_eq!(runtime.lan_suffix, crate::DEFAULT_DNS_LAN_SUFFIX);
    }

    #[test]
    fn runtime_config_can_disable_lan_hostname_resolution() {
        let runtime = LanHostnameConfig::from_file_config(&LandscapeLanHostnameConfig {
            enable: Some(false),
            lan_suffix: Some("home".to_string()),
        })
        .unwrap();

        assert!(!runtime.enable);
        assert_eq!(runtime.lan_suffix, "home");
    }

    #[test]
    fn empty_lan_suffix_uses_default() {
        let normalized = LandscapeLanHostnameConfig {
            enable: Some(true),
            lan_suffix: Some("   ".to_string()),
        }
        .normalized()
        .unwrap();
        let runtime = LanHostnameConfig::from_file_config(&normalized).unwrap();

        assert!(normalized.lan_suffix.is_none());
        assert_eq!(runtime.lan_suffix, crate::DEFAULT_DNS_LAN_SUFFIX);
    }

    #[test]
    fn normalizes_lan_suffix_to_ascii_lowercase_label() {
        assert_eq!(normalize_lan_suffix(" BÜCHER. ").unwrap(), "xn--bcher-kva");
        assert_eq!(normalize_lan_suffix("LAN").unwrap(), "lan");
    }

    #[test]
    fn empty_lan_suffix_remains_empty() {
        assert_eq!(normalize_lan_suffix("   ").unwrap(), "");
    }

    #[test]
    fn rejects_multi_label_lan_suffix() {
        let error = normalize_lan_suffix("home.arpa").unwrap_err();

        assert!(matches!(error, LanHostnameError::MultipleLabels { .. }));
        assert_eq!(error.error_id(), "lan_hostname.invalid_suffix.multiple_labels");
    }

    #[test]
    fn rejects_multiple_trailing_dots() {
        let error = normalize_lan_suffix("lan..").unwrap_err();

        assert!(matches!(error, LanHostnameError::MultipleLabels { .. }));
        assert_eq!(error.error_id(), "lan_hostname.invalid_suffix.multiple_labels");
    }

    #[test]
    fn reports_specific_lan_suffix_validation_errors() {
        let invalid_idna = normalize_lan_suffix("\u{200d}").unwrap_err();
        assert!(matches!(invalid_idna, LanHostnameError::InvalidIdna { .. }));
        assert_eq!(invalid_idna.error_id(), "lan_hostname.invalid_suffix.invalid_idna");

        let too_long = normalize_lan_suffix(&"a".repeat(64)).unwrap_err();
        assert!(matches!(too_long, LanHostnameError::TooLong { .. }));
        assert_eq!(too_long.error_id(), "lan_hostname.invalid_suffix.too_long");

        let invalid_hyphen = normalize_lan_suffix("-lan").unwrap_err();
        assert!(matches!(invalid_hyphen, LanHostnameError::InvalidHyphen { .. }));
        assert_eq!(invalid_hyphen.error_id(), "lan_hostname.invalid_suffix.invalid_hyphen");

        let invalid_character = normalize_lan_suffix("lan_name").unwrap_err();
        assert!(matches!(invalid_character, LanHostnameError::InvalidCharacter { .. }));
        assert_eq!(invalid_character.error_id(), "lan_hostname.invalid_suffix.invalid_character");
    }

    #[test]
    fn rejects_suffixes_reserved_by_the_dns_resolver() {
        for suffix in ["invalid", "test", "onion", "localhost", "arpa"] {
            let error = normalize_lan_suffix(suffix).unwrap_err();

            assert!(matches!(error, LanHostnameError::Reserved { .. }));
            assert_eq!(error.error_id(), "lan_hostname.invalid_suffix.reserved");
        }
    }
}

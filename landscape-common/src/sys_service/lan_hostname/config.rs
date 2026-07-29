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

    // Accept the surrounding dots operators commonly use when entering a DNS
    // suffix, but reject empty labels inside the suffix.
    let trimmed = trimmed.trim_matches('.');
    if trimmed.is_empty() || trimmed.split('.').any(str::is_empty) {
        return Err(LanHostnameError::EmptyLabel { suffix: suffix.to_string() });
    }

    let normalized = normalize_domain_name(trimmed)
        .map_err(|_| LanHostnameError::InvalidIdna { suffix: suffix.to_string() })?;
    if normalized.len() > 253 || normalized.split('.').any(|label| label.len() > 63) {
        return Err(LanHostnameError::TooLong { suffix: suffix.to_string() });
    }
    if normalized.split('.').any(|label| label.starts_with('-') || label.ends_with('-')) {
        return Err(LanHostnameError::InvalidHyphen { suffix: suffix.to_string() });
    }
    if !normalized
        .split('.')
        .all(|label| label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
    {
        return Err(LanHostnameError::InvalidCharacter { suffix: suffix.to_string() });
    }
    if conflicts_with_resolver_namespace(&normalized) {
        return Err(LanHostnameError::Reserved { suffix: suffix.to_string() });
    }

    Ok(normalized)
}

fn conflicts_with_resolver_namespace(suffix: &str) -> bool {
    const RESERVED_TLDS: &[&str] = &["invalid", "test", "onion", "localhost", "local"];
    const RESERVED_ARPA_ZONES: &[&str] =
        &["in-addr.arpa", "ip6.arpa", "resolver.arpa", "ipv4only.arpa"];

    let tld = suffix.rsplit('.').next().unwrap_or_default();
    RESERVED_TLDS.contains(&tld)
        || suffix == "arpa"
        || RESERVED_ARPA_ZONES.iter().any(|zone| is_same_or_subdomain(suffix, zone))
}

fn is_same_or_subdomain(name: &str, zone: &str) -> bool {
    name == zone || name.strip_suffix(zone).is_some_and(|prefix| prefix.ends_with('.'))
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
    fn normalizes_lan_suffix_to_ascii_lowercase_domain() {
        assert_eq!(normalize_lan_suffix(" BÜCHER. ").unwrap(), "xn--bcher-kva");
        assert_eq!(normalize_lan_suffix("LAN").unwrap(), "lan");
        assert_eq!(normalize_lan_suffix(".Home.ARPA.").unwrap(), "home.arpa");
    }

    #[test]
    fn empty_lan_suffix_remains_empty() {
        assert_eq!(normalize_lan_suffix("   ").unwrap(), "");
    }

    #[test]
    fn accepts_multi_label_lan_suffix() {
        assert_eq!(normalize_lan_suffix("home.arpa").unwrap(), "home.arpa");
    }

    #[test]
    fn rejects_empty_labels() {
        let error = normalize_lan_suffix("home..arpa").unwrap_err();

        assert!(matches!(error, LanHostnameError::EmptyLabel { .. }));
        assert_eq!(error.error_id(), "lan_hostname.invalid_suffix.empty_label");
    }

    #[test]
    fn reports_specific_lan_suffix_validation_errors() {
        let invalid_idna = normalize_lan_suffix("\u{200d}").unwrap_err();
        assert!(matches!(invalid_idna, LanHostnameError::InvalidIdna { .. }));
        assert_eq!(invalid_idna.error_id(), "lan_hostname.invalid_suffix.invalid_idna");

        let too_long = normalize_lan_suffix(&"a".repeat(64)).unwrap_err();
        assert!(matches!(too_long, LanHostnameError::TooLong { .. }));
        assert_eq!(too_long.error_id(), "lan_hostname.invalid_suffix.too_long");

        let long_domain = (0..4).map(|_| "a".repeat(63)).collect::<Vec<_>>().join(".");
        let too_long = normalize_lan_suffix(&long_domain).unwrap_err();
        assert!(matches!(too_long, LanHostnameError::TooLong { .. }));

        let invalid_hyphen = normalize_lan_suffix("-lan").unwrap_err();
        assert!(matches!(invalid_hyphen, LanHostnameError::InvalidHyphen { .. }));
        assert_eq!(invalid_hyphen.error_id(), "lan_hostname.invalid_suffix.invalid_hyphen");

        let invalid_character = normalize_lan_suffix("lan_name").unwrap_err();
        assert!(matches!(invalid_character, LanHostnameError::InvalidCharacter { .. }));
        assert_eq!(invalid_character.error_id(), "lan_hostname.invalid_suffix.invalid_character");
    }

    #[test]
    fn rejects_suffixes_reserved_by_the_dns_resolver() {
        for suffix in [
            "invalid",
            "corp.test",
            "service.onion",
            "localhost",
            "corp.localhost",
            "local",
            "office.local",
            "arpa",
            "in-addr.arpa",
            "corp.in-addr.arpa",
            "ip6.arpa",
            "corp.ip6.arpa",
            "resolver.arpa",
            "corp.resolver.arpa",
            "ipv4only.arpa",
            "corp.ipv4only.arpa",
        ] {
            let error = normalize_lan_suffix(suffix).unwrap_err();

            assert!(matches!(error, LanHostnameError::Reserved { .. }));
            assert_eq!(error.error_id(), "lan_hostname.invalid_suffix.reserved");
        }
    }

    #[test]
    fn accepts_non_reserved_arpa_suffixes() {
        for suffix in ["home.arpa", "mylan.arpa", "in-addr.home.arpa"] {
            assert_eq!(normalize_lan_suffix(suffix).unwrap(), suffix);
        }
    }
}

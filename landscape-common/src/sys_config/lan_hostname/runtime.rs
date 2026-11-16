use super::config::LandscapeLanHostnameConfig;
use super::error::LanHostnameError;
use crate::dns::domain::normalize_domain_name;
use crate::sys_config::{RuntimeConfigSource, runtime::warn_repair};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanHostnameRuntimeConfig {
    pub enable: bool,
    pub lan_suffix: String,
}

impl Default for LanHostnameRuntimeConfig {
    fn default() -> Self {
        Self {
            enable: crate::DEFAULT_LAN_HOSTNAME_ENABLE,
            lan_suffix: crate::DEFAULT_DNS_LAN_SUFFIX.to_string(),
        }
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

impl RuntimeConfigSource for LandscapeLanHostnameConfig {
    type Runtime = LanHostnameRuntimeConfig;
    type Error = LanHostnameError;

    fn validate(&self) -> Result<(), Self::Error> {
        if let Some(suffix) = &self.lan_suffix {
            normalize_lan_suffix(suffix)?;
        }
        Ok(())
    }

    fn build_runtime(&self) -> Self::Runtime {
        let mut runtime = LanHostnameRuntimeConfig {
            enable: self.enable.unwrap_or(crate::DEFAULT_LAN_HOSTNAME_ENABLE),
            ..Default::default()
        };
        match self.lan_suffix.as_deref().map(normalize_lan_suffix).transpose() {
            Ok(Some(suffix)) if !suffix.is_empty() => runtime.lan_suffix = suffix,
            Ok(_) => {}
            Err(error) => {
                warn_repair(
                    "lan_hostname",
                    "lan_suffix",
                    error,
                    "disabled LAN hostname resolution",
                    false,
                );
                runtime.enable = false;
            }
        }
        runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_disables_invalid_suffix_for_all_enable_settings() {
        for enable in [None, Some(true), Some(false)] {
            for suffix in ["corp.test", "home..arpa", "-lan"] {
                let config = LandscapeLanHostnameConfig { enable, lan_suffix: Some(suffix.into()) };
                assert!(config.to_runtime().is_err());
                let runtime = config.build_runtime();
                assert!(!runtime.enable);
                assert_eq!(runtime.lan_suffix, crate::DEFAULT_DNS_LAN_SUFFIX);
                assert_eq!(config.enable, enable);
                assert_eq!(config.lan_suffix.as_deref(), Some(suffix));
            }
        }
    }

    #[test]
    fn valid_suffix_has_identical_strict_and_startup_results() {
        let config = LandscapeLanHostnameConfig {
            enable: Some(false),
            lan_suffix: Some(" .Home.ARPA. ".into()),
        };
        assert_eq!(config.to_runtime().unwrap(), config.build_runtime());
        assert_eq!(config.build_runtime().lan_suffix, "home.arpa");
        assert_eq!(
            LandscapeLanHostnameConfig::default().to_runtime().unwrap(),
            LanHostnameRuntimeConfig::default()
        );
    }
}

use serde::{Deserialize, Serialize};

use crate::service::ServiceConfigError;

use super::WAN_IID_MARKER;

pub const DEFAULT_IA_NA_POOL_SPAN: u64 = 0xFFFF;

/// DHCPv6 server config — parameters only.
/// Prefix pools are defined in LanIPv6ConfigV2.prefix_groups.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv6ServerConfig {
    pub enable: bool,

    /// IA_NA: stateful address assignment
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub ia_na: Option<DHCPv6IANAConfig>,

    /// IA_PD: prefix delegation to downstream routers
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub ia_pd: Option<DHCPv6IAPDConfig>,
}

impl Default for DHCPv6ServerConfig {
    fn default() -> Self {
        Self { enable: false, ia_na: None, ia_pd: None }
    }
}

/// IA_NA config — address assignment parameters.
/// Prefixes come from prefix groups with an NA configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv6IANAConfig {
    /// Max prefix length to qualify (e.g., 64 means prefixes with len <= 64 are used).
    pub max_prefix_len: u8,

    /// Host part range start (suffix value, e.g., 0x100 = 256)
    pub pool_start: u64,

    /// Host part range end (exclusive; defaults to pool_start + 65535)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub pool_end: Option<u64>,

    // Deprecated: IA_NA lifetimes now come from LanIPv6ConfigV2::lifetime.
    // Remove both fields and their validation together. Configs saved without them
    // can roll back to this version through the 300/600 serde defaults below.
    /// Legacy preferred lifetime (seconds), default: 300.
    #[serde(default = "default_preferred_lifetime")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub preferred_lifetime: u32,

    /// Legacy valid lifetime (seconds), default: 600.
    #[serde(default = "default_valid_lifetime")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub valid_lifetime: u32,
}

/// IA_PD config — prefix delegation parameters.
/// `delegate_prefix_len` sets the minimum network size for qualifying pool blocks:
/// only blocks whose `prefix_len <= delegate_prefix_len` (i.e. at least as large as a /N network)
/// enter the pool. The actual delegated prefix length in the DHCPv6 response is determined
/// by the pool block's own `PdPrefixRangeConfig.pool_len`.
/// Prefixes come from prefix groups with a PD configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv6IAPDConfig {
    /// Minimum network size for qualifying PD pool blocks (upper bound on prefix_len).
    /// Blocks with prefix_len > this value (i.e. smaller networks) are excluded.
    /// Example: setting /56 means /48 and /56 blocks qualify, but /60 does not.
    /// The actual delegated prefix length is taken from the block's own config.
    pub delegate_prefix_len: u8,

    // Deprecated: IA_PD lifetimes now come from LanIPv6ConfigV2::lifetime.
    // Remove both fields and their validation together. Configs saved without them
    // can roll back to this version through the 300/600 serde defaults below.
    /// Legacy preferred lifetime (seconds), default: 300.
    #[serde(default = "default_preferred_lifetime")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub preferred_lifetime: u32,

    /// Legacy valid lifetime (seconds), default: 600.
    #[serde(default = "default_valid_lifetime")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub valid_lifetime: u32,
}

fn default_preferred_lifetime() -> u32 {
    300
}

fn default_valid_lifetime() -> u32 {
    600
}

impl DHCPv6ServerConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if !self.enable {
            return Ok(());
        }

        if let Some(ia_na) = &self.ia_na {
            if ia_na.max_prefix_len == 0 || ia_na.max_prefix_len > 127 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA max_prefix_len ({}) must be between 1 and 127",
                        ia_na.max_prefix_len
                    ),
                });
            }

            if ia_na.pool_start >= WAN_IID_MARKER {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_start ({}) must keep IID bit 63 clear",
                        ia_na.pool_start
                    ),
                });
            }

            let pool_end = ia_na
                .pool_end
                .unwrap_or_else(|| ia_na.pool_start.saturating_add(DEFAULT_IA_NA_POOL_SPAN));
            if pool_end <= ia_na.pool_start {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_end ({}) must be > pool_start ({})",
                        pool_end, ia_na.pool_start
                    ),
                });
            }
            if pool_end > WAN_IID_MARKER {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_end ({}) must not exceed the LAN IID exclusive upper bound ({})",
                        pool_end, WAN_IID_MARKER
                    ),
                });
            }
            if ia_na.valid_lifetime == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "IA_NA valid_lifetime must be > 0".to_string(),
                });
            }

            if ia_na.preferred_lifetime > ia_na.valid_lifetime {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "IA_NA preferred_lifetime must be <= valid_lifetime".to_string(),
                });
            }
        }

        if let Some(ia_pd) = &self.ia_pd {
            if ia_pd.delegate_prefix_len == 0 || ia_pd.delegate_prefix_len > 128 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD delegate_prefix_len ({}) must be between 1 and 128",
                        ia_pd.delegate_prefix_len
                    ),
                });
            }

            if ia_pd.valid_lifetime == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "IA_PD valid_lifetime must be > 0".to_string(),
                });
            }

            if ia_pd.preferred_lifetime > ia_pd.valid_lifetime {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "IA_PD preferred_lifetime must be <= valid_lifetime".to_string(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_ia_na(pool_start: u64, pool_end: Option<u64>) -> DHCPv6ServerConfig {
        DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start,
                pool_end,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }),
            ia_pd: None,
        }
    }

    #[test]
    fn validate_allows_temporarily_disabling_ia_na_and_ia_pd() {
        let config = DHCPv6ServerConfig { enable: true, ia_na: None, ia_pd: None };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_accepts_lan_pool_ending_at_namespace_boundary() {
        let config = enabled_ia_na(WAN_IID_MARKER - 2, Some(WAN_IID_MARKER));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_pool_start_in_wan_namespace() {
        let config = enabled_ia_na(WAN_IID_MARKER, Some(WAN_IID_MARKER + 1));
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_explicit_pool_end_past_namespace_boundary() {
        let config = enabled_ia_na(WAN_IID_MARKER - 2, Some(WAN_IID_MARKER + 1));
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_default_pool_crossing_namespace_boundary() {
        let config = enabled_ia_na(WAN_IID_MARKER - DEFAULT_IA_NA_POOL_SPAN + 1, None);
        assert!(config.validate().is_err());
    }
}

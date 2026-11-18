use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(from = "DnsFileConfig")]
pub struct LandscapeDnsConfig {
    pub cache: LandscapeDnsCacheConfig,
    pub doh: LandscapeDohConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeDnsCacheConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub negative_ttl: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeDohConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub http_endpoint: Option<String>,
}

/// Old flat keys can coexist with nested tables until both blocks have been edited.
#[derive(Default, Deserialize)]
#[serde(default)]
struct DnsFileConfig {
    cache: LandscapeDnsCacheConfig,
    doh: LandscapeDohConfig,
    cache_capacity: Option<u32>,
    cache_ttl: Option<u32>,
    negative_cache_ttl: Option<u32>,
    doh_listen_port: Option<u16>,
    doh_http_endpoint: Option<String>,
}

impl From<DnsFileConfig> for LandscapeDnsConfig {
    fn from(file: DnsFileConfig) -> Self {
        Self {
            cache: LandscapeDnsCacheConfig {
                capacity: file.cache.capacity.or(file.cache_capacity),
                ttl: file.cache.ttl.or(file.cache_ttl),
                negative_ttl: file.cache.negative_ttl.or(file.negative_cache_ttl),
            },
            doh: LandscapeDohConfig {
                listen_port: file.doh.listen_port.or(file.doh_listen_port),
                http_endpoint: file.doh.http_endpoint.or(file.doh_http_endpoint),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_fields_override_flat_keys_and_export_in_the_new_format() {
        let config: LandscapeDnsConfig = toml::from_str(
            r#"
            cache_capacity = 100
            cache_ttl = 300
            doh_http_endpoint = '/old'
            tcp_enabled = false
            [cache]
            ttl = 600
            [doh]
            listen_port = 8443
            "#,
        )
        .unwrap();
        assert_eq!(config.cache.capacity, Some(100));
        assert_eq!(config.cache.ttl, Some(600));
        assert_eq!(config.doh.http_endpoint.as_deref(), Some("/old"));
        assert_eq!(config.doh.listen_port, Some(8443));
        let saved = toml::to_string(&config).unwrap();
        assert!(!saved.contains("tcp_enabled") && !saved.contains("cache_ttl"));
        assert_eq!(toml::from_str::<LandscapeDnsConfig>(&saved).unwrap(), config);
    }
}

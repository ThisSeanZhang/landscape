use landscape_macro::LdApiError;

use crate::config::ConfigId;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum GatewayError {
    #[error("Gateway rule '{0}' not found")]
    #[api_error(id = "gateway.rule_not_found", status = 404)]
    NotFound(ConfigId),
    #[error("Gateway rule type 'legacy_path_prefix' is read-only and cannot be created or updated")]
    #[api_error(id = "gateway.legacy_path_prefix_unsupported", status = 400)]
    LegacyPathPrefixUnsupported,
    #[error("Gateway rule '{rule_name}' requires at least one domain")]
    #[api_error(id = "gateway.domains_required", status = 400)]
    DomainsRequired { rule_name: String },
    #[error("Host domain conflict: domain '{domain}' already used by rule '{rule_name}'")]
    #[api_error(id = "gateway.host_conflict", status = 409)]
    HostConflict { domain: String, rule_name: String },
    #[error("Wildcard domain '{wildcard}' covers specific domain '{domain}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.wildcard_covers_domain", status = 409)]
    WildcardCoversDomain { wildcard: String, domain: String, rule_name: String },
    #[error("Domain pattern '{domain}' overlaps with '{other_domain}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.domain_pattern_overlap", status = 409)]
    DomainPatternOverlap { domain: String, other_domain: String, rule_name: String },
    #[error("Path prefix '{new_prefix}' overlaps with '{existing_prefix}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.path_prefix_overlap", status = 409)]
    PathPrefixOverlap { new_prefix: String, existing_prefix: String, rule_name: String },
    #[error("Path prefix '{prefix}' is invalid")]
    #[api_error(id = "gateway.invalid_path_prefix", status = 400)]
    InvalidPathPrefix { prefix: String },
    #[error("Duplicate path prefix '{prefix}' in rule '{rule_name}'")]
    #[api_error(id = "gateway.duplicate_path_group_prefix", status = 409)]
    DuplicatePathGroupPrefix { prefix: String, rule_name: String },
    #[error("SNI passthrough rules do not support request header injection or client IP headers")]
    #[api_error(id = "gateway.sni_proxy_header_unsupported", status = 400)]
    SniProxyHeaderUnsupported,
    #[error("Invalid request header name '{name}'")]
    #[api_error(id = "gateway.invalid_header_name", status = 400)]
    InvalidHeaderName { name: String },
    #[error("Invalid request header value for '{name}'")]
    #[api_error(id = "gateway.invalid_header_value", status = 400)]
    InvalidHeaderValue { name: String },
}

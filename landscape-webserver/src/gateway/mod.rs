use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::{header::HeaderName, HeaderValue};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::dns::redirect::{
    DnsRedirectAnswerMode, DynamicDnsMatch, DynamicDnsRedirectBatch, DynamicDnsRedirectRecord,
    DynamicDnsRedirectScope, DEFAULT_BLOCK_METADATA_QUERIES, DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
};
use landscape_common::service::ServiceStatus;
use landscape_common::sys_service::gateway::{
    ClientIpHeaderPolicy, GatewayError, HttpPathGroup, HttpUpstreamConfig, HttpUpstreamMatchRule,
    HttpUpstreamRuleConfig,
};
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{
    api::LandscapeApiResp,
    error::{LandscapeApiError, LandscapeApiResult},
};

const GATEWAY_DYNAMIC_DNS_REDIRECT_SOURCE_ID: &str = "gateway-auto-local-ips";

pub fn get_gateway_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_gateway_rules, create_gateway_rule))
        .routes(routes!(get_gateway_rule, delete_gateway_rule))
        .routes(routes!(get_gateway_status, restart_gateway))
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct GatewayStatus {
    pub supported: bool,
    pub status: ServiceStatus,
    pub http_port: u16,
    pub https_port: u16,
    pub https_ready: bool,
    pub rule_count: usize,
}

#[utoipa::path(
    get,
    path = "/rules",
    tag = "Gateway",
    responses((status = 200, body = CommonApiResp<Vec<HttpUpstreamRuleConfig>>))
)]
async fn list_gateway_rules(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<HttpUpstreamRuleConfig>> {
    ensure_gateway_supported(&state)?;
    let result = state.gateway_service.list_rules().await.unwrap_or_default();
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/rules",
    tag = "Gateway",
    request_body = HttpUpstreamRuleConfig,
    responses((status = 200, body = CommonApiResp<HttpUpstreamRuleConfig>))
)]
async fn create_gateway_rule(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<HttpUpstreamRuleConfig>,
) -> LandscapeApiResult<HttpUpstreamRuleConfig> {
    ensure_gateway_supported(&state)?;
    validate_gateway_rule(&state, &config).await?;

    let saved = state.gateway_service.save_rule(config).await?;

    sync_gateway_dynamic_dns_redirects(&state).await;
    reload_gateway_rules(&state).await;

    LandscapeApiResp::success(saved)
}

#[utoipa::path(
    get,
    path = "/rules/{id}",
    tag = "Gateway",
    params(("id" = Uuid, Path, description = "Gateway rule ID")),
    responses(
        (status = 200, body = CommonApiResp<HttpUpstreamRuleConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_gateway_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<HttpUpstreamRuleConfig> {
    ensure_gateway_supported(&state)?;
    let result = state.gateway_service.find_rule(id).await?;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(GatewayError::NotFound(id))?
    }
}

#[utoipa::path(
    delete,
    path = "/rules/{id}",
    tag = "Gateway",
    params(("id" = Uuid, Path, description = "Gateway rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn delete_gateway_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    ensure_gateway_supported(&state)?;
    state.gateway_service.delete_rule(id).await?;

    sync_gateway_dynamic_dns_redirects(&state).await;
    reload_gateway_rules(&state).await;

    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/status",
    tag = "Gateway",
    responses((status = 200, body = CommonApiResp<GatewayStatus>))
)]
async fn get_gateway_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GatewayStatus> {
    LandscapeApiResp::success(build_gateway_status(&state).await)
}

#[utoipa::path(
    post,
    path = "/restart",
    tag = "Gateway",
    responses((status = 200, body = CommonApiResp<GatewayStatus>))
)]
async fn restart_gateway(State(state): State<LandscapeApp>) -> LandscapeApiResult<GatewayStatus> {
    ensure_gateway_supported(&state)?;
    let gateway_config = state.config_service.get_gateway_runtime_config();
    state.gateway_service.restart(gateway_config, std::time::Duration::from_secs(10)).await;
    LandscapeApiResp::success(build_gateway_status(&state).await)
}

async fn reload_gateway_rules(state: &LandscapeApp) {
    state.gateway_service.reload_rules().await;
}

async fn build_gateway_status(state: &LandscapeApp) -> GatewayStatus {
    let config = state.gateway_service.config();
    GatewayStatus {
        supported: state.gateway_service.is_supported(),
        status: state.gateway_service.status(),
        http_port: config.http_port,
        https_port: config.https_port,
        https_ready: state.gateway_service.has_https_listener(),
        rule_count: state.gateway_service.stored_rule_count().await,
    }
}

pub(crate) async fn sync_gateway_dynamic_dns_redirects(state: &LandscapeApp) {
    let rules = if state.gateway_service.is_supported() {
        state.gateway_service.list_rules().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let batch = build_gateway_dynamic_dns_redirect_batch(&rules);
    let _ = state.dns_redirect_service.set_dynamic_batch(batch).await;
}

async fn validate_gateway_rule(
    state: &LandscapeApp,
    config: &HttpUpstreamRuleConfig,
) -> Result<(), GatewayError> {
    let existing_rules = state.gateway_service.list_rules().await.unwrap_or_default();

    validate_rule_shape(config)?;

    match &config.match_rule {
        HttpUpstreamMatchRule::Host { .. } | HttpUpstreamMatchRule::SniProxy => {
            check_domain_conflicts(&config.domains, config, &existing_rules)?;
        }
        HttpUpstreamMatchRule::LegacyPathPrefix { .. } => {
            return Err(GatewayError::LegacyPathPrefixUnsupported);
        }
    }

    Ok(())
}

fn ensure_gateway_supported(state: &LandscapeApp) -> Result<(), LandscapeApiError> {
    if state.gateway_service.is_supported() {
        Ok(())
    } else {
        Err(LandscapeApiError::GatewayUnsupportedTarget)
    }
}

fn validate_rule_shape(config: &HttpUpstreamRuleConfig) -> Result<(), GatewayError> {
    match &config.match_rule {
        HttpUpstreamMatchRule::Host { path_groups } => {
            validate_domains(config)?;
            validate_http_upstream(&config.upstream)?;
            validate_path_groups(&config.name, path_groups)?;
        }
        HttpUpstreamMatchRule::SniProxy => {
            validate_domains(config)?;
            validate_sni_upstream(&config.upstream)?;
        }
        HttpUpstreamMatchRule::LegacyPathPrefix { .. } => {
            return Err(GatewayError::LegacyPathPrefixUnsupported);
        }
    }

    Ok(())
}

fn validate_domains(config: &HttpUpstreamRuleConfig) -> Result<(), GatewayError> {
    if config.domains.iter().any(|domain| !domain.trim().is_empty()) {
        Ok(())
    } else {
        Err(GatewayError::DomainsRequired { rule_name: config.name.clone() })
    }
}

fn validate_http_upstream(upstream: &HttpUpstreamConfig) -> Result<(), GatewayError> {
    validate_header_block(upstream)
}

fn validate_sni_upstream(upstream: &HttpUpstreamConfig) -> Result<(), GatewayError> {
    if !upstream.request_headers.is_empty()
        || !matches!(upstream.client_ip_headers, ClientIpHeaderPolicy::None)
    {
        return Err(GatewayError::SniProxyHeaderUnsupported);
    }

    validate_header_block(upstream)
}

fn validate_header_block(upstream: &HttpUpstreamConfig) -> Result<(), GatewayError> {
    for header in &upstream.request_headers {
        HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| GatewayError::InvalidHeaderName { name: header.name.clone() })?;
        HeaderValue::from_str(&header.value)
            .map_err(|_| GatewayError::InvalidHeaderValue { name: header.name.clone() })?;
    }

    Ok(())
}

fn validate_path_groups(
    rule_name: &str,
    path_groups: &[HttpPathGroup],
) -> Result<(), GatewayError> {
    let mut seen = HashSet::new();

    for group in path_groups {
        let normalized = normalize_prefix(&group.prefix)?;
        if !seen.insert(normalized.clone()) {
            return Err(GatewayError::DuplicatePathGroupPrefix {
                prefix: group.prefix.clone(),
                rule_name: rule_name.to_string(),
            });
        }
        validate_http_upstream(&group.upstream)?;
    }

    Ok(())
}

fn check_domain_conflicts(
    new_domains: &[String],
    config: &HttpUpstreamRuleConfig,
    existing_rules: &[HttpUpstreamRuleConfig],
) -> Result<(), GatewayError> {
    if new_domains.is_empty() {
        return Ok(());
    }

    for existing in existing_rules {
        if existing.id == config.id {
            continue;
        }

        if !matches!(
            existing.match_rule,
            HttpUpstreamMatchRule::Host { .. } | HttpUpstreamMatchRule::SniProxy
        ) {
            continue;
        }

        for new_domain in new_domains {
            let new_lower = new_domain.to_ascii_lowercase();
            let new_is_wildcard = new_lower.starts_with("*.");

            for existing_domain in &existing.domains {
                let existing_lower = existing_domain.to_ascii_lowercase();
                let existing_is_wildcard = existing_lower.starts_with("*.");

                if new_lower == existing_lower {
                    return Err(GatewayError::HostConflict {
                        domain: new_domain.clone(),
                        rule_name: existing.name.clone(),
                    });
                }

                if new_is_wildcard
                    && !existing_is_wildcard
                    && wildcard_matches(new_domain, existing_domain)
                {
                    return Err(GatewayError::WildcardCoversDomain {
                        wildcard: new_domain.clone(),
                        domain: existing_domain.clone(),
                        rule_name: existing.name.clone(),
                    });
                }

                if existing_is_wildcard
                    && !new_is_wildcard
                    && wildcard_matches(existing_domain, new_domain)
                {
                    return Err(GatewayError::WildcardCoversDomain {
                        wildcard: existing_domain.clone(),
                        domain: new_domain.clone(),
                        rule_name: existing.name.clone(),
                    });
                }

                if new_is_wildcard
                    && existing_is_wildcard
                    && wildcard_patterns_overlap(new_domain, existing_domain)
                {
                    return Err(GatewayError::DomainPatternOverlap {
                        domain: new_domain.clone(),
                        other_domain: existing_domain.clone(),
                        rule_name: existing.name.clone(),
                    });
                }
            }
        }
    }

    Ok(())
}

fn wildcard_matches(pattern: &str, host: &str) -> bool {
    pattern
        .strip_prefix("*.")
        .map(|suffix| {
            let suffix_lower = suffix.to_ascii_lowercase();
            let host_lower = host.to_ascii_lowercase();
            host_lower.ends_with(&suffix_lower)
                && host_lower.len() > suffix_lower.len()
                && host_lower.as_bytes()[host_lower.len() - suffix_lower.len() - 1] == b'.'
        })
        .unwrap_or(false)
}

fn wildcard_patterns_overlap(left: &str, right: &str) -> bool {
    let Some(left_suffix) = left.strip_prefix("*.").map(|s| s.to_ascii_lowercase()) else {
        return false;
    };
    let Some(right_suffix) = right.strip_prefix("*.").map(|s| s.to_ascii_lowercase()) else {
        return false;
    };

    left_suffix == right_suffix
        || left_suffix.ends_with(&format!(".{right_suffix}"))
        || right_suffix.ends_with(&format!(".{left_suffix}"))
}

fn normalize_prefix(prefix: &str) -> Result<String, GatewayError> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err(GatewayError::InvalidPathPrefix { prefix: prefix.to_string() });
    }

    if trimmed == "/" {
        return Ok("/".to_string());
    }

    let normalized = trimmed.trim_end_matches('/');
    if normalized.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(normalized.to_string())
    }
}

fn build_gateway_dynamic_dns_redirect_batch(
    rules: &[HttpUpstreamRuleConfig],
) -> DynamicDnsRedirectBatch {
    let mut domains = rules
        .iter()
        .filter(|rule| rule.enable)
        .flat_map(|rule| rule.domains.iter())
        .filter_map(|domain| normalize_gateway_domain(domain))
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();

    DynamicDnsRedirectBatch {
        source_id: GATEWAY_DYNAMIC_DNS_REDIRECT_SOURCE_ID.to_string(),
        scope: DynamicDnsRedirectScope::Global,
        records: domains
            .into_iter()
            .map(|domain| DynamicDnsRedirectRecord {
                match_rule: gateway_domain_to_dynamic_match(&domain),
                answer_mode: DnsRedirectAnswerMode::AllLocalIps,
                result_info: vec![],
                ttl_secs: DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
                block_metadata_queries: DEFAULT_BLOCK_METADATA_QUERIES,
            })
            .collect(),
    }
}

fn normalize_gateway_domain(domain: &str) -> Option<String> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn gateway_domain_to_dynamic_match(domain: &str) -> DynamicDnsMatch {
    if let Some(suffix) = domain.strip_prefix("*.") {
        DynamicDnsMatch::Domain(suffix.to_string())
    } else {
        DynamicDnsMatch::Full(domain.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use landscape_common::dns::redirect::{DnsRedirectAnswerMode, DynamicDnsRedirectScope};
    use landscape_common::sys_service::gateway::{
        ClientIpHeaderPolicy, HttpUpstreamConfig, HttpUpstreamTarget, LoadBalanceMethod,
        ProxyHeaderConflictMode, ProxyRequestHeader,
    };

    fn upstream_target() -> HttpUpstreamTarget {
        HttpUpstreamTarget {
            address: "127.0.0.1".to_string(),
            port: 8080,
            weight: 1,
            tls: false,
            skip_cert_verify: false,
        }
    }

    fn upstream() -> HttpUpstreamConfig {
        HttpUpstreamConfig {
            targets: vec![upstream_target()],
            load_balance: LoadBalanceMethod::RoundRobin,
            health_check: None,
            request_headers: vec![],
            header_conflict_mode: ProxyHeaderConflictMode::Set,
            client_ip_headers: ClientIpHeaderPolicy::Standard,
        }
    }

    fn rule(
        name: &str,
        domains: &[&str],
        match_rule: HttpUpstreamMatchRule,
    ) -> HttpUpstreamRuleConfig {
        HttpUpstreamRuleConfig {
            id: uuid::Uuid::new_v4(),
            enable: true,
            name: name.to_string(),
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            match_rule,
            upstream: upstream(),
            update_at: 0.0,
        }
    }

    #[test]
    fn domain_conflicts_detect_cross_type_exact_match() {
        let existing = rule(
            "host-rule",
            &["api.example.com"],
            HttpUpstreamMatchRule::Host { path_groups: vec![] },
        );
        let new_rule = rule("sni-rule", &["api.example.com"], HttpUpstreamMatchRule::SniProxy);

        let err = check_domain_conflicts(&["api.example.com".to_string()], &new_rule, &[existing])
            .unwrap_err();

        assert!(matches!(err, GatewayError::HostConflict { .. }));
    }

    #[test]
    fn domain_conflicts_detect_existing_wildcard_covering_specific_domain() {
        let existing = rule(
            "wildcard-host",
            &["*.example.com"],
            HttpUpstreamMatchRule::Host { path_groups: vec![] },
        );
        let new_rule = rule("sni-specific", &["api.example.com"], HttpUpstreamMatchRule::SniProxy);

        let err = check_domain_conflicts(&["api.example.com".to_string()], &new_rule, &[existing])
            .unwrap_err();

        assert!(matches!(err, GatewayError::WildcardCoversDomain { .. }));
    }

    #[test]
    fn domain_conflicts_allow_distinct_domains() {
        let existing = rule(
            "host-rule",
            &["api.example.com"],
            HttpUpstreamMatchRule::Host { path_groups: vec![] },
        );
        let new_rule = rule("sni-rule", &["static.example.com"], HttpUpstreamMatchRule::SniProxy);

        let result =
            check_domain_conflicts(&["static.example.com".to_string()], &new_rule, &[existing]);
        assert!(result.is_ok());
    }

    #[test]
    fn domain_conflicts_detect_overlapping_wildcards() {
        let existing = rule(
            "wildcard-host",
            &["*.example.com"],
            HttpUpstreamMatchRule::Host { path_groups: vec![] },
        );
        let new_rule =
            rule("nested-wildcard", &["*.api.example.com"], HttpUpstreamMatchRule::SniProxy);

        let err =
            check_domain_conflicts(&["*.api.example.com".to_string()], &new_rule, &[existing])
                .unwrap_err();

        assert!(matches!(err, GatewayError::DomainPatternOverlap { .. }));
    }

    #[test]
    fn validate_path_groups_rejects_duplicate_normalized_prefixes() {
        let path_groups = vec![
            HttpPathGroup {
                prefix: "/api".to_string(),
                rewrite_mode: Default::default(),
                upstream: upstream(),
            },
            HttpPathGroup {
                prefix: "/api/".to_string(),
                rewrite_mode: Default::default(),
                upstream: upstream(),
            },
        ];

        let err = validate_path_groups("api-host", &path_groups).unwrap_err();
        assert!(matches!(err, GatewayError::DuplicatePathGroupPrefix { .. }));
    }

    #[test]
    fn validate_path_groups_allows_nested_prefixes() {
        let path_groups = vec![
            HttpPathGroup {
                prefix: "/api".to_string(),
                rewrite_mode: Default::default(),
                upstream: upstream(),
            },
            HttpPathGroup {
                prefix: "/api/v1".to_string(),
                rewrite_mode: Default::default(),
                upstream: upstream(),
            },
        ];

        assert!(validate_path_groups("api-host", &path_groups).is_ok());
    }

    #[test]
    fn validate_rule_shape_rejects_missing_domains() {
        let rule =
            rule("host-without-domain", &[], HttpUpstreamMatchRule::Host { path_groups: vec![] });

        let err = validate_rule_shape(&rule).unwrap_err();
        assert!(matches!(err, GatewayError::DomainsRequired { .. }));
    }

    #[test]
    fn validate_rule_shape_rejects_sni_proxy_headers() {
        let mut rule =
            rule("sni-with-headers", &["api.example.com"], HttpUpstreamMatchRule::SniProxy);
        rule.upstream.request_headers =
            vec![ProxyRequestHeader { name: "X-Test".to_string(), value: "1".to_string() }];

        let err = validate_rule_shape(&rule).unwrap_err();
        assert!(matches!(err, GatewayError::SniProxyHeaderUnsupported));
    }

    #[test]
    fn validate_rule_shape_rejects_invalid_header_name() {
        let mut rule = rule(
            "host-with-invalid-header",
            &["api.example.com"],
            HttpUpstreamMatchRule::Host { path_groups: vec![] },
        );
        rule.upstream.request_headers = vec![ProxyRequestHeader {
            name: "bad header".to_string(),
            value: "1".to_string(),
        }];
        rule.upstream.client_ip_headers = ClientIpHeaderPolicy::None;

        let err = validate_rule_shape(&rule).unwrap_err();
        assert!(matches!(err, GatewayError::InvalidHeaderName { .. }));
    }

    #[test]
    fn validate_rule_shape_rejects_legacy_path_prefix_updates() {
        let rule = rule(
            "legacy-path",
            &["api.example.com"],
            HttpUpstreamMatchRule::LegacyPathPrefix { prefix: "/api".to_string() },
        );

        let err = validate_rule_shape(&rule).unwrap_err();
        assert!(matches!(err, GatewayError::LegacyPathPrefixUnsupported));
    }

    #[test]
    fn normalize_prefix_trims_trailing_slash() {
        assert_eq!(normalize_prefix("/api").unwrap(), "/api");
        assert_eq!(normalize_prefix("/api/").unwrap(), "/api");
        assert_eq!(normalize_prefix("/").unwrap(), "/");
    }

    #[test]
    fn normalize_prefix_rejects_missing_leading_slash() {
        let err = normalize_prefix("api").unwrap_err();
        assert!(matches!(err, GatewayError::InvalidPathPrefix { .. }));
    }

    #[test]
    fn build_gateway_dynamic_dns_redirect_batch_uses_all_local_ips() {
        let rules = vec![
            rule(
                "gateway-host",
                &["Example.com.", "*.svc.example.com", " example.com "],
                HttpUpstreamMatchRule::Host { path_groups: vec![] },
            ),
            rule("disabled", &["ignored.example.com"], HttpUpstreamMatchRule::SniProxy),
        ];
        let mut rules = rules;
        rules[1].enable = false;

        let batch = build_gateway_dynamic_dns_redirect_batch(&rules);

        assert_eq!(batch.source_id, GATEWAY_DYNAMIC_DNS_REDIRECT_SOURCE_ID);
        assert_eq!(batch.scope, DynamicDnsRedirectScope::Global);
        assert_eq!(batch.records.len(), 2);
        assert!(batch.records.iter().all(|record| {
            record.answer_mode == DnsRedirectAnswerMode::AllLocalIps
                && record.result_info.is_empty()
                && record.ttl_secs == DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS
        }));
        assert!(batch
            .records
            .iter()
            .any(|record| record.match_rule == DynamicDnsMatch::Full("example.com".to_string())));
        assert!(batch.records.iter().any(|record| {
            record.match_rule == DynamicDnsMatch::Domain("svc.example.com".to_string())
        }));
    }

    #[test]
    fn gateway_domain_to_dynamic_match_maps_wildcard_to_domain_match() {
        assert_eq!(
            gateway_domain_to_dynamic_match("*.example.com"),
            DynamicDnsMatch::Domain("example.com".to_string())
        );
        assert_eq!(
            gateway_domain_to_dynamic_match("api.example.com"),
            DynamicDnsMatch::Full("api.example.com".to_string())
        );
    }

    #[test]
    fn normalize_gateway_domain_skips_empty_values() {
        assert_eq!(normalize_gateway_domain(""), None);
        assert_eq!(normalize_gateway_domain("  "), None);
        assert_eq!(
            normalize_gateway_domain("Api.Example.Com."),
            Some("api.example.com".to_string())
        );
    }
}

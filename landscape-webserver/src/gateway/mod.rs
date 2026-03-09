use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::gateway::{
    GatewayError, HttpUpstreamMatchRule, HttpUpstreamRuleConfig,
};
use landscape_common::config::ConfigId;
use landscape_common::database::LandscapeStore;
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_gateway_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_gateway_rules, create_gateway_rule))
        .routes(routes!(get_gateway_rule, delete_gateway_rule))
        .routes(routes!(get_gateway_status))
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct GatewayStatus {
    pub running: bool,
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
    let result = state.gateway_service.store().list().await.unwrap_or_default();
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
    // Host conflict detection
    check_host_conflicts(&state, &config).await?;

    let saved = state
        .gateway_service
        .store()
        .set(config)
        .await
        .map_err(|e| landscape_common::error::LdError::ConfigError(e.to_string()))?;

    // Reload gateway rules
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
    let result = state
        .gateway_service
        .store()
        .find_by_id(id)
        .await
        .map_err(|e| landscape_common::error::LdError::ConfigError(e.to_string()))?;
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
    state
        .gateway_service
        .store()
        .delete(id)
        .await
        .map_err(|e| landscape_common::error::LdError::ConfigError(e.to_string()))?;

    // Reload gateway rules
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
    let rules = state.gateway_service.store().list().await.unwrap_or_default();
    let status = GatewayStatus {
        running: state.gateway_service.is_running(),
        http_port: state.gateway_service.config().http_port,
        https_port: state.gateway_service.config().https_port,
        https_ready: state.gateway_service.has_https_listener(),
        rule_count: rules.len(),
    };
    LandscapeApiResp::success(status)
}

async fn reload_gateway_rules(state: &LandscapeApp) {
    state.gateway_service.reload_rules().await;
}

async fn check_host_conflicts(
    state: &LandscapeApp,
    config: &HttpUpstreamRuleConfig,
) -> Result<(), GatewayError> {
    let existing_rules = state.gateway_service.store().list().await.unwrap_or_default();

    match &config.match_rule {
        HttpUpstreamMatchRule::Host { domains } => {
            check_domain_conflicts(domains, config, &existing_rules)?;
        }
        HttpUpstreamMatchRule::SniProxy { domains } => {
            check_domain_conflicts(domains, config, &existing_rules)?;
        }
        HttpUpstreamMatchRule::PathPrefix { prefix } => {
            check_path_prefix_conflicts(prefix, config, &existing_rules)?;
        }
    }

    Ok(())
}

/// Check domain conflicts for Host and SniProxy rules.
/// Detects: exact duplicates, wildcard-covers-specific, specific-covers-wildcard.
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

        let existing_domains = match &existing.match_rule {
            HttpUpstreamMatchRule::Host { domains }
            | HttpUpstreamMatchRule::SniProxy { domains } => domains,
            _ => continue,
        };

        for new_domain in new_domains {
            let new_lower = new_domain.to_ascii_lowercase();
            let new_is_wildcard = new_lower.starts_with("*.");

            for existing_domain in existing_domains {
                let existing_lower = existing_domain.to_ascii_lowercase();
                let existing_is_wildcard = existing_lower.starts_with("*.");

                // Exact match (including wildcard == wildcard)
                if new_lower == existing_lower {
                    return Err(GatewayError::HostConflict {
                        domain: new_domain.clone(),
                        rule_name: existing.name.clone(),
                    });
                }

                // New wildcard covers existing specific domain
                // e.g., new = *.example.com, existing = foo.example.com
                if new_is_wildcard && !existing_is_wildcard {
                    let suffix = &new_lower[1..]; // ".example.com"
                    if existing_lower.ends_with(suffix)
                        && !existing_lower[..existing_lower.len() - suffix.len()].contains('.')
                    {
                        return Err(GatewayError::WildcardCoversDomain {
                            wildcard: new_domain.clone(),
                            domain: existing_domain.clone(),
                            rule_name: existing.name.clone(),
                        });
                    }
                }

                // Existing wildcard covers new specific domain
                // e.g., existing = *.example.com, new = foo.example.com
                if existing_is_wildcard && !new_is_wildcard {
                    let suffix = &existing_lower[1..]; // ".example.com"
                    if new_lower.ends_with(suffix)
                        && !new_lower[..new_lower.len() - suffix.len()].contains('.')
                    {
                        return Err(GatewayError::WildcardCoversDomain {
                            wildcard: existing_domain.clone(),
                            domain: new_domain.clone(),
                            rule_name: existing.name.clone(),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check path prefix overlap.
/// Two prefixes conflict if one is a prefix of the other.
fn check_path_prefix_conflicts(
    new_prefix: &str,
    config: &HttpUpstreamRuleConfig,
    existing_rules: &[HttpUpstreamRuleConfig],
) -> Result<(), GatewayError> {
    let new_normalized = normalize_prefix(new_prefix);

    for existing in existing_rules {
        if existing.id == config.id {
            continue;
        }

        if let HttpUpstreamMatchRule::PathPrefix { prefix: existing_prefix } = &existing.match_rule
        {
            let existing_normalized = normalize_prefix(existing_prefix);

            if new_normalized.starts_with(&existing_normalized)
                || existing_normalized.starts_with(&new_normalized)
            {
                return Err(GatewayError::PathPrefixOverlap {
                    new_prefix: new_prefix.to_string(),
                    existing_prefix: existing_prefix.clone(),
                    rule_name: existing.name.clone(),
                });
            }
        }
    }

    Ok(())
}

/// Normalize a path prefix for comparison: ensure trailing slash.
/// "/api" -> "/api/", "/api/" -> "/api/"
fn normalize_prefix(prefix: &str) -> String {
    if prefix.ends_with('/') {
        prefix.to_string()
    } else {
        format!("{prefix}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use landscape_common::config::gateway::{
        HttpUpstreamConfig, HttpUpstreamTarget, LoadBalanceMethod,
    };

    fn upstream_target() -> HttpUpstreamTarget {
        HttpUpstreamTarget {
            address: "127.0.0.1".to_string(),
            port: 8080,
            weight: 1,
            tls: false,
        }
    }

    fn rule(name: &str, match_rule: HttpUpstreamMatchRule) -> HttpUpstreamRuleConfig {
        HttpUpstreamRuleConfig {
            id: uuid::Uuid::new_v4(),
            enable: true,
            name: name.to_string(),
            match_rule,
            upstream: HttpUpstreamConfig {
                targets: vec![upstream_target()],
                load_balance: LoadBalanceMethod::RoundRobin,
                health_check: None,
            },
            update_at: 0.0,
        }
    }

    #[test]
    fn domain_conflicts_detect_cross_type_exact_match() {
        let existing = rule(
            "host-rule",
            HttpUpstreamMatchRule::Host { domains: vec!["api.example.com".to_string()] },
        );
        let new_rule = rule(
            "sni-rule",
            HttpUpstreamMatchRule::SniProxy { domains: vec!["api.example.com".to_string()] },
        );

        let err = check_domain_conflicts(&["api.example.com".to_string()], &new_rule, &[existing])
            .unwrap_err();

        assert!(matches!(err, GatewayError::HostConflict { .. }));
    }

    #[test]
    fn domain_conflicts_detect_existing_wildcard_covering_specific_domain() {
        let existing = rule(
            "wildcard-host",
            HttpUpstreamMatchRule::Host { domains: vec!["*.example.com".to_string()] },
        );
        let new_rule = rule(
            "sni-specific",
            HttpUpstreamMatchRule::SniProxy { domains: vec!["api.example.com".to_string()] },
        );

        let err = check_domain_conflicts(&["api.example.com".to_string()], &new_rule, &[existing])
            .unwrap_err();

        assert!(matches!(err, GatewayError::WildcardCoversDomain { .. }));
    }

    #[test]
    fn domain_conflicts_allow_distinct_domains() {
        let existing = rule(
            "host-rule",
            HttpUpstreamMatchRule::Host { domains: vec!["api.example.com".to_string()] },
        );
        let new_rule = rule(
            "sni-rule",
            HttpUpstreamMatchRule::SniProxy { domains: vec!["static.example.com".to_string()] },
        );

        let result =
            check_domain_conflicts(&["static.example.com".to_string()], &new_rule, &[existing]);
        assert!(result.is_ok());
    }

    #[test]
    fn path_prefix_conflicts_detect_overlap() {
        let existing =
            rule("api-root", HttpUpstreamMatchRule::PathPrefix { prefix: "/api".to_string() });
        let new_rule =
            rule("api-v1", HttpUpstreamMatchRule::PathPrefix { prefix: "/api/v1".to_string() });

        let err = check_path_prefix_conflicts("/api/v1", &new_rule, &[existing]).unwrap_err();
        assert!(matches!(err, GatewayError::PathPrefixOverlap { .. }));
    }

    #[test]
    fn normalize_prefix_adds_trailing_slash() {
        assert_eq!(normalize_prefix("/api"), "/api/");
        assert_eq!(normalize_prefix("/api/"), "/api/");
    }
}

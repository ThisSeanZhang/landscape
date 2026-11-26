use axum::extract::{Path, State};
use landscape::config_service::gateway_rule_service::GatewayRuleConfigService;
use landscape::sys_service::{config_service::LandscapeConfigService, gateway::GatewayService};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

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
    /// Whether the HTTPS listener has bound successfully and is accepting connections.
    pub https_ready: bool,
    /// Gateway service diagnostic, including startup errors or a pending restart.
    #[serde(default)]
    pub last_error: Option<String>,
    pub rule_count: usize,
}

#[utoipa::path(
    get,
    path = "/rules",
    tag = "Gateway",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<HttpUpstreamRuleConfig>>))
)]
async fn list_gateway_rules(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<HttpUpstreamRuleConfig>> {
    let result = state.managed.gateway_rules.list_rules().await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/rules",
    tag = "Gateway",
    request_body = HttpUpstreamRuleConfig,
    responses((status = 200, description = "Success", body = CommonApiResp<HttpUpstreamRuleConfig>))
)]
async fn create_gateway_rule(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<HttpUpstreamRuleConfig>,
) -> LandscapeApiResult<HttpUpstreamRuleConfig> {
    let saved = state.managed.gateway_rules.save_rule(config).await?;

    LandscapeApiResp::success(saved)
}

#[utoipa::path(
    get,
    path = "/rules/{id}",
    tag = "Gateway",
    params(("id" = Uuid, Path, description = "Gateway rule ID")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<HttpUpstreamRuleConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_gateway_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<HttpUpstreamRuleConfig> {
    let result = state.managed.gateway_rules.find_rule(id).await?;
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
    responses((status = 200, description = "Deleted or already absent"))
)]
async fn delete_gateway_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.managed.gateway_rules.delete_rule(id).await?;

    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/status",
    tag = "Gateway",
    responses((status = 200, description = "Success", body = CommonApiResp<GatewayStatus>))
)]
async fn get_gateway_status(
    State(state): State<LandscapeApp>,
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<GatewayStatus> {
    LandscapeApiResp::success(
        build_gateway_status(&state.managed.gateway_service, &state.managed.gateway_rules, &config)
            .await,
    )
}

#[utoipa::path(
    post,
    path = "/restart",
    tag = "Gateway",
    responses(
        (status = 200, description = "Success", body = CommonApiResp<GatewayStatus>),
        (status = 500, description = "gateway.stop_failed: Failed to stop the previous gateway server"),
        (status = 504, description = "gateway.stop_timeout: Shutdown timed out; the previous gateway server is retained")
    )
)]
async fn restart_gateway(
    State(state): State<LandscapeApp>,
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<GatewayStatus> {
    let gateway_config = config.get_gateway_runtime_config();
    state
        .managed
        .gateway_service
        .restart(gateway_config, std::time::Duration::from_secs(10))
        .await?;
    LandscapeApiResp::success(
        build_gateway_status(&state.managed.gateway_service, &state.managed.gateway_rules, &config)
            .await,
    )
}

async fn build_gateway_status(
    service: &GatewayService,
    rules: &GatewayRuleConfigService,
    config_service: &LandscapeConfigService,
) -> GatewayStatus {
    let runtime = service.runtime_status();
    let config = runtime.config.unwrap_or_else(|| config_service.get_gateway_runtime_config());
    GatewayStatus {
        supported: service.is_supported(),
        status: runtime.status,
        http_port: config.http_port,
        https_port: config.https_port,
        https_ready: runtime.https_ready,
        last_error: runtime.last_error,
        rule_count: rules.stored_rule_count().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape::cert::{account_service::CertAccountService, order_service::CertService};
    use landscape::dns::redirect_service::DNSRedirectService;
    use landscape_common::args::WebCommArgs;
    use landscape_common::database::store::ConfigStore;
    use landscape_common::sys_config::{LandscapeConfig, LandscapeGatewayConfig, RuntimeConfig};
    use landscape_database::provider::LandscapeDBServiceProvider;
    use std::time::Duration;

    #[tokio::test]
    async fn gateway_status_uses_server_config_or_latest_saved_config() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let runtime = RuntimeConfig::new_with_file_config(
            WebCommArgs {
                config_dir: Some(dir.path().to_path_buf()),
                database_path: Some("sqlite::memory:".into()),
                ..Default::default()
            },
            Some(LandscapeConfig::default()),
        );
        let initial_http_port = runtime.gateway.http_port;
        let initial_https_port = runtime.gateway.https_port;
        let db = LandscapeDBServiceProvider::mem_test_db().await;
        let (events_tx, _events_rx) = tokio::sync::mpsc::channel(32);
        let dns = DNSRedirectService::new(db.clone(), events_tx).await;
        let accounts = CertAccountService::new(db.clone()).await;
        let certs = CertService::new(db.clone(), accounts, Some(dns.clone())).await;
        // A stored rule is still counted by status in unsupported builds.
        let rule: HttpUpstreamRuleConfig = serde_json::from_value(serde_json::json!({
            "name": "app", "enable": true, "domains": ["app.example.com"],
            "match_rule": { "t": "host" },
            "upstream": { "targets": [{ "address": "127.0.0.1", "port": 8080 }] }
        }))
        .unwrap();
        db.gateway_http_upstream_store().upsert(rule).await.unwrap();
        let rules = GatewayRuleConfigService::new(db.gateway_http_upstream_store(), dns).await;
        let service =
            GatewayService::init_service(rules.clone(), runtime.gateway.clone(), &certs).await;
        let config_service = LandscapeConfigService::new(runtime, db).await;
        std::fs::write(config_service.get_config_path(), "").unwrap();
        let before = build_gateway_status(&service, &rules, &config_service).await;
        assert_eq!(before.http_port, initial_http_port);
        assert_eq!(before.https_port, initial_https_port);
        assert_eq!(before.rule_count, 1);
        assert_eq!(before.supported, cfg!(feature = "gateway"));
        assert_eq!(before.status, ServiceStatus::Stop);
        assert!(before.last_error.is_none());
        // Disabled gateways have no bound HTTPS listener.
        assert!(!before.https_ready);

        let (_, hash) = config_service.get_gateway_config_from_file().unwrap();
        config_service
            .update_gateway_config(
                LandscapeGatewayConfig {
                    enable: Some(false),
                    http_port: Some(18080),
                    https_port: Some(18443),
                },
                hash,
            )
            .await
            .unwrap();
        let after_save = build_gateway_status(&service, &rules, &config_service).await;
        assert!(!after_save.https_ready);
        let clone = service.clone();
        #[cfg(feature = "gateway")]
        {
            // Saving alone must not claim the server is using the new ports.
            assert_eq!(after_save.http_port, initial_http_port);
            assert_eq!(after_save.https_port, initial_https_port);
            service
                .restart(config_service.get_gateway_runtime_config(), Duration::from_secs(1))
                .await
                .unwrap();
            assert_eq!(clone.runtime_config().unwrap().http_port, 18080);
        }
        #[cfg(not(feature = "gateway"))]
        {
            assert_eq!(after_save.http_port, 18080);
            assert_eq!(after_save.https_port, 18443);
            assert!(!after_save.supported);
            assert!(!after_save.https_ready);
            assert!(clone.runtime_config().is_none());
            assert!(matches!(
                service
                    .restart(config_service.get_gateway_runtime_config(), Duration::from_secs(1),)
                    .await,
                Err(GatewayError::Unsupported)
            ));
        }
        let after = build_gateway_status(&clone, &rules, &config_service).await;
        assert_eq!(after.http_port, 18080);
        assert_eq!(after.https_port, 18443);
        assert_eq!(after.status, ServiceStatus::Stop);
        assert_eq!(after.rule_count, 1);
        assert!(!after.https_ready);
        assert!(after.last_error.is_none());
        service.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[cfg(feature = "gateway")]
    #[tokio::test]
    async fn gateway_status_exposes_startup_error_until_repaired_rules_are_restarted() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let runtime = RuntimeConfig::new_with_file_config(
            WebCommArgs {
                config_dir: Some(dir.path().to_path_buf()),
                database_path: Some("sqlite::memory:".into()),
                ..Default::default()
            },
            Some(LandscapeConfig::default()),
        );
        let db = LandscapeDBServiceProvider::mem_test_db().await;
        let (events_tx, _events_rx) = tokio::sync::mpsc::channel(32);
        let dns = DNSRedirectService::new(db.clone(), events_tx).await;
        let accounts = CertAccountService::new(db.clone()).await;
        let certs = CertService::new(db.clone(), accounts, Some(dns.clone())).await;
        let mut stored_rules = Vec::new();
        for domain in ["first.example.com", "second.example.com"] {
            let rule: HttpUpstreamRuleConfig = serde_json::from_value(serde_json::json!({
                "name": domain, "enable": true, "domains": [domain],
                "match_rule": { "t": "host" },
                "upstream": {
                    "targets": [{ "address": "127.0.0.1", "port": 8080 }],
                    "request_headers": [{ "name": "invalid header", "value": "value" }]
                }
            }))
            .unwrap();
            stored_rules.push(db.gateway_http_upstream_store().upsert(rule).await.unwrap().new);
        }
        let rules = GatewayRuleConfigService::new(db.gateway_http_upstream_store(), dns).await;
        let service =
            GatewayService::init_service(rules.clone(), runtime.gateway.clone(), &certs).await;
        let config_service = LandscapeConfigService::new(runtime, db).await;
        let failed = build_gateway_status(&service, &rules, &config_service).await;
        assert!(failed.supported);
        assert_eq!(failed.status, ServiceStatus::Failed);
        assert_eq!(failed.rule_count, 2);
        assert!(!failed.https_ready);
        assert!(failed.last_error.as_ref().is_some_and(|error| error.contains("invalid header")));
        assert!(serde_json::to_value(&failed).unwrap()["last_error"].is_string());

        // Startup failure must leave stored rules accessible for incremental repair.
        assert_eq!(rules.list_rules().await.unwrap().len(), 2);
        let mut repaired = rules.find_rule(stored_rules[0].id).await.unwrap().unwrap();
        repaired.upstream.request_headers.clear();
        rules.save_rule(repaired).await.unwrap();
        let partially_repaired = build_gateway_status(&service, &rules, &config_service).await;
        assert_eq!(partially_repaired.status, ServiceStatus::Failed);
        assert_eq!(partially_repaired.rule_count, 2);
        assert!(partially_repaired.last_error.is_some());

        rules.delete_rule(stored_rules[1].id).await.unwrap();
        let pending = build_gateway_status(&service, &rules, &config_service).await;
        assert_eq!(pending.status, ServiceStatus::Failed);
        assert_eq!(pending.rule_count, 1);
        assert!(!pending.https_ready);
        assert!(pending.last_error.is_some());
        assert_ne!(pending.last_error, failed.last_error);

        service
            .restart(config_service.get_gateway_runtime_config(), Duration::from_secs(1))
            .await
            .unwrap();
        let recovered = build_gateway_status(&service, &rules, &config_service).await;
        assert_eq!(recovered.status, ServiceStatus::Stop);
        assert_eq!(recovered.rule_count, 1);
        assert!(!recovered.https_ready);
        assert!(recovered.last_error.is_none());
        assert!(serde_json::to_value(&recovered).unwrap()["last_error"].is_null());
        service.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }
}

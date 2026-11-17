use axum::extract::{Path, State};
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
    pub https_ready: bool,
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
    let result = state.managed.gateway_service.list_rules().await?;
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
    let saved = state.managed.gateway_service.save_rule(config).await?;

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
    let result = state.managed.gateway_service.find_rule(id).await?;
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
    state.managed.gateway_service.delete_rule(id).await?;

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
) -> LandscapeApiResult<GatewayStatus> {
    LandscapeApiResp::success(
        build_gateway_status(&state.managed.gateway_service, &state.system.config_service).await,
    )
}

#[utoipa::path(
    post,
    path = "/restart",
    tag = "Gateway",
    responses((status = 200, description = "Success", body = CommonApiResp<GatewayStatus>))
)]
async fn restart_gateway(State(state): State<LandscapeApp>) -> LandscapeApiResult<GatewayStatus> {
    let gateway_config = state.system.config_service.get_gateway_runtime_config();
    state
        .managed
        .gateway_service
        .restart(gateway_config, std::time::Duration::from_secs(10))
        .await?;
    LandscapeApiResp::success(
        build_gateway_status(&state.managed.gateway_service, &state.system.config_service).await,
    )
}

async fn build_gateway_status(
    service: &GatewayService,
    config_service: &LandscapeConfigService,
) -> GatewayStatus {
    let config =
        service.runtime_config().unwrap_or_else(|| config_service.get_gateway_runtime_config());
    GatewayStatus {
        supported: service.is_supported(),
        status: service.status(),
        http_port: config.http_port,
        https_port: config.https_port,
        https_ready: service.has_https_listener(),
        rule_count: service.stored_rule_count().await,
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
        let service = GatewayService::init_service(
            db.gateway_http_upstream_store(),
            runtime.gateway.clone(),
            &certs,
            dns,
        )
        .await
        .unwrap();
        let config_service = LandscapeConfigService::new(runtime, db).await;
        std::fs::write(config_service.get_config_path(), "").unwrap();
        let before = build_gateway_status(&service, &config_service).await;
        assert_eq!(before.http_port, initial_http_port);
        assert_eq!(before.https_port, initial_https_port);
        assert_eq!(before.rule_count, 1);
        assert_eq!(before.supported, cfg!(feature = "gateway"));
        assert_eq!(before.status, ServiceStatus::Stop);

        let (_, hash) = config_service.get_gateway_config_from_file().await;
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
        let after_save = build_gateway_status(&service, &config_service).await;
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
        let after = build_gateway_status(&clone, &config_service).await;
        assert_eq!(after.http_port, 18080);
        assert_eq!(after.https_port, 18443);
        assert_eq!(after.status, ServiceStatus::Stop);
        assert_eq!(after.rule_count, 1);
        service.shutdown_and_wait(Duration::from_secs(1)).await;
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }
}

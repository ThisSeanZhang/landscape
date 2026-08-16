use axum::extract::{DefaultBodyLimit, Multipart, Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{InitConfig, InitConfigError};
use landscape_common::database::error::DbError;
use landscape_common::sys_service::time_sync::TimeSyncStatus;
use landscape_common::{INIT_FILE_NAME, INIT_LOCK_FILE_NAME};
use landscape_core::time::get_time_sync_status as read_time_sync_status;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Write};
use tempfile::NamedTempFile;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::{LandscapeApiResp, UploadFileForm};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

const UPLOAD_INIT_CONFIG_SIZE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ExportInitConfigResponse {
    pub filename: String,
    pub version: String,
    pub content: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ImportInitConfigQuery {
    #[serde(default = "default_upload_only")]
    pub upload_only: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ImportInitConfigResponse {
    pub version: String,
    pub filename: Option<String>,
    pub upload_only: bool,
}

fn default_upload_only() -> bool {
    true
}

fn init_config_filename(version: &str) -> String {
    format!("landscape_init_v{version}.toml")
}

fn parse_and_validate_init_config(content: &str) -> Result<InitConfig, InitConfigError> {
    let init_config: InitConfig =
        toml::from_str(content).map_err(|e| InitConfigError::Invalid { reason: e.to_string() })?;
    landscape::boot::validate_init_config_version(&init_config)?;
    Ok(init_config)
}

async fn validate_init_config_can_import(
    init_config: InitConfig,
) -> Result<InitConfig, InitConfigError> {
    landscape_database::provider::LandscapeDBServiceProvider::validate_init_config_can_import(
        init_config.clone(),
    )
    .await
    .map_err(|e| InitConfigError::Invalid { reason: e.to_string() })?;
    Ok(init_config)
}

async fn read_init_config_upload(mut multipart: Multipart) -> Result<Vec<u8>, InitConfigError> {
    while let Some(field) =
        multipart.next_field().await.map_err(|_| InitConfigError::FileReadError)?
    {
        if field.name() == Some("file") {
            let bytes = field.bytes().await.map_err(|_| InitConfigError::FileReadError)?;
            return Ok(bytes.to_vec());
        }
    }

    Err(InitConfigError::FileNotFound)
}

pub fn get_sys_config_paths() -> OpenApiRouter<LandscapeApp> {
    let import_router = OpenApiRouter::new()
        .routes(routes!(import_init_config))
        .layer(DefaultBodyLimit::max(UPLOAD_INIT_CONFIG_SIZE_LIMIT));

    OpenApiRouter::new()
        .routes(routes!(export_init_config))
        .merge(import_router)
        .routes(routes!(get_time_sync_status))
        .routes(routes!(super::time_config::get_time_config_fast))
        .routes(routes!(
            super::time_config::get_time_config,
            super::time_config::update_time_config
        ))
        .routes(routes!(super::ui_config::get_ui_config_fast))
        .routes(routes!(super::ui_config::get_ui_config, super::ui_config::update_ui_config))
        .routes(routes!(super::metric_config::get_metric_config_fast))
        .routes(routes!(
            super::metric_config::get_metric_config,
            super::metric_config::update_metric_config
        ))
        .routes(routes!(super::dns_config::get_dns_config_fast))
        .routes(routes!(super::dns_config::get_dns_config, super::dns_config::update_dns_config))
        .routes(routes!(super::lan_hostname_config::get_lan_hostname_config_fast))
        .routes(routes!(
            super::lan_hostname_config::get_lan_hostname_config,
            super::lan_hostname_config::update_lan_hostname_config
        ))
        .routes(routes!(super::gateway_config::get_gateway_config_fast))
        .routes(routes!(
            super::gateway_config::get_gateway_config,
            super::gateway_config::update_gateway_config
        ))
        .routes(routes!(super::auth_config::update_auth_config))
}

#[utoipa::path(
    get,
    path = "/config/export",
    tag = "System Config",
    operation_id = "export_init_config",
    responses((status = 200, body = CommonApiResp<ExportInitConfigResponse>))
)]
async fn export_init_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<ExportInitConfigResponse> {
    let config = state.config_service.export_init_config().await;
    let version = config.version.clone();
    let content = toml::to_string(&config).unwrap();

    LandscapeApiResp::success(ExportInitConfigResponse {
        filename: init_config_filename(&version),
        version,
        content,
    })
}

#[utoipa::path(
    post,
    path = "/config/import",
    tag = "System Config",
    operation_id = "import_init_config",
    params(ImportInitConfigQuery),
    request_body(content = inline(UploadFileForm), content_type = "multipart/form-data"),
    responses((status = 200, body = CommonApiResp<ImportInitConfigResponse>))
)]
async fn import_init_config(
    State(state): State<LandscapeApp>,
    Query(query): Query<ImportInitConfigQuery>,
    multipart: Multipart,
) -> LandscapeApiResult<ImportInitConfigResponse> {
    // Upload only validates the init file. When upload_only is disabled, this endpoint only
    // writes landscape_init.toml and removes the init lock; it does not mutate the running DB,
    // runtime config, or trigger initialization in the current process.
    let bytes = read_init_config_upload(multipart).await?;

    let content = std::str::from_utf8(&bytes)
        .map_err(|e| InitConfigError::Invalid { reason: e.to_string() })?;
    let init_config =
        validate_init_config_can_import(parse_and_validate_init_config(content)?).await?;

    let filename = if query.upload_only {
        None
    } else {
        let init_config_content = toml::to_string(&init_config)
            .map_err(|e| InitConfigError::Invalid { reason: e.to_string() })?;
        let config_path = state.home_path.join(INIT_FILE_NAME);
        let previous_init_config = match std::fs::read(&config_path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(DbError::from(e))?,
        };
        let mut temp_file = NamedTempFile::new_in(&state.home_path).map_err(DbError::from)?;
        temp_file.write_all(init_config_content.as_bytes()).map_err(DbError::from)?;
        temp_file.as_file().sync_all().map_err(DbError::from)?;
        temp_file.persist(&config_path).map_err(|e| DbError::from(e.error))?;

        let lock_path = state.home_path.join(INIT_LOCK_FILE_NAME);
        match std::fs::remove_file(lock_path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                let rollback_result = if let Some(previous_init_config) = previous_init_config {
                    std::fs::write(&config_path, previous_init_config)
                } else {
                    match std::fs::remove_file(&config_path) {
                        Ok(()) => Ok(()),
                        Err(remove_err) if remove_err.kind() == ErrorKind::NotFound => Ok(()),
                        Err(remove_err) => Err(remove_err),
                    }
                };
                if let Err(rollback_err) = rollback_result {
                    tracing::warn!(
                        "failed to rollback init config after init lock removal failed: {rollback_err}"
                    );
                }
                Err(DbError::from(e))?;
            }
        }

        Some(INIT_FILE_NAME.to_string())
    };

    LandscapeApiResp::success(ImportInitConfigResponse {
        version: init_config.version,
        filename,
        upload_only: query.upload_only,
    })
}

#[utoipa::path(
    get,
    path = "/time/sync_status",
    tag = "System Config",
    operation_id = "get_time_sync_status",
    responses((status = 200, body = CommonApiResp<TimeSyncStatus>))
)]
async fn get_time_sync_status() -> LandscapeApiResult<TimeSyncStatus> {
    LandscapeApiResp::success(read_time_sync_status())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        extract::{Multipart, Request},
        routing::post,
        Router,
    };
    use landscape_common::{config::InitConfig, VERSION};
    use tower::ServiceExt;

    use super::{
        parse_and_validate_init_config, read_init_config_upload, validate_init_config_can_import,
    };

    const BOUNDARY: &str = "landscape-test-boundary";

    fn multipart_request(body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
            .body(Body::from(body))
            .unwrap()
    }

    fn multipart_part(name: &str, content: &str) -> String {
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{content}\r\n"
        )
    }

    async fn read_upload_from_body(
        body: String,
    ) -> Result<Vec<u8>, landscape_common::config::InitConfigError> {
        let app = Router::new().route(
            "/",
            post(|multipart: Multipart| async move {
                match read_init_config_upload(multipart).await {
                    Ok(bytes) => String::from_utf8(bytes).unwrap(),
                    Err(e) => e.to_string(),
                }
            }),
        );

        let response = app.oneshot(multipart_request(body)).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        Ok(bytes.to_vec())
    }

    #[test]
    fn parse_and_validate_init_config_rejects_missing_version() {
        let result = parse_and_validate_init_config("");

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_init_config_can_import_accepts_valid_config() {
        let init_config = InitConfig { version: VERSION.to_string(), ..Default::default() };

        validate_init_config_can_import(init_config).await.unwrap();
    }

    #[tokio::test]
    async fn read_init_config_upload_skips_non_file_fields() {
        let body = format!(
            "{}{}--{BOUNDARY}--\r\n",
            multipart_part("note", "ignored"),
            multipart_part("file", "version = \"test\"\n"),
        );

        let bytes = read_upload_from_body(body).await.unwrap();

        assert_eq!(String::from_utf8(bytes).unwrap(), "version = \"test\"\n");
    }

    #[tokio::test]
    async fn read_init_config_upload_requires_file_field() {
        let body = format!("{}--{BOUNDARY}--\r\n", multipart_part("note", "ignored"));

        let bytes = read_upload_from_body(body).await.unwrap();

        assert!(String::from_utf8(bytes).unwrap().contains("not found"));
    }
}

use axum::extract::{DefaultBodyLimit, Multipart, Query, State};
use landscape::boot::prepare_init_config_import;
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{InitConfig, InitConfigError};
use landscape_common::database::error::DbError;
use landscape_common::{INIT_FILE_NAME, INIT_LOCK_FILE_NAME};
use serde::{Deserialize, Serialize};
use std::{
    io::{ErrorKind, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::{LandscapeApiResp, UploadFileForm};
use crate::error::{LandscapeApiError, LandscapeApiResult};

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
        .routes(routes!(super::time_config::get_time_sync_status))
        .routes(routes!(super::time_config::sync_time_now))
        .routes(routes!(super::time_config::get_time_config_fast))
        .routes(routes!(
            super::time_config::get_time_config,
            super::time_config::update_time_config
        ))
        .routes(routes!(super::ui_config::get_ui_config_fast))
        .routes(routes!(super::ui_config::get_ui_config, super::ui_config::update_ui_config))
        .merge(super::metric_config::paths())
        .routes(routes!(
            super::dns_config::get_dns_cache_config,
            super::dns_config::update_dns_cache_config
        ))
        .routes(routes!(super::dns_config::get_doh_config, super::dns_config::update_doh_config))
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
    responses((status = 200, description = "Success", body = CommonApiResp<ExportInitConfigResponse>))
)]
async fn export_init_config(
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<ExportInitConfigResponse> {
    let config = config.export_init_config().await?;
    let version = config.version.clone();
    let content = toml::to_string(&config).map_err(InitConfigError::ExportSerialization)?;

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
    responses((status = 200, description = "Success", body = CommonApiResp<ImportInitConfigResponse>))
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
    LandscapeApiResp::success(
        import_init_config_content(&state.home_path, content, query.upload_only).await?,
    )
}

async fn import_init_config_content(
    home_path: &Path,
    content: &str,
    upload_only: bool,
) -> Result<ImportInitConfigResponse, LandscapeApiError> {
    // Complete the same preparation used by startup before replacing the init
    // file or removing its lock. Persist the normalized configuration on success.
    let init_config = prepare_init_config_import(parse_and_validate_init_config(content)?).await?;

    let filename = if upload_only {
        None
    } else {
        let init_config_content = toml::to_string(&init_config)
            .map_err(|e| InitConfigError::Invalid { reason: e.to_string() })?;
        let config_path = home_path.join(INIT_FILE_NAME);
        let previous_init_config = match std::fs::read(&config_path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(DbError::from(e))?,
        };
        let mut temp_file = NamedTempFile::new_in(home_path).map_err(DbError::from)?;
        temp_file.write_all(init_config_content.as_bytes()).map_err(DbError::from)?;
        temp_file.as_file().sync_all().map_err(DbError::from)?;
        temp_file.persist(&config_path).map_err(|e| DbError::from(e.error))?;

        let lock_path = home_path.join(INIT_LOCK_FILE_NAME);
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

    Ok(ImportInitConfigResponse {
        version: init_config.version,
        filename,
        upload_only,
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        extract::{Multipart, Request},
        routing::post,
    };
    use landscape_common::{
        INIT_FILE_NAME, INIT_LOCK_FILE_NAME, LAND_CONFIG, VERSION,
        config::{InitConfig, InitConfigError},
        sys_service::gateway::ClientIpHeaderPolicy,
    };
    use tower::ServiceExt;

    use super::{
        import_init_config_content, parse_and_validate_init_config, prepare_init_config_import,
        read_init_config_upload,
    };
    use crate::error::LandscapeApiError;

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
    async fn prepare_init_config_import_accepts_valid_config() {
        let init_config = InitConfig { version: VERSION.to_string(), ..Default::default() };

        prepare_init_config_import(init_config).await.unwrap();
    }

    fn gateway_rule_content(name: &str, kind: &str, upstream_options: &str) -> String {
        format!(
            r#"
[[gateway_rules]]
enable = true
name = "{name}"
domains = ["{name}.example.com"]
[gateway_rules.match_rule]
t = "{kind}"
[gateway_rules.upstream]
targets = [{{ address = "127.0.0.1", port = 443 }}]
{upstream_options}
"#
        )
    }

    #[tokio::test]
    async fn invalid_gateway_upload_preserves_existing_files_and_lock() {
        let cases = [
            ("host", r#"request_headers = [{ name = "bad header", value = "x" }]"#, "bad header"),
            (
                "sni_proxy",
                r#"request_headers = [{ name = "x-test", value = "x" }]"#,
                "SNI passthrough",
            ),
        ];
        for (kind, upstream_options, expected_error) in cases {
            for upload_only in [true, false] {
                let home = tempfile::tempdir().unwrap();
                let original_files = [
                    (INIT_FILE_NAME, "original init config"),
                    (LAND_CONFIG, "original system config"),
                    (INIT_LOCK_FILE_NAME, "original init lock"),
                ];
                for (name, content) in original_files {
                    std::fs::write(home.path().join(name), content).unwrap();
                }
                let content = format!(
                    "version = \"{VERSION}\"\n{}",
                    gateway_rule_content("invalid", kind, upstream_options),
                );

                let error = import_init_config_content(home.path(), &content, upload_only)
                    .await
                    .unwrap_err();
                let LandscapeApiError::InitConfig(InitConfigError::Invalid { reason }) = error
                else {
                    panic!("expected invalid import error, got {error:?}");
                };
                assert!(reason.contains(expected_error), "unexpected validation error: {reason}");
                for (name, content) in original_files {
                    assert_eq!(std::fs::read(home.path().join(name)).unwrap(), content.as_bytes());
                }
            }
        }
    }

    #[tokio::test]
    async fn legacy_sni_upload_persists_none_and_preserves_http_default() {
        for old_policy in ["", "client_ip_headers = \"standard\""] {
            let home = tempfile::tempdir().unwrap();
            std::fs::write(home.path().join(INIT_FILE_NAME), "original init config").unwrap();
            std::fs::write(home.path().join(LAND_CONFIG), "original system config").unwrap();
            std::fs::write(home.path().join(INIT_LOCK_FILE_NAME), "original init lock").unwrap();
            let content = format!(
                "version = \"{VERSION}\"\n{}{}",
                gateway_rule_content("sni", "sni_proxy", old_policy),
                gateway_rule_content("http", "host", ""),
            );

            let preview = import_init_config_content(home.path(), &content, true).await.unwrap();
            assert!(preview.upload_only);
            assert!(preview.filename.is_none());
            assert_eq!(
                std::fs::read_to_string(home.path().join(INIT_FILE_NAME)).unwrap(),
                "original init config",
            );
            assert_eq!(
                std::fs::read_to_string(home.path().join(INIT_LOCK_FILE_NAME)).unwrap(),
                "original init lock",
            );

            let staged = import_init_config_content(home.path(), &content, false).await.unwrap();
            assert!(!staged.upload_only);
            assert_eq!(staged.filename.as_deref(), Some(INIT_FILE_NAME));
            let persisted: InitConfig =
                toml::from_str(&std::fs::read_to_string(home.path().join(INIT_FILE_NAME)).unwrap())
                    .unwrap();
            assert!(matches!(
                persisted.gateway_rules[0].upstream.client_ip_headers,
                ClientIpHeaderPolicy::None,
            ));
            assert!(matches!(
                persisted.gateway_rules[1].upstream.client_ip_headers,
                ClientIpHeaderPolicy::Standard,
            ));
            assert!(!home.path().join(INIT_LOCK_FILE_NAME).exists());
            assert_eq!(
                std::fs::read_to_string(home.path().join(LAND_CONFIG)).unwrap(),
                "original system config",
            );
        }
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

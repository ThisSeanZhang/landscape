use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::cert::order::CertConfig;
use landscape_common::cert::CertError;
use landscape_common::config::ConfigId;
use landscape_common::service::controller::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_cert_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_certs, create_cert))
        .routes(routes!(get_cert, delete_cert))
        .routes(routes!(issue_cert))
        .routes(routes!(revoke_cert))
        .routes(routes!(renew_cert))
}

#[utoipa::path(
    get,
    path = "/certs",
    tag = "Certificates",
    responses((status = 200, body = CommonApiResp<Vec<CertConfig>>))
)]
async fn list_certs(State(state): State<LandscapeApp>) -> LandscapeApiResult<Vec<CertConfig>> {
    let result = state.cert_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/certs",
    tag = "Certificates",
    request_body = CertConfig,
    responses((status = 200, body = CommonApiResp<CertConfig>))
)]
async fn create_cert(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<CertConfig>,
) -> LandscapeApiResult<CertConfig> {
    let result = state.cert_service.create_or_update_cert(config).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/certs/{id}",
    tag = "Certificates",
    params(("id" = Uuid, Path, description = "Certificate ID")),
    responses(
        (status = 200, body = CommonApiResp<CertConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_cert(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<CertConfig> {
    let result = state.cert_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(CertError::CertNotFound(id))?
    }
}

#[utoipa::path(
    delete,
    path = "/certs/{id}",
    tag = "Certificates",
    params(("id" = Uuid, Path, description = "Certificate ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn delete_cert(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.cert_service.delete(id).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/certs/{id}/issue",
    tag = "Certificates",
    params(("id" = Uuid, Path, description = "Certificate ID")),
    responses(
        (status = 200, body = CommonApiResp<CertConfig>),
        (status = 404, description = "Not found"),
        (status = 500, description = "Issuance failed")
    )
)]
async fn issue_cert(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<CertConfig> {
    let result = state.cert_service.issue_cert(id).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/certs/{id}/revoke",
    tag = "Certificates",
    params(("id" = Uuid, Path, description = "Certificate ID")),
    responses(
        (status = 200, body = CommonApiResp<CertConfig>),
        (status = 404, description = "Not found"),
        (status = 500, description = "Revocation failed")
    )
)]
async fn revoke_cert(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<CertConfig> {
    let result = state.cert_service.revoke_cert(id).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/certs/{id}/renew",
    tag = "Certificates",
    params(("id" = Uuid, Path, description = "Certificate ID")),
    responses(
        (status = 200, body = CommonApiResp<CertConfig>),
        (status = 404, description = "Not found"),
        (status = 500, description = "Renewal failed")
    )
)]
async fn renew_cert(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<CertConfig> {
    let result = state.cert_service.renew_cert(id).await?;
    LandscapeApiResp::success(result)
}

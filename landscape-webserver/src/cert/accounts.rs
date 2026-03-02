use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::cert::account::CertAccountConfig;
use landscape_common::cert::CertError;
use landscape_common::config::ConfigId;
use landscape_common::service::controller::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_cert_account_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_cert_accounts, create_cert_account))
        .routes(routes!(get_cert_account, delete_cert_account))
}

#[utoipa::path(
    get,
    path = "/accounts",
    tag = "Certificate Accounts",
    responses((status = 200, body = CommonApiResp<Vec<CertAccountConfig>>))
)]
async fn list_cert_accounts(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<CertAccountConfig>> {
    let result = state.cert_account_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/accounts",
    tag = "Certificate Accounts",
    request_body = CertAccountConfig,
    responses((status = 200, body = CommonApiResp<CertAccountConfig>))
)]
async fn create_cert_account(
    State(state): State<LandscapeApp>,
    JsonBody(account): JsonBody<CertAccountConfig>,
) -> LandscapeApiResult<CertAccountConfig> {
    let result = state.cert_account_service.checked_set(account).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/accounts/{id}",
    tag = "Certificate Accounts",
    params(("id" = Uuid, Path, description = "Certificate account ID")),
    responses(
        (status = 200, body = CommonApiResp<CertAccountConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_cert_account(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<CertAccountConfig> {
    let result = state.cert_account_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(CertError::AccountNotFound(id))?
    }
}

#[utoipa::path(
    delete,
    path = "/accounts/{id}",
    tag = "Certificate Accounts",
    params(("id" = Uuid, Path, description = "Certificate account ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn delete_cert_account(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.cert_account_service.delete(id).await;
    LandscapeApiResp::success(())
}

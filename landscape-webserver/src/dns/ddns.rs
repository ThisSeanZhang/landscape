use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::ddns::{DdnsJob, DdnsJobRuntime};
use landscape_common::service::controller::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub fn get_ddns_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_ddns_jobs))
        .routes(routes!(list_ddns_job_status))
        .routes(routes!(create_ddns_job))
        .routes(routes!(trigger_ddns_job_sync))
        .routes(routes!(get_ddns_job))
        .routes(routes!(update_ddns_job))
        .routes(routes!(delete_ddns_job))
}

#[utoipa::path(
    get,
    path = "/ddns",
    tag = "DDNS",
    responses((status = 200, body = CommonApiResp<Vec<DdnsJob>>))
)]
async fn list_ddns_jobs(State(app): State<LandscapeApp>) -> LandscapeApiResult<Vec<DdnsJob>> {
    LandscapeApiResp::success(app.ddns_service.list().await)
}

#[utoipa::path(
    get,
    path = "/ddns/status",
    tag = "DDNS",
    responses((status = 200, body = CommonApiResp<Vec<DdnsJobRuntime>>))
)]
async fn list_ddns_job_status(
    State(app): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DdnsJobRuntime>> {
    LandscapeApiResp::success(app.ddns_service.get_runtime_statuses().await.into_values().collect())
}

#[utoipa::path(
    get,
    path = "/ddns/{id}",
    tag = "DDNS",
    params(("id" = Uuid, Path, description = "DDNS job ID")),
    responses((status = 200, body = CommonApiResp<Option<DdnsJob>>))
)]
async fn get_ddns_job(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<DdnsJob>> {
    LandscapeApiResp::success(app.ddns_service.find_by_id(id).await)
}

#[utoipa::path(
    post,
    path = "/ddns",
    tag = "DDNS",
    request_body = DdnsJob,
    responses((status = 200, body = CommonApiResp<DdnsJob>))
)]
async fn create_ddns_job(
    State(app): State<LandscapeApp>,
    JsonBody(payload): JsonBody<DdnsJob>,
) -> LandscapeApiResult<DdnsJob> {
    LandscapeApiResp::success(app.ddns_service.checked_set_job(payload).await?)
}

#[utoipa::path(
    post,
    path = "/ddns/{id}/sync",
    tag = "DDNS",
    params(("id" = Uuid, Path, description = "DDNS job ID")),
    responses((status = 200, body = CommonApiResp<DdnsJobRuntime>))
)]
async fn trigger_ddns_job_sync(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DdnsJobRuntime> {
    LandscapeApiResp::success(app.ddns_service.sync_job_now(id).await?)
}

#[utoipa::path(
    put,
    path = "/ddns/{id}",
    tag = "DDNS",
    params(("id" = Uuid, Path, description = "DDNS job ID")),
    request_body = DdnsJob,
    responses((status = 200, body = CommonApiResp<DdnsJob>))
)]
async fn update_ddns_job(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(mut payload): JsonBody<DdnsJob>,
) -> LandscapeApiResult<DdnsJob> {
    payload.id = id;
    LandscapeApiResp::success(app.ddns_service.checked_set_job(payload).await?)
}

#[utoipa::path(
    delete,
    path = "/ddns/{id}",
    tag = "DDNS",
    params(("id" = Uuid, Path, description = "DDNS job ID")),
    responses((status = 200, description = "Success"))
)]
async fn delete_ddns_job(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    app.ddns_service.delete(id).await;
    LandscapeApiResp::success(())
}

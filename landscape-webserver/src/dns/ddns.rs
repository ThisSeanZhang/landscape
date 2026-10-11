use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::ddns::{DdnsJobRuntime, DdnsTaskProgress};
use landscape_common::service::controller::ConfigStoreController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::{LandscapeApp, api::LandscapeApiResp, error::LandscapeApiResult};

use landscape_common::ddns::api::ApiDdnsJob;

pub fn get_ddns_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_ddns_jobs))
        .routes(routes!(list_ddns_job_status))
        .routes(routes!(list_ddns_tasks))
        .routes(routes!(create_ddns_job))
        .routes(routes!(trigger_ddns_job_sync))
        .routes(routes!(cancel_ddns_job_sync))
        .routes(routes!(get_ddns_job))
        .routes(routes!(update_ddns_job))
        .routes(routes!(delete_ddns_job))
}

#[utoipa::path(
    get,
    path = "/ddns",
    tag = "DDNS",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<ApiDdnsJob>>))
)]
async fn list_ddns_jobs(State(app): State<LandscapeApp>) -> LandscapeApiResult<Vec<ApiDdnsJob>> {
    LandscapeApiResp::success(app.ddns_service.list().await?.into_iter().map(Into::into).collect())
}

#[utoipa::path(
    get,
    path = "/ddns/status",
    tag = "DDNS",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<DdnsJobRuntime>>))
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
    responses((status = 200, description = "Success", body = CommonApiResp<Option<ApiDdnsJob>>))
)]
async fn get_ddns_job(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<ApiDdnsJob>> {
    LandscapeApiResp::success(app.ddns_service.find_by_id(id).await?.map(Into::into))
}

#[utoipa::path(
    post,
    path = "/ddns",
    tag = "DDNS",
    request_body = ApiDdnsJob,
    responses((status = 200, description = "Success", body = CommonApiResp<ApiDdnsJob>))
)]
async fn create_ddns_job(
    State(app): State<LandscapeApp>,
    JsonBody(payload): JsonBody<ApiDdnsJob>,
) -> LandscapeApiResult<ApiDdnsJob> {
    LandscapeApiResp::success(app.ddns_service.checked_set_job(payload.into()).await?.into())
}

#[utoipa::path(
    get,
    path = "/ddns/tasks",
    tag = "DDNS",
    responses((status = 200, description = "In-flight DDNS sync task progress", body = CommonApiResp<Vec<DdnsTaskProgress>>))
)]
async fn list_ddns_tasks(
    State(app): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DdnsTaskProgress>> {
    LandscapeApiResp::success(app.ddns_service.task_progress_snapshot())
}

#[utoipa::path(
    post,
    path = "/ddns/{id}/sync",
    tag = "DDNS",
    params(("id" = Uuid, Path, description = "DDNS job ID")),
    responses(
        (status = 200, description = "Sync triggered; poll /ddns/tasks for progress", body = CommonApiResp<DdnsJobRuntime>),
        (status = 404, description = "Job not found"),
        (status = 409, description = "Sync task is already running")
    )
)]
async fn trigger_ddns_job_sync(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DdnsJobRuntime> {
    LandscapeApiResp::success(app.ddns_service.sync_job_now(id).await?)
}

#[utoipa::path(
    post,
    path = "/ddns/{id}/cancel",
    tag = "DDNS",
    params(("id" = Uuid, Path, description = "DDNS job ID")),
    responses(
        (status = 200, description = "Cancel requested", body = CommonApiResp<DdnsJobRuntime>),
        (status = 404, description = "Job not found")
    )
)]
async fn cancel_ddns_job_sync(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DdnsJobRuntime> {
    LandscapeApiResp::success(app.ddns_service.cancel_job_sync(id).await?)
}

#[utoipa::path(
    put,
    path = "/ddns/{id}",
    tag = "DDNS",
    params(("id" = Uuid, Path, description = "DDNS job ID")),
    request_body = ApiDdnsJob,
    responses((status = 200, description = "Success", body = CommonApiResp<ApiDdnsJob>))
)]
async fn update_ddns_job(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(mut payload): JsonBody<ApiDdnsJob>,
) -> LandscapeApiResult<ApiDdnsJob> {
    payload.id = id;
    LandscapeApiResp::success(app.ddns_service.checked_set_job(payload.into()).await?.into())
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
    app.ddns_service.delete(id).await?;
    LandscapeApiResp::success(())
}

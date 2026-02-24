use crate::LandscapeApp;
use axum::extract::{Path, State};
use bollard::{query_parameters::ListImagesOptions, secret::ImageSummary, Docker};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::docker::image::{PullImageReq, PullImgTask};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

pub fn get_docker_images_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_images))
        .routes(routes!(pull_image_by_image_name))
        .routes(routes!(delete_image_by_id))
        .routes(routes!(get_current_task))
}

#[utoipa::path(
    get,
    path = "/images/tasks",
    tag = "Docker Images",
    operation_id = "get_docker_pull_tasks",
    responses((status = 200, body = CommonApiResp<Vec<PullImgTask>>))
)]
async fn get_current_task(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<PullImgTask>> {
    LandscapeApiResp::success(state.docker_service.pull_manager.get_info().await)
}

#[utoipa::path(
    get,
    path = "/images",
    tag = "Docker Images",
    operation_id = "get_all_docker_images",
    responses((status = 200, body = inline(CommonApiResp<serde_json::Value>)))
)]
async fn get_all_images() -> LandscapeApiResult<Vec<ImageSummary>> {
    let mut summarys: Vec<ImageSummary> = vec![];
    let docker = Docker::connect_with_socket_defaults();

    if let Ok(docker) = docker {
        let option = ListImagesOptions { all: true, ..Default::default() };
        if let Ok(images) = docker.list_images(Some(option)).await {
            summarys = images;
        }
    }
    LandscapeApiResp::success(summarys)
}

#[utoipa::path(
    post,
    path = "/images/pull",
    tag = "Docker Images",
    operation_id = "pull_docker_image",
    request_body = PullImageReq,
    responses((status = 200, description = "Success"))
)]
async fn pull_image_by_image_name(
    State(state): State<LandscapeApp>,
    JsonBody(pull): JsonBody<PullImageReq>,
) -> LandscapeApiResult<()> {
    state.docker_service.pull_manager.pull_img(pull.image_name).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/images/{id}",
    tag = "Docker Images",
    operation_id = "delete_docker_image",
    params(("id" = String, Path, description = "Image ID")),
    responses((status = 200, description = "Success"))
)]
async fn delete_image_by_id(Path(image_id): Path<String>) -> LandscapeApiResult<()> {
    let command = ["docker", "rmi", &image_id];
    if let Ok(status) = tokio::process::Command::new(&command[0]).args(&command[1..]).status().await
    {
        if status.success() {
            tracing::info!("Docker command executed successfully.");
        } else {
            tracing::error!("Docker command failed with status: {:?}", status);
        }
    }

    LandscapeApiResp::success(())
}

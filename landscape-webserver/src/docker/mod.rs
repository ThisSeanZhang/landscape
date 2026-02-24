use axum::extract::{Path, State};

use bollard::{
    query_parameters::{
        CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
        StartContainerOptions, StopContainerOptions,
    },
    secret::{ContainerCreateBody, ContainerSummary},
    Docker,
};

use image::get_docker_images_paths;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::{
    docker::DockerCmd,
    service::{DefaultWatchServiceStatus, ServiceStatus},
};
use network::get_docker_networks_paths;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::{docker::error::DockerError, LandscapeApp};

pub mod error;
mod image;
mod network;

pub fn get_docker_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_docker_status, start_docker_status, stop_docker_status))
        .routes(routes!(get_all_container_summarys))
        .routes(routes!(run_container))
        .routes(routes!(run_cmd_container))
        .routes(routes!(start_container))
        .routes(routes!(stop_container))
        .routes(routes!(remove_container))
        .merge(get_docker_images_paths())
        .merge(get_docker_networks_paths())
}

#[utoipa::path(
    get,
    path = "/docker/status",
    tag = "Docker",
    operation_id = "get_docker_status",
    responses((status = 200, body = inline(CommonApiResp<ServiceStatus>)))
)]
async fn get_docker_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<DefaultWatchServiceStatus> {
    LandscapeApiResp::success(state.docker_service.status)
}

#[utoipa::path(
    post,
    path = "/docker/status",
    tag = "Docker",
    operation_id = "start_docker_status",
    responses((status = 200, body = inline(CommonApiResp<ServiceStatus>)))
)]
async fn start_docker_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<DefaultWatchServiceStatus> {
    state.docker_service.start_to_listen_event().await;
    LandscapeApiResp::success(state.docker_service.status)
}

#[utoipa::path(
    delete,
    path = "/docker/status",
    tag = "Docker",
    operation_id = "stop_docker_status",
    responses((status = 200, body = inline(CommonApiResp<ServiceStatus>)))
)]
async fn stop_docker_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<DefaultWatchServiceStatus> {
    state.docker_service.status.wait_stop().await;
    LandscapeApiResp::success(state.docker_service.status)
}

#[utoipa::path(
    get,
    path = "/docker/container_summarys",
    tag = "Docker",
    operation_id = "get_all_container_summarys",
    responses((status = 200, body = inline(CommonApiResp<serde_json::Value>)))
)]
async fn get_all_container_summarys() -> LandscapeApiResult<Vec<ContainerSummary>> {
    let mut container_summarys: Vec<ContainerSummary> = vec![];
    let docker = Docker::connect_with_socket_defaults();

    if let Ok(docker) = docker {
        let option = ListContainersOptions { all: true, ..Default::default() };
        if let Ok(containers) = docker.list_containers(Some(option)).await {
            container_summarys = containers;
        }
    }

    LandscapeApiResp::success(container_summarys)
}

#[utoipa::path(
    post,
    path = "/docker/run/{container_name}",
    tag = "Docker",
    operation_id = "run_container",
    params(("container_name" = String, Path, description = "Container name")),
    request_body = serde_json::Value,
    responses((status = 200, description = "Success"))
)]
async fn run_container(
    Path(container_name): Path<String>,
    JsonBody(container_config): JsonBody<ContainerCreateBody>,
) -> LandscapeApiResult<()> {
    let docker = Docker::connect_with_socket_defaults().unwrap();
    if let Err(e) = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some(container_name.clone()),
                platform: "".to_string(),
            }),
            container_config,
        )
        .await
    {
        tracing::error!("{:?}", e);
        return Err(DockerError::CreateContainerError)?;
    } else {
        let query: Option<StartContainerOptions> = None;
        if let Err(e) = &docker.start_container(&container_name, query).await {
            tracing::error!("{:?}", e);
            return Err(DockerError::StartContainerError)?;
        }
    }
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/docker/run_cmd",
    tag = "Docker",
    operation_id = "run_cmd_container",
    request_body = DockerCmd,
    responses((status = 200, description = "Success"))
)]
async fn run_cmd_container(
    State(state): State<LandscapeApp>,
    JsonBody(docker_cmd): JsonBody<DockerCmd>,
) -> LandscapeApiResult<()> {
    if let Err(_) = docker_cmd.execute_docker_command(&state.home_path).await {
        return Err(DockerError::FailToRunContainerByCmd)?;
    }
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/docker/start/{container_name}",
    tag = "Docker",
    operation_id = "start_container",
    params(("container_name" = String, Path, description = "Container name")),
    responses((status = 200, description = "Success"))
)]
async fn start_container(Path(container_name): Path<String>) -> LandscapeApiResult<()> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    if let Err(e) = &docker.start_container(&container_name, None::<StartContainerOptions>).await {
        tracing::error!("{:?}", e);
        return Err(DockerError::StartContainerError)?;
    }

    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/docker/stop/{container_name}",
    tag = "Docker",
    operation_id = "stop_container",
    params(("container_name" = String, Path, description = "Container name")),
    responses((status = 200, description = "Success"))
)]
async fn stop_container(Path(container_name): Path<String>) -> LandscapeApiResult<()> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    if let Err(e) = &docker.stop_container(&container_name, None::<StopContainerOptions>).await {
        tracing::error!("{:?}", e);
        return Err(DockerError::StopContainerError)?;
    }

    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/docker/remove/{container_name}",
    tag = "Docker",
    operation_id = "remove_container",
    params(("container_name" = String, Path, description = "Container name")),
    responses((status = 200, description = "Success"))
)]
async fn remove_container(Path(container_name): Path<String>) -> LandscapeApiResult<()> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let config = RemoveContainerOptions { force: true, v: false, link: false };
    if let Err(e) = &docker.remove_container(&container_name, Some(config)).await {
        tracing::error!("{:?}", e);
        return Err(DockerError::FailToRemoveContainer)?;
    }

    LandscapeApiResp::success(())
}

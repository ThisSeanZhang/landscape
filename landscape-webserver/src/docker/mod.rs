use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::{container::ListContainersOptions, secret::ContainerSummary, Docker};

use image::get_docker_images_paths;
use landscape::docker::LandscapeDockerService;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

use crate::SimpleResult;

mod image;

pub async fn get_docker_paths(home_path: PathBuf) -> Router {
    let docker_service = LandscapeDockerService::new(home_path.join("docker_info"));
    docker_service.start_to_listen_event().await;
    Router::new()
        .route(
            "/status",
            get(get_docker_status).post(start_docker_status).delete(stop_docker_status),
        )
        .route("/container_summarys", get(get_all_container_summarys))
        .route("/run/:container_name", post(run_container))
        .route("/run_cmd", post(run_cmd_container))
        .route("/start/:container_name", post(start_container))
        .route("/stop/:container_name", post(stop_container))
        .route("/remove/:container_name", post(remove_container))
        .with_state(docker_service)
        .nest("/images", get_docker_images_paths().await)
}

async fn get_docker_status(State(state): State<LandscapeDockerService>) -> Json<Value> {
    let result = serde_json::to_value(&state.status);
    Json(result.unwrap())
}

async fn start_docker_status(State(state): State<LandscapeDockerService>) -> Json<Value> {
    state.start_to_listen_event().await;
    let result = serde_json::to_value(&state.status);
    Json(result.unwrap())
}

async fn stop_docker_status(State(state): State<LandscapeDockerService>) -> Json<Value> {
    state.status.stop().await;
    let result = serde_json::to_value(&state.status);
    Json(result.unwrap())
}

async fn get_all_container_summarys() -> Json<Value> {
    let mut container_summarys: Vec<ContainerSummary> = vec![];
    let docker = Docker::connect_with_socket_defaults();

    if let Ok(docker) = docker {
        let option = ListContainersOptions { all: true, ..Default::default() };
        if let Ok(containers) = docker.list_containers::<String>(Some(option)).await {
            container_summarys = containers;
        }
    }

    let result = serde_json::to_value(&container_summarys);
    Json(result.unwrap())
}

async fn run_container(
    Path(container_name): Path<String>,
    Json(container_config): Json<Config<String>>,
) -> Json<Value> {
    let mut result = SimpleResult { success: false };
    let docker = Docker::connect_with_socket_defaults().unwrap();
    if let Err(e) = &docker
        .create_container(
            Some(CreateContainerOptions { name: &container_name, platform: None }),
            container_config,
        )
        .await
    {
        result.success = false;
        tracing::error!("create_container error: {:?}", e);
    } else {
        if let Err(e) =
            &docker.start_container(&container_name, None::<StartContainerOptions<String>>).await
        {
            result.success = false;
            tracing::info!("start_container error: {:?}", e);
        } else {
            result.success = true;
        }
    }
    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

async fn start_container(Path(container_name): Path<String>) -> Json<Value> {
    let mut result = SimpleResult { success: false };
    let docker = Docker::connect_with_socket_defaults().unwrap();

    if let Err(e) =
        &docker.start_container(&container_name, None::<StartContainerOptions<String>>).await
    {
        result.success = false;
        tracing::error!("start_container error: {:?}", e);
    } else {
        result.success = true;
    }

    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

async fn stop_container(Path(container_name): Path<String>) -> Json<Value> {
    let mut result = SimpleResult { success: false };
    let docker = Docker::connect_with_socket_defaults().unwrap();

    if let Err(e) = &docker.stop_container(&container_name, None::<StopContainerOptions>).await {
        result.success = false;
        tracing::error!("stop_container error: {:?}", e);
    } else {
        result.success = true;
    }

    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

async fn remove_container(Path(container_name): Path<String>) -> Json<Value> {
    let mut result = SimpleResult { success: false };
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let config = RemoveContainerOptions { force: true, v: false, link: false };
    if let Err(e) = &docker.remove_container(&container_name, Some(config)).await {
        result.success = false;
        tracing::error!("remove_container error: {:?}", e);
    } else {
        result.success = true;
    }

    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

async fn run_cmd_container(Json(docker_cmd): Json<DockerCmd>) -> Json<Value> {
    let mut result = SimpleResult { success: false };
    if let Err(e) = docker_cmd.execute_docker_command().await {
        tracing::error!("error: {:?}", e);
    } else {
        result.success = true;
    };
    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyValuePair {
    key: String,
    value: String,
}

impl KeyValuePair {
    pub fn separator(&self, separator: &str) -> String {
        format!("{}{separator}{}", self.key, self.value)
    }
}
#[derive(Debug, Serialize, Deserialize)]
struct DockerCmd {
    image_name: String,
    container_name: Option<String>,
    ports: Option<Vec<KeyValuePair>>,
    environment: Option<Vec<KeyValuePair>>,
    volumes: Option<Vec<KeyValuePair>>,
    labels: Option<Vec<KeyValuePair>>,
}

impl DockerCmd {
    // 生成 Docker 命令
    fn generate_docker_command(&self) -> Vec<String> {
        let mut command = vec!["docker".to_string(), "run".to_string(), "-d".to_string()];

        if let Some(container_name) = &self.container_name {
            command.push("--name".to_string());
            command.push(container_name.clone());
        }

        if let Some(ports) = &self.ports {
            for port in ports {
                command.push("-p".to_string());
                command.push(port.separator(":"));
            }
        }

        if let Some(environments) = &self.environment {
            for environment in environments {
                command.push("-e".to_string());
                command.push(environment.separator("="));
            }
        }

        if let Some(volumes) = &self.volumes {
            for volume in volumes {
                command.push("-v".to_string());
                command.push(volume.separator(":"));
            }
        }

        let mut accept_local = false;
        if let Some(labels) = &self.labels {
            for label in labels {
                if label.key == "ld_red_id" {
                    accept_local = true;
                }
                command.push("--label".to_string());
                command.push(label.separator("="));
            }
        }

        if accept_local {
            command.push("--sysctl".to_string());
            command.push("net.ipv4.conf.lo.accept_local=1".to_string());
            command.push("--cap-add=NET_ADMIN".to_string());
            command.push("--cap-add=BPF".to_string());
            command.push("--cap-add=PERFMON".to_string());
        }

        command.push(self.image_name.clone());

        tracing::info!("command: {:?}", command);
        command
    }

    // 执行 Docker 命令
    async fn execute_docker_command(&self) -> Result<(), ()> {
        let command = self.generate_docker_command();
        if let Ok(status) =
            tokio::process::Command::new(&command[0]).args(&command[1..]).status().await
        {
            if status.success() {
                tracing::info!("Docker command executed successfully.");
            } else {
                tracing::error!("Docker command failed with status: {:?}", status);
                return Err(());
            }
        } else {
            return Err(());
        }

        Ok(())
    }
}

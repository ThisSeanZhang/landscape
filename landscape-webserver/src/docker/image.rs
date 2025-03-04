use axum::{
    extract::Path,
    routing::{delete, get, post},
    Json, Router,
};
use bollard::{image::ListImagesOptions, secret::ImageSummary, Docker};
use serde_json::Value;

use crate::SimpleResult;

pub async fn get_docker_images_paths() -> Router {
    Router::new()
        .route("/", get(get_all_images))
        .route("/:image_name", post(pull_image_by_image_name))
        .route("/id/:image_id", delete(delete_image_by_id))
}

async fn get_all_images() -> Json<Value> {
    let mut summarys: Vec<ImageSummary> = vec![];
    let docker = Docker::connect_with_socket_defaults();

    if let Ok(docker) = docker {
        let option = ListImagesOptions { all: true, ..Default::default() };
        if let Ok(images) = docker.list_images::<String>(Some(option)).await {
            summarys = images;
        }
    }

    let result = serde_json::to_value(&summarys);
    Json(result.unwrap())
}

async fn pull_image_by_image_name(Path(image_name): Path<String>) -> Json<Value> {
    let mut result = SimpleResult { success: false };

    let command = ["docker", "pull", &image_name];
    if let Ok(status) = tokio::process::Command::new(&command[0]).args(&command[1..]).status().await
    {
        if status.success() {
            result.success = true;
            tracing::info!("Docker command executed successfully.");
        } else {
            tracing::error!("Docker command failed with status: {:?}", status);
        }
    }

    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

async fn delete_image_by_id(Path(image_id): Path<String>) -> Json<Value> {
    let mut result = SimpleResult { success: false };

    let command = ["docker", "rmi", &image_id];
    if let Ok(status) = tokio::process::Command::new(&command[0]).args(&command[1..]).status().await
    {
        if status.success() {
            result.success = true;
            tracing::info!("Docker command executed successfully.");
        } else {
            tracing::error!("Docker command failed with status: {:?}", status);
        }
    }

    let result = serde_json::to_value(&result);
    Json(result.unwrap())
}

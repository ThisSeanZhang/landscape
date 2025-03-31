use axum::{routing::get, Json, Router};

use landscape::docker::network::inspect_all_networks;
use serde_json::Value;

pub async fn get_docker_networks_paths() -> Router {
    Router::new().route("/", get(get_all_networks))
}

async fn get_all_networks() -> Json<Value> {
    let networks = inspect_all_networks().await;

    let result = serde_json::to_value(&networks);
    Json(result.unwrap())
}

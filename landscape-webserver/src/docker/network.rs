use landscape::docker::network::inspect_all_networks;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::docker::network::LandscapeDockerNetwork;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_docker_networks_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().routes(routes!(get_all_networks))
}

#[utoipa::path(
    get,
    path = "/networks",
    tag = "Docker Networks",
    operation_id = "get_all_docker_networks",
    responses((status = 200, body = inline(CommonApiResp<Vec<LandscapeDockerNetwork>>)))
)]
async fn get_all_networks() -> LandscapeApiResult<Vec<LandscapeDockerNetwork>> {
    let networks = inspect_all_networks().await;

    LandscapeApiResp::success(networks)
}

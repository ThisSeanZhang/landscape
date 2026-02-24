use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::LandscapeApiResp;
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

pub fn get_sys_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(export_init_config))
        .routes(routes!(super::ui_config::get_ui_config_fast))
        .routes(routes!(super::ui_config::get_ui_config, super::ui_config::update_ui_config))
        .routes(routes!(super::metric_config::get_metric_config_fast))
        .routes(routes!(
            super::metric_config::get_metric_config,
            super::metric_config::update_metric_config
        ))
        .routes(routes!(super::dns_config::get_dns_config_fast))
        .routes(routes!(super::dns_config::get_dns_config, super::dns_config::update_dns_config))
}

#[utoipa::path(
    get,
    path = "/config/export",
    tag = "System Config",
    operation_id = "export_init_config",
    responses((status = 200, body = CommonApiResp<String>))
)]
async fn export_init_config(State(state): State<LandscapeApp>) -> LandscapeApiResult<String> {
    let config = state.config_service.export_init_config().await;
    let config_file_content = toml::to_string(&config).unwrap();

    LandscapeApiResp::success(config_file_content)
}

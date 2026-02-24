use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::LandscapeApiResp;
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

pub mod dns;
pub mod metric;
pub mod ui;

pub fn get_sys_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(export_init_config))
        .routes(routes!(ui::get_ui_config_fast))
        .routes(routes!(ui::get_ui_config, ui::update_ui_config))
        .routes(routes!(metric::get_metric_config_fast))
        .routes(routes!(metric::get_metric_config, metric::update_metric_config))
        .routes(routes!(dns::get_dns_config_fast))
        .routes(routes!(dns::get_dns_config, dns::update_dns_config))
}

#[utoipa::path(
    get,
    path = "/config/export",
    tag = "System Config",
    operation_id = "export_init_config",
    responses((status = 200, body = inline(CommonApiResp<String>)))
)]
async fn export_init_config(State(state): State<LandscapeApp>) -> LandscapeApiResult<String> {
    let config = state.config_service.export_init_config().await;
    let config_file_content = toml::to_string(&config).unwrap();

    LandscapeApiResp::success(config_file_content)
}

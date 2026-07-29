use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{
    GetMetricConfigResponse, LandscapeMetricConfig, UpdateMetricConfigRequest,
};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

#[utoipa::path(
    get,
    path = "/config/edit/metric",
    tag = "System Config",
    operation_id = "get_metric_config",
    responses((status = 200, body = CommonApiResp<GetMetricConfigResponse>))
)]
pub async fn get_metric_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetMetricConfigResponse> {
    let (metric, hash) = state.config_service.get_metric_config_from_file().await?;
    LandscapeApiResp::success(GetMetricConfigResponse { metric, hash })
}

#[utoipa::path(
    get,
    path = "/config/metric",
    tag = "System Config",
    operation_id = "get_metric_config_fast",
    responses((status = 200, body = CommonApiResp<LandscapeMetricConfig>))
)]
pub async fn get_metric_config_fast(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<LandscapeMetricConfig> {
    let metric_config = state.config_service.get_metric_config_from_memory();
    LandscapeApiResp::success(metric_config)
}

#[utoipa::path(
    post,
    path = "/config/edit/metric",
    tag = "System Config",
    operation_id = "update_metric_config",
    request_body = UpdateMetricConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_metric_config(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<UpdateMetricConfigRequest>,
) -> LandscapeApiResult<()> {
    state.config_service.update_metric_config(payload.new_metric, payload.expected_hash).await?;
    let metric_runtime = state.config_service.get_metric_runtime_config();
    state.metric_service.apply_runtime_config(metric_runtime).await;
    state.dns_service.update_metric_sender(state.metric_service.get_dns_metric_channel());
    LandscapeApiResp::success(())
}

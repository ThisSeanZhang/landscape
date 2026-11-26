use crate::app::system_config::{SystemConfigChange, SystemConfigEditor};
use axum::extract::{FromRef, State};
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::sys_config::{
    GetConnectMetricConfigResponse, GetDnsMetricConfigResponse, GetSelfMonitorConfigResponse,
    LandscapeMetricConfig, UpdateConnectMetricConfigRequest, UpdateDnsMetricConfigRequest,
    UpdateSelfMonitorConfigRequest,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

pub(super) fn paths<S>() -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    LandscapeConfigService: FromRef<S>,
    SystemConfigEditor: FromRef<S>,
{
    OpenApiRouter::new()
        .routes(routes!(get_metric_config_fast))
        .routes(routes!(get_connect_metric_config, update_connect_metric_config))
        .routes(routes!(get_dns_metric_config, update_dns_metric_config))
        .routes(routes!(get_self_monitor_config, update_self_monitor_config))
}

#[utoipa::path(
    get,
    path = "/config/metric",
    tag = "System Config",
    operation_id = "get_metric_config_fast",
    responses((status = 200, description = "Success", body = CommonApiResp<LandscapeMetricConfig>))
)]
pub async fn get_metric_config_fast(
    State(configs): State<LandscapeConfigService>,
) -> LandscapeApiResult<LandscapeMetricConfig> {
    let metric_config = configs.get_metric_config_from_memory();
    LandscapeApiResp::success(metric_config)
}

#[utoipa::path(get,path="/config/edit/metric/connect",tag="System Config",operation_id="get_connect_metric_config",
        responses((status=200,description="Success",body=CommonApiResp<GetConnectMetricConfigResponse>)))]
pub async fn get_connect_metric_config(
    State(configs): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetConnectMetricConfigResponse> {
    let (config, hash) = configs.get_connect_metric_from_file()?;
    LandscapeApiResp::success(GetConnectMetricConfigResponse { config, hash })
}

#[utoipa::path(post,path="/config/edit/metric/connect",tag="System Config",operation_id="update_connect_metric_config",request_body=UpdateConnectMetricConfigRequest,
        responses((status=200,description="Success")))]
pub async fn update_connect_metric_config(
    State(editor): State<SystemConfigEditor>,
    JsonBody(payload): JsonBody<UpdateConnectMetricConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::ConnectMetric(payload)).await?;
    LandscapeApiResp::success(())
}
#[utoipa::path(get,path="/config/edit/metric/dns",tag="System Config",operation_id="get_dns_metric_config",
        responses((status=200,description="Success",body=CommonApiResp<GetDnsMetricConfigResponse>)))]
pub async fn get_dns_metric_config(
    State(configs): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetDnsMetricConfigResponse> {
    let (config, hash) = configs.get_dns_metric_from_file()?;
    LandscapeApiResp::success(GetDnsMetricConfigResponse { config, hash })
}

#[utoipa::path(post,path="/config/edit/metric/dns",tag="System Config",operation_id="update_dns_metric_config",request_body=UpdateDnsMetricConfigRequest,
        responses((status=200,description="Success")))]
pub async fn update_dns_metric_config(
    State(editor): State<SystemConfigEditor>,
    JsonBody(payload): JsonBody<UpdateDnsMetricConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::DnsMetric(payload)).await?;
    LandscapeApiResp::success(())
}
#[utoipa::path(get,path="/config/edit/self_monitor",tag="System Config",operation_id="get_self_monitor_config",
        responses((status=200,description="Success",body=CommonApiResp<GetSelfMonitorConfigResponse>)))]
pub async fn get_self_monitor_config(
    State(configs): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetSelfMonitorConfigResponse> {
    let (config, hash) = configs.get_self_monitor_from_file()?;
    LandscapeApiResp::success(GetSelfMonitorConfigResponse { config, hash })
}

#[utoipa::path(post,path="/config/edit/self_monitor",tag="System Config",operation_id="update_self_monitor_config",request_body=UpdateSelfMonitorConfigRequest,
        responses((status=200,description="Success")))]
pub async fn update_self_monitor_config(
    State(editor): State<SystemConfigEditor>,
    JsonBody(payload): JsonBody<UpdateSelfMonitorConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::SelfMonitor(payload)).await?;
    LandscapeApiResp::success(())
}

#[cfg(test)]
mod tests;

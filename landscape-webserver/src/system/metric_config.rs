use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{
    GetMetricConfigResponse, LandscapeMetricConfig, UpdateMetricConfigRequest,
};
use landscape_common::database::error::DbError;

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

static METRIC_CONFIG_UPDATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    payload.new_metric.validate()?;
    let _guard = METRIC_CONFIG_UPDATE_LOCK.lock().await;

    let (previous_file_config, current_hash) =
        state.config_service.get_metric_config_from_file().await?;
    if current_hash != payload.expected_hash {
        return Err(DbError::Conflict.into());
    }
    let previous_runtime = state.config_service.get_metric_runtime_config();

    // 先落盘(原子替换 + CAS)再应用运行时:进程在任意时刻崩溃,重启后都会
    // 从文件重建运行时,不会出现"运行时新、文件旧"的配置漂移。
    if let Err(error) =
        state.config_service.update_metric_config(payload.new_metric, payload.expected_hash).await
    {
        return Err(error.into());
    }

    // update_section 提交后内存 runtime 已合并新文件配置,直接应用它,
    // 保证引擎与 config 内存/文件三者一致。
    let metric_runtime = state.config_service.get_metric_runtime_config();
    if let Err(error) = state.metric_service.apply_runtime_config(metric_runtime).await {
        // 引擎重建失败:apply_runtime_config 内部基于内存配置的 restore 此时
        // 读到的是已提交的新配置,不能依赖它还原引擎,这里显式回滚文件并重建上一引擎。
        if let Err(rollback_error) = rollback_metric_config(&state, previous_file_config).await {
            tracing::error!(
                "failed to roll back metric config file after runtime apply failure: {}",
                rollback_error
            );
        }
        if let Err(restore_error) =
            state.metric_service.apply_runtime_config(previous_runtime).await
        {
            tracing::error!(
                "failed to restore previous metric runtime after apply failure: {}",
                restore_error
            );
        }
        state.dns_service.update_metric_sender(state.metric_service.get_dns_metric_channel());
        return Err(DbError::Internal(format!("failed to apply metric config: {error}")).into());
    }

    state.dns_service.update_metric_sender(state.metric_service.get_dns_metric_channel());
    LandscapeApiResp::success(())
}

/// 以刚读到的文件 hash 作为 expected_hash,用上一版配置覆盖当前文件
/// (同时把内存配置还原)。
async fn rollback_metric_config(
    state: &LandscapeApp,
    previous_config: LandscapeMetricConfig,
) -> Result<(), DbError> {
    let (_, current_hash) = state.config_service.get_metric_config_from_file().await?;
    state.config_service.update_metric_config(previous_config, current_hash).await
}

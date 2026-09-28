//! `/api/v1/system/memory` — 进程内按子系统的内存占用。
//!
//! - `GET /memory/modules`:即时全量快照(计数器 + RSS 校准)。
//! - `GET /memory/modules/history`:RAM 环形缓冲的最近快照(1s 粒度,
//!   最近 1 小时),重启即空。
//! - `GET /memory/history`:分钟级持久化历史(1m 聚合,默认保留 30 天,
//!   仅 persistent 构建),服务跨重启的趋势/泄漏排查。

use axum::extract::{Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::memtrack::{self, MemorySnapshot};
use landscape_common::metric::memory::{MemHistoryQueryParams, MemHistoryResponse};
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub fn get_memory_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_memory_modules))
        .routes(routes!(get_memory_modules_history))
        .routes(routes!(get_memory_persisted_history))
}

/// 历史查询缺省返回的快照数量(300 = 最近 5 分钟);显式传 0 仍返回全部
/// (最多环形缓冲容量,1s × 3600,响应可达数十 MB,谨慎使用)。
const DEFAULT_HISTORY_LIMIT: usize = 300;

#[derive(Debug, Default, serde::Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct MemoryRecentParams {
    /// 最近快照数量;0 返回全部,缺省 300。
    limit: Option<usize>,
}

#[utoipa::path(
    get,
    path = "/memory/modules",
    tag = "Memory",
    operation_id = "get_memory_modules",
    responses((status = 200, description = "Success", body = CommonApiResp<MemorySnapshot>))
)]
async fn get_memory_modules() -> LandscapeApiResult<MemorySnapshot> {
    LandscapeApiResp::success(memtrack::snapshot())
}

#[utoipa::path(
    get,
    path = "/memory/modules/history",
    tag = "Memory",
    operation_id = "get_memory_modules_history",
    params(MemoryRecentParams),
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<MemorySnapshot>>))
)]
async fn get_memory_modules_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<MemoryRecentParams>,
) -> LandscapeApiResult<Vec<MemorySnapshot>> {
    LandscapeApiResp::success(
        state.memory_history.recent(params.limit.unwrap_or(DEFAULT_HISTORY_LIMIT)),
    )
}

#[utoipa::path(
    get,
    path = "/memory/history",
    tag = "Memory",
    operation_id = "get_memory_persisted_history",
    params(MemHistoryQueryParams),
    responses((status = 200, description = "Success", body = CommonApiResp<MemHistoryResponse>))
)]
async fn get_memory_persisted_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<MemHistoryQueryParams>,
) -> LandscapeApiResult<MemHistoryResponse> {
    LandscapeApiResp::success(state.metric_service.query_memory_history(params).await)
}

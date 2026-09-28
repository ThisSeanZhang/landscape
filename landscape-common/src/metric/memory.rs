//! 进程内存指标的共享类型:RAM 快照(见 `memtrack`)之外的分钟级持久化
//! 记录与查询参数,由 landscape-metric 的 memory store 写入/查询,
//! webserver 暴露为 `/api/v1/metrics/memory` 系列 API。

/// 一个子系统在一分钟内的聚合值。
///
/// 进程级 RSS 以保留名 `(process)` 作为 subsystem 存于同一张表。
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemMinuteRecord {
    /// 分钟起始时间戳(ms)。
    pub minute_ts: u64,
    pub subsystem: String,
    /// live = allocated − freed 的分钟内平均。
    pub live_avg_bytes: u64,
    /// live 分钟内最大(泄漏排查用)。
    pub live_max_bytes: u64,
    /// 分钟内累计分配字节。
    pub alloc_delta_bytes: u64,
    /// 分钟内累计释放字节。
    pub free_delta_bytes: u64,
}

/// 保留子系统名:进程 RSS 行。
pub const PROCESS_SUBSYSTEM: &str = "(process)";

/// 内存历史查询参数。`start_time`/`end_time` 为毫秒时间戳;0/0 表示
/// 最近 24 小时,`end_time = 0` 补全为当前时间。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct MemHistoryQueryParams {
    /// 起始时间戳(ms),0 表示 end − 24h。
    pub start_time: u64,
    /// 结束时间戳(ms),0 表示当前时间。
    pub end_time: u64,
    /// 按子系统过滤,缺省返回全部。
    pub subsystem: Option<String>,
    /// 最多返回行数(每分钟每子系统一行),0 表示不限。
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemHistoryResponse {
    pub items: Vec<MemMinuteRecord>,
}

/// 内存指标默认保留天数(行数小:每分钟每子系统 1 行)。
pub const DEFAULT_MEM_METRIC_RETENTION_DAYS: u64 = 30;

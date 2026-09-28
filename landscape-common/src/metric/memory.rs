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
    /// 时间轴上的分钟数上限(最近 N 分钟),0 表示不限。
    pub limit: Option<u32>,
}

/// 位置数组形式的分钟聚合点:JSON 为
/// `[live_avg_bytes, live_max_bytes, alloc_delta_bytes, free_delta_bytes]`。
/// 字段顺序即契约,勿调整。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct MinutePoint(pub [u64; 4]);

impl From<&MemMinuteRecord> for MinutePoint {
    fn from(record: &MemMinuteRecord) -> Self {
        MinutePoint([
            record.live_avg_bytes,
            record.live_max_bytes,
            record.alloc_delta_bytes,
            record.free_delta_bytes,
        ])
    }
}

/// 单个子系统在一段共享时间轴上的分钟取值。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemSubsystemSeries {
    pub subsystem: String,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<Vec<u64>>))]
    pub points: Vec<MinutePoint>,
}

/// 分钟级持久化历史的批量响应。形状与 RAM 历史
/// (`memtrack::MemorySeriesResponse`)统一:共享 `timestamps` 轴、各 series
/// 按位置对齐;`precise`/`meta` 为 RAM 专有,此处恒为 `None`。
///
/// 缺失分钟以全零点补零对齐——**注意这会把“无数据”显示为“用量为 0”**。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemHistoryResponse {
    pub timestamps: Vec<u64>,
    pub precise: Option<bool>,
    pub meta: Option<Vec<crate::memtrack::SnapshotMeta>>,
    pub series: Vec<MemSubsystemSeries>,
}

impl MemHistoryResponse {
    /// 由分钟行与共享时间轴构建各子系统序列;缺失分钟补零对齐。
    pub fn from_rows(rows: Vec<MemMinuteRecord>, timeline: Vec<u64>) -> Self {
        use std::collections::{BTreeMap, HashMap};

        let mut grouped: BTreeMap<String, HashMap<u64, MinutePoint>> = BTreeMap::new();
        for row in rows {
            let point = MinutePoint::from(&row);
            grouped.entry(row.subsystem).or_default().insert(row.minute_ts, point);
        }

        let series = grouped
            .into_iter()
            .map(|(subsystem, by_ts)| MemSubsystemSeries {
                subsystem,
                points: timeline
                    .iter()
                    .map(|ts| by_ts.get(ts).copied().unwrap_or_default())
                    .collect(),
            })
            .collect();

        MemHistoryResponse {
            timestamps: timeline,
            precise: None,
            meta: None,
            series,
        }
    }
}

/// 内存指标默认保留天数(行数小:每分钟每子系统 1 行)。
pub const DEFAULT_MEM_METRIC_RETENTION_DAYS: u64 = 30;

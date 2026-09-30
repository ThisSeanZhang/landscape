/// RAM 环形缓冲历史的批量响应:所有 series 共享一条 `timestamps` 轴,
/// 缺失时刻按位置数组补零对齐。`meta` 为进程级信息(内存历史恒有值;
/// SQLite 分钟历史复用同一形状但置 `None`)。是否启用内存跟踪由
/// `/api/v1/info/capabilities` 的 `Capability::MemTrack` 上报。
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemorySeriesResponse {
    pub timestamps: Vec<u64>,
    pub meta: Option<Vec<super::registry::SnapshotMeta>>,
    pub series: Vec<super::registry::SubsystemSeries>,
}

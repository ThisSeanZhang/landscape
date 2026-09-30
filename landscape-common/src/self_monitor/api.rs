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
    pub series: Vec<super::memory::MemSubsystemSeries>,
}

impl MemHistoryResponse {
    /// 由分钟行与共享时间轴构建各子系统序列;缺失分钟补零对齐。
    pub fn from_rows(rows: Vec<super::memory::MemMinuteRecord>, timeline: Vec<u64>) -> Self {
        use super::memory::MinutePoint;
        use std::collections::{BTreeMap, HashMap};

        let mut grouped: BTreeMap<String, HashMap<u64, MinutePoint>> = BTreeMap::new();
        for row in rows {
            let point = MinutePoint::from(&row);
            grouped.entry(row.subsystem).or_default().insert(row.minute_ts, point);
        }

        let series = grouped
            .into_iter()
            .map(|(subsystem, by_ts)| super::memory::MemSubsystemSeries {
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

//! 非 persistent 构建的 no-op 实现(整个文件由 mod.rs 门禁,内部零 cfg)。
//!
//! 与 `super::persistent` 的 [`MemRecording`]/[`start_memory_recording`]
//! API 完全同签名:行为退化为"无记录能力、查询返回空",调用方
//! (MetricService)因此无需任何 cfg 分叉。

use std::path::PathBuf;

use landscape_common::metric::memory::{MemHistoryQueryParams, MemMinuteRecord};

/// no-op 记录句柄。
pub struct MemRecording;

impl MemRecording {
    /// 恒返回空:非 persistent 构建不落库。
    pub async fn query_history(&self, _params: &MemHistoryQueryParams) -> Vec<MemMinuteRecord> {
        Vec::new()
    }

    pub async fn stop_recorder(&mut self) {}

    pub fn spawn_recorder(&mut self, _retention_days: u64) {}
}

/// 恒返回 None:非 persistent 构建无记录能力。
pub async fn start_memory_recording(
    _base_path: PathBuf,
    _retention_days: u64,
) -> Option<MemRecording> {
    None
}

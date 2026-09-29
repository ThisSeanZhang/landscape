//! 自监控(self-monitor)内存记录的分钟级持久化
//! (`metrics_v{version}_memory.sqlite`)。
//!
//! 属于自监控域(进程自身资源占用,将来含 CPU),暂借宿于 metric 服务
//! 共享持久化设施:与 connect/dns 两条 writer 管线相互独立,由独立的
//! 采样记录任务驱动(直接读 `landscape_common::memtrack` 全局注册表),
//! 每分钟每子系统一行,行数小、无容量控制,仅按保留天数清理。
//!
//! 文件组织(feature 门禁集中在本文件):
//! - [`aggregate`] — 分钟聚合纯逻辑,两种构建均编译、可测试。
//! - [`persistent`] — SQLite 存储与后台记录任务,仅 `metric-persistent` 构建。
//! - [`stub`] — 非 persistent 构建的 no-op [`MemRecording`],与 persistent
//!   版本 API 完全一致,调用方(MetricService)因此无需任何 cfg。

mod aggregate;

#[cfg(feature = "metric-persistent")]
mod persistent;
#[cfg(feature = "metric-persistent")]
pub use persistent::{start_memory_recording, MemMetricStore, MemRecording};

#[cfg(not(feature = "metric-persistent"))]
mod stub;
#[cfg(not(feature = "metric-persistent"))]
pub use stub::{start_memory_recording, MemRecording};

pub use aggregate::MinuteAggregator;

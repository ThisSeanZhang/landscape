//! 路由器进程自监控(self-monitor)的共享类型。
//!
//! 当前仅内存:分钟级持久化记录与查询参数(见 `memory`)。后续 CPU 等
//! 进程自监控类型也归入本模块,与整机/网络指标(`metric`)区分。

pub mod api;
pub mod memory;

pub use api::MemHistoryResponse;

//! `/api/v1/self-monitor` — 路由器进程自监控。
//!
//! 与整机/网络指标(`/api/v1/metrics`)区分:这里只暴露进程自身的
//! 资源占用,当前为内存(`memory`),后续可扩展 CPU 等。

pub mod memory;

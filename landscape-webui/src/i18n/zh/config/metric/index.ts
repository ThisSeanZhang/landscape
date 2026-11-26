import connect from "./connect";
import dns from "./dns";

export default {
  metric_title: "指标监控配置",
  save_metric: "保存指标配置",
  metric_enabled: "启用采集",
  metric_backend: "存储后端",

  metric_mode: "指标模式",
  metric_mode_desc: "关闭、仅内存实时、或启用历史持久化",
  metric_mode_off: "关闭 (OFF)",
  metric_mode_memory: "内存实时 (MEM)",
  metric_mode_persistent: "持久化 (SQLite)",

  db_cap_min_hint: "容量上限需为 0（不限制）或不小于 16MB",
  performance_settings: "性能与维护参数",
  write_flush_interval: "强制提交间隔 (秒)",
  write_flush_interval_desc:
    "指标数据写入磁盘的强制刷新时间间隔；DNS 日志实际按 ≤15 秒强制落库",

  maintenance_settings: "自动清理设置",
  cleanup_interval: "数据清理间隔 (秒)",
  cleanup_interval_desc: "执行过期指标历史清理任务的时间间隔",
  cleanup_budget: "清理时间预算 (秒)",
  cleanup_budget_desc: "单次清理任务允许运行的最大秒数（切片清理）",
  cleanup_slice_window: "清理分片窗口 (秒)",
  cleanup_slice_window_desc: "单次清理事务处理的时间范围粒度",

  ...connect,
  ...dns,
};

export default {
  connect_metric_title: "连接指标",
  conn_retention_mins: "连接指标设置",
  connect_second_window_mins: "秒级热窗口 (分钟)",
  connect_second_window_mins_desc: "秒级连接图表在内存中的保留窗口",
  conn_retention_minute_days: "聚合数据保存 (分钟级)",
  conn_retention_minute_days_desc: "按分钟聚合的连接指标保存期限（天）",
  conn_retention_hour_days: "聚合数据保存 (小时级)",
  conn_retention_hour_days_desc: "按小时聚合的连接指标保存期限（天）",
  conn_retention_day_days: "聚合数据保存 (天级)",
  conn_retention_day_days_desc: "按天聚合的连接指标保存期限（天）",

  conn_detail_settings: "连接明细设置",
  conn_summary_retention_days: "明细保存天数",
  conn_summary_retention_days_desc: "单连接明细汇总行的保存期限（天）",
  conn_summary_max_rows: "明细行数上限",
  conn_summary_max_rows_desc:
    "conn_summaries 表保留的最大明细汇总行数（0 = 不限制）",
  connect_db_max_mb: "连接指标数据库容量上限（MB）",
  connect_db_max_mb_desc:
    "连接指标数据库的最大容量（0 = 不限制，非 0 最小 16MB）；接近上限时会提前清理最旧数据以保留写入余量",
  write_batch_size: "写入批处理大小",
  write_batch_size_desc: "指标数据每次刷盘的最大记录数",
};

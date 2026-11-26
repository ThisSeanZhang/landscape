export default {
  dns_metric_title: "DNS 指标",
  dns_retention_days: "DNS 数据保存天数",
  dns_retention_days_desc: "DNS 查询日志和指标的保存期限（天）",
  dns_1m_retention_days: "DNS 1分钟聚合桶保留天数",
  dns_1m_retention_days_desc:
    "1 分钟预聚合桶的保存期限（天），用于状态卡与仪表盘统计，通常大于原始日志保留期",
  dns_db_max_mb: "DNS 指标数据库容量上限（MB）",
  dns_db_max_mb_desc:
    "DNS 指标数据库的最大容量（0 = 不限制，非 0 最小 16MB）；接近上限时会提前清理最旧数据以保留写入余量",
};

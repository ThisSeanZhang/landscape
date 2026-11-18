export default {
  "self_monitor.invalid_retention": "内存历史记录至少保留一天。",
  "metric.sqlite_unavailable": "当前构建未启用 SQLite 指标存储。",
  "metric.invalid_db_max_mb":
    "{field} 必须为 0（不限制）或介于 16～1048576 MB 之间，当前为 {value}",
  "metric.invalid_cleanup_time_budget":
    "cleanup_time_budget_secs 必须介于 1～60 秒之间，当前为 {value}",
  "init_config.file_not_found": "上传中未找到 Init 文件",
  "init_config.export_serialization_failed": "导出配置序列化失败",
  "init_config.file_read_error": "Init 文件读取失败",
  "init_config.invalid": "Init 文件格式无效: {reason}",
  "init_config.version_mismatch":
    "Init 文件版本不匹配，文件版本: {file_version}，当前版本: {current_version}",
  "config.conflict": "配置已被他人修改，请刷新后重试",
  "lan_hostname.invalid_suffix.invalid_idna":
    "局域网主机名后缀 '{suffix}' 不是有效的 IDNA 标签",
  "lan_hostname.invalid_suffix.empty_label":
    "局域网主机名后缀 '{suffix}' 包含空的 DNS 标签",
  "lan_hostname.invalid_suffix.too_long":
    "局域网主机名后缀 '{suffix}' 超出 DNS 域名或标签长度限制",
  "lan_hostname.invalid_suffix.invalid_hyphen":
    "局域网主机名后缀 '{suffix}' 不能以连字符开头或结尾",
  "lan_hostname.invalid_suffix.invalid_character":
    "局域网主机名后缀 '{suffix}' 只能包含字母、数字和连字符",
  "lan_hostname.invalid_suffix.reserved":
    "局域网主机名后缀 '{suffix}' 已被 DNS 解析器保留",
};

export default {
  "gateway.invalid_health_check":
    "健康检查的间隔、超时和阈值必须大于零且在有效范围内。",
  "gateway.invalid_upstream_endpoint": "请填写有效的上游地址和非零端口。",
  "gateway.config.zero_port": "网关 {field} 必须大于零",
  "gateway.config.port_conflict": "网关 HTTP 和 HTTPS 不能同时使用端口 {port}",
  "gateway.stop_timeout": "网关未能在 {timeout_ms} 毫秒内停止，已保留原实例",
  "gateway.stop_failed": "网关停止失败：{reason}",
  "gateway.invalid_stored_rule": "已存储的网关规则 '{id}' 无效：{reason}",
  "gateway.rule_not_found": "找不到网关规则 (ID: {0})",
  "gateway.legacy_path_prefix_unsupported":
    "旧版路径前缀规则仅支持只读兼容，不能新建或更新",
  "gateway.domains_required": "规则 '{rule_name}' 至少需要一个域名",
  "gateway.host_conflict": "域名 '{domain}' 已被规则 '{rule_name}' 使用",
  "gateway.wildcard_covers_domain":
    "泛域名 '{wildcard}' 覆盖了规则 '{rule_name}' 中的域名 '{domain}'",
  "gateway.domain_pattern_overlap":
    "域名模式 '{domain}' 与规则 '{rule_name}' 中的 '{other_domain}' 存在重叠",
  "gateway.path_prefix_overlap":
    "路径前缀 '{new_prefix}' 与规则 '{rule_name}' 的前缀 '{existing_prefix}' 重叠",
  "gateway.invalid_path_prefix": "路径前缀 '{prefix}' 无效",
  "gateway.duplicate_path_group_prefix":
    "规则 '{rule_name}' 中存在重复的路径前缀 '{prefix}'",
  "gateway.sni_proxy_header_unsupported":
    "SNI 透传规则不支持请求头注入或客户端 IP 透传",
  "gateway.invalid_header_name": "请求头名称 '{name}' 无效",
  "gateway.invalid_header_value": "请求头 '{name}' 的值无效",
};

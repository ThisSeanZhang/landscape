export default {
  edit_title: "网关规则",
  name: "规则名称",
  name_required: "规则名称不能为空",
  enabled: "启用",
  match_type: "匹配类型",
  type_host: "域名匹配",
  type_path_prefix: "路径前缀",
  type_sni_proxy: "SNI 透传",
  domains: "域名列表",
  domains_required: "至少需要一个域名",
  domain_placeholder: "输入域名, 如 example.com 或 *.example.com",
  domain_invalid: "域名格式不正确",
  path_prefix: "路径前缀",
  path_prefix_required: "路径前缀不能为空",
  path_prefix_placeholder: "输入路径前缀, 如 /api",

  // Upstream
  upstream: "上游配置",
  targets: "目标列表",
  target_address: "地址",
  target_port: "端口",
  target_weight: "权重",
  target_tls: "TLS",
  add_target: "添加目标",
  target_address_required: "地址不能为空",
  target_required: "至少需要一个上游目标",

  // Load balance
  load_balance: "负载均衡",
  lb_round_robin: "轮询",
  lb_random: "随机",
  lb_consistent: "一致性哈希",

  // Health check
  health_check: "健康检查",
  health_check_enable: "启用健康检查",
  hc_interval: "检查间隔 (秒)",
  hc_timeout: "超时 (秒)",
  hc_healthy_threshold: "健康阈值",
  hc_unhealthy_threshold: "不健康阈值",

  // Status
  status_title: "网关状态",
  status_running: "运行中",
  status_stopped: "已停止",
  http_port: "HTTP 端口",
  https_port: "HTTPS 端口",
  rule_count: "规则数量",

  // Card
  no_rules: "暂无网关规则",
  add_domain: "添加域名",
};

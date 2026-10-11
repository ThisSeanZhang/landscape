export default {
  iface_cpu_balance: {
    title: "配置网卡软负载",
    intro:
      "选择要处理网络队列的 CPU 核心。选中多个核心可以将负载分布到不同核心，提升性能。",
    hint_prefix: "提示：",
    hint_suffix: '可以点击下方的"设置为0"恢复默认',
    tx_title: "发送队列 (XPS) 核心选择",
    rx_title: "接收队列 (RPS) 核心选择",
    set_zero: "设置为0",
    selected: "已选择",
    none: "无",
    bitmask: "位掩码",
    loading_cpu: "正在获取 CPU 信息...",
    reset: "重置选择",
    cancel: "取消",
    save: "保存配置",
  },
  iface_risk_guard: {
    title: "确认对当前连接网卡进行操作",
    warning:
      "检测到你当前正通过这张网卡访问管理界面，执行操作后可能会立即断开连接。",
    current_iface: "当前访问归属网卡: {iface}",
    current_ip: "当前访问 IP: {ip}",
    current_source: "识别来源: {source}",
    current_hostname: "主机名: {hostname}",
    input_label: "请输入网卡名称 {iface} 以确认操作",
    input_placeholder: "输入 {iface}",
    input_hint: "只有输入内容与网卡名称完全一致时，才允许继续操作。",
    confirm_button: "确认继续",
  },
  route_lan: {
    title: "Lan 路由转发服务",
    static_route_limit: "静态路由 (当前只能设置一个)",
    add_subnet: "增加可达子网",
    next_hop: "下一跳",
    subnet_range: "子网范围",
  },
  route_wan: {
    title: "Wan 路由转发服务",
  },
  mss_clamp: {
    title: "配置 TCP MSS 钳制",
    clamp_value: "钳制值",
  },
  health_check: {
    title: "WAN 链路健康检查",
    targets: "探测目标 (IPv4)",
    targets_tooltip:
      "最多配置 4 个 IPv4 地址。开启网关探测后，每轮会额外探测会话学习到的网关。",
    target_placeholder: "例如 1.1.1.1",
    add_target: "添加探测目标",
    probe_gateway: "探测默认网关",
    probe_gateway_hint: "额外探测会话（DHCP/PPPoE）学习到的网关地址。",
    interval_secs: "探测间隔 (秒)",
    interval_tooltip: "每轮探测之间的间隔时间。取值 1-65535 秒，默认 10 秒。",
    timeout_ms: "超时 (毫秒)",
    timeout_tooltip:
      "单个探测等待应答的超时时间。取值 1-10000 毫秒，默认 1000 毫秒，且必须小于探测间隔。",
    failure_threshold: "失败阈值",
    failure_threshold_tooltip:
      "连续失败多少轮后判定链路不健康。取值 1-100，默认 3。",
    recovery_threshold: "恢复阈值",
    recovery_threshold_tooltip:
      "判定不健康后，连续成功多少轮才恢复为健康。取值 1-100，默认 3；建议不小于失败阈值，以避免状态反复抖动。",
    reliability: "每轮最少应答目标数",
    reliability_tooltip:
      "每轮探测会向所有已启用的目标（配置的目标 + 网关，如开启）发送 ping。至少需要该数量的目标应答，本轮才算成功。连续达到「失败阈值」轮失败后判定链路不健康；连续达到「恢复阈值」轮成功后恢复。取值 1-100，且不能超过目标总数。示例：目标 1.1.1.1、8.8.8.8 加网关共 3 个，设为 2 时单个目标失联不影响判定。",
    reliability_range: "可靠度取值范围为 1-100",
    invalid_target: "探测目标必须是有效的 IPv4 地址",
    nothing_to_probe: "没有可探测目标：请添加至少一个目标或启用网关探测",
    save_failed: "保存失败",
  },
};

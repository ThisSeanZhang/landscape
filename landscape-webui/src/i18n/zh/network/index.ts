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
};

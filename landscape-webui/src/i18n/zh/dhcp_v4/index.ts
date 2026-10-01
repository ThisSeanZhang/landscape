export default {
  service: {
    title: "DHCPv4 服务配置",
    warning: "关闭 DHCP 服务将导致 LAN 下主机无法访问路由",
    server_ip: "DHCP 服务 IP",
    range_start: "分配 IP起始地址 (包含)",
    range_end: "分配 IP结束地址 (不包含)",
    save_success: "保存成功",
    save_failed: "保存失败",
  },
  lease_time: "租约时间 (秒)",
  lease_time_tip: "客户端获得 IP 后在此时间内需要续约，默认 86400 (24 小时)",
  custom_options: "自定义 DHCP Options",
  invalid_ipv4_check: "请输入有效的 IPv4 地址和掩码后再保存",
  duplicate_option_check: "存在重复的 Option 类型，请修改后再保存",
  invalid_option_check: "存在无效的 DHCP Option 值，请修改后再保存",
  option_dnr: {
    use_local: "使用本机 DoH",
    use_custom: "自定义 DoH",
    local_alert:
      "自动使用本机 API/DoH 证书域名、当前 DHCP 服务地址、DoH 端口和 DoH 路径生成 DHCP Option 162。",
    custom_alert:
      "未填写的字段会回退到本机 DoH 配置；域名必须填写证书实际覆盖的精确主机名，不会自动把通配符域名转换为裸域名。",
    domain_label: "DoH 域名",
    ipv4_label: "IPv4 地址",
    port_label: "端口",
    port_placeholder: "默认使用本机 DoH 端口",
    path_label: "DoH 路径",
    path_placeholder: "默认使用本机 DoH 路径，例如 /dns-query",
  },
};

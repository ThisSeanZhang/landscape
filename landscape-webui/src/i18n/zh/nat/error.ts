export default {
  "static_nat.not_found": "找不到静态 NAT 映射 (ID: {0})",
  "static_nat.device_not_found": "静态 NAT 配置中引用的设备不存在 (ID: {0})",
  "static_nat.device_missing_ipv4": "设备没有 IPv4 地址 (ID: {0})",
  "static_nat.device_missing_ipv6": "设备没有 IPv6 地址 (ID: {0})",
  "static_nat.invalid_target": "静态 NAT 目标必须解析为有效目标: {0}",
  "static_nat.port_conflict":
    "静态 NAT 端口 {port} 与接口 '{iface_name}' 的动态范围冲突 (协议 {protocol}, 范围 {start}-{end})",
  "static_nat.port_in_dynamic_range":
    "静态 NAT 映射 {mapping_id} 端口 {port} 与动态协议 {protocol} 范围 {start}-{end} 重叠",
  "static_nat.internal": "静态 NAT 服务器内部错误",
};

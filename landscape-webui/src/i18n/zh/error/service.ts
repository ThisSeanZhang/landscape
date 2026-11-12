export default {
  "service.config_not_found": "找不到 {service_name} 服务配置",
  "service.invalid_config": "无效的服务配置: {reason}",
  "service.flow_id_out_of_range":
    "分流编号 {flow_id} 超出范围，请使用 1～255；编号 0 保留给默认分流。",
  "service.wan_dns_flow_unsupported":
    "分流 {flow_id} 无法确定唯一 DNS 出口。请启用主备模式，或只保留一个有效 WAN 出口，再使用独立运营商 DNS 组。",
  "service.dns_upstream_in_use":
    "此 DNS 上游仍被以下配置使用，请先解除引用再删除：{references}",
  "service.wan_link_in_use":
    "此 WAN 仍被以下配置使用，请先解除引用再删除；临时维护请停用线路：{references}",
  "service.flow_redirect_target_missing":
    "重定向目标分流 {flow_id} 不存在，请先创建目标分流或修改规则。",
  "service.flow_referenced":
    "分流 {flow_id} 仍被以下规则引用，请先修改这些规则，再删除或更改分流编号：{references}",
};

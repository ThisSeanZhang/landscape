export default {
  service_edit: {
    title: "防火墙服务配置",
  },
  blacklist_edit: {
    title: "防火墙黑名单编辑",
    remark: "备注",
    source: "黑名单来源",
    add_source: "增加一条来源",
    block_all_tip: "将会阻止所有 IP 的访问",
    geo_key_required: "第 {index} 条来源: GeoIP Key 不能为空",
    ip_required: "第 {index} 条来源: IP 地址不能为空",
  },
  blacklist_card: {
    no_source_rules: "无来源规则, 没有任何作用",
  },
  card: {
    title: "防火墙",
    ip_blacklist_desc:
      "当前配置为 IP 黑名单, 命中规则的 IP 将被阻止访问. ICMP 默认不放行.",
  },
};

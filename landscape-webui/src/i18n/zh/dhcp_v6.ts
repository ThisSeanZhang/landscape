export default {
  ia_na_title: "IA_NA 地址分配",
  ia_pd_title: "IA_PD 前缀委派",

  // DHCPv6AssignedTable
  hostname: "主机名",
  mac: "MAC",
  ipv6_address: "IPv6 地址",
  request_time: "请求时间",
  remaining_lease: "剩余租期 (s)",
  static_allocation: "静态分配",
  delegated_prefix: "委派前缀",
  prefix_length: "前缀长度",
  duid: "DUID",
  no_records: "暂无 DHCPv6 分配记录",

  // DHCPv6ConfigSection
  enable_dhcpv6: "启用 DHCPv6",
  m_flag_warning:
    "DHCPv6 已启用但 RA M 标志未设置，客户端可能不会请求 DHCPv6 地址",
  ia_na: "IA_NA（地址分配）",
  ia_pd: "IA_PD（前缀委派）",
  max_prefix_len: "最大前缀长度",
  max_prefix_len_desc:
    "RA 中前缀长度 ≤ 此值的前缀将用于地址分配。例如: 64 表示 /64 及更短的前缀可用。",
  pool_start: "地址池起始后缀",
  pool_end: "地址池结束后缀",
  pool_end_placeholder: "默认: 起始 + 65535",
  preferred_lifetime: "首选生存期(秒)",
  valid_lifetime: "有效生存期(秒)",
  delegate_prefix_length: "池块网络大小下限",

  // IPv6RA view
  dhcpv6_assigned_info: "DHCPv6 分配信息",
};

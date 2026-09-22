export default {
  editor: {
    title: "编辑 PPPD 服务",
    create_title: "新建 PPPD 配置",
    attach_iface: "拨号网卡",
    default_route: "设置默认路由",
    ppp_iface_name: "ppp网口名称",
    iface_required: "网卡名称不能为空",
    iface_invalid_format:
      "PPPoE 网卡名称只能包含字母、数字、-、_，长度不超过 15，且不能有首尾空白",
    iface_same_as_attach: "PPPoE 网卡名称不能与拨号网卡相同",
    iface_conflict_existing: "PPPoE 网卡名称不能与现有网卡重名",
    username: "用户名",
    password: "密码",
    ac_name:
      "请求连接的 AC 名称 (没有特殊需求的话请留空, 否则可能导致拨号异常)",
    ac_name_tip: "设置后只会与 AC 名称一致的服务端进行连接",
    plugin: "PPPoE Plugin",
  },
  status_not_dialed: "未成功拨号",
  status_disabled: "未启用",
  attach_to: "拨号网卡: {iface_name}",
  service_locked_hint: "拨通后可用",
};

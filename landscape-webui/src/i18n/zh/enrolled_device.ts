export default {
  title: "设备管理",
  edit_title: "编辑设备绑定",
  add_title: "添加设备绑定",

  name: "展示名称",
  name_placeholder: "例如: 我的手机",
  name_required: "请输入展示名称",

  hostname: "主机名",
  hostname_placeholder: "例如: my-device",
  hostname_invalid: "主机名标签长度 1-63 字符，且不能以连字符开头或结尾",

  mac: "MAC 地址",
  mac_placeholder: "00:11:22:33:44:55",
  mac_required: "MAC 地址不能为空",
  mac_invalid: "请输入有效的 MAC 地址 (XX:XX:XX:XX:XX:XX)",

  iface: "所属网络",
  iface_placeholder: "选择网卡 (可选)",
  iface_none: "不限制 (全局)",

  fake_name: "隐私名称",
  fake_name_placeholder: "可选: 隐私模式下显示的名称",

  ipv4: "IPv4",
  ipv4_placeholder: "可选: 192.168.x.x",
  ipv4_invalid: "请输入有效的 IP 地址",
  ipv4_out_of_range: "IP 地址不在网卡 {iface} 的 DHCP 网段范围内",

  ipv6: "IPv6 后缀",
  ipv6_placeholder: "可选: ::100",
  ipv6_random: "随机生成",

  tag: "标签",
  remark: "备注",
  remark_placeholder: "关于该设备的更多信息...",

  save_success: "保存成功",
  save_failed: "保存失败",
  load_failed: "加载失败",
  cancel: "取消",
  save: "保存",

  empty_desc: "暂无设备绑定信息",
  add_now: "立刻添加",
  add_btn: "新增设备",
  delete_confirm: "确定要删除该设备绑定吗?",
  delete_title: "确认删除",

  invalid_status: "配置失效",
  invalid_bindings_title: "检测到失效的 IP-MAC 绑定",
  invalid_bindings_warning:
    "网卡 {iface} 的 DHCP 修改完成后，检测到有 {count} 个 IP-MAC 绑定不再属于当前网段，请及时调整。",
  lease_ip_mismatch: "当前 IP 与设备配置不一致",
  configured_ip: "配置 IP",
  observed_ip: "当前 IP",
  advanced_settings: "高级设置",
  dhcp_custom_options: "DHCP 自定义 Options",
  dhcp_filter_options: "DHCP Option 过滤",
  filter_options_placeholder: "选择要过滤的 option...",
  go_to_manage: "前往管理",
};

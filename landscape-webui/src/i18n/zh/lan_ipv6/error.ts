export default {
  "lan_ipv6.config_conflict": "LAN IPv6 配置已被他人修改，请刷新后重试",
  "lan_ipv6.prefix_conflict.wan_reserved":
    "接口 {iface_name}（组 {group_id}）的 {service_kind} 前缀索引 {index_range}（/{pool_len}）占用了 WAN 保留的 /64 槽位 0",
  "lan_ipv6.prefix_conflict.overlap":
    "LAN IPv6 /64 槽位 {slot_range} 冲突：接口 {left_iface_name}（组 {left_group_id}）的 {left_service_kind} 索引 {left_index_range}（/{left_pool_len}）与接口 {right_iface_name}（组 {right_group_id}）的 {right_service_kind} 索引 {right_index_range}（/{right_pool_len}）重叠",
  "lan_ipv6.internal": "LAN IPv6 配置更新失败",
};

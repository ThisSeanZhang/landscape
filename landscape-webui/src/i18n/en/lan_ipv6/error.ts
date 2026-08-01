export default {
  "lan_ipv6.config_conflict":
    "LAN IPv6 configuration has been modified. Please refresh and try again",
  "lan_ipv6.prefix_conflict.wan_reserved":
    "{service_kind} prefix index {index_range} (/{pool_len}) on {iface_name} (group {group_id}) occupies WAN-reserved /64 slot 0",
  "lan_ipv6.prefix_conflict.overlap":
    "LAN IPv6 /64 slot {slot_range} conflict: {left_service_kind} index {left_index_range} (/{left_pool_len}) on {left_iface_name} (group {left_group_id}) overlaps {right_service_kind} index {right_index_range} (/{right_pool_len}) on {right_iface_name} (group {right_group_id})",
  "lan_ipv6.internal": "Failed to update LAN IPv6 configuration",
};

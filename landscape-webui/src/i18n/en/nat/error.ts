export default {
  "static_nat.not_found": "Static NAT mapping not found (ID: {0})",
  "static_nat.device_not_found":
    "Device referenced in static NAT config does not exist (ID: {0})",
  "static_nat.device_missing_ipv4":
    "Device does not have an IPv4 address (ID: {0})",
  "static_nat.device_missing_ipv6":
    "Device does not have an IPv6 address (ID: {0})",
  "static_nat.invalid_target":
    "Static NAT target must resolve to a valid target: {0}",
  "static_nat.port_conflict":
    "Static NAT port {port} conflicts with dynamic range on '{iface_name}' (protocol {protocol}, range {start}-{end})",
  "static_nat.port_in_dynamic_range":
    "Static NAT mapping {mapping_id} port {port} overlaps with dynamic protocol {protocol} range {start}-{end}",
  "static_nat.internal": "Static NAT internal server error",
};

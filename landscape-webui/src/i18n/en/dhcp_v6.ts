export default {
  ia_na_title: "IA_NA Address Assignment",
  ia_pd_title: "IA_PD Prefix Delegation",

  // DHCPv6AssignedTable
  hostname: "Hostname",
  mac: "MAC",
  ipv6_address: "IPv6 Address",
  request_time: "Request Time",
  remaining_lease: "Remaining Lease (s)",
  static_allocation: "Static Allocation",
  delegated_prefix: "Delegated Prefix",
  prefix_length: "Prefix Length",
  duid: "DUID",
  no_records: "No DHCPv6 assignment records",

  // DHCPv6ConfigSection
  enable_dhcpv6: "Enable DHCPv6",
  m_flag_warning:
    "DHCPv6 is enabled but RA M flag is not set. Clients may not request DHCPv6 addresses.",
  ia_na: "IA_NA (Address Assignment)",
  ia_pd: "IA_PD (Prefix Delegation)",
  max_prefix_len: "Max Prefix Length",
  max_prefix_len_desc:
    "Only prefixes with length <= this value from RA will be used for address assignment. e.g. 64 means /64 and shorter prefixes are usable.",
  pool_start: "Pool Start Suffix",
  pool_end: "Pool End Suffix",
  pool_end_placeholder: "Default: start + 65535",
  preferred_lifetime: "Preferred Lifetime (s)",
  valid_lifetime: "Valid Lifetime (s)",
  delegate_prefix_length: "Min Network Size for Pool",

  // IPv6RA view
  dhcpv6_assigned_info: "DHCPv6 Assignment Info",
};

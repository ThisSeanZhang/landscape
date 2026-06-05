export default {
  title: "LAN IPv6 Configuration",

  enable: "Enable",
  enabled: "Enabled",
  disabled: "Disabled",

  mode: "Mode",
  mode_slaac: "RA Only (SLAAC)",
  mode_stateful: "DHCPv6 Only (Stateful)",
  mode_slaac_dhcpv6: "RA + DHCPv6",

  mode_slaac_desc:
    "Devices automatically obtain IPv6 addresses via Router Advertisement. No additional address management needed. Suitable for most home and small networks. Downside: some devices cannot have a fixed address suffix.",
  mode_stateful_desc:
    "The DHCPv6 server centrally assigns addresses, giving you precise control over each device's address. Router Advertisement only guides devices to contact the DHCPv6 server. Some older devices may not support DHCPv6, but if you have no such devices this is the recommended mode.",
  mode_slaac_dhcpv6_desc:
    "Router Advertisement provides local private addresses (ULA) to ensure basic connectivity for devices that don't support DHCPv6. DHCPv6 assigns public addresses (GUA) when possible. Devices automatically prefer public addresses for internet access.",

  ra_prefix_source: "RA Prefix Configuration",
  ra_prefix_source_desc:
    "Configure the address prefixes announced by Router Advertisement. You can specify static prefixes manually or use prefixes obtained from upstream Prefix Delegation (PD). Devices will generate addresses based on these prefixes.",

  dhcpv6_prefix_source: "DHCPv6 Prefix Source",
  dhcpv6_prefix_source_desc:
    "Configure the address ranges the DHCPv6 server can assign. You can specify static prefixes manually or use prefixes obtained from upstream Prefix Delegation (PD).",

  ra_prefix_source_ula: "RA Prefix Source (ULA)",
  ra_prefix_source_ula_desc:
    "Local private prefixes (ULA) that ensure connectivity between LAN devices and provide basic internet access.",
  dhcpv6_prefix_source_combo_desc:
    "Prefixes assigned by DHCPv6, typically public addresses (GUA). Devices will prefer these addresses for internet access.",

  add: "Add",
  no_prefix: "No prefixes configured",
  no_dhcpv6_prefix: "No DHCPv6 prefixes configured",
  no_ra_prefix: "No RA prefixes configured",

  ra_config: "Router Advertisement",
  ad_interval: "Advertisement Interval",
  ad_interval_desc:
    "How often the router sends periodic advertisements (in seconds). Default is 300 seconds.",

  m_flag: "Obtain Address via DHCPv6 (M)",
  m_flag_desc:
    "When enabled, devices will obtain addresses from the DHCPv6 server instead of generating them automatically.",
  o_flag: "Obtain Config via DHCPv6 (O)",
  o_flag_desc:
    "When enabled, devices will obtain DNS and other network settings via DHCPv6.",

  ra_flags_auto: "RA Flags (Auto)",
  ra_flags_auto_desc:
    "M and O flags are automatically enabled in this mode to direct devices to the DHCPv6 server.",

  route_priority: "Default Route Priority",
  priority_low: "Low",
  priority_medium: "Medium (Default)",
  priority_high: "High",

  update: "Update",
  cancel: "Cancel",
  confirm: "OK",
  form_validation_failed: "Please check the configuration fields",
  cross_source_conflict:
    "Subnet index {idx} conflicts between RA and DHCPv6 prefix sources",

  // Source binding modal
  source_edit_title: "Prefix Source Editor",
  service_kind_ra: "RA",
  service_kind_na: "DHCPv6 NA",
  service_kind_pd: "DHCPv6 PD",
  source_type_static: "Static Prefix",
  source_type_pd: "IPv6 PD",
  add_static_prefix: "Add Static Prefix",
  add_pd_prefix: "Add Upstream PD",
  delete: "Delete",
  prefix_overview: "Prefix Overview",
  prefix_overview_desc:
    "There are currently {total} configured prefix results, and {active} of them are active under the current service mode.",
  prefix_group_static: "Static Prefix Results",
  prefix_group_static_desc:
    "All static prefix results for this interface, including RA / IA_NA / IA_PD.",
  prefix_group_pd: "Upstream PD Results",
  prefix_group_pd_desc:
    "All upstream PD derived prefix results for this interface, including RA / IA_NA / IA_PD.",
  prefix_group_pd_parent_hint:
    "All prefix results under this upstream interface are planned on the same canvas.",
  prefix_group_count: "{count} results",
  prefix_group_empty_kind:
    "No {kind} result exists under this parent prefix yet.",
  prefix_single_unit: "One {prefix} unit selected.",
  prefix_continuous_range:
    "{count} continuous units selected at granularity {prefix}.",
  prefix_pd_range: "Unit {prefix}, Range {start}-{end}",
  prefix_state_compact_configured: "Configured",
  prefix_state_compact_inactive: "Inactive",
  prefix_state_compact_empty: "Empty",
  prefix_group_edit: "Edit Group",
  prefix_group_delete_confirm: "Delete this prefix group?",
  prefix_group_open_kind: "Open Shared Canvas",
  prefix_group_editor_title: "Edit Parent Prefix {parent}",
  prefix_group_editor_parent: "Current Parent:",
  prefix_group_editor_kind: "Current Result Type",
  prefix_group_editor_results: "Current Results",
  prefix_group_editor_details: "Result Details",
  prefix_group_editor_canvas_hint:
    "You are editing with {kind}. The unified canvas below shows RA / IA_NA / IA_PD together under this parent prefix.",
  pd_must_be_continuous:
    "PD results must stay continuous and cannot be split into disconnected blocks.",
  prefix_state_active: "Active In Mode",
  prefix_state_inactive: "Inactive In Mode",
  prefix_state_inactive_hint_slaac: "SLAAC mode only uses RA prefix results.",
  prefix_state_inactive_hint_stateful_ra:
    "Stateful mode still sends RA flags, but it does not use RA prefix results.",
  prefix_state_inactive_hint_slaac_dhcpv6_ra_dynamic:
    "In SLAAC + DHCPv6 mode, RA is only allowed on static prefixes.",
  prefix_parent: "Parent:",
  prefix_block: "Block:",

  source_base_prefix: "Base Prefix Address",
  source_base_prefix_cidr: "Parent Prefix (CIDR)",
  source_base_prefix_hint:
    "Note: You can customize up to /60. Format must keep trailing zeros (e.g., ::xxx0).",
  source_depend_iface: "Associated Interface (DHCPv6-PD must be enabled)",
  source_depend_iface_placeholder: "Select the interface for prefix delegation",
  source_no_iface: "No PD interface selected",

  source_pool_index: "Pool Block Index",
  source_pool_index_desc:
    "Block index within the parent prefix. For RA/NA this is the /64 subnet number; for PD it's the block number at the pool prefix length.",
  source_pool_len: "Pool Block Prefix Length",
  source_pool_len_desc:
    "Prefix length of each pool block. E.g., parent=/48, pool_len=56 means each block is a /56, containing multiple delegatable sub-prefixes.",
  source_max_source_prefix_len: "Max Source Prefix Length",
  source_max_source_prefix_len_desc:
    "Filter upstream PD prefixes: only prefixes with length <= this value are used for delegation.",
  source_preferred_lifetime: "Preferred Lifetime (s)",
  source_preferred_lifetime_desc:
    "Devices will prefer using this IP during the preferred lifetime, over IPs that have exceeded their preferred lifetime but are still within valid lifetime.",
  source_valid_lifetime: "Valid Lifetime (s)",

  planner_title: "Prefix Planner",
  planner_brush_picker: "Current Type",
  planner_current_brush: "Current Type:",
  planner_brush_ra: "RA",
  planner_brush_na: "IA_NA",
  planner_brush_pd: "IA_PD",
  planner_mode_dynamic_hint:
    "The current source comes from upstream PD. Choose {kind}, then click blocks in the main area below.",
  planner_mode_static_hint:
    "The current source is static. Define the base prefix first, then configure the block range for {kind}.",
  planner_state_preview: "Preview mode",
  planner_state_active: "Using live prefix",
  planner_state_degraded: "Current prefix cannot satisfy this plan",
  planner_parent_iface: "Parent interface:",
  planner_actual_prefix: "Live parent prefix:",
  planner_static_prefix: "Static parent prefix:",
  planner_preview_prefix_len: "Assumed parent prefix length:",
  planner_target_prefix: "Current target block:",
  planner_reason_no_parent_iface:
    "Select an interface with DHCPv6-PD enabled first.",
  planner_reason_no_static_prefix:
    "Enter the static parent prefix first, then choose a block from the canvas below.",
  planner_reason_target_shorter_than_parent:
    "The current target block /{target} is larger than the parent prefix /{parent}, so it cannot be carved from this parent.",
  planner_reason_filtered_parent:
    "The live upstream prefix length /{actual} is filtered out by Max Source Prefix Length, so this source would not actually delegate.",
  planner_reason_more_specific_than_64:
    "The current target block is more specific than /64, so the /64 canvas cannot represent it accurately. Use the summary below instead.",
  planner_reason_too_many_units:
    "The current parent prefix contains {count} /64 units, so the planner switched to summary mode.",
  planner_legend_wan: "WAN reserved",
  planner_legend_current_subnet: "Current LAN subnet",
  planner_legend_current_pd: "Current LAN PD pool",
  planner_legend_other_lan: "Other LAN occupied",
  planner_legend_blocked: "Blocked by current block alignment",
  planner_too_many_cells:
    "There are more than {count} candidate /{target} blocks under parent /{parent}, so the grid is hidden for now. You can still edit the advanced fields manually.",
  planner_empty: "No blocks can be shown with the current settings.",
  planner_available: "Available",
  planner_other_lan_label: "Other LAN ({iface})",
  planner_conflict: "Conflict",
  planner_block: "Block",
  planner_block_status: "Status",
  planner_selected_prefix: "Selected Prefix",
  planner_selected_status: "Selected Status",
  planner_hover_pool_index: "Hovered Pool Index",
  planner_selected_block: "Selected Block",
  planner_hover_prefix: "Hovered Prefix",
  planner_occupants: "Occupants",
  planner_advanced_settings: "Advanced Settings",
  planner_scope_current: "This LAN ({iface})",
  planner_scope_other: "Other LAN ({iface})",
  planner_status_idle: "Waiting for selection",
  planner_status_available: "Ready to save",
  planner_status_shared: "Shared with RA/NA, ready to save",
  planner_summary_only:
    "The current settings only support summary mode, so the interactive canvas is hidden.",
  planner_save_error_no_parent_iface: "Select an upstream PD interface first.",
  planner_save_error_no_static_prefix: "Enter the static parent prefix first.",
  planner_save_error_wan_reserved:
    "The current selection hits the WAN-reserved block and cannot be saved.",
  planner_save_error_conflict:
    "The current selection overlaps with an existing source and cannot be saved.",
  planner_save_error_filtered_parent:
    "The live upstream prefix is filtered out by Max Source Prefix Length, so this source cannot be saved.",
  planner_save_error_target_shorter_than_parent:
    "The target block is larger than the parent prefix, so the current configuration is invalid.",
  planner_save_error_target_more_specific_than_64:
    "The current target block is more specific than /64 and cannot be selected from the canvas yet.",

  // DHCPv6 Server Card
  dhcpv6_server: "DHCPv6 Server",
  ia_na: "IA_NA (Address Assignment)",
  ia_pd: "IA_PD (Prefix Delegation)",
  enable_ia_na: "Enable IA_NA",
  enable_ia_pd: "Enable IA_PD",

  ia_na_max_prefix_len: "Filter Prefix Length",
  ia_na_max_prefix_len_desc:
    "Only assign addresses from prefix sources with a prefix length no greater than this value. For example, set to 64 to skip any prefix source longer than /64.",
  ia_na_pool_start: "Address Pool Start",
  ia_na_pool_start_desc:
    "The starting number for address suffixes. For example, set to 256 and the first assigned address suffix will be ::100.",
  ia_na_preferred_lifetime: "Preferred Lifetime",
  ia_na_preferred_lifetime_desc:
    "How long (in seconds) the device will prefer using this address. After expiry the address is still valid but no longer preferred.",
  ia_na_valid_lifetime: "Valid Lifetime",
  ia_na_valid_lifetime_desc:
    "Maximum time (in seconds) the address remains valid. After expiry the device must request a new address. Should be greater than the preferred lifetime.",

  ia_pd_delegate_prefix_len: "Min Network Size for Pool Blocks",
  ia_pd_delegate_prefix_len_desc:
    "Lower bound on the network size of qualifying pool blocks. Only blocks at least as large as a /N network can be used. Example: setting this to /56 means blocks with prefix_len ≤ 56 qualify — /48 ✅ (larger network) and /56 ✅ qualify, but /60 ❌ (smaller network) is excluded. The actual delegated prefix length in the DHCPv6 response comes from the pool block's own config (e.g. PdStatic.pool_len).",
  ia_pd_preferred_lifetime: "Preferred Lifetime",
  ia_pd_preferred_lifetime_desc:
    "How long (in seconds) the device will prefer using this delegated prefix. After expiry the prefix is still valid but no longer preferred.",
  ia_pd_valid_lifetime: "Valid Lifetime",
  ia_pd_valid_lifetime_desc:
    "Maximum time (in seconds) the delegated prefix remains valid. After expiry the device must request again. Should be greater than the preferred lifetime.",

  // IAPrefixInfoCard
  prefix_info: {
    ip_preferred_time: "IP Preferred Time",
    ip_preferred_time_desc:
      "When multiple IPs exist, the time this IP is preferred",
    ip_valid_time: "IP Valid Time",
    ip_valid_time_desc:
      "Time from obtaining to discarding this IP, including preferred time",
    prefix: "Prefix",
    last_update: "Last Update",
    dhcpv6_client_prefix_time: "Time when DHCPv6 Client obtained the prefix",
    no_prefix_yet: "IPv6 PD has not obtained a prefix yet",
  },

  // IPv6PDEditModal
  ipv6_pd_config: "IPv6-PD Client Config",
  mac_required: "MAC address cannot be empty",
  mac_hint: "MAC address used for request (virtual on PPP interfaces)",

  // ICMPRaShowItem
  neighbor_count_unknown: "IPv6 neighbor count unknown",
};

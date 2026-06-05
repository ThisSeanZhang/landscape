export default {
  title: "LAN IPv6 配置",

  enable: "是否启用",
  enabled: "启用",
  disabled: "禁用",

  mode: "模式",
  mode_slaac: "纯 RA (SLAAC)",
  mode_stateful: "纯 DHCPv6 (Stateful)",
  mode_slaac_dhcpv6: "RA + DHCPv6",

  mode_slaac_desc:
    "设备将通过路由通告自动获取 IPv6 地址，无需额外的地址管理服务。适合大多数家庭和小型网络。缺点是部分设备无法固定地址后缀。",
  mode_stateful_desc:
    "由 DHCPv6 服务器统一分配地址，可精确控制每台设备的地址。部分老旧设备可能不支持 DHCPv6，但若无此类设备建议默认使用此模式。",
  mode_slaac_dhcpv6_desc:
    "路由通告提供本地私有地址 (ULA)，保障不支持 DHCPv6 的设备基础上网条件；DHCPv6 尽量分配公网地址 (GUA)。设备访问外网时将自动优先使用公网地址。",

  ra_prefix_source: "RA 前缀配置",
  ra_prefix_source_desc:
    "设置路由通告的地址前缀。支持手动指定静态前缀，或自动使用从上游获取的前缀委派 (PD)。设备将基于这些前缀自动生成地址。",

  dhcpv6_prefix_source: "DHCPv6 前缀源",
  dhcpv6_prefix_source_desc:
    "设置 DHCPv6 服务器可分配的地址范围。支持手动指定静态前缀，或自动使用从上游获取的前缀委派 (PD)。",

  ra_prefix_source_ula: "RA 前缀源（ULA）",
  ra_prefix_source_ula_desc:
    "本地私有前缀 (ULA)，用于保障局域网设备之间的互通。以及基础的上网能力。",
  dhcpv6_prefix_source_combo_desc:
    "DHCPv6 分配的地址前缀，通常为公网地址 (GUA)。设备访问外网时将优先使用此地址。",

  add: "增加",
  no_prefix: "暂无前缀配置",
  no_dhcpv6_prefix: "暂无 DHCPv6 前缀配置",
  no_ra_prefix: "暂无 RA 前缀配置",

  ra_config: "路由通告",
  ad_interval: "路由通告间隔",
  ad_interval_desc: "路由器定期发送通告的时间间隔（秒），默认 300 秒。",

  m_flag: "通过 DHCPv6 获取地址 (M)",
  m_flag_desc: "开启后，设备将通过 DHCPv6 服务器获取地址，而非自动生成。",
  o_flag: "通过 DHCPv6 获取配置 (O)",
  o_flag_desc: "开启后，设备将通过 DHCPv6 获取 DNS 等网络配置信息。",

  ra_flags_auto: "RA 标志（自动）",
  ra_flags_auto_desc:
    "当前模式已自动启用 M 和 O 标志，引导设备使用 DHCPv6 服务。",

  route_priority: "默认路由优先级",
  priority_low: "低",
  priority_medium: "中（默认）",
  priority_high: "高",

  update: "更新",
  cancel: "取消",
  confirm: "确定",
  form_validation_failed: "请检查配置项是否填写正确",
  cross_source_conflict: "RA 前缀源与 DHCPv6 前缀源的子网索引 {idx} 重复",

  // Source binding modal
  source_edit_title: "前缀来源编辑",
  service_kind_ra: "RA",
  service_kind_na: "DHCPv6 NA",
  service_kind_pd: "DHCPv6 PD",
  source_type_static: "静态前缀",
  source_type_pd: "IPv6 PD",
  add_static_prefix: "新增静态前缀",
  add_pd_prefix: "新增上游 PD 前缀",
  delete: "删除",
  prefix_overview: "前缀结果总览",
  prefix_overview_desc:
    "当前共配置 {total} 条前缀结果，其中 {active} 条会在当前服务模式下生效。",
  prefix_group_static: "静态前缀结果",
  prefix_group_static_desc:
    "这里展示当前接口下所有静态前缀结果，包括 RA / IA_NA / IA_PD。",
  prefix_group_pd: "上游 PD 前缀结果",
  prefix_group_pd_desc:
    "这里展示基于上游 PD 切分得到的前缀结果，包括 RA / IA_NA / IA_PD。",
  prefix_group_pd_parent_hint:
    "该上游接口下的所有前缀结果会在同一张画布中规划。",
  prefix_group_count: "共 {count} 条结果",
  prefix_group_empty_kind: "当前父前缀下暂无 {kind} 结果。",
  prefix_single_unit: "已选择一个 {prefix} 单元。",
  prefix_continuous_range: "已选择 {count} 个连续区间单元，粒度 {prefix}。",
  prefix_pd_range: "分配单元 {prefix}, 范围 {start}-{end}",
  prefix_state_compact_configured: "已配置",
  prefix_state_compact_inactive: "未生效",
  prefix_state_compact_empty: "未配置",
  prefix_group_edit: "编辑这一组",
  prefix_group_delete_confirm: "确定删除这一组前缀吗？",
  prefix_group_open_kind: "进入共享画布",
  prefix_group_editor_title: "编辑父前缀 {parent}",
  prefix_group_editor_parent: "当前父前缀:",
  prefix_group_editor_kind: "当前编辑结果类型",
  prefix_group_editor_results: "当前结果",
  prefix_group_editor_details: "结果详情",
  prefix_group_editor_canvas_hint:
    "当前使用 {kind}，下方是这个父前缀下的统一画布，RA / IA_NA / IA_PD 会一起显示在上面。",
  pd_must_be_continuous: "PD 结果必须保持连续，不能形成断开的区块。",
  prefix_state_active: "当前模式生效",
  prefix_state_inactive: "当前模式不生效",
  prefix_state_inactive_hint_slaac: "SLAAC 模式下仅使用 RA 前缀结果。",
  prefix_state_inactive_hint_stateful_ra:
    "Stateful 模式会发送 RA 标志，但不会使用 RA 前缀结果。",
  prefix_state_inactive_hint_slaac_dhcpv6_ra_dynamic:
    "SLAAC + DHCPv6 模式下，RA 仅允许使用静态前缀。",
  prefix_parent: "父前缀:",
  prefix_block: "结果块:",

  source_base_prefix: "基础前缀地址",
  source_base_prefix_cidr: "父前缀 (CIDR)",
  source_base_prefix_hint:
    "注意! 最多只可自定义到 /60, 格式需要保持 ::xxx0, 因为低位 0 不可省略",
  source_depend_iface: "关联网卡（须开启 DHCPv6-PD）",
  source_depend_iface_placeholder: "选择进行前缀申请的网卡",
  source_no_iface: "未选择 PD 网卡",

  source_pool_index: "池块序号",
  source_pool_index_desc:
    "在父前缀内的块序号。RA/NA 对应第几个 /64 子网，PD 对应以池块前缀长度划分的第几块。",
  source_pool_len: "池块前缀长度",
  source_pool_len_desc:
    "池块的前缀长度。例如：父前缀=/48，池块长度=56，则每个池块为 /56，可容纳多个委派子前缀。",
  source_max_source_prefix_len: "最大源前缀长度",
  source_max_source_prefix_len_desc:
    "过滤上游 PD 前缀：只有前缀长度不超过此值的上游前缀才用于委派。",
  source_preferred_lifetime: "首选生存期 (s)",
  source_preferred_lifetime_desc:
    "主机会优先使用在首选时间内的 IP，相对于超过首选时间但未超过有效时间的 IP。",
  source_valid_lifetime: "有效生存期 (s)",

  planner_title: "前缀切分规划",
  planner_brush_picker: "当前类型",
  planner_current_brush: "当前类型:",
  planner_brush_ra: "RA",
  planner_brush_na: "IA_NA",
  planner_brush_pd: "IA_PD",
  planner_mode_dynamic_hint:
    "当前来源为上游 PD。选择 {kind} 后，直接在下方总区域上点选要占用的块。",
  planner_mode_static_hint:
    "当前来源为静态前缀。先确定基础前缀，再按 {kind} 的方式配置块范围。",
  planner_state_preview: "预览模式",
  planner_state_active: "真实前缀已匹配",
  planner_state_degraded: "当前前缀无法完整匹配规划",
  planner_parent_iface: "上游接口:",
  planner_actual_prefix: "真实父前缀:",
  planner_static_prefix: "静态父前缀:",
  planner_preview_prefix_len: "假设父前缀长度:",
  planner_target_prefix: "当前目标块长度:",
  planner_reason_no_parent_iface: "先选择一个开启 DHCPv6-PD 的上游接口。",
  planner_reason_no_static_prefix: "先填写静态父前缀，再在下方画布中选择块。",
  planner_reason_target_shorter_than_parent:
    "当前目标块 /{target} 比父前缀 /{parent} 更大，无法从该父前缀中切分。",
  planner_reason_filtered_parent:
    "当前上游前缀长度 /{actual} 被“最大源前缀长度”过滤掉，这个源不会实际参与委派。",
  planner_reason_more_specific_than_64:
    "当前目标块比 /64 更细，画布无法按 /64 基础网格准确展开，请改用下方摘要信息判断。",
  planner_reason_too_many_units:
    "当前父前缀下共有 {count} 个 /64 单元，数量过多，已切换为摘要模式。",
  planner_legend_wan: "WAN 保留",
  planner_legend_current_subnet: "本 LAN 子网",
  planner_legend_current_pd: "本 LAN PD 池",
  planner_legend_other_lan: "其他 LAN 占用",
  planner_legend_blocked: "因当前块对齐不可分配",
  planner_too_many_cells:
    "当前共有超过 {count} 个 /{target} 候选块（父前缀 /{parent}），暂不展开网格。你仍可手动填写高级字段。",
  planner_empty: "当前条件下暂无可显示的切分结果。",
  planner_available: "可选",
  planner_other_lan_label: "其他 LAN（{iface}）",
  planner_conflict: "冲突",
  planner_block: "块",
  planner_block_status: "状态",
  planner_selected_prefix: "当前块前缀",
  planner_selected_status: "当前块状态",
  planner_hover_pool_index: "悬停块序号",
  planner_selected_block: "当前选择",
  planner_hover_prefix: "悬停前缀",
  planner_occupants: "占用详情",
  planner_advanced_settings: "高级设置",
  planner_scope_current: "本 LAN（{iface}）",
  planner_scope_other: "其他 LAN（{iface}）",
  planner_status_idle: "待选择",
  planner_status_available: "可保存",
  planner_status_shared: "与 RA/NA 共享，可保存",
  planner_summary_only: "当前条件下仅展示摘要，不展开可点击画布。",
  planner_save_error_no_parent_iface: "请先选择上游 PD 接口。",
  planner_save_error_no_static_prefix: "请先填写静态父前缀。",
  planner_save_error_wan_reserved: "当前选择命中了 WAN 保留块，不能保存。",
  planner_save_error_conflict: "当前选择与已有来源冲突，不能保存。",
  planner_save_error_filtered_parent:
    "当前真实上游前缀被最大源前缀长度过滤，不能保存。",
  planner_save_error_target_shorter_than_parent:
    "目标块长度比父前缀更大，当前配置无效。",
  planner_save_error_target_more_specific_than_64:
    "当前目标块比 /64 更细，暂不支持通过画布选择。",

  // DHCPv6 Server Card
  dhcpv6_server: "DHCPv6 服务器",
  ia_na: "IA_NA（地址分配）",
  ia_pd: "IA_PD（前缀委派）",
  enable_ia_na: "启用 IA_NA",
  enable_ia_pd: "启用 IA_PD",

  ia_na_max_prefix_len: "过滤前缀长度",
  ia_na_max_prefix_len_desc:
    "只从前缀长度不超过此值的前缀源中分配地址。例如设为 64，则长度大于 /64 的前缀源会被跳过。",
  ia_na_pool_start: "地址池起始",
  ia_na_pool_start_desc:
    "地址后缀的起始编号。例如设为 256，则分配的第一个地址后缀为 ::100。",
  ia_na_preferred_lifetime: "首选生存期",
  ia_na_preferred_lifetime_desc:
    "设备优先使用该地址的时长（秒）。到期后地址仍可用但不再优先选择。",
  ia_na_valid_lifetime: "有效生存期",
  ia_na_valid_lifetime_desc:
    "地址的最长有效时间（秒）。到期后设备必须重新申请地址。应大于首选生存期。",

  ia_pd_delegate_prefix_len: "池块网络大小下限",
  ia_pd_delegate_prefix_len_desc:
    "入池块网络大小的下限（对应前缀长度上限）。只有至少和 /N 一样大的块才能入池。举例：设为 /56 时，前缀长度 ≤ 56 的块才合格—— /48（更大网络）✅、/56 ✅ 可入池，/60（更小网络）❌ 被过滤。实际下发给设备的前缀长度由池块自身配置（如 PdStatic.pool_len）决定。",
  ia_pd_preferred_lifetime: "首选生存期",
  ia_pd_preferred_lifetime_desc:
    "设备优先使用该委派前缀的时长（秒）。到期后前缀仍可用但不再优先选择。",
  ia_pd_valid_lifetime: "有效生存期",
  ia_pd_valid_lifetime_desc:
    "委派前缀的最长有效时间（秒）。到期后设备必须重新申请。应大于首选生存期。",

  // IAPrefixInfoCard
  prefix_info: {
    ip_preferred_time: "IP 首选时间",
    ip_preferred_time_desc: "当有多个 IP 时, 作为首选IP的时间",
    ip_valid_time: "IP 有效时间",
    ip_valid_time_desc: "从获得到丢弃该 IP 的时间, 包含首选时间",
    prefix: "前缀",
    last_update: "最近更新时间",
    dhcpv6_client_prefix_time: "DHCPv6 Client 得到前缀的时间",
    no_prefix_yet: "IPv6 PD 还未获得前缀",
  },

  // IPv6PDEditModal
  ipv6_pd_config: "IPv6-PD 客户端配置",
  mac_required: "MAC 地址不能为空",
  mac_hint: "申请使用的 mac 地址 (PPP网卡上是生成虚拟的)",

  // ICMPRaShowItem
  neighbor_count_unknown: "IPv6 邻居数量未知",
};

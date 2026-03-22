import dns from "./metric/dns";
import connect from "./metric/connect";
import sysinfo from "./sysinfo";
import config from "./config";
import not_found from "./not_found";
import errors from "./api_errors";
import enrolled_device from "./enrolled_device";
import lan_ipv6 from "./lan_ipv6";
import flow from "./flow";
import nat from "./nat";
import dns_editor from "./dns_editor";
import firewall from "./firewall";
import misc from "./misc";
import geo_editor from "./geo_editor";
import ipconfig_editor from "./ipconfig_editor";
import dhcp_editor from "./dhcp_editor";
import pppd_editor from "./pppd_editor";
import dhcp_v6 from "./dhcp_v6";
import cert from "./cert";
import gateway from "./gateway";

export default {
  metric: {
    dns,
    connect,
  },
  sysinfo,
  config,
  not_found,
  errors,
  enrolled_device,
  lan_ipv6,
  flow,
  nat,
  dns_editor,
  firewall,
  misc,
  geo_editor,
  ipconfig_editor,
  dhcp_editor,
  pppd_editor,
  dhcp_v6,
  cert,
  gateway,
  common: {
    private_mode: "隐私模式",
    create: "创建",
    edit: "编辑",
    delete: "删除",
    confirm_delete: "确定删除吗",
    no_remark: "无备注",
    not_configured: "未配置",
    starting: "启动中",
    running: "运行中",
    stopping: "停止中",
    stopped: "停止",
    confirm_stop: "确定停止吗",
    created_at: "创建时间",
    create_bridge_device: "创建桥接设备",
    add_bridge: "添加桥接设备",
    refresh: "刷新",
    force_refresh: "强制刷新",
    force_refresh_confirm: "强制刷新吗? 将会清空所有 key 并且重新下载",
    force_refresh_confirm_long:
      "强制刷新吗? 将会清空所有 key 并且重新下载. 可能会持续一段时间",
    domain_rule_source_config: "域名规则来源配置",
    ip_rule_source_config: "IP 规则来源配置",
    image: "镜像",
    close_listener: "关闭监听",
    docker_image_list: "Docker 镜像列表",
    pull_image: "拉取镜像",
    pull_image_name_required: "拉取的镜像名称不能为空",
    port_mapping: "端口映射",
    ipv4_target: "IPv4 目标",
    ipv6_target: "IPv6 目标",
    updated_at: "更新于",
    no_firewall_rules: "暂无黑名单规则",
    list_no_auto_refresh: "目前列表不会自动刷新， 30s 不活跃的 IP 将会被标记为",
    refresh_interval_ms: "设置刷新间隔 (ms):",
    confirm: "确定",
    logout: "退出登录",
    switch_current: "切换当前",
    privacy_mode: "隐私模式",
    privacy_mode_desc: "将会隐藏大部分的 IP MAC 等敏感信息",
    select_geo_name: "选择 geo 名称",
    filter_key: "筛选key",
    filter_attr: "筛选 attr",
    inverse: "反选",

    // 按钮/动作
    enable: "启用",
    disable: "禁用",
    cancel: "取消",
    save: "保存",
    update: "更新",
    login: "登录",
    close: "关闭",
    open: "开启",
    override: "覆盖",
    add: "增加",

    // 表单标签
    username: "用户名",
    password: "密码",
    remark: "备注",
    priority: "优先级",
    status: "状态",
    type: "类型",
    time: "时间",
    size: "大小",
    name: "名称",
    tags: "标签",
    unknown: "未知",
    unnamed: "未命名",
    undefined: "未定义",

    // 表单提示
    enable_question: "是否启用",
    ip_format_invalid: "IP 格式不正确",
    ip_input_placeholder: "请输入 IPv4 或者 IPv6",

    // 操作反馈
    update_success: "更新成功",

    // 布局
    topology_divider: "网络拓扑",
  },
  routes: {
    dashboard: "系统概览",
    status: "服务状态",
    dns: "DNS 相关",
    "dns-redirect": "DNS 重定向",
    "dns-upstream": "上游 DNS",
    nat: "静态 NAT",
    flow: "分流设置",
    docker: "Docker 管理",
    firewall: "防火墙",
    geo: "地理数据库管理",
    "geo-domain": "地理域名",
    "geo-ip": "地理 IP",
    config: "系统配置",
    "metric-group": "指标监控",
    "connect-info": "连接信息",
    "connect-live": "活跃连接",
    "connect-history": "历史查询",
    "connect-src": "源 IP 统计",
    "connect-dst": "目的 IP 统计",
    "connect-history-src": "源 IP 历史",
    "connect-history-dst": "目的 IP 历史",
    "dns-metric": "DNS 指标",
    "ipv6-pd": "IPv6 PD",
    "dhcp-v4": "DHCPv4 服务",
    "ipv6-ra": "IPv6 RA",
    "mac-binding": "设备管理",
    cert: "证书管理",
    "cert-accounts": "ACME 账户",
    certs: "证书管理",
    gateway: "内网 HTTP 反代",
  },
};

export default {
  "dns_check.flow_not_found": "找不到 DNS Flow 运行时 (Flow: {0})",
  "dns_check.refresh_requires_rule":
    "当前域名没有匹配到可刷新的上游 DNS 规则: {0}",
  "dns_check.refresh_redirected":
    "当前域名命中了 DNS 重定向，不能执行回源刷新: {0}",
  "dns_check.refresh_failed": "DNS 回源刷新失败: {0}",
  "dns_rule.not_found": "找不到 DNS 规则 (ID: {0})",
  "dns_upstream.not_found": "找不到 DNS 上游配置 (ID: {0})",
  "dns_redirect.not_found": "找不到 DNS 重定向规则 (ID: {0})",
  "firewall_rule.not_found": "找不到防火墙规则 (ID: {0})",
  "firewall_blacklist.not_found": "找不到防火墙黑名单 (ID: {0})",
  "dhcp.config_not_found": "找不到 '{0}' 的 DHCP 服务配置",
  "dhcp.ip_conflict": "DHCP IP 地址范围冲突: {0}",
  "geo_site.not_found": "找不到 GeoSite 配置 (ID: {0})",
  "geo_site.cache_not_found": "找不到 GeoSite 缓存 (key: {0})",
  "geo_site.file_not_found": "上传中未找到 GeoSite 文件",
  "geo_site.file_read_error": "GeoSite 文件读取错误",
  "geo_ip.not_found": "找不到 GeoIP 配置 (ID: {0})",
  "geo_ip.cache_not_found": "找不到 GeoIP 缓存 (key: {0})",
  "geo_ip.file_not_found": "上传中未找到 GeoIP 文件",
  "geo_ip.file_read_error": "GeoIP 文件读取错误",
  "geo_ip.config_not_found": "找不到 GeoIP 配置 ({0})",
  "geo_ip.dat_decode_error": "GeoIP DAT 文件解析错误",
  "geo_ip.no_valid_cidr": "GeoIP TXT 文件中没有合法的 CIDR 条目",
  "dst_ip_rule.not_found": "找不到目标 IP 规则 (ID: {0})",
  "enrolled_device.invalid": "设备数据无效: {0}",
  "service.config_not_found": "找不到 {service_name} 服务配置",
  "auth.missing_header": "缺少认证头",
  "auth.invalid_format": "认证头格式无效",
  "auth.invalid_token": "登录令牌无效，请重新登录",
  "auth.unauthorized": "未授权用户",
  "auth.invalid_credentials": "用户名或密码错误",
  "auth.token_creation_failed": "令牌创建失败",
  "auth.current_password_incorrect": "当前密码不正确",
  "auth.password_too_weak":
    "新密码不符合复杂度要求（≥8位，含大小写字母和数字）",
  "auth.password_mismatch": "新密码与确认密码不一致",
  "auth.password_same_as_old": "新密码不能与旧密码相同",
  "docker.create_failed": "创建容器失败",
  "docker.start_failed": "启动容器失败",
  "docker.stop_failed": "停止容器失败",
  "docker.remove_failed": "移除容器失败",
  "docker.run_cmd_failed": "通过命令运行容器失败",
  "cert.account_not_found": "找不到证书账户 (ID: {0})",
  "cert.cert_not_found": "找不到证书 (ID: {0})",
  "cert.provider_profile_not_found": "找不到 DNS 服务商配置 (ID: {0})",
  "cert.registration_failed": "ACME 账户注册失败: {0}",
  "cert.deactivation_failed": "ACME 账户注销失败: {0}",
  "cert.verification_failed": "ACME 账户验证失败: {0}",
  "cert.staging_not_supported": "当前 ACME 提供商不支持测试环境",
  "cert.invalid_status_transition": "当前状态不允许该操作: {0}",
  "cert.account_has_active_certificates":
    "该账户下仍有进行中或可续期证书，请先吊销后再变更: {0}",
  "cert.issuance_failed": "证书签发失败: {0}",
  "cert.revocation_failed": "证书吊销失败: {0}",
  "cert.dns_challenge_failed": "DNS 验证配置失败: {0}",
  "cert.acme_account_change_requires_revocation":
    "证书处于有效状态时不能切换 ACME 账户，请先吊销证书",
  "gateway.rule_not_found": "找不到网关规则 (ID: {0})",
  "gateway.legacy_path_prefix_unsupported":
    "旧版路径前缀规则仅支持只读兼容，不能新建或更新",
  "gateway.domains_required": "规则 '{rule_name}' 至少需要一个域名",
  "gateway.host_conflict": "域名 '{domain}' 已被规则 '{rule_name}' 使用",
  "gateway.wildcard_covers_domain":
    "泛域名 '{wildcard}' 覆盖了规则 '{rule_name}' 中的域名 '{domain}'",
  "gateway.domain_pattern_overlap":
    "域名模式 '{domain}' 与规则 '{rule_name}' 中的 '{other_domain}' 存在重叠",
  "gateway.path_prefix_overlap":
    "路径前缀 '{new_prefix}' 与规则 '{rule_name}' 的前缀 '{existing_prefix}' 重叠",
  "gateway.invalid_path_prefix": "路径前缀 '{prefix}' 无效",
  "gateway.duplicate_path_group_prefix":
    "规则 '{rule_name}' 中存在重复的路径前缀 '{prefix}'",
  "gateway.sni_proxy_header_unsupported":
    "SNI 透传规则不支持请求头注入或客户端 IP 透传",
  "gateway.invalid_header_name": "请求头名称 '{name}' 无效",
  "gateway.invalid_header_value": "请求头 '{name}' 的值无效",
  "init_config.file_not_found": "上传中未找到 Init 文件",
  "init_config.file_read_error": "Init 文件读取失败",
  "init_config.invalid": "Init 文件格式无效: {reason}",
  "init_config.version_mismatch":
    "Init 文件版本不匹配，文件版本: {file_version}，当前版本: {current_version}",
  "config.conflict": "配置已被他人修改，请刷新后重试",
  "lan_hostname.invalid_suffix.invalid_idna":
    "局域网主机名后缀 '{suffix}' 不是有效的 IDNA 标签",
  "lan_hostname.invalid_suffix.empty_label":
    "局域网主机名后缀 '{suffix}' 包含空的 DNS 标签",
  "lan_hostname.invalid_suffix.too_long":
    "局域网主机名后缀 '{suffix}' 超出 DNS 域名或标签长度限制",
  "lan_hostname.invalid_suffix.invalid_hyphen":
    "局域网主机名后缀 '{suffix}' 不能以连字符开头或结尾",
  "lan_hostname.invalid_suffix.invalid_character":
    "局域网主机名后缀 '{suffix}' 只能包含字母、数字和连字符",
  "lan_hostname.invalid_suffix.reserved":
    "局域网主机名后缀 '{suffix}' 已被 DNS 解析器保留",
  "lan_ipv6.config_conflict": "LAN IPv6 配置已被他人修改，请刷新后重试",
  "lan_ipv6.prefix_conflict": "LAN IPv6 前缀槽位冲突：{reason}",
  "lan_ipv6.internal": "LAN IPv6 配置更新失败",
  "internal.error": "服务器内部错误",
  "request.invalid_json": "请求数据格式错误",
};

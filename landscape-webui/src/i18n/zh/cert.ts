export default {
  // Account
  account_title: "ACME 账户",
  account_name: "账户名称",
  account_email: "邮箱",
  account_provider: "提供商",
  account_staging: "测试环境",
  account_terms: "同意条款",
  account_active: "启用",
  account_status: "状态",
  account_private_key: "账户私钥",
  account_acme_url: "ACME 账户 URL",
  account_edit_title: "ACME 账户",
  account_name_required: "账户名称不能为空",
  account_email_required: "邮箱不能为空",
  account_email_invalid: "邮箱格式不正确",
  account_eab_kid: "EAB Key ID",
  account_eab_hmac: "EAB HMAC Key",
  account_eab_kid_required: "ZeroSSL 需要 EAB Key ID",
  account_eab_hmac_required: "ZeroSSL 需要 EAB HMAC Key",
  account_use_staging: "使用测试环境",
  account_has_credentials: "已注册",

  // Certificate
  cert_title: "证书管理",
  cert_name: "名称",
  cert_domains: "域名",
  cert_status: "状态",
  cert_issued_at: "签发时间",
  cert_expires: "过期时间",
  cert_edit_title: "证书",
  cert_name_required: "证书名称不能为空",
  cert_domains_required: "至少需要一个域名",
  cert_domain_invalid: "域名格式不正确",

  // Cert type
  cert_type: "类型",
  type_acme: "ACME",
  type_manual: "手动上传",

  // Manual upload
  upload_cert: "证书 (PEM)",
  upload_key: "私钥 (PEM)",
  upload_chain: "证书链 (PEM)",

  // ACME fields
  acme_account: "ACME 账户",
  acme_account_required: "请选择 ACME 账户",
  acme_challenge: "验证方式",
  acme_key_type: "密钥类型",
  acme_auto_renew: "自动续期",
  acme_renew_before_days: "提前续期（天）",

  // Challenge
  challenge_http: "HTTP-01",
  challenge_dns: "DNS-01",
  http_challenge_port: "HTTP 端口",
  dns_provider: "DNS 提供商",
  dns_provider_manual: "手动",
  dns_provider_cloudflare: "Cloudflare",
  dns_provider_aliyun: "阿里云",
  dns_provider_tencent: "腾讯云",
  dns_provider_aws: "AWS Route53",
  dns_provider_google: "Google Cloud",
  dns_provider_custom: "自定义脚本",

  // Status
  status_unregistered: "未注册",
  status_registering: "注册中",
  status_registered: "已注册",
  status_error: "错误",
  status_pending: "待处理",
  status_ready: "已就绪",
  status_processing: "处理中",
  status_valid: "有效",
  status_invalid: "无效",
  status_expired: "已过期",
  status_revoked: "已撤销",

  // Provider
  provider_lets_encrypt: "Let's Encrypt",
  provider_zero_ssl: "ZeroSSL",

  // Key type
  key_ecdsa_p256: "ECDSA P-256",
  key_ecdsa_p384: "ECDSA P-384",
  key_rsa2048: "RSA 2048",
  key_rsa4096: "RSA 4096",

  // Actions
  action_register: "注册",
  action_verify: "验证",
  action_deactivate: "注销",
  action_issue: "签发",
  action_revoke: "吊销",
  action_renew: "续期",
  confirm_deactivate: "注销此 ACME 账户？此操作不可撤销。",
  confirm_revoke: "吊销此证书？此操作不可撤销。",

  // Misc
  days: "天",
  no_accounts: "暂无 ACME 账户",
  no_certs: "暂无证书",
  no_accounts_hint: "请先创建 ACME 账户",
};

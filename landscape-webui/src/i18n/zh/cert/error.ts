export default {
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
};

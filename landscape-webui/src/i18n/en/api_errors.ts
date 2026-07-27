export default {
  "dns_check.flow_not_found": "DNS flow runtime not found (Flow: {0})",
  "dns_check.refresh_requires_rule":
    "No upstream DNS rule matched for refresh: {0}",
  "dns_check.refresh_redirected":
    "DNS refresh is unavailable because this domain is redirected: {0}",
  "dns_check.refresh_failed": "DNS upstream refresh failed: {0}",
  "dns_rule.not_found": "DNS rule not found (ID: {0})",
  "dns_upstream.not_found": "DNS upstream config not found (ID: {0})",
  "dns_redirect.not_found": "DNS redirect rule not found (ID: {0})",
  "firewall_rule.not_found": "Firewall rule not found (ID: {0})",
  "firewall_blacklist.not_found": "Firewall blacklist not found (ID: {0})",
  "dhcp.config_not_found": "DHCP service config for '{0}' not found",
  "dhcp.ip_conflict": "DHCP IP range conflict: {0}",
  "geo_site.not_found": "GeoSite config not found (ID: {0})",
  "geo_site.cache_not_found": "GeoSite cache not found (key: {0})",
  "geo_site.file_not_found": "GeoSite file not found in upload",
  "geo_site.file_read_error": "GeoSite file read error",
  "geo_ip.not_found": "GeoIP config not found (ID: {0})",
  "geo_ip.cache_not_found": "GeoIP cache not found (key: {0})",
  "geo_ip.file_not_found": "GeoIP file not found in upload",
  "geo_ip.file_read_error": "GeoIP file read error",
  "geo_ip.config_not_found": "GeoIP config not found ({0})",
  "geo_ip.dat_decode_error": "GeoIP DAT file decode error",
  "geo_ip.no_valid_cidr": "GeoIP TXT file contains no valid CIDR entries",
  "dst_ip_rule.not_found": "Destination IP rule not found (ID: {0})",
  "enrolled_device.invalid": "Invalid enrolled device data: {0}",
  "service.config_not_found": "{service_name} service config not found",
  "auth.missing_header": "Missing Authorization header",
  "auth.invalid_format": "Invalid Authorization header format",
  "auth.invalid_token": "Invalid token, please log in again",
  "auth.unauthorized": "Unauthorized user",
  "auth.invalid_credentials": "Invalid username or password",
  "auth.token_creation_failed": "Token creation failed",
  "auth.current_password_incorrect": "Current password is incorrect",
  "auth.password_too_weak":
    "New password does not meet complexity requirements (min 8 chars, uppercase, lowercase and digit)",
  "auth.password_mismatch": "New password and confirmation do not match",
  "auth.password_same_as_old":
    "New password cannot be the same as current password",
  "docker.create_failed": "Failed to create container",
  "docker.start_failed": "Failed to start container",
  "docker.stop_failed": "Failed to stop container",
  "docker.remove_failed": "Failed to remove container",
  "docker.run_cmd_failed": "Failed to run container by command",
  "cert.account_not_found": "Certificate account not found (ID: {0})",
  "cert.cert_not_found": "Certificate not found (ID: {0})",
  "cert.provider_profile_not_found": "DNS provider profile not found (ID: {0})",
  "cert.registration_failed": "ACME account registration failed: {0}",
  "cert.deactivation_failed": "ACME account deactivation failed: {0}",
  "cert.verification_failed": "ACME account verification failed: {0}",
  "cert.staging_not_supported":
    "Current ACME provider does not support staging",
  "cert.invalid_status_transition":
    "Operation is not allowed in current status: {0}",
  "cert.account_has_active_certificates":
    "This account still has active or renewable certificates. Revoke them first: {0}",
  "cert.issuance_failed": "Certificate issuance failed: {0}",
  "cert.revocation_failed": "Certificate revocation failed: {0}",
  "cert.dns_challenge_failed": "DNS challenge setup failed: {0}",
  "cert.acme_account_change_requires_revocation":
    "Cannot change ACME account while certificate is valid; revoke it first",
  "gateway.rule_not_found": "Gateway rule not found (ID: {0})",
  "gateway.legacy_path_prefix_unsupported":
    "Legacy path-prefix rules are read-only and cannot be created or updated",
  "gateway.domains_required": "Rule '{rule_name}' requires at least one domain",
  "gateway.host_conflict":
    "Domain '{domain}' is already used by rule '{rule_name}'",
  "gateway.wildcard_covers_domain":
    "Wildcard '{wildcard}' covers domain '{domain}' in rule '{rule_name}'",
  "gateway.domain_pattern_overlap":
    "Domain pattern '{domain}' overlaps with '{other_domain}' in rule '{rule_name}'",
  "gateway.path_prefix_overlap":
    "Path prefix '{new_prefix}' overlaps with '{existing_prefix}' in rule '{rule_name}'",
  "gateway.invalid_path_prefix": "Path prefix '{prefix}' is invalid",
  "gateway.duplicate_path_group_prefix":
    "Duplicate path prefix '{prefix}' in rule '{rule_name}'",
  "gateway.sni_proxy_header_unsupported":
    "SNI passthrough rules do not support request header injection or client IP forwarding",
  "gateway.invalid_header_name": "Invalid request header name '{name}'",
  "gateway.invalid_header_value": "Invalid request header value for '{name}'",
  "init_config.file_not_found": "Init file not found in upload",
  "init_config.file_read_error": "Failed to read init file",
  "init_config.invalid": "Invalid init file: {reason}",
  "init_config.version_mismatch":
    "Init file version mismatch. File version: {file_version}, current version: {current_version}",
  "config.conflict":
    "Configuration has been modified. Please refresh and try again",
  "lan_ipv6.config_conflict":
    "LAN IPv6 configuration has been modified. Please refresh and try again",
  "lan_ipv6.prefix_conflict": "LAN IPv6 prefix slot conflict: {reason}",
  "lan_ipv6.internal": "Failed to update LAN IPv6 configuration",
  "internal.error": "Internal server error",
  "request.invalid_json": "Invalid request data format",
};

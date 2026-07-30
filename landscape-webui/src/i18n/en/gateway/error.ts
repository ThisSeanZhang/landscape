export default {
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
};

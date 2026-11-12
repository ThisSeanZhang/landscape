export default {
  "service.config_not_found": "{service_name} service config not found",
  "service.invalid_config": "Invalid service config: {reason}",
  "service.flow_id_out_of_range":
    "Flow ID {flow_id} is out of range. Use 1–255; 0 is reserved for the default flow.",
  "service.wan_dns_flow_unsupported":
    "Flow {flow_id} has no unambiguous DNS WAN. Enable primary/backup mode or keep one effective WAN target before selecting independent DNS groups.",
  "service.dns_upstream_in_use":
    "This DNS upstream is still in use. Remove these references before deleting it: {references}",
  "service.wan_link_in_use":
    "This WAN is still in use. Remove these references before deleting it, or disable the link for maintenance: {references}",
  "service.flow_redirect_target_missing":
    "Redirect target flow {flow_id} does not exist. Create it or update the rule first.",
  "service.flow_referenced":
    "Flow {flow_id} is still referenced. Update these rules before deleting or renumbering it: {references}",
};

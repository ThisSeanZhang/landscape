export default {
  service_edit: {
    title: "Firewall Service Config",
  },
  blacklist_edit: {
    title: "Firewall Blacklist Editor",
    remark: "Remark",
    source: "Blacklist Source",
    add_source: "Add source",
    block_all_tip: "This will block access from all IP addresses",
    geo_key_required: "Source #{index}: GeoIP key is required",
    ip_required: "Source #{index}: IP address is required",
  },
  blacklist_card: {
    no_source_rules: "No source rules. No effect.",
  },
  card: {
    title: "Firewall",
    ip_blacklist_desc:
      "Currently configured as IP blacklist. Matched IPs will be blocked. ICMP is not allowed by default.",
  },
};

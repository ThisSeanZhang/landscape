export default {
  dns_title: "DNS Cache",
  dns_transports: "DNS listens on both UDP/53 and TCP/53.",
  save_cache: "Save Cache Settings",
  cache_capacity: "Cache Capacity",
  cache_capacity_desc: "Maximum records allowed in DNS cache",
  cache_ttl: "Cache TTL (s)",
  cache_ttl_desc: "Maximum retention time for DNS cache records",
  cache_negative_ttl: "Negative Cache TTL (s)",
  cache_negative_ttl_desc:
    "Retention time for negative (NXDOMAIN/NODATA) DNS records",

  doh_title: "DNS over HTTPS (DoH)",
  save_doh: "Save DoH Settings",
  doh_listen_port: "DoH Listen Port",
  doh_port_reserved: "Port 53 is reserved for DNS and cannot be used for DoH",
  doh_port_desc: "Leave empty for port 6053. Port 53 is reserved.",
  doh_http_endpoint: "DoH Request Path",
  doh_dhcp_renewal:
    "After an endpoint change, existing DHCPv4 clients may use the previous endpoint until they renew their lease.",
};

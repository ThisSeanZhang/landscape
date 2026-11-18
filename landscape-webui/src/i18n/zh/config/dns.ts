export default {
  dns_title: "DNS 缓存",
  dns_transports: "DNS 同时监听 UDP/53 和 TCP/53。",
  save_cache: "保存缓存配置",
  cache_capacity: "缓存容量",
  cache_capacity_desc: "DNS 缓存允许保存的最大记录数",
  cache_ttl: "缓存 TTL (秒)",
  cache_ttl_desc: "DNS 缓存记录的最长保存时间",
  cache_negative_ttl: "否定缓存 TTL (秒)",
  cache_negative_ttl_desc: "DNS 否定缓存（NXDOMAIN/NODATA）记录的保存时间",

  doh_title: "DNS over HTTPS（DoH）",
  save_doh: "保存 DoH 配置",
  doh_listen_port: "DoH 监听端口",
  doh_port_reserved: "端口 53 已保留给 DNS，不能用于 DoH",
  doh_port_desc: "留空使用默认端口 6053；不能使用端口 53。",
  doh_http_endpoint: "DoH 请求路径",
  doh_dhcp_renewal:
    "端点切换后，已有 DHCPv4 客户端可能会继续使用旧端点，直到下次续租。",
};

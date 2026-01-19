#include "vmlinux_wrapper.h"
#include <bpf/bpf_endian.h>

#include "landscape.h"
#include "nat/nat_maps.h"
#include "land_wan_ip.h"
#include "firewall_share.h"
#include "metric.h"
#include "flow_match.h"
#include "land_dns_dispatcher.h"

#include "route/route_maps_v4.h"
#include "route/route_maps_v6.h"

#include "neigh_ip.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc/ingress")
int placeholder(struct __sk_buff *skb) { return TC_ACT_UNSPEC; }

#include <bpf/bpf_endian.h>

#include "landscape.h"
#include "nat/nat_common.h"
#include "nat/nat_metric.h"
#include "nat/nat4_static.h"
#include "nat/nat4_dyn_map.h"
#include "nat/nat6_static.h"
#include "nat/nat6_dyn_map.h"
#include "land_wan_ip.h"
#include "firewall/firewall_share.h"
#include "metric.h"
#include "flow_match.h"
#include "land_dns_dispatcher.h"

#include "route/route_maps_v4.h"
#include "route/route_maps_v6.h"

#include "neigh_ip4.h"
#include "neigh_ip6.h"
#include "neigh_ip6_event.h"
#include "chain/redirect_able.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/ingress")
int placeholder(struct __sk_buff *skb) { return TC_ACT_UNSPEC; }

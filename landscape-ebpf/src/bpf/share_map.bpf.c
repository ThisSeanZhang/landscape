#include "landscape.h"
#include "share_ifindex_ip.h"
#include "packet_mark.h"
#include "firewall_share.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc")
int placeholder(struct __sk_buff *skb) { return TC_ACT_UNSPEC; }

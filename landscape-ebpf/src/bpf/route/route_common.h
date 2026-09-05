#ifndef __LD_ROUTE_COMMON_H__
#define __LD_ROUTE_COMMON_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "../landscape.h"
#include "../pkg_scanner.h"

#define WAN_CACHE 0
#define LAN_CACHE 1

#define ROUTE_TYPE_LAN 0
#define ROUTE_TYPE_NEXTHOP 1
#define ROUTE_TYPE_WAN 2

static __always_inline int scan_route_packet(struct __sk_buff *skb, u32 current_l3_offset,
                                             struct packet_offset_info *offset_info) {
    return scan_packet_l3(skb, current_l3_offset, offset_info);
}

static __always_inline u16 route_flow_mark_vlan_id(u32 mark_value) {
    return get_flow_vlan_id(get_flow_id(mark_value));
}

#endif /* __LD_ROUTE_COMMON_H__ */

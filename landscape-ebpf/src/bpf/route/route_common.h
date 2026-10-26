#ifndef __LD_ROUTE_COMMON_H__
#define __LD_ROUTE_COMMON_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"

#define WAN_CACHE 0
#define LAN_CACHE 1

#define ROUTE_TYPE_LAN 0
#define ROUTE_TYPE_NEXTHOP 1
#define ROUTE_TYPE_WAN 2

struct route_view {
    u32 l3_offset;
    u8 l3_protocol;
};

static __always_inline int scan_route_packet(struct __sk_buff *skb, u32 l3_offset,
                                             struct route_view *view) {
    if (!view) return TC_ACT_UNSPEC;

    int ret = current_l3_protocol(skb, l3_offset, &view->l3_protocol);
    if (ret != TC_ACT_OK) return ret;

    view->l3_offset = l3_offset;
    return TC_ACT_OK;
}

static __always_inline u16 route_flow_mark_vlan_id(u32 mark_value) {
    return get_flow_vlan_id(get_flow_id(mark_value));
}

#endif /* __LD_ROUTE_COMMON_H__ */

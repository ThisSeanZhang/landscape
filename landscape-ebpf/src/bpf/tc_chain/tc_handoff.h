#ifndef __LD_TC_HANDOFF_H_
#define __LD_TC_HANDOFF_H_

#include "chain/xdp_meta.h"
#include "route/route_index.h"

const volatile bool xdp_handoff_enabled = false;

static __always_inline int xdp_handoff_check(struct __sk_buff *skb, bool from_lan) {
    if (!xdp_handoff_enabled) return TC_ACT_OK;

    void *dm = (void *)(long)skb->data_meta;
    void *d = (void *)(long)skb->data;
    if (dm + sizeof(struct xdp_handoff_meta) <= d) {
        struct xdp_handoff_meta *ho = dm;
        if (ho->magic == XDP_HANDOFF_DOCKER_MAGIC) {
            u32 ho_mark = ho->payload.docker.mark;
            u32 ho_ifindex = ho->payload.docker.target_ifindex;
            u16 vlan_id = route_flow_mark_vlan_id(ho_mark);
            int ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, vlan_id);
            if (ret) return TC_ACT_SHOT;
            return bpf_redirect(ho_ifindex, 0);
        }
        if (ho->magic == XDP_HANDOFF_TC_REDIRECT_MAGIC) {
            skb->mark = ho->payload.tc_redirect.mark;
            return bpf_redirect(ho->payload.tc_redirect.target_ifindex, 0);
        }
    }

    return from_lan ? TC_ACT_OK : TC_ACT_UNSPEC;
}

#endif /* __LD_TC_HANDOFF_H_ */

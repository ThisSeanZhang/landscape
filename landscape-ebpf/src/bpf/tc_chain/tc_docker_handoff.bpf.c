#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "pipeline/pipeline.h"
#include "route/route_index.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/ingress")
int tc_docker_handoff(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_docker_handoff"
    void *dm = (void *)(long)skb->data_meta;
    void *d = (void *)(long)skb->data;

    if (dm + sizeof(struct xdp_docker_handoff) <= d) {
        struct xdp_docker_handoff *ho = dm;
        if (ho->magic == XDP_DOCKER_HANDOFF_MAGIC) {
            u32 ho_mark = ho->mark;
            u32 ho_ifindex = ho->target_ifindex;
            u16 vlan_id = route_flow_mark_vlan_id(ho_mark);
            int ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, vlan_id);
            if (ret) return TC_ACT_SHOT;
            // ld_bpf_log("docker target ifindex: %d", ho_ifindex);
            return bpf_redirect(ho_ifindex, 0);
        }
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

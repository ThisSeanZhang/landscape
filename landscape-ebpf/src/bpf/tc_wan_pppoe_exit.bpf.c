#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"

#include "chain/tc_exit_redirect.h"

char LICENSE[] SEC("license") = "GPL";

struct pppoe_egress_tmpl {
    unsigned char dmac[6];
    unsigned char smac[6];
    __be16 eth_proto;
    __u8 ver_type;
    __u8 code;
    __be16 session_id;
    __be16 length;
    __be16 protocol;
} __attribute__((packed));

const volatile struct pppoe_egress_tmpl pppoe_tmpl = {};

// Native PPPoE terminal: the dedicated exit encapsulates with the
// per-link session template before the shared neighbour finish.
static __always_inline void tc_pppoe_encap(struct __sk_buff *skb) {
    u8 l3_protocol = 0;
    if (current_l3_protocol(skb, 14, &l3_protocol) != TC_ACT_OK) return;

    bool is_v6 = l3_protocol == LANDSCAPE_IPV6_TYPE;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return;

    u64 adj_flag = is_v6 ? BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 : BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;

    struct pppoe_egress_tmpl hdr = pppoe_tmpl;
    hdr.length = bpf_htons(skb->len - 14 + 2);
    hdr.protocol = is_v6 ? ETH_P_PPP_IPV6 : ETH_P_PPP_IPV4;

    int ret = bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_MAC, adj_flag);
    if (ret) return;

    bpf_skb_store_bytes(skb, 0, &hdr, sizeof(hdr), 0);
}

SEC("tc/egress")
int tc_wan_pppoe_exit_redirect(struct __sk_buff *skb) {
    tc_pppoe_encap(skb);
    return tc_exit_neigh4(skb);
}

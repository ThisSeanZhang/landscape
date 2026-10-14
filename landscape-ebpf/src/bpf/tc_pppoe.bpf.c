#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"
#include "chain/tc_cb.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"

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

// Family-agnostic PPPoE encap: the per-family entry program passes the
// family flag (the chain root already forked on the L3 protocol), and
// the hop slot likewise comes from the entry.
static __always_inline void tc_pppoe_encap(struct __sk_buff *skb, bool is_v6) {
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

// Terminal per-link egress stage: encapsulates only the packets that
// traversed this link's chain, with this link's session template.
SEC("tc/egress")
int tc_pppoe_wan_egress_v4(struct __sk_buff *skb) {
    tc_pppoe_encap(skb, false);

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int tc_pppoe_wan_egress_v6(struct __sk_buff *skb) {
    tc_pppoe_encap(skb, true);

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

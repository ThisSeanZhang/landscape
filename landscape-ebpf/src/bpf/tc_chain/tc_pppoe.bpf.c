#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_PPP_IP bpf_htons(0x0021)
#define ETH_PPP_IPV6 bpf_htons(0x0057)
#define ETH_IPV4 bpf_htons(0x0800)
#define ETH_IPV6 bpf_htons(0x86DD)

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

static __always_inline void tc_pppoe_encap(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return;

    bool is_v6 = (eth->h_proto == ETH_IPV6);
    if (!is_v6 && eth->h_proto != ETH_IPV4) return;

    u64 adj_flag = is_v6 ? BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 : BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;

    struct pppoe_egress_tmpl hdr = pppoe_tmpl;
    hdr.length = bpf_htons(skb->len - 14 + 2);
    hdr.protocol = is_v6 ? ETH_PPP_IPV6 : ETH_PPP_IP;

    int ret = bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_MAC, adj_flag);
    if (ret) return;

    bpf_skb_store_bytes(skb, 0, &hdr, sizeof(hdr), 0);
}

SEC("tc/egress")
int tc_pppoe_wan_egress(struct __sk_buff *skb) {
    tc_pppoe_encap(skb);
    return TC_ACT_UNSPEC;
}

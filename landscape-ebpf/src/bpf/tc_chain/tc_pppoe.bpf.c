#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 session_id = 0x00;

#define ETH_PPP bpf_htons(0x8864)
#define ETH_PPP_IP bpf_htons(0x0021)
#define ETH_PPP_IPV6 bpf_htons(0x0057)
#define ETH_IPV4 bpf_htons(0x0800)
#define ETH_IPV6 bpf_htons(0x86DD)

struct pppoe_header {
    u8 version_and_type;
    u8 code;
    u16 session_id;
    u16 length;
    u16 protocol;
} __attribute__((packed));

static __always_inline void tc_pppoe_encap(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return;

    bool is_v6 = (eth->h_proto == ETH_IPV6);
    if (!is_v6 && eth->h_proto != ETH_IPV4) return;

    u32 pkt_sz = skb->len - 14;
    u16 ppp_proto = is_v6 ? ETH_PPP_IPV6 : ETH_PPP_IP;
    u64 adj_flag = is_v6 ? BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 : BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;

    u16 l2_proto = ETH_PPP;
    bpf_skb_store_bytes(skb, 12, &l2_proto, sizeof(u16), 0);

    int ret = bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_MAC, adj_flag);
    if (ret) return;

    struct pppoe_header hdr = {
        .version_and_type = 0x11,
        .code = 0x00,
        .session_id = session_id,
        .length = bpf_htons(pkt_sz + 2),
        .protocol = ppp_proto,
    };
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &hdr, sizeof(hdr), 0);
}

SEC("tc/egress")
int tc_pppoe_wan_egress(struct __sk_buff *skb) {
    tc_pppoe_encap(skb);
    TC_CHAIN_WAN_EGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_OK;
}

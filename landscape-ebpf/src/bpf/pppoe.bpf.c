#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "wan_tc_pipeline.h"

#undef BPF_LOG_TOPIC

char LICENSE[] SEC("license") = "GPL";

struct __attribute__((__packed__)) pppoe_header {
    u8 version_and_type;
    u8 code;
    u16 session_id;
    u16 length;
    u16 protocol;
};

const volatile u16 session_id = 0x00;

#define ETH_PPP_DIS bpf_htons(0x8863)
#define ETH_PPP bpf_htons(0x8864)

#define ETH_PPP_IPV4 bpf_htons(0x0021)
#define ETH_PPP_IPV6 bpf_htons(0x0057)

#define ETH_IPV4 bpf_htons(0x0800)
#define ETH_IPV6 bpf_htons(0x86DD)

SEC("tc")
int pppoe_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "pppoe_ingress"
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        ld_bpf_log("ingress packet too small for ethhdr");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != ETH_PPP) {
        return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_PPPOE, TC_ACT_UNSPEC);
    }

    struct pppoe_header *pppoe_h = (struct pppoe_header *)(eth + 1);
    if ((void *)(pppoe_h + 1) > data_end) {
        ld_bpf_log("ingress pppoe header out of range");
        return TC_ACT_SHOT;
    }

    if (pppoe_h->protocol != ETH_PPP_IPV4 && pppoe_h->protocol != ETH_PPP_IPV6) {
        return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_PPPOE, TC_ACT_UNSPEC);
    }

    u16 new_proto = ETH_IPV4;
    if (pppoe_h->protocol == ETH_PPP_IPV6) {
        new_proto = ETH_IPV6;
    }

    int result = bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_MAC, 0);
    if (result) {
        ld_bpf_log("ingress adjust room -8 failed %d", result);
        return TC_ACT_SHOT;
    }

    bpf_skb_store_bytes(skb, 12, &new_proto, sizeof(u16), 0);
    bpf_skb_change_proto(skb, new_proto, 0);

    return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_PPPOE, TC_ACT_UNSPEC);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int pppoe_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "pppoe_egress"
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        ld_bpf_log("egress packet too small for ethhdr");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != ETH_IPV4 && eth->h_proto != ETH_IPV6) {
        return TC_ACT_UNSPEC;
    }

    u32 pkt_sz = skb->len - 14;
    u16 ppp_proto = ETH_PPP_IPV4;
    u64 adj_room_flag = BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;
    if (eth->h_proto == ETH_IPV6) {
        ppp_proto = ETH_PPP_IPV6;
        adj_room_flag = BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;
    }

    u16 l2_proto = bpf_htons(0x8864);
    bpf_skb_store_bytes(skb, 12, &l2_proto, sizeof(u16), 0);
    bpf_skb_change_proto(skb, l2_proto, 0);

    int result = bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_MAC, adj_room_flag);
    if (result) {
        ld_bpf_log("egress adjust room +8 failed %d", result);
        return TC_ACT_SHOT;
    }

    struct pppoe_header pppoe = {
        .version_and_type = 0x11,
        .code = 0x00,
        .session_id = bpf_htons(session_id),
        .length = bpf_htons(pkt_sz + 2),
        .protocol = ppp_proto,
    };
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &pppoe, sizeof(struct pppoe_header), 0);

    return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_PPPOE, TC_ACT_UNSPEC);
#undef BPF_LOG_TOPIC
}

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "chain/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

// Ethertype buckets for the ingress sniffer.
#define SNIFF_V4 0
#define SNIFF_V6 1
#define SNIFF_PPPOE 2
#define SNIFF_OTHER 3

struct sniff_ingress_record {
    u64 count[4];
    __be16 last_pppoe_sid;
};

struct sniff_chain_record {
    u64 count;
    u32 chain_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct sniff_ingress_record);
    __uint(max_entries, 1);
} sniff_ingress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct sniff_chain_record);
    __uint(max_entries, 1);
} sniff_chain_map SEC(".maps");

// Attached to the interface TC ingress: observes what actually reached the
// kernel path after XDP (verdict + frame shape), e.g. proving that
// unregistered PPPoE sessions pass through with the header intact.
SEC("tc/ingress")
int tc_test_sniff(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    u32 k = 0;
    struct sniff_ingress_record *rec = bpf_map_lookup_elem(&sniff_ingress_map, &k);
    if (!rec) return TC_ACT_OK;

    u16 eth_type = bpf_ntohs(eth->h_proto);
    u32 bucket = SNIFF_OTHER;
    if (eth_type == 0x0800) {
        bucket = SNIFF_V4;
    } else if (eth_type == 0x86DD) {
        bucket = SNIFF_V6;
    } else if (eth_type == 0x8864) {
        bucket = SNIFF_PPPOE;
        struct pppoe_hdr_min {
            u8 ver_type;
            u8 code;
            __be16 session_id;
        } __attribute__((packed)) *pppoe = (void *)(eth + 1);
        if ((void *)(pppoe + 1) <= data_end) {
            rec->last_pppoe_sid = pppoe->session_id;
        }
    }

    __sync_fetch_and_add(&rec->count[bucket], 1);
    return TC_ACT_OK;
}

// Registered as a TC chain root: counts packets the WAN ingress intro
// dispatched and records the chain id it found in skb->cb.
SEC("tc/ingress")
int tc_test_chain_stage(struct __sk_buff *skb) {
    u32 k = 0;
    struct sniff_chain_record *rec = bpf_map_lookup_elem(&sniff_chain_map, &k);
    if (rec) {
        __sync_fetch_and_add(&rec->count, 1);
        rec->chain_id = tc_cb_chain_id(skb);
    }
    return TC_ACT_OK;
}

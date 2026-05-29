#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"

#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES bpf_htons(0x8864)
#endif
#define ETH_P_PPP_IPV4 bpf_htons(0x0021)
#define ETH_P_PPP_IPV6 bpf_htons(0x0057)

#define TC_INTRO_IFINDEX_TYPE 2

struct __attribute__((packed)) pppoe_header {
    u8 version_and_type;
    u8 code;
    __be16 session_id;
    __be16 length;
    __be16 protocol;
};

struct dispatch_v4 {
    u8 _pad[4];
    __be32 daddr;
};

struct dispatch_v6 {
    __be64 prefix64;
};

struct dispatch_ppp {
    u8 _pad[4];
    __be32 session_id;
};

struct dispatch_key {
    u32 dispatch_type;
    union {
        struct dispatch_v4 v4;
        struct dispatch_v6 v6;
        struct dispatch_ppp ppp;
        u32 ifindex;
    };
};

struct dispatch_value {
    u32 next_pipe_root_index;
};

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_root_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dispatch_key);
    __type(value, struct dispatch_value);
    __uint(max_entries, 1024);
} wan_intro_dispatch_map SEC(".maps");

static __always_inline void tc_intro_dispatch(struct __sk_buff *skb, struct dispatch_key *key) {
    struct dispatch_value *value = bpf_map_lookup_elem(&wan_intro_dispatch_map, key);
    if (!value) return;
    bpf_tail_call(skb, &tc_pipe_root_progs, value->next_pipe_root_index);
}

SEC("tc/ingress")
int tc_wan_intro(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct dispatch_key key = {};

    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    if (eth->h_proto == bpf_htons(0x0800)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

        key.dispatch_type = LANDSCAPE_IPV4_TYPE;
        key.v4.daddr = iph->daddr;
        tc_intro_dispatch(skb, &key);

        key.v6.prefix64 = 0;
        key.dispatch_type = TC_INTRO_IFINDEX_TYPE;
        key.ifindex = skb->ingress_ifindex;
        tc_intro_dispatch(skb, &key);
        return TC_ACT_OK;
    }

    if (eth->h_proto == bpf_htons(0x86DD)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return TC_ACT_OK;

        key.dispatch_type = LANDSCAPE_IPV6_TYPE;
        __builtin_memcpy(&key.v6.prefix64, &ip6h->daddr, sizeof(key.v6.prefix64));
        tc_intro_dispatch(skb, &key);

        key.v6.prefix64 = 0;
        key.dispatch_type = TC_INTRO_IFINDEX_TYPE;
        key.ifindex = skb->ingress_ifindex;
        tc_intro_dispatch(skb, &key);
        return TC_ACT_OK;
    }

    if (eth->h_proto == ETH_P_PPP_SES) {
        struct pppoe_header *pppoe = (struct pppoe_header *)(eth + 1);
        if ((void *)(pppoe + 1) > data_end) return TC_ACT_OK;

        if (pppoe->protocol != ETH_P_PPP_IPV4 && pppoe->protocol != ETH_P_PPP_IPV6)
            return TC_ACT_OK;

        bool is_v6 = pppoe->protocol == ETH_P_PPP_IPV6;

        key.dispatch_type = is_v6 ? LANDSCAPE_IPV6_TYPE : LANDSCAPE_IPV4_TYPE;
        key.ppp.session_id = bpf_htonl((__u32)bpf_ntohs(pppoe->session_id));
        tc_intro_dispatch(skb, &key);

        key.v6.prefix64 = 0;
        key.dispatch_type = TC_INTRO_IFINDEX_TYPE;
        key.ifindex = skb->ingress_ifindex;
        tc_intro_dispatch(skb, &key);
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"

#include "pipeline/pipeline.h"

#ifndef ETH_P_PPP_DISC
#define ETH_P_PPP_DISC bpf_htons(0x8863)
#endif

#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES bpf_htons(0x8864)
#endif

#define ETH_P_PPP_IPV4 bpf_htons(0x0021)
#define ETH_P_PPP_IPV6 bpf_htons(0x0057)

struct __attribute__((packed)) pppoe_header {
    u8 version_and_type;
    u8 code;
    __be16 session_id;
    __be16 length;
    __be16 protocol;
};

char LICENSE[] SEC("license") = "GPL";

struct dispatch_v4 {
    // Reserve 4 bytes so v4/v6 share the same 8-byte address slot
    u8 _pad[4];
    __be32 daddr;
};

struct dispatch_v6 {
    // IPv6 /64 prefix
    __be64 prefix64;
};

struct dispatch_ppp {
    // PPPoE session id in 32bit slot, sharing key layout with v4/v6
    u8 _pad[4];
    __be32 session_id;
};

struct dispatch_key {
    // Dispatch type: PPPoE inner IPv4/IPv6, or direct IPv4/IPv6
    u32 dispatch_type;
    union {
        struct dispatch_v4 v4;
        struct dispatch_v6 v6;
        struct dispatch_ppp ppp;
    };
};

struct dispatch_value {
    // Prog array index of the matched next intro pipe
    u32 next_pipe_intro_index;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dispatch_key);
    __type(value, struct dispatch_value);
    __uint(max_entries, PIPELINE_COUNT);
} intro_dispatch_map SEC(".maps");

static __always_inline int intro_dispatch_tailcall(struct xdp_md *ctx, struct dispatch_key *key) {
    struct dispatch_value *value = bpf_map_lookup_elem(&intro_dispatch_map, key);
    if (!value) {
        return XDP_PASS;
    }

    bpf_tail_call(ctx, &xdp_pipe_progs, value->next_pipe_intro_index);
    ld_bpf_log("intro_dispatch tail call failed, dispatch_type=%u index=%u", key->dispatch_type,
               value->next_pipe_intro_index);
    return XDP_PASS;
}

SEC("xdp")
int intro_dispatch(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "intro_dispatch"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct dispatch_key key = {};

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // 1. Dispatch PPPoE inner IPv4/IPv6 and direct IPv4/IPv6.
    // 2. Pass packets not meant for interception.
    // 3. Look up hash map with dispatch_type + address slot.
    // 4. On hit, tail call to the matched pipe; otherwise pass.

    if (eth->h_proto == ETH_IPV4) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }

        key.dispatch_type = LANDSCAPE_IPV4_TYPE;
        key.v4.daddr = iph->daddr;
        return intro_dispatch_tailcall(ctx, &key);
    }

    if (eth->h_proto == ETH_IPV6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) {
            return XDP_PASS;
        }

        key.dispatch_type = LANDSCAPE_IPV6_TYPE;
        __builtin_memcpy(&key.v6.prefix64, &ip6h->daddr, sizeof(key.v6.prefix64));
        return intro_dispatch_tailcall(ctx, &key);
    }

    if (eth->h_proto != ETH_P_PPP_SES) {
        return XDP_PASS;
    }

    struct pppoe_header *pppoe = (struct pppoe_header *)(eth + 1);
    if ((void *)(pppoe + 1) > data_end) {
        return XDP_PASS;
    }

    if (pppoe->protocol != ETH_P_PPP_IPV4 && pppoe->protocol != ETH_P_PPP_IPV6) {
        ld_bpf_log("unknown ppp protocol: %x", bpf_ntohs(pppoe->protocol));
        return XDP_PASS;
    }

    bool is_v6 = pppoe->protocol == ETH_P_PPP_IPV6;
    u16 l2_proto = is_v6 ? ETH_IPV6 : ETH_IPV4;

    key.dispatch_type = is_v6 ? LANDSCAPE_IPV6_TYPE : LANDSCAPE_IPV4_TYPE;
    key.ppp.session_id = bpf_htonl((__u32)bpf_ntohs(pppoe->session_id));

    if (is_v6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(pppoe + 1);
        if ((void *)(ip6h + 1) > data_end) {
            return XDP_PASS;
        }
        __builtin_memcpy(&key.v6.prefix64, &ip6h->daddr, sizeof(key.v6.prefix64));
    } else {
        struct iphdr *iph = (struct iphdr *)(pppoe + 1);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }
        key.v4.daddr = iph->daddr;
    }

    u8 mac_pair[12];
    __builtin_memcpy(mac_pair, eth->h_dest, sizeof(mac_pair));

    int result = bpf_xdp_adjust_head(ctx, -8);
    if (result != 0) {
        ld_bpf_log("bpf_xdp_adjust_head failed: %d", result);
        return XDP_DROP;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    __builtin_memcpy(eth->h_dest, mac_pair, sizeof(mac_pair));
    eth->h_proto = l2_proto;

    return intro_dispatch_tailcall(ctx, &key);

#undef BPF_LOG_TOPIC
}

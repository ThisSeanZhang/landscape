#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "pipeline/pipeline.h"

#define TEST_ETH_P_IP 0x0800
#define TEST_ETH_P_IPV6 0x86DD

struct dummy_recv_record {
    u64 count;
};

struct dummy_meta_record {
    u32 mark;
    u32 ifindex;
};

struct dummy_tcp_mss_record {
    u16 mss;
    u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct dummy_recv_record);
    __uint(max_entries, 2);
} dummy_recv_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct dummy_meta_record);
    __uint(max_entries, 2);
} dummy_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct dummy_tcp_mss_record);
    __uint(max_entries, 2);
} dummy_tcp_mss_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_test_dummy(struct xdp_md *ctx) {
    u32 pkt_len = (u32)((long)ctx->data_end - (long)ctx->data);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct xdp_pipe_meta meta = {};

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) goto log_len_only;

    u16 eth_type = bpf_ntohs(eth->h_proto);

    if (xdp_get_meta(ctx, &meta) == 0) {
        u32 mkey = (eth_type == TEST_ETH_P_IPV6) ? 1 : 0;
        struct dummy_meta_record *mrec = bpf_map_lookup_elem(&dummy_meta_map, &mkey);
        if (mrec) {
            mrec->mark = meta.mark;
            mrec->ifindex = meta.target_ifindex;
        }
    }

    if (eth_type == TEST_ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end) goto log_len_only;

        u8 proto = iph->protocol;
        __be16 sport = 0, dport = 0;

        if (proto == IPPROTO_TCP && !(iph->frag_off & bpf_htons(0x1FFF)) && iph->ihl == 5) {
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if ((void *)(tcph + 1) <= data_end) {
                sport = tcph->source;
                dport = tcph->dest;
                if (tcph->syn && !tcph->ack &&
                    (void *)((u8 *)(tcph) + sizeof(*tcph) + 4) <= data_end) {
                    __be16 mss = *(__be16 *)((u8 *)(tcph) + sizeof(*tcph) + 2);
                    u32 mk = 0;
                    struct dummy_tcp_mss_record *mr = bpf_map_lookup_elem(&dummy_tcp_mss_map, &mk);
                    if (mr) {
                        mr->mss = mss;
                        __sync_fetch_and_add(&mr->count, 1);
                    }
                }
            }
            struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
            if ((void *)(udph + 1) <= data_end) {
                sport = udph->source;
                dport = udph->dest;
            }
        }

        u32 k = 0;
        struct dummy_recv_record *rec = bpf_map_lookup_elem(&dummy_recv_map, &k);
        if (rec) __sync_fetch_and_add(&rec->count, 1);
        return XDP_PASS;
    }

    if (eth_type == TEST_ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end) goto log_len_only;

        u8 proto = ip6h->nexthdr;
        u16 l4_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

#pragma unroll
        for (int i = 0; i < 6; i++) {
            struct ipv6_opt_hdr *oh;
            switch (proto) {
            case 0:
            case 43:
            case 60:
                oh = data + l4_off;
                if ((void *)(oh + 1) > data_end) goto log_len_only;
                proto = oh->nexthdr;
                l4_off += (oh->hdrlen + 1) * 8;
                break;
            case 44: {
                struct frag_hdr *fh = data + l4_off;
                if ((void *)(fh + 1) > data_end) goto log_len_only;
                proto = fh->nexthdr;
                l4_off += sizeof(struct frag_hdr);
                break;
            }
            default:
                goto v6_parse_l4;
            }
        }

    v6_parse_l4: {
        __be16 sport = 0, dport = 0;

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = data + l4_off;
            if ((void *)(tcph + 1) <= data_end) {
                sport = tcph->source;
                dport = tcph->dest;
            }
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = data + l4_off;
            if ((void *)(udph + 1) <= data_end) {
                sport = udph->source;
                dport = udph->dest;
            }
        }

        u32 k = 1;
        struct dummy_recv_record *rec = bpf_map_lookup_elem(&dummy_recv_map, &k);
        if (rec) __sync_fetch_and_add(&rec->count, 1);
        return XDP_PASS;
    }
    }

log_len_only:
    return XDP_PASS;
}

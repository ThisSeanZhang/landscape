#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

/* Define constants not captured by BTF */
#define BPF_F_CURRENT_NETNS (-1L)

#define PACKET_HOST 0
#define PACKET_BROADCAST 1
#define PACKET_MULTICAST 2
#define PACKET_OTHERHOST 3

volatile const __be32 proxy_addr = 0;
volatile const __be16 proxy_port = 0;

static inline struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb, u16 *l3_protocol,
                                               u8 *l4_protocol) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct bpf_sock_tuple *result;
    struct ethhdr *eth;
    __u64 tuple_len;
    __u8 proto = 0;
    __u64 ihl_len;

    eth = (struct ethhdr *)(data);
    if (eth + 1 > data_end) return NULL;

    /* Only support ipv4 */
    *l3_protocol = eth->h_proto;
    if (eth->h_proto != ETH_IPV4) return NULL;

    struct iphdr *iph = (struct iphdr *)(data + sizeof(*eth));
    if (iph + 1 > data_end) return NULL;
    if (iph->ihl != 5) /* Options are not supported */
        return NULL;
    ihl_len = iph->ihl * 4;
    *l4_protocol = iph->protocol;
    result = (struct bpf_sock_tuple *)&iph->saddr;

    /* Only support TCP */
    // if (proto != IPPROTO_TCP) return NULL;

    return result;
}

static inline int handle_pkg(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, u8 l4_protocol) {
#define BPF_LOG_TOPIC "handle_pkg"
    struct bpf_sock_tuple server = {};
    struct bpf_sock *sk;
    size_t tuple_len;
    int ret;
    int change_type_err;

    tuple_len = sizeof(tuple->ipv4);
    if ((void *)tuple + tuple_len > (void *)(long)skb->data_end) return TC_ACT_SHOT;

    /* Reuse existing connection if it exists */
    if (l4_protocol == IPPROTO_TCP) {
        sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
        if (sk) {
            if (sk->state != BPF_TCP_LISTEN) goto assign;
            bpf_sk_release(sk);
        }
    }

    /* Lookup port server is listening on */
    server.ipv4.saddr = tuple->ipv4.saddr;
    server.ipv4.daddr = proxy_addr;
    server.ipv4.sport = tuple->ipv4.sport;
    server.ipv4.dport = proxy_port;

    if (l4_protocol == IPPROTO_TCP) {
        sk = bpf_skc_lookup_tcp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
    } else if (l4_protocol == IPPROTO_UDP) {
        sk = bpf_sk_lookup_udp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
    }

    if (!sk) {
        return TC_ACT_SHOT;
    }
    if (l4_protocol == IPPROTO_TCP && sk->state != BPF_TCP_LISTEN) {
        bpf_sk_release(sk);
        return TC_ACT_SHOT;
    }
assign:
    skb->mark = 1;
    change_type_err = bpf_skb_change_type(skb, PACKET_HOST);
    if (change_type_err) {
        bpf_log_info("change_type_err %d", change_type_err);
        bpf_log_info("pkt_type %d", skb->pkt_type);
    }
    ret = bpf_sk_assign(skb, sk, 0);
    if (ret) {
        bpf_log_info("bpf_sk_assign ret %d", ret);
    }
    bpf_sk_release(sk);
    return ret;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int tproxy_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tproxy_ingress"

    u32 vlan_id = skb->vlan_tci;
    if (vlan_id != LAND_REDIRECT_NETNS_VLAN_ID) {
        return TC_ACT_OK;
    }
    bpf_skb_vlan_pop(skb);

    struct bpf_sock_tuple *tuple;
    u16 l3_protocol;
    u8 l4_protocol;
    int ret = 0;

    tuple = get_tuple(skb, &l3_protocol, &l4_protocol);
    if (!tuple) return TC_ACT_OK;

    /* Only support TCP/UDP TODO ICMP */
    if (l4_protocol != IPPROTO_TCP && l4_protocol != IPPROTO_UDP) {
        bpf_log_info("not support protocol %u", l3_protocol);
        return TC_ACT_OK;
    }

    ret = handle_pkg(skb, tuple, l4_protocol);
    return ret == 0 ? TC_ACT_OK : TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

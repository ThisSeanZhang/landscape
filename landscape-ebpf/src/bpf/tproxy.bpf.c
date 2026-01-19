#include "vmlinux_wrapper.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "pkg_scanner.h"

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

volatile const u8 proxy_ipv6_addr[16] = {0};
volatile const __be32 proxy_addr = 0;
volatile const __be16 proxy_port = 0;

static __always_inline int handle_pkg(struct __sk_buff *skb, struct packet_offset_info *offset,
                                      struct inet_pair *ip_pair, __be16 flow_port) {
#define BPF_LOG_TOPIC "handle_pkg"
    struct bpf_sock_tuple server = {0};
    struct bpf_sock *sk;
    size_t tuple_len;
    int ret;
    int change_type_err;
    u8 l4_protocol = offset->l4_protocol;

    if (offset->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        tuple_len = sizeof(server.ipv4);
        server.ipv4.saddr = ip_pair->src_addr.ip;
        server.ipv4.daddr = ip_pair->dst_addr.ip;
        server.ipv4.sport = ip_pair->src_port;
        server.ipv4.dport = ip_pair->dst_port;
    } else {
        tuple_len = sizeof(server.ipv6);
        COPY_ADDR_FROM(server.ipv6.saddr, ip_pair->src_addr.all);
        COPY_ADDR_FROM(server.ipv6.daddr, ip_pair->dst_addr.all);
        server.ipv6.sport = ip_pair->src_port;
        server.ipv6.dport = ip_pair->dst_port;
    }

    /* Reuse existing connection if it exists */
    if (l4_protocol == IPPROTO_TCP) {
        sk = bpf_skc_lookup_tcp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
        if (sk) {
            if (sk->state != BPF_TCP_LISTEN) {
                // bpf_log_info("reuse exist tcp: %p4I", );
                goto assign;
            }
            bpf_sk_release(sk);
            sk = NULL;
        }
    }

    /* Lookup port server is listening on */
    if (offset->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        server.ipv4.daddr = proxy_addr;
        server.ipv4.dport = proxy_port ? proxy_port : flow_port;
    } else {
        COPY_ADDR_FROM(server.ipv6.daddr, &proxy_ipv6_addr);
        server.ipv6.dport = proxy_port ? proxy_port : flow_port;
    }

    if (l4_protocol == IPPROTO_TCP) {
        sk = bpf_skc_lookup_tcp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
    } else if (l4_protocol == IPPROTO_UDP) {
        sk = bpf_sk_lookup_udp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
    }

    if (!sk) {
        if (offset->l3_protocol == LANDSCAPE_IPV4_TYPE) {
            bpf_log_info("can not find sk: l4_protocol: %d ip: %pI4:%u =>  %pI4:%u", l4_protocol,
                         &server.ipv4.saddr, bpf_ntohs(server.ipv4.sport), &server.ipv4.daddr,
                         bpf_ntohs(server.ipv4.dport));
        } else {
            bpf_log_info("can not find sk: l4_protocol: %d ip: %pI6:[%u] =>  %pI6:[%u]",
                         l4_protocol, &server.ipv6.saddr, bpf_ntohs(server.ipv6.sport),
                         &server.ipv6.daddr, bpf_ntohs(server.ipv6.dport));
        }
        return TC_ACT_SHOT;
    }

    if (l4_protocol == IPPROTO_TCP && sk->state != BPF_TCP_LISTEN) {
        bpf_sk_release(sk);
        bpf_log_info("sk not ready");
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

static __always_inline int is_tproxy_handle_protocol(const u8 protocol) {
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP ||
        protocol == NEXTHDR_ICMP) {
        return TC_ACT_OK;
    } else {
        return TC_ACT_UNSPEC;
    }
}

SEC("tc/ingress")
int tproxy_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tproxy_ingress"

    u32 vlan_id = skb->vlan_tci;
    if (!is_landscape_tag(vlan_id)) {
        return TC_ACT_OK;
    }
    u8 flow_id = get_flow_id_in_vlan_id(vlan_id);
    u16 flow_port = 12000 + flow_id;
    __u16 be_flow_port = bpf_ntohs(flow_port);

    bpf_skb_vlan_pop(skb);

    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair = {0};

    int ret = 0;

    ret = scan_packet(skb, 14, &pkg_offset);
    if (ret) {
        bpf_log_info("scan_packet ret %d", ret);
        return ret;
    }

    ret = is_tproxy_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) {
        bpf_log_info("is_tproxy_handle_protocol ret %d protocol: %u", ret, pkg_offset.l4_protocol);
        return ret;
    }

    ret = read_packet_info(skb, &pkg_offset, &ip_pair);
    if (ret) {
        bpf_log_info("read_packet_info ret %d", ret);
        return ret;
    }
    ret = handle_pkg(skb, &pkg_offset, &ip_pair, be_flow_port);

    return ret == 0 ? TC_ACT_OK : TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int route_mode_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "route_mode_ingress"

    u32 vlan_id = skb->vlan_tci;
    if (vlan_id != LAND_REDIRECT_NETNS_VLAN_ID) {
        return TC_ACT_OK;
    }
    int ret = bpf_skb_vlan_pop(skb);
    if (ret) {
        bpf_log_info("remove vlan error %d", ret);
        return TC_ACT_SHOT;
    }

    bpf_skb_change_type(skb, PACKET_HOST);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

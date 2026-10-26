#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "base/landscape.h"
#include "tproxy/tproxy_packet.h"

char LICENSE[] SEC("license") = "GPL";

/* Define constants not captured by BTF */
#define BPF_F_CURRENT_NETNS (-1L)

#define PACKET_HOST 0
#define PACKET_BROADCAST 1
#define PACKET_MULTICAST 2
#define PACKET_OTHERHOST 3

volatile const u8 proxy_ipv6_addr[16] = {0};
volatile const __be32 proxy_addr = 0;
volatile const __be16 proxy_port = 0;
volatile const bool enable_icmp_passthrough = false;
volatile const u32 icmp_mark_value = 2;

static __always_inline int handle_pkg(struct __sk_buff *skb, struct tproxy_view *view,
                                      struct inet_pair *ip_pair, __be16 flow_port) {
    struct bpf_sock_tuple server = {0};
    struct bpf_sock *sk = NULL;
    size_t tuple_len;
    int ret;
    int change_type_err;
    u8 l4_protocol = view->l4_protocol;

    if (view->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        tuple_len = sizeof(server.ipv4);
        server.ipv4.saddr = ip_pair->src_addr.in6_u.u6_addr32[0];
        server.ipv4.daddr = ip_pair->dst_addr.in6_u.u6_addr32[0];
        server.ipv4.sport = ip_pair->src_port;
        server.ipv4.dport = ip_pair->dst_port;
    } else {
        tuple_len = sizeof(server.ipv6);
        COPY_ADDR_FROM(server.ipv6.saddr, ip_pair->src_addr.in6_u.u6_addr32);
        COPY_ADDR_FROM(server.ipv6.daddr, ip_pair->dst_addr.in6_u.u6_addr32);
        server.ipv6.sport = ip_pair->src_port;
        server.ipv6.dport = ip_pair->dst_port;
    }

    /* Reuse existing connection if it exists */
    if (l4_protocol == IPPROTO_TCP) {
        sk = bpf_skc_lookup_tcp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
        if (sk) {
            if (sk->state != BPF_TCP_LISTEN) {
                // ld_log("reuse exist tcp: %p4I", );
                goto assign;
            }
            bpf_sk_release(sk);
            sk = NULL;
        }
    }

    /* Lookup port server is listening on */
    if (view->l3_protocol == LANDSCAPE_IPV4_TYPE) {
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
        if (view->l3_protocol == LANDSCAPE_IPV4_TYPE) {
            ld_log("can not find sk: l4_protocol: %d ip: %pI4:%u =>  %pI4:%u", l4_protocol,
                   &server.ipv4.saddr, bpf_ntohs(server.ipv4.sport), &server.ipv4.daddr,
                   bpf_ntohs(server.ipv4.dport));
        } else {
            ld_log("can not find sk: l4_protocol: %d ip: %pI6:[%u] =>  %pI6:[%u]", l4_protocol,
                   &server.ipv6.saddr, bpf_ntohs(server.ipv6.sport), &server.ipv6.daddr,
                   bpf_ntohs(server.ipv6.dport));
        }
        return TC_ACT_SHOT;
    }

    if (l4_protocol == IPPROTO_TCP && sk->state != BPF_TCP_LISTEN) {
        bpf_sk_release(sk);
        ld_log("sk not ready");
        return TC_ACT_SHOT;
    }

assign:
    skb->mark = 1;
    change_type_err = bpf_skb_change_type(skb, PACKET_HOST);
    if (change_type_err) {
        ld_log("change_type_err %d", change_type_err);
        ld_log("pkt_type %d", skb->pkt_type);
    }
    ret = bpf_sk_assign(skb, sk, 0);
    if (ret) {
        ld_log("bpf_sk_assign ret %d", ret);
    }
    bpf_sk_release(sk);
    return ret;
}

SEC("tc/ingress")
int tproxy_ingress(struct __sk_buff *skb) {
    u32 vlan_id = skb->vlan_tci;
    if (!is_landscape_tag(vlan_id)) {
        return TC_ACT_OK;
    }
    u8 flow_id = get_flow_id_in_vlan_id(vlan_id);
    u16 flow_port = 12000 + flow_id;
    __u16 be_flow_port = bpf_ntohs(flow_port);

    bpf_skb_vlan_pop(skb);

    struct tproxy_view view = {0};
    struct inet_pair ip_pair = {0};

    int ret = 0;

    ret = scan_tproxy_packet(skb, 14, &view, &ip_pair);
    if (ret) {
        ld_log("scan_tproxy_packet ret %d", ret);
        return ret;
    }

    u8 l4_protocol = view.l4_protocol;
    if (l4_protocol == IPPROTO_ICMP || l4_protocol == NEXTHDR_ICMP) {
        if (!enable_icmp_passthrough) return TC_ACT_SHOT;

        skb->mark = icmp_mark_value;
        bpf_skb_change_type(skb, PACKET_HOST);
        return TC_ACT_OK;
    } else if (l4_protocol == IPPROTO_TCP || l4_protocol == IPPROTO_UDP) {
        ret = read_tproxy_packet_info(skb, &view, &ip_pair);
        if (ret) {
            ld_log("read_tproxy_packet_info ret %d", ret);
            return ret;
        }
        ret = handle_pkg(skb, &view, &ip_pair, be_flow_port);

        return ret == 0 ? TC_ACT_OK : TC_ACT_SHOT;
    } else {
        ld_log("unsupported tproxy protocol: %u", l4_protocol);
        return TC_ACT_UNSPEC;
    }
}

SEC("tc/ingress")
int route_mode_ingress(struct __sk_buff *skb) {
    u32 vlan_id = skb->vlan_tci;
    if (!is_landscape_tag(vlan_id)) {
        return TC_ACT_OK;
    }
    int ret = bpf_skb_vlan_pop(skb);
    if (ret) {
        ld_log("remove vlan error %d", ret);
        return TC_ACT_SHOT;
    }

    bpf_skb_change_type(skb, PACKET_HOST);

    return TC_ACT_OK;
}

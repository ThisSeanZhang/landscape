#include "vmlinux_wrapper.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct __attribute__((__packed__)) pppoe_header {
    u8 version_and_type;
    u8 code;
    u16 session_id;
    u16 length;
    u16 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} icmp_notice_events SEC(".maps");

const volatile u16 session_id = 0x00;
const volatile u16 pppoe_mtu = 1492;

const volatile u8 iface_mac[6];

#define ETH_DROP bpf_htons(0xfffa)

#define ETH_PPP_DIS bpf_htons(0x8863)
#define ETH_PPP bpf_htons(0x8864)

#define ETH_PPP_IPV4 bpf_htons(0x0021)
#define ETH_PPP_IPV6 bpf_htons(0x0057)

#define ETH_IPV4 bpf_htons(0x0800)
#define ETH_IPV6 bpf_htons(0x86DD)

/// @brief 发送 ICMP 消息时间驱动
/// 对于 IPV4 只要携带 IP头 + 8 bit
/// [Destination Unreachable Message](https://datatracker.ietf.org/doc/html/rfc792#page-4)
/// [fragmentation
/// needed](https://www.cloudshark.org/captures/4ebfd727cc6c?filter=!(tcp.stream%20eq%200))
///
/// 对于 IPV6 需要携带原数据包的 1240 大小的数据(从 ip 报文开始)
/// 1232 = 1280 - 40(IPv6 头部) - 8 (ICMPv6 头部); 其中 1280 是IPV6 的最小 MTU
/// [最小 MTU](https://datatracker.ietf.org/doc/html/rfc2460#section-5)
/// [IPV6 Packet Too Big Message](https://datatracker.ietf.org/doc/html/rfc4443#section-3.2)
/// [example package](https://www.cloudshark.org/captures/7dd0b50eb768)
#define IPV4_TOO_LARGE_MSG_SIZE 8
#define IPV6_TOO_LARGE_MSG_SIZE 1232
struct icmp_send_event {
    u8 eth_proto;
    u8 data[];
};

SEC("tc")
int pppoe_egress_pkt_size_filter(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "pppoe_egress_pkt_size_filter"
    u32 pkt_sz = skb->len - 14;
    // 满足检查 进入下一个步骤
    if (pkt_sz < pppoe_mtu) {
        return TC_ACT_PIPE;
    } else if (pkt_sz == pppoe_mtu) {
        return TC_ACT_PIPE;
    }

    bpf_log_info("try send icmp large size is: %u, current mtu: %u", skb->len, pppoe_mtu);

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != ETH_IPV4 && eth->h_proto != ETH_IPV6) {
        return TC_ACT_UNSPEC;
    }

    u8 eth_proto;
    u32 offset = 14;
    u16 msg_size = 0;
    if (eth->h_proto == ETH_IPV6) {
        struct ipv6hdr *iph6;
        if (VALIDATE_READ_DATA(skb, &iph6, offset, sizeof(*iph6))) {
            return TC_ACT_SHOT;
        }
        msg_size = IPV6_TOO_LARGE_MSG_SIZE;
        eth_proto = 0;
    } else {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        // u8 head_size = (iph->ihl * 4);
        msg_size = IPV4_TOO_LARGE_MSG_SIZE + 60;
        eth_proto = 1;
    }

    // bpf_log_info("has packet large then mtu, protocol: %d, msg_size: %d", protocol, msg_size);

    struct icmp_send_event *e;
    u16 reserve_size = msg_size + sizeof(struct icmp_send_event);
    e = bpf_ringbuf_reserve(&icmp_notice_events, reserve_size, 0);
    if (e == NULL) {
        bpf_log_error("ring buff reserve error: %d", e);
        return TC_ACT_SHOT;
    }
    e->eth_proto = eth_proto;
    if (bpf_skb_load_bytes(skb, 14, e->data, msg_size)) {
        bpf_log_error("bpf_skb_load_bytes error");
        bpf_ringbuf_discard(e, 0);
    } else {
        bpf_ringbuf_submit(e, 0);
    }
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}
// SEC("tc")
// int pppoe_ingress(struct __sk_buff *skb) {
// #define BPF_LOG_TOPIC "pppoe_ingress"

//     void *data_end = (void *)(long)skb->data_end;
//     void *data = (void *)(long)skb->data;

//     int pkt_sz = data_end - data;

//     struct ethhdr *eth = (struct ethhdr *)(data);
//     if ((void *)(eth + 1) > data_end) {
//         bpf_log_info("ingress packet less then 14 byte");
//         return TC_ACT_SHOT;
//     }

//     if (eth->h_proto != ETH_PPP) {
//         bpf_log_info("ingress eth proto is error: %x", eth->h_proto);
//         return TC_ACT_UNSPEC;
//     }

//     struct pppoe_header *pppoe_h = (struct pppoe_header *)(eth + 1);
//     if ((void *)(pppoe_h + 1) > data_end) {
//         bpf_log_info("ingress pppoe_header out of range");
//         return TC_ACT_SHOT;
//     }

//     if (pppoe_h->protocol != ETH_PPP_IPV4 && pppoe_h->protocol != ETH_PPP_IPV6) {
//         bpf_log_info("ingress is not ppp session");
//         return TC_ACT_UNSPEC;
//     }

//     u16 l2_proto = ETH_IPV4;
//     if (pppoe_h->protocol == ETH_PPP_IPV6) {
//         l2_proto = ETH_IPV6;
//     }

//     int l2_proto_result = bpf_skb_store_bytes(skb, 12, &l2_proto, sizeof(u16), 0);
//     if (l2_proto_result == 0) {
//         bpf_log_info("ingress modify protocol to: %x success", l2_proto);
//         bpf_log_info("ingress modify protocol to skb->protocol: %x", skb->protocol);
//     } else {
//         bpf_log_info("ingress modify protocol to: %x error, code: %d", l2_proto_result);
//     }

//     data_end = (void *)(long)skb->data_end;
//     data = (void *)(long)skb->data;

//     pkt_sz = data_end - data;

//     eth = (struct ethhdr *)(data);
//     if ((void *)(eth + 1) > data_end) {
//         return TC_ACT_SHOT;
//     }
//     bpf_log_info("ingress eth->h_proto is : %x", eth->h_proto);
//     bpf_log_info("ingress skb->protocol is : %x", skb->protocol);

//     // bpf_skb_store_bytes(skb, offsetof(struct sk_buff, protocol), &l2_proto, sizeof(u16), 0);
//     int result = bpf_skb_adjust_room(skb, -8, BPF_ADJ_ROOM_MAC, 0);
//     if (result) {
//         bpf_log_info("ingress adjust room error %d", result);
//         return TC_ACT_SHOT;
//     } else {
//         bpf_log_info("ingress adjust room success");
//     }
//     return TC_ACT_UNSPEC;
// #undef BPF_LOG_TOPIC
// }
#define MAX_SEGMENT_SIZE 2
struct tcp_option_hdr {
    u8 kind;
    u8 len;
};
static __always_inline void mss_clamp(struct __sk_buff *skb, u32 offset, u16 mss_value) {
#define BPF_LOG_TOPIC "mss_clamp"
    struct tcphdr *tcph;
    if (VALIDATE_READ_DATA(skb, &tcph, offset, sizeof(*tcph))) {
        return;
    }
    if (!tcph->syn) {
        return;
    }
    u8 tcp_size = (tcph->doff * 4);
    if (tcp_size <= 20) {
        return;
    }
    // tcp option start offset
    u32 option_offset = offset + 20;
    u32 option_offset_end = offset + tcp_size;
    u16 *mss;
    // tcp hdr max is 60 - 20 = 40; 40 / 2 = 20;
    int times = (tcp_size - 20) / 2;
    times = times > 20 ? 20 : times;
    for (int i = 0; i < times; i++) {
        struct tcp_option_hdr *top_hdr;
        if (VALIDATE_READ_DATA(skb, &top_hdr, option_offset, sizeof(*top_hdr))) {
            return;
        }

        if (top_hdr->kind == MAX_SEGMENT_SIZE) {
            if (VALIDATE_READ_DATA(skb, &mss, option_offset + 2, sizeof(*mss))) {
                return;
            }
            // bpf_log_info("fond mss: %u", *mss);
            // bpf_log_info("fond mss: %u", bpf_ntohs(*mss));
            if (bpf_ntohs(*mss) > mss_value) {
                __be16 target_mss = bpf_ntohs(mss_value);
                if (bpf_l4_csum_replace(skb, offset + offsetof(struct tcphdr, check), *mss,
                                        target_mss, 2 | 0)) {
                    bpf_log_error("modify checksum error");
                    return;
                }
                if (bpf_skb_store_bytes(skb, option_offset + 2, &target_mss, sizeof(target_mss),
                                        0)) {
                    bpf_log_error("modify mss error");
                    return;
                }
            }

            return;
        }
        option_offset = option_offset + top_hdr->len;
        if (option_offset >= option_offset_end) {
            return;
        }
    }

#undef BPF_LOG_TOPIC
}

SEC("tc")
int pppoe_ingress_mss_filter(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "pppoe_ingress_mss_filter"
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != ETH_IPV4 && eth->h_proto != ETH_IPV6) {
        return TC_ACT_UNSPEC;
    }

    u32 offset = 14;
    u8 protocol = 0;
    u16 mss_value = 0;
    if (eth->h_proto == ETH_IPV6) {
        struct ipv6hdr *iph6;
        if (VALIDATE_READ_DATA(skb, &iph6, offset, sizeof(*iph6))) {
            return TC_ACT_SHOT;
        }
        protocol = iph6->nexthdr;
        offset = offset + 40;
        mss_value = pppoe_mtu - 40 - 20;
    } else {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        protocol = iph->protocol;
        offset = offset + (iph->ihl * 4);
        mss_value = pppoe_mtu - (iph->ihl * 4) - 20;
    }

    if (protocol == IPPROTO_TCP) {
        // for test
        mss_clamp(skb, offset, mss_value);
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int pppoe_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "pppoe_egress"
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    u32 pkt_sz = skb->len - 14;
    // // TODO: 消除这个魔法变量
    // if (pkt_sz > pppoe_mtu) {
    //     bpf_log_info("egress package too large size is: %u", pkt_sz);
    //     return TC_ACT_SHOT;
    //     // } else if (pkt_sz == pppoe_mtu) {
    //     //     bpf_log_info("exactly large size is: %u", pkt_sz);
    // }

    struct ethhdr *eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        bpf_log_info("package size smaller then ethhdr");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != ETH_IPV4 && eth->h_proto != ETH_IPV6) {
        bpf_log_info("egress eth proto is error: %x", eth->h_proto);
        return TC_ACT_PIPE;
    }

    u32 offset = 14;
    u8 protocol = 0;
    u16 mss_value = 0;
    u16 ppp_proto = ETH_PPP_IPV4;
    // DECAP support since linux kernel 6.3
    u64 adj_room_flag = BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;
    if (eth->h_proto == ETH_IPV6) {
        ppp_proto = ETH_PPP_IPV6;
        adj_room_flag = BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;

        struct ipv6hdr *iph6;
        if (VALIDATE_READ_DATA(skb, &iph6, offset, sizeof(*iph6))) {
            return TC_ACT_SHOT;
        }
        protocol = iph6->nexthdr;
        offset = offset + 40;
        mss_value = pppoe_mtu - 40 - 20;
    } else {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        protocol = iph->protocol;
        offset = offset + (iph->ihl * 4);
        mss_value = pppoe_mtu - (iph->ihl * 4) - 20;
    }

    if (protocol == IPPROTO_TCP) {
        // for test
        mss_clamp(skb, offset, mss_value);
    }

    u16 l2_proto = bpf_htons(0x8864);
    bpf_skb_store_bytes(skb, 12, &l2_proto, sizeof(u16), 0);

    int result = bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_MAC, adj_room_flag);
    if (result) {
        bpf_log_info("egress adjust room error %d", result);
        return TC_ACT_SHOT;
        // } else {
        //     bpf_log_info("egress adjust room success");
    }

    struct pppoe_header pppoe = {
        .version_and_type = 0x11,
        .code = 0x00,
        .session_id = bpf_htons(session_id),
        .length = bpf_htons(pkt_sz + 2),
        .protocol = ppp_proto,
    };

    bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &pppoe, sizeof(struct pppoe_header), 0);
    return TC_ACT_PIPE;
#undef BPF_LOG_TOPIC
}

// only ingress
SEC("xdp")
int pppoe_xdp_ingress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "xdp_pass"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    if (pkt_sz > 1514) {
        bpf_printk("has frame size large then 1514: %u", pkt_sz);
    }

    struct ethhdr *eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        bpf_log_info("package size smaller then ethhdr");
        return XDP_DROP;
    }

    u8 src_mac[6];
    u8 dst_mac[6];
    __builtin_memcpy(src_mac, eth->h_source, 6);
    __builtin_memcpy(dst_mac, eth->h_dest, 6);

    // if (src_mac[0] == iface_mac[0] && src_mac[1] == iface_mac[1] && src_mac[2] == iface_mac[2] &&
    //     src_mac[3] == iface_mac[3] && src_mac[4] == iface_mac[4] && src_mac[5] == iface_mac[5]) {
    //     bpf_log_info("Source MAC matches interface MAC, passing packet.");
    //     return XDP_PASS;  // 允许通过
    // }

    if (eth->h_proto != ETH_PPP) {
        if (eth->h_proto != ETH_IPV4 && eth->h_proto != ETH_IPV6 && eth->h_proto != ETH_DROP) {
            bpf_log_info("is not ppp session packet proto: %x", bpf_htons(eth->h_proto));
        }
        return XDP_PASS;
    }

    struct pppoe_header *pppoe_h = (struct pppoe_header *)(eth + 1);
    if ((void *)(pppoe_h + 1) > data_end) {
        bpf_log_info("out of pppoe_header range");
        return XDP_DROP;
    }

    if (pppoe_h->protocol != ETH_PPP_IPV4 && pppoe_h->protocol != ETH_PPP_IPV6) {
        bpf_log_info("is not ppp ipv4 or ppp ipv6: %x", bpf_htons(pppoe_h->protocol));
        return XDP_PASS;
    }

    u16 l2_proto = ETH_IPV4;
    if (pppoe_h->protocol == ETH_PPP_IPV6) {
        l2_proto = ETH_IPV6;
    }

    // 打印 MAC 地址
    // bpf_log_info("before MAC: %02x:%02x:%02x:%02x:%02x:%02x", eth->h_source[0], eth->h_source[1],
    //              eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    // bpf_log_info("before packet size: %d", pkt_sz);
    int result = bpf_xdp_adjust_head(ctx, 8);
    if (result != 0) {
        bpf_printk("bpf_xdp_adjust_head result %d", result);
        return XDP_DROP;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    int after_pkt_sz = data_end - data;
    // bpf_log_info("after packet size: %d", after_pkt_sz);

    eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        bpf_log_info("out of ethhdr range2");
        return XDP_DROP;
    }

    __builtin_memcpy(eth->h_source, src_mac, 6);
    __builtin_memcpy(eth->h_dest, dst_mac, 6);
    eth->h_proto = l2_proto;
    // bpf_log_info("after old eth MAC: %02x:%02x:%02x:%02x:%02x:%02x", eth->h_source[0],
    //              eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4],
    //              eth->h_source[5]);

    return XDP_PASS;
#undef BPF_LOG_TOPIC
}
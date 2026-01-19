#include "vmlinux_wrapper.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "pkg_scanner.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u32 current_l3_offset = 14;
const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

const volatile u32 KEY = 0;
const volatile u64 VALUE = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct route_context_test);
} test_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} test_sync_map SEC(".maps");

static __always_inline int get_route_context(struct __sk_buff *skb, u32 current_l3_offset,
                                             struct route_context_test *context) {
#define BPF_LOG_TOPIC "get_route_context"
    bool is_ipv4;
    int ret;
    if (current_l3_offset != 0) {
        struct ethhdr *eth;
        if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
            return TC_ACT_UNSPEC;
        }

        if (eth->h_proto == ETH_IPV4) {
            is_ipv4 = true;
        } else if (eth->h_proto == ETH_IPV6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 *p_version;
        if (VALIDATE_READ_DATA(skb, &p_version, 0, sizeof(*p_version))) {
            return TC_ACT_UNSPEC;
        }
        u8 ip_version = (*p_version) >> 4;
        if (ip_version == 4) {
            is_ipv4 = true;
        } else if (ip_version == 6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    }

    if (is_ipv4) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(struct iphdr))) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        context->l3_protocol = LANDSCAPE_IPV4_TYPE;
        context->l4_protocol = iph->protocol;
        context->daddr.ip = iph->daddr;
        context->saddr.ip = iph->saddr;
    } else {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(struct ipv6hdr))) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }

        context->l3_protocol = LANDSCAPE_IPV6_TYPE;
        // l4 proto
        // context->l4_protocol
        COPY_ADDR_FROM(context->saddr.all, ip6h->saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(context->daddr.all, ip6h->daddr.in6_u.u6_addr32);
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
get_route_context_from_scanner(struct __sk_buff *skb, u32 current_l3_offset,
                               struct route_context_test *context,
                               const struct packet_offset_info *offset_info) {
#define BPF_LOG_TOPIC "get_route_context_from_scanner"

    int ret;

    if (offset_info->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset_info->l3_offset_when_scan, sizeof(struct iphdr))) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        context->l3_protocol = LANDSCAPE_IPV4_TYPE;
        context->l4_protocol = iph->protocol;
        context->daddr.ip = iph->daddr;
        context->saddr.ip = iph->saddr;
    } else {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, offset_info->l3_offset_when_scan,
                               sizeof(struct ipv6hdr))) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }

        context->l3_protocol = LANDSCAPE_IPV6_TYPE;
        COPY_ADDR_FROM(context->saddr.all, ip6h->saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(context->daddr.all, ip6h->daddr.in6_u.u6_addr32);
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
get_route_context_from_scanner_v2(struct __sk_buff *skb, u32 current_l3_offset,
                                  const struct packet_offset_info *offset_info,
                                  struct route_context_test *context, struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "get_route_context_from_scanner"

    int ret;

    if (offset_info->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset_info->l3_offset_when_scan, sizeof(struct iphdr))) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        context->l3_protocol = LANDSCAPE_IPV4_TYPE;
        context->l4_protocol = iph->protocol;
        context->daddr.ip = iph->daddr;
        context->saddr.ip = iph->saddr;
    } else {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, offset_info->l3_offset_when_scan,
                               sizeof(struct ipv6hdr))) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }

        context->l3_protocol = LANDSCAPE_IPV6_TYPE;
        // l4 proto
        // context->l4_protocol
        COPY_ADDR_FROM(context->saddr.all, ip6h->saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(context->daddr.all, ip6h->daddr.in6_u.u6_addr32);
    }

    if (offset_info->l4_protocol == IPPROTO_TCP || offset_info->l4_protocol == IPPROTO_UDP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, offset_info->l4_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = tcph->source;
        ip_pair->dst_port = tcph->dest;
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
get_ipv4_route_context_from_scanner(struct __sk_buff *skb, u32 current_l3_offset,
                                    struct route_context_test *context,
                                    const struct packet_offset_info *offset_info) {
#define BPF_LOG_TOPIC "get_ipv4_route_context_from_scanner"

    int ret;

    struct iphdr iph;
    ret = bpf_skb_load_bytes(skb, offset_info->l3_offset_when_scan, &iph, sizeof(iph));
    if (ret) {
        bpf_log_info("ipv4 bpf_skb_load_bytes error");
        return TC_ACT_SHOT;
    }
    context->l3_protocol = LANDSCAPE_IPV4_TYPE;
    context->l4_protocol = iph.protocol;
    context->daddr.ip = iph.daddr;
    context->saddr.ip = iph.saddr;

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int scanner_baseline(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "scanner_baseline"
    int ret;
    struct route_context_test context = {0};
    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int direct_read_info(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "direct_read_info"
    int ret;
    struct route_context_test context = {0};
    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair;

    ret = get_route_context(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int scanner_without_offset_info(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "scanner_without_offset_info"
    int ret;
    struct route_context_test context = {0};
    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair;

    ret = scan_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) {
        return ret;
    }

    ret =
        get_route_context_from_scanner_v2(skb, current_l3_offset, &pkg_offset, &context, &ip_pair);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    return ret;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int scanner_has_offset(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "scanner_has_offset"
    int ret;
    struct route_context_test context = {0};
    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair;

    if (is_offset_cached(skb)) {
        cb_to_packet_offset_info(skb, &pkg_offset, current_l3_offset);
    } else {
        pkg_offset.status = 1;
        ret = scan_packet(skb, current_l3_offset, &pkg_offset);
        if (ret) {
            return ret;
        }
        PACKET_OFFSET_INFO_TO_CB(skb, &pkg_offset);
    }

    ret =
        get_route_context_from_scanner_v2(skb, current_l3_offset, &pkg_offset, &context, &ip_pair);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    return ret;
#undef BPF_LOG_TOPIC
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct packet_info);
} scanner_test_result_map SEC(".maps");

static __always_inline int set_pkg_info_with_offset_info(struct __sk_buff *skb,
                                                         struct packet_offset_info *offset_info,
                                                         struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "set_pkg_info_with_offset_info"

    int ret;
    if (offset_info->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset_info->l3_offset_when_scan, sizeof(struct iphdr))) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        ip_pair->dst_addr.ip = iph->daddr;
        ip_pair->src_addr.ip = iph->saddr;
    } else {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, offset_info->l3_offset_when_scan,
                               sizeof(struct ipv6hdr))) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        COPY_ADDR_FROM(ip_pair->src_addr.all, ip6h->saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(ip_pair->dst_addr.all, ip6h->daddr.in6_u.u6_addr32);
    }

    if (offset_info->l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, offset_info->l4_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = tcph->source;
        ip_pair->dst_port = tcph->dest;

        if (tcph->fin) {
            offset_info->pkt_type = PKT_TCP_FIN_V2;
        } else if (tcph->rst) {
            offset_info->pkt_type = PKT_TCP_RST_V2;
        } else if (tcph->syn) {
            offset_info->pkt_type = PKT_TCP_SYN_V2;
        } else {
            offset_info->pkt_type = PKT_TCP_DATA_V2;
        }
    } else if (offset_info->l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, offset_info->l4_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = udph->source;
        ip_pair->dst_port = udph->dest;
    } else if (offset_info->l4_protocol == IPPROTO_ICMP ||
               offset_info->l4_protocol == IPPROTO_ICMPV6) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }

        ip_pair->src_port = ip_pair->dst_port = icmph->un.echo.id;
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int test_scanner(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_scanner"
    int ret;
    u32 key = 0;
    struct packet_info info = {};
    __builtin_memset(&info, 0, sizeof(info));

    ret = scan_packet(skb, current_l3_offset, &info.offset);
    if (ret) {
        return ret;
    }

    ret = set_pkg_info_with_offset_info(skb, &info.offset, &info.ip_pair);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    info.ip_pair.dst_port = bpf_ntohs(info.ip_pair.dst_port);
    info.ip_pair.src_port = bpf_ntohs(info.ip_pair.src_port);
    ret = bpf_map_update_elem(&scanner_test_result_map, &key, &info, BPF_ANY);
    if (ret) {
        return TC_ACT_UNSPEC;
    }

    PACKET_OFFSET_INFO_TO_CB(skb, &info.offset);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

// SEC("tc/ingress")
// int test_ipv4_info_scanner(struct __sk_buff *skb) {
// #define BPF_LOG_TOPIC "test_ipv4_info_scanner"
//     int ret;
//     u64 key = 0;
//     struct packet_offset_info pkg_offset = {0};
//     struct route_context_test context = {0};
//     struct inet_pair ip_pair;

//     if (skb->cb[0] & 0xFF == 1) {
//         cb_to_packet_offset_info(skb, &pkg_offset, current_l3_offset);
//     } else {
//         pkg_offset.status = 1;
//         ret = scan_packet(skb, current_l3_offset, &pkg_offset);
//         if (ret) {
//             return ret;
//         }
//         PACKET_OFFSET_INFO_TO_CB(skb, &pkg_offset);
//     }

//     // ret = scan_packet(skb, current_l3_offset, &pkg_offset);
//     // if (ret) {
//     //     return ret;
//     // }

//     ret = get_route_context_from_scanner_v2(skb, current_l3_offset, &pkg_offset, &context,
//                                             &ip_pair);
//     if (ret != TC_ACT_OK) {
//         return TC_ACT_UNSPEC;
//     }

//     u64 *data;
//     data = bpf_map_lookup_elem(&test_sync_map, &KEY);
//     if (data) {
//         __sync_fetch_and_add(data, 1);
//     }

//     return ret;
// #undef BPF_LOG_TOPIC
// }

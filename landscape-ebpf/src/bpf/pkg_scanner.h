#ifndef __LD_PACKET_SCANNER_H__
#define __LD_PACKET_SCANNER_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include "landscape_log.h"
#include "landscape.h"
#include "pkg_def.h"

// size limit 5 u32
// icmp type
struct packet_offset_info {
    u8 icmp_error_l3_protocol;
    u8 icmp_error_l4_protocol;
    u16 status;

    u8 pkt_type;
    /// LANDSCAPE_IPV4_TYPE | LANDSCAPE_IPV6_TYPE
    u8 l3_protocol;
    u8 l4_protocol;
    u8 fragment_type;

    u16 fragment_off;
    u16 fragment_id;

    // TCP / UDP / ICMP
    u16 l4_offset;
    u16 l3_offset_when_scan;

    // ICMP err msg offset ( IPv4/v6 )
    // l4_offset + fix ICMP HDR LEN, maybe can store other info
    u16 icmp_error_l3_offset;
    // ICMP err msg offset ( TCP / UDP )
    u16 icmp_error_inner_l4_offset;
};

// struct packet_offset_info_v2 {
//     u8 icmp_error_l3_protocol;
//     u8 icmp_error_l4_protocol;
//     u16 status;

//     u8 pkt_type;
//     /// LANDSCAPE_IPV4_TYPE | LANDSCAPE_IPV6_TYPE
//     u8 l3_protocol;
//     u8 l4_protocol;
//     u8 fragment_type;

//     u16 fragment_off;
//     u16 fragment_id;

//     u8 icmp_type;
//     u8 l3_offset_when_scan;
//     // TCP / UDP / ICMP
//     u16 l4_offset;

//     // ICMP err msg offset ( IPv4/v6 )
//     // l4_offset + fix ICMP HDR LEN, maybe can store other info
//     u16 icmp_error_l3_offset;
//     // ICMP err msg offset ( TCP / UDP )
//     u16 icmp_error_inner_l4_offset;
// };

struct packet_info {
    struct packet_offset_info offset;
    struct inet_pair ip_pair;
};

struct ip_scanner_ctx {
    u8 l4_protocol;
    u8 fragment_type;
    u16 fragment_off;
    u16 fragment_id;
    u16 l4_offset;
};

enum land_scan_result {
    LD_SCAN_OK = 0,
    LD_SCAN_ERR = 2,
    LD_SCAN_UNSPEC = -1,
};

enum packet_scan_depth {
    LD_SCAN_DEPTH_NONE = 0,
    LD_SCAN_DEPTH_PROTO = 1,
    LD_SCAN_DEPTH_L3 = 2,
    LD_SCAN_DEPTH_FULL = 3,
};

union u_ld_ip {
    __be32 all[4];
    __be32 ip;
    __be32 ip6[4];
    u8 bits[16];
};

static __always_inline bool ld_ip_addr_equal(const union u_ld_ip *a, const union u_ld_ip *b) {
    return a->all[0] == b->all[0] && a->all[1] == b->all[1] && a->all[2] == b->all[2] &&
           a->all[3] == b->all[3];
}

static __always_inline int scan_ipv4(struct __sk_buff *skb, struct ip_scanner_ctx *scanner_ctx) {
#define BPF_LOG_TOPIC "scan_ipv4"

    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, scanner_ctx->l4_offset, sizeof(struct iphdr))) {
        return LD_SCAN_ERR;
    }

    if (iph->version != 4) {
        return LD_SCAN_ERR;
    }

    u16 frag_off_host = bpf_ntohs(iph->frag_off);
    scanner_ctx->fragment_off = (frag_off_host & LD_IP_OFFSET) << 3;

    bool mf = frag_off_host & LD_IP_MF;
    bool has_offset = scanner_ctx->fragment_off != 0;

    if (!has_offset && !mf) {
        scanner_ctx->fragment_type = FRAG_SINGLE;
    } else if (!has_offset && mf) {
        scanner_ctx->fragment_type = FRAG_FIRST;
    } else if (has_offset && mf) {
        scanner_ctx->fragment_type = FRAG_MIDDLE;
    } else {  // has_offset && !mf
        scanner_ctx->fragment_type = FRAG_LAST;
    }

    scanner_ctx->fragment_id = bpf_ntohs(iph->id);
    scanner_ctx->l4_protocol = iph->protocol;
    scanner_ctx->l4_offset += (iph->ihl * 4);

    return LD_SCAN_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int scan_ipv6(struct __sk_buff *skb, struct ip_scanner_ctx *scanner_ctx) {
#define BPF_LOG_TOPIC "scan_ipv6"

    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, scanner_ctx->l4_offset, sizeof(*ip6h))) {
        return LD_SCAN_ERR;
    }

    if (ip6h->version != 6) {
        return LD_SCAN_ERR;
    }

    int payload_relative_pos = sizeof(struct ipv6hdr) + scanner_ctx->l4_offset;
    u32 frag_hdr_off = 0;
    u8 nexthdr = ip6h->nexthdr;

    struct ipv6_opt_hdr *opthdr;
    struct frag_hdr *frag_hdr;

    for (int i = 0; i < LD_MAX_IPV6_EXT_NUM; i++) {
        switch (nexthdr) {
        case NEXTHDR_AUTH:
            return TC_ACT_UNSPEC;
        case NEXTHDR_FRAGMENT: {
            if (VALIDATE_READ_DATA(skb, &frag_hdr, payload_relative_pos, sizeof(*frag_hdr))) {
                return TC_ACT_SHOT;
            }
            frag_hdr_off = payload_relative_pos;
            nexthdr = frag_hdr->nexthdr;
            payload_relative_pos += sizeof(*frag_hdr);
            break;
        }
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST: {
            if (VALIDATE_READ_DATA(skb, &opthdr, payload_relative_pos, sizeof(*opthdr))) {
                return TC_ACT_SHOT;
            }
            payload_relative_pos += (opthdr->hdrlen + 1) * 8;
            nexthdr = opthdr->nexthdr;
            break;
        }
        default:
            goto found_upper_layer;
        }
    }

    switch (nexthdr) {
    case NEXTHDR_TCP:
    case NEXTHDR_UDP:
    case NEXTHDR_ICMP:
        goto found_upper_layer;
    default:
        return LD_SCAN_ERR;
    }

found_upper_layer:
    if (frag_hdr_off) {
        if (VALIDATE_READ_DATA(skb, &frag_hdr, frag_hdr_off, sizeof(*frag_hdr))) {
            return TC_ACT_SHOT;
        }
        scanner_ctx->fragment_id = bpf_ntohl(frag_hdr->identification);

        // IPv6 offset is already in 8-byte units, do NOT <<3
        u16 raw_off = bpf_ntohs(frag_hdr->frag_off);
        scanner_ctx->fragment_off = raw_off & IPV6_FRAG_OFFSET;

        bool mf = raw_off & IPV6_FRAG_MF;
        bool has_offset = scanner_ctx->fragment_off != 0;

        if (!has_offset && !mf) {
            scanner_ctx->fragment_type = FRAG_SINGLE;
        } else if (!has_offset && mf) {
            scanner_ctx->fragment_type = FRAG_FIRST;
        } else if (has_offset && mf) {
            scanner_ctx->fragment_type = FRAG_MIDDLE;
        } else {  // has_offset && !mf
            scanner_ctx->fragment_type = FRAG_LAST;
        }
    }

    scanner_ctx->l4_protocol = nexthdr;
    scanner_ctx->l4_offset = payload_relative_pos;

    return LD_SCAN_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int icmp_msg_type(struct icmphdr *icmph) {
    switch (icmph->type) {
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAMETERPROB:
        return ICMP_ERROR_MSG;
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}

static __always_inline int icmp6_msg_type(struct icmp6hdr *icmp6h) {
    switch (icmp6h->icmp6_type) {
    case ICMPV6_DEST_UNREACH:
    case ICMPV6_PKT_TOOBIG:
    case ICMPV6_TIME_EXCEED:
    case ICMPV6_PARAMPROB:
        return ICMP_ERROR_MSG;
    case ICMPV6_ECHO_REQUEST:
    case ICMPV6_ECHO_REPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}

static __always_inline int scan_packet_l3(struct __sk_buff *skb, u32 current_l3_offset,
                                          struct packet_offset_info *offset_info) {
#define BPF_LOG_TOPIC "scan_packet_l3"

    int ret = current_l3_protocol(skb, current_l3_offset, &offset_info->l3_protocol);
    if (ret == TC_ACT_SHOT) return LD_SCAN_ERR;
    if (ret != TC_ACT_OK) return LD_SCAN_UNSPEC;

    offset_info->l3_offset_when_scan = current_l3_offset;
    return LD_SCAN_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int scan_packet_outer_l4(struct __sk_buff *skb, u32 current_l3_offset,
                                                struct packet_offset_info *offset_info) {
#define BPF_LOG_TOPIC "scan_packet_outer_l4"

    bool is_ipv4;
    int ret = current_l3_protocol(skb, current_l3_offset, &offset_info->l3_protocol);
    if (ret == TC_ACT_SHOT) return LD_SCAN_ERR;
    if (ret != TC_ACT_OK) return LD_SCAN_UNSPEC;
    is_ipv4 = offset_info->l3_protocol == LANDSCAPE_IPV4_TYPE;

    struct ip_scanner_ctx ctx = {0};
    offset_info->l3_offset_when_scan = current_l3_offset;
    ctx.l4_offset = current_l3_offset;
    if (is_ipv4) {
        if (scan_ipv4(skb, &ctx)) {
            ld_bpf_log("scan ip v4 err");
            return LD_SCAN_ERR;
        }
    } else {
        if (scan_ipv6(skb, &ctx)) {
            ld_bpf_log("scan ip v6 err");
            return LD_SCAN_ERR;
        }
    }

    __builtin_memcpy(&offset_info->l4_protocol, &ctx, sizeof(struct ip_scanner_ctx));

    if (offset_info->fragment_type >= FRAG_MIDDLE) {
        // 不是第一个数据包， 整个都是 payload
        // 因为没有头部信息, 所以 需要进行查询已有的 track 记录
        offset_info->l4_offset = 0;
    }

    return LD_SCAN_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int scan_packet_full(struct __sk_buff *skb, u32 current_l3_offset,
                                            struct packet_offset_info *offset_info) {
#define BPF_LOG_TOPIC "scan_packet_full"

    int ret = scan_packet_outer_l4(skb, current_l3_offset, offset_info);
    if (ret) return ret;

    if (offset_info->fragment_type >= FRAG_MIDDLE) {
        return LD_SCAN_OK;
    }

    struct ip_scanner_ctx ctx = {0};
    if (offset_info->l4_protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
            ld_bpf_log("icmphdr error, offset_info->l4_offset: %u", offset_info->l4_offset);
            return LD_SCAN_ERR;
        }
        switch (icmp_msg_type(icmph)) {
        case ICMP_ERROR_MSG: {
            offset_info->icmp_error_l3_offset = offset_info->l4_offset + ICMP_HDR_LEN;
            barrier_var(offset_info->icmp_error_l3_offset);
            ctx.l4_offset = offset_info->icmp_error_l3_offset;
            if (scan_ipv4(skb, &ctx)) {
                ld_bpf_log("scan icmp inner ipv4 error: %u", ctx.l4_offset);
                return LD_SCAN_ERR;
            }

            if (ctx.fragment_off) {
                // icmp 不处理分片导致的 icmp 错误
                ld_bpf_log("could not handle icmp with fragment");
                return LD_SCAN_ERR;
            }

            offset_info->icmp_error_inner_l4_offset = ctx.l4_offset;
            offset_info->icmp_error_l3_protocol = LANDSCAPE_IPV4_TYPE;
            offset_info->icmp_error_l4_protocol = ctx.l4_protocol;

            u32 *temp_addr;
            u32 dst_ip_val, icmp_src_ip_val;
            if (VALIDATE_READ_DATA(skb, &temp_addr,
                                   offset_info->l3_offset_when_scan + offsetof(struct iphdr, daddr),
                                   sizeof(u32))) {
                return TC_ACT_SHOT;
            }
            dst_ip_val = *temp_addr;
            if (VALIDATE_READ_DATA(skb, &temp_addr,
                                   offset_info->icmp_error_l3_offset +
                                       offsetof(struct iphdr, saddr),
                                   sizeof(u32))) {
                return TC_ACT_SHOT;
            }
            icmp_src_ip_val = *temp_addr;

            if (dst_ip_val != icmp_src_ip_val) {
                ld_bpf_log("IP destination address does not match source "
                           "address inside ICMP error message");
                return LD_SCAN_ERR;
            }
            break;
        }
        case ICMP_QUERY_MSG: {
            break;
        }
        case ICMP_ACT_UNSPEC:
            return LD_SCAN_UNSPEC;
        default:
            ld_bpf_log("icmp shot");
            return LD_SCAN_ERR;
        }
    } else if (offset_info->l4_protocol == IPPROTO_ICMPV6) {
        struct icmp6hdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmp6hdr))) {
            return TC_ACT_SHOT;
        }

        switch (icmp6_msg_type(icmph)) {
        case ICMP_ERROR_MSG: {
            offset_info->icmp_error_l3_offset = offset_info->l4_offset + ICMP_HDR_LEN;
            ctx.l4_offset = offset_info->icmp_error_l3_offset;
            if (scan_ipv6(skb, &ctx)) {
                ld_bpf_log("scan icmpv6 inner ipv6 error: %u", ctx.l4_offset);
                return LD_SCAN_ERR;
            }

            if (ctx.fragment_off) {
                // icmp 不处理分片导致的 icmp 错误
                return LD_SCAN_ERR;
            }

            offset_info->icmp_error_inner_l4_offset = ctx.l4_offset;
            offset_info->icmp_error_l3_protocol = LANDSCAPE_IPV6_TYPE;
            offset_info->icmp_error_l4_protocol = ctx.l4_protocol;

            union u_ld_ip *temp_addr;
            union u_ld_ip dst_ip_val, icmp_src_ip_val;

            if (VALIDATE_READ_DATA(skb, &temp_addr,
                                   offset_info->l3_offset_when_scan +
                                       offsetof(struct ipv6hdr, daddr),
                                   sizeof(union u_ld_ip))) {
                return TC_ACT_SHOT;
            }
            COPY_ADDR_FROM(dst_ip_val.all, temp_addr->all);
            if (VALIDATE_READ_DATA(skb, &temp_addr,
                                   offset_info->icmp_error_l3_offset +
                                       offsetof(struct ipv6hdr, saddr),
                                   sizeof(union u_ld_ip))) {
                return TC_ACT_SHOT;
            }
            COPY_ADDR_FROM(icmp_src_ip_val.all, temp_addr->all);

            if (!ld_ip_addr_equal(&dst_ip_val, &icmp_src_ip_val)) {
                ld_bpf_log("IP destination address does not match source "
                           "address inside ICMP error message");
                return LD_SCAN_ERR;
            }
            break;
        }
        case ICMP_QUERY_MSG: {
            break;
        }
        case ICMP_ACT_UNSPEC:
            return LD_SCAN_UNSPEC;
        default:
            ld_bpf_log("icmp shot");
            return LD_SCAN_ERR;
        }
    }

    return LD_SCAN_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline bool is_icmp_error_pkt(const struct packet_offset_info *offset) {
    return offset->icmp_error_l3_offset > 0 && offset->icmp_error_inner_l4_offset > 0;
}

#endif /* __LD_PACKET_SCANNER_H__ */

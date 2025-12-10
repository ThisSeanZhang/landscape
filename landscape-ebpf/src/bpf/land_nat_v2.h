#ifndef LD_NAT_V2_H
#define LD_NAT_V2_H
#include "vmlinux.h"
#include "landscape_log.h"
#include "pkg_scanner.h"
#include "pkg_fragment.h"
#include "land_nat_common.h"
#include "share_ifindex_ip.h"
#include "counter.h"

///
struct ip_packet_info_v2 {
    struct packet_offset_info offset;
    struct inet_pair pair_ip;
};

#define LAND_IPV6_NET_PREFIX_TRANS_MASK (0x0FULL << 56)

struct ipv6_prefix_mapping_key {
    u8 client_suffix[8];
    u16 client_port;
    // client suffix is 8 byte + 4 bit
    u8 id_byte;
    // TCP / UDP / ICMP6
    u8 l4_protocol;
};

struct ipv6_prefix_mapping_value {
    // client prefix is 7 byte + 4 bit
    u8 client_prefix[8];
    union u_inet_addr trigger_addr;
    u16 trigger_port;
    u8 is_allow_reuse;
    u8 _pad;
};

#define CLIENT_PREFIX_CACHE_SIZE 65536 * 3
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ipv6_prefix_mapping_key);
    __type(value, struct ipv6_prefix_mapping_value);
    __uint(max_entries, CLIENT_PREFIX_CACHE_SIZE);
} ip6_client_map SEC(".maps");

static __always_inline int get_l4_checksum_offset(u32 l4_offset, u8 l4_protocol,
                                                  u32 *l4_checksum_offset) {
    if (l4_protocol == IPPROTO_TCP) {
        *l4_checksum_offset = l4_offset + offsetof(struct tcphdr, check);
    } else if (l4_protocol == IPPROTO_UDP) {
        *l4_checksum_offset = l4_offset + offsetof(struct udphdr, check);
    } else if (l4_protocol == IPPROTO_ICMPV6) {
        *l4_checksum_offset = l4_offset + offsetof(struct icmp6hdr, icmp6_cksum);
    } else {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

static __always_inline bool is_same_prefix(const u8 prefix[7], const union u_inet_addr *a) {
    const u8 *b = a->bits;
    return prefix[0] == b[0] && prefix[1] == b[1] && prefix[2] == b[2] && prefix[3] == b[3] &&
           prefix[4] == b[4] && prefix[5] == b[5] && ((prefix[6] & 0xF0) == (b[6] & 0xF0));
    ;
}

static __always_inline int update_ipv6_cache_value(struct __sk_buff *skb, struct inet_pair *ip_pair,
                                                   struct ipv6_prefix_mapping_value *value) {
    COPY_ADDR_FROM(value->client_prefix, ip_pair->src_addr.bits);
    bool allow_reuse_port = get_flow_allow_reuse_port(skb->mark);
    value->is_allow_reuse = allow_reuse_port ? 1 : 0;
    COPY_ADDR_FROM(value->trigger_addr.all, ip_pair->dst_addr.all);
    value->trigger_port = ip_pair->dst_port;
}

static __always_inline int search_ipv6_mapping_egress(struct __sk_buff *skb,
                                                      struct packet_offset_info *offset_info,
                                                      struct inet_pair *ip_pair) {
    struct ipv6_prefix_mapping_key key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
    key.id_byte = ip_pair->src_addr.bits[7] & 0x0F;
    // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
    key.l4_protocol = offset_info->l4_protocol;

    struct ipv6_prefix_mapping_value *value;
    value = bpf_map_lookup_elem(&ip6_client_map, &key);
    if (value) {
        if (!is_same_prefix(value->client_prefix, ip_pair->src_addr.bits)) {
            update_ipv6_cache_value(skb, ip_pair, value);
        }
    } else {
        struct ipv6_prefix_mapping_value new_value = {0};
        update_ipv6_cache_value(skb, ip_pair, &new_value);
        bpf_map_update_elem(&ip6_client_map, &key, &new_value, BPF_ANY);
    }

    return TC_ACT_OK;
}

#define READ_SKB_U16(skb_ptr, offset, var)                                                         \
    do {                                                                                           \
        u16 *tmp_ptr;                                                                              \
        if (VALIDATE_READ_DATA(skb_ptr, &tmp_ptr, offset, sizeof(*tmp_ptr))) return TC_ACT_SHOT;   \
        var = *tmp_ptr;                                                                            \
    } while (0)

#define L4_CSUM_REPLACE_U64_OR_SHOT(skb_ptr, csum_offset, old_val, new_val, flags)                 \
    do {                                                                                           \
        int _ret;                                                                                  \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) >> 32, (new_val) >> 32,         \
                                   flags | 4);                                                     \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace high 32bit err: %d", _ret);                                \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) & 0xFFFFFFFF,                   \
                                   (new_val) & 0xFFFFFFFF, flags | 4);                             \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace low 32bit err: %d", _ret);                                 \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

static __always_inline int check_egress_mapping_exist(struct __sk_buff *skb, u8 ip_protocol,
                                                      const struct inet_pair *pkt_ip_pair) {
#define BPF_LOG_TOPIC "check_egress_mapping_exist"
    struct static_nat_mapping_key egress_key = {0};
    struct nat_mapping_value *nat_gress_value = NULL;


    egress_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    egress_key.l4_protocol = ip_protocol;
    egress_key.gress = NAT_MAPPING_EGRESS;
    egress_key.prefixlen = 192;
    egress_key.port = pkt_ip_pair->src_port;
    COPY_ADDR_FROM(egress_key.addr.all, pkt_ip_pair->src_addr.all);

    nat_gress_value = bpf_map_lookup_elem(&static_nat_mappings, &egress_key);
    if (nat_gress_value) {
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

static __always_inline int
ipv6_egress_prefix_check_and_replace(struct __sk_buff *skb, struct packet_offset_info *offset_info,
                                     struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "ipv6_egress_prefix_check_and_replace"
    int ret;
    ret = check_egress_mapping_exist(skb, offset_info->l4_protocol, ip_pair);
    if (ret != TC_ACT_OK) {
        // Static mapping does not exist
        ret = search_ipv6_mapping_egress(skb, offset_info, ip_pair);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }
    }

    
    if (offset_info->l4_protocol == NEXTHDR_ICMP) {
        struct icmphdr *icmph;
        if (!VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
            if (icmph->type == 128) {
                u32 key = 4;
                u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                if (count) {
                    __sync_fetch_and_add(count, 1);
                }
            }
        }
    }

    struct wan_ip_info_key wan_search_key = {0};
    wan_search_key.ifindex = skb->ifindex;
    wan_search_key.l3_protocol = LANDSCAPE_IPV6_TYPE;

    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ipv4_binding, &wan_search_key);
    if (wan_ip_info == NULL) {
        return TC_ACT_SHOT;
    }

    if (is_icmp_error_pkt(offset_info)) {
        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->src_addr.all);
        COPY_ADDR_FROM(&new_ip_prefix, wan_ip_info->addr.all);
        new_ip_prefix = (old_ip_prefix & LAND_IPV6_NET_PREFIX_TRANS_MASK) |
                        (new_ip_prefix & ~LAND_IPV6_NET_PREFIX_TRANS_MASK);

        u32 error_sender_offset =
            offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, saddr);
        u32 inner_l3_ip_dst_offset =
            offset_info->icmp_error_l3_offset + offsetof(struct ipv6hdr, daddr);

        __be64 *error_sender_point;
        __be64 old_sender_ip_prefix, new_sender_ip_prefix;
        if (VALIDATE_READ_DATA(skb, &error_sender_point, error_sender_offset,
                               sizeof(*error_sender_point))) {
            return TC_ACT_SHOT;
        }

        old_sender_ip_prefix = *error_sender_point;
        COPY_ADDR_FROM(&new_sender_ip_prefix, wan_ip_info->addr.all);

        new_sender_ip_prefix = (old_sender_ip_prefix & LAND_IPV6_NET_PREFIX_TRANS_MASK) |
                               (new_sender_ip_prefix & ~LAND_IPV6_NET_PREFIX_TRANS_MASK);

        u32 inner_l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->icmp_error_inner_l4_offset,
                                   offset_info->icmp_error_l4_protocol,
                                   &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_dst_offset, &new_ip_prefix, 8, 0);
        if (ret) {
            bpf_printk("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        // ret = bpf_l4_csum_replace(skb, inner_l4_checksum_offset, old_inner_ip_prefix >> 32,
        //                           new_inner_ip_prefix >> 32, 4);

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, inner_l4_checksum_offset, old_ip_prefix, new_ip_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, new_ip_prefix, 0);

        // 因为更新了内层 checksum  所以要先更新内部checksum 改变导致外部 icmp checksum 改变的代码
        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);

        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            bpf_printk("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        bpf_skb_store_bytes(skb, error_sender_offset, &new_sender_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_sender_ip_prefix,
                                    new_sender_ip_prefix, BPF_F_PSEUDO_HDR);

    } else {
        // ipv6 sceck sum
        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 ip_src_offset = offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, saddr);

        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->src_addr.all);
        COPY_ADDR_FROM(&new_ip_prefix, wan_ip_info->addr.all);
        new_ip_prefix = (old_ip_prefix & LAND_IPV6_NET_PREFIX_TRANS_MASK) |
                        (new_ip_prefix & ~LAND_IPV6_NET_PREFIX_TRANS_MASK);
        bpf_skb_store_bytes(skb, ip_src_offset, &new_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, new_ip_prefix,
                                    BPF_F_PSEUDO_HDR);

                                    
    
        if (offset_info->l4_protocol == NEXTHDR_ICMP) {
            struct icmphdr *icmph;
            if (!VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
                if (icmph->type == 128) {
                    u32 key = 5;
                    u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                    if (count) {
                        __sync_fetch_and_add(count, 1);
                    }
                }
            }
        }
    }

    
    
    if (offset_info->l4_protocol == NEXTHDR_ICMP) {
        struct icmphdr *icmph;
        if (!VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
            if (icmph->type == 128) {
                u32 key = 6;
                u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                if (count) {
                    __sync_fetch_and_add(count, 1);
                }
            }
        }
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

static __always_inline int check_ingress_mapping_exist(struct __sk_buff *skb, u8 ip_protocol,
                                                      const struct inet_pair *pkt_ip_pair,
                                                    __be64 *local_client_prefix) {
#define BPF_LOG_TOPIC "check_ingress_mapping_exist"
    struct static_nat_mapping_key ingress_key = {0};
    struct nat_mapping_value *value = NULL;

    __be64 dst_suffix, mapping_suffix;

    ingress_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    ingress_key.l4_protocol = ip_protocol;
    ingress_key.gress = NAT_MAPPING_INGRESS;
    ingress_key.prefixlen = 96;
    ingress_key.port = pkt_ip_pair->dst_port;

    value = bpf_map_lookup_elem(&static_nat_mappings, &ingress_key);
    if (value) {
        // 映射到当前的主机, 相对于 suffix 是空的
        if (value->addr.all[3] == 0 && value->addr.all[2] == 0) {
            return TC_ACT_UNSPEC;
        }

        // 映射中设置了前缀, 那么要进行修改
        if (value->addr.ip !=0) {
            COPY_ADDR_FROM(local_client_prefix, value->addr.bits);
            return TC_ACT_OK;
        }

        // 映射中只设置了后缀, 所以就只校验, 不修改
        COPY_ADDR_FROM(&mapping_suffix, value->addr.bits + 8);
        COPY_ADDR_FROM(&dst_suffix, pkt_ip_pair->dst_addr.bits + 8);

        if(mapping_suffix == dst_suffix) {
            return TC_ACT_UNSPEC;
        }
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

static __always_inline int
ipv6_ingress_prefix_check_and_replace(struct __sk_buff *skb, struct packet_offset_info *offset_info,
                                      struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "ipv6_ingress_prefix_check_and_replace"
    int ret;
    __be64 local_client_prefix = {0};

    ret = check_ingress_mapping_exist(skb, offset_info->l4_protocol, ip_pair, &local_client_prefix);
    if (ret == TC_ACT_UNSPEC) {
        return TC_ACT_UNSPEC;
    }

    if(ret == TC_ACT_SHOT) {
        struct ipv6_prefix_mapping_key key = {0};
        key.client_port = ip_pair->dst_port;
        COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
        // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
        key.id_byte = ip_pair->dst_addr.bits[7] & 0x0F;
        // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
        key.l4_protocol = offset_info->l4_protocol;

        if (offset_info->l4_protocol == NEXTHDR_ICMP) {
            struct icmphdr *icmph;
            if (!VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
                if (icmph->type == 129) {
                    u32 key = 11;
                    u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                    if (count) {
                        __sync_fetch_and_add(count, 1);
                    }
                }
            }
        }
        struct ipv6_prefix_mapping_value *value = bpf_map_lookup_elem(&ip6_client_map, &key);
        if (value == NULL) {
            bpf_printk("lookup client prefix error, key.id_byte: %x", key.id_byte);
            // bpf_printk("lookup client prefix error, key.client_suffix: %02x %02x %02x %02x %02x %02x
            // %02x %02x %02x", key.client_suffix[0], key.client_suffix[1], key.client_suffix[2],
            // key.client_suffix[3], key.client_suffix[4], key.client_suffix[5], key.client_suffix[6],
            // key.client_suffix[7], key.client_suffix[8]);
            bpf_printk("lookup client prefix error, key.l4_protocol: %u", key.l4_protocol);
            bpf_printk("lookup client prefix error, key.client_port: %04x", key.client_port);
            return TC_ACT_SHOT;
        }

        COPY_ADDR_FROM(&local_client_prefix, value->client_prefix);

        
        // bpf_printk("is_allow_reuse: %u", value->is_allow_reuse);

        if (value->is_allow_reuse == 0 && offset_info->l4_protocol != IPPROTO_ICMPV6) {
            if (!ip_addr_equal(&ip_pair->src_addr, &value->trigger_addr) ||
                ip_pair->src_port != value->trigger_port) {
                bpf_printk("FLOW_ALLOW_REUSE MARK not set, DROP PACKET");
                bpf_printk("src info: [%pI6]:%u", &ip_pair->src_addr, bpf_ntohs(ip_pair->src_port));
                bpf_printk("trigger ip: [%pI6]:%u,", &value->trigger_addr,
                        bpf_ntohs(value->trigger_port));
                return TC_ACT_SHOT;
            }
        }

        if (offset_info->l4_protocol == NEXTHDR_ICMP) {
            struct icmphdr *icmph;
            if (!VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
                if (icmph->type == 129) {
                    u32 key = 12;
                    u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                    if (count) {
                        __sync_fetch_and_add(count, 1);
                    }
                }
            }
        }
    }
    

    if (is_icmp_error_pkt(offset_info)) {
        // 修改原数据包的 dst ip， 内部数据包的 src ip
        u32 inner_l3_ip_src_offset =
            offset_info->icmp_error_l3_offset + offsetof(struct ipv6hdr, saddr);

        __be64 *old_inner_ip_point;
        __be64 old_inner_ip_prefix;
        if (VALIDATE_READ_DATA(skb, &old_inner_ip_point, inner_l3_ip_src_offset,
                               sizeof(*old_inner_ip_point))) {
            return TC_ACT_SHOT;
        }
        old_inner_ip_prefix = *old_inner_ip_point;

        u32 inner_l4_checksum_offset = 0;
        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->icmp_error_inner_l4_offset,
                                   offset_info->icmp_error_l4_protocol,
                                   &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_src_offset, &local_client_prefix, 8, 0);
        if (ret) {
            bpf_printk("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, inner_l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, 0);
        // 因为更新了内层 checksum  所以要先更新内部checksum 改变导致外部 icmp checksum 改变的代码
        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);
        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            bpf_printk("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        u32 ipv6_dst_offset = offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, daddr);
        bpf_skb_store_bytes(skb, ipv6_dst_offset, &local_client_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, BPF_F_PSEUDO_HDR);
    } else {
        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 dst_ip_offset = offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, daddr);

        __be64 old_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->dst_addr.all);
        bpf_skb_store_bytes(skb, dst_ip_offset, &local_client_prefix, 8, 0);

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, local_client_prefix,
                                    BPF_F_PSEUDO_HDR);
        if (offset_info->l4_protocol == NEXTHDR_ICMP) {
            struct icmphdr *icmph;
            if (!VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
                if (icmph->type == 129) {
                    u32 key = 13;
                    u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                    if (count) {
                        __sync_fetch_and_add(count, 1);
                    }
                }
            }
        }
    }

    if (offset_info->l4_protocol == NEXTHDR_ICMP) {
        struct icmphdr *icmph;
        if (!VALIDATE_READ_DATA(skb, &icmph, offset_info->l4_offset, sizeof(struct icmphdr))) {
            if (icmph->type == 129) {
                u32 key = 14;
                u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                if (count) {
                    __sync_fetch_and_add(count,1);
                }
            }
        }
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

#endif /* LD_NAT_V2_H */

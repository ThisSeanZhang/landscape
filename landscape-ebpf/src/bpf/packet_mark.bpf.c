#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "packet_mark.h"

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;
char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int current_eth_net_offset = 14;

static int prepend_dummy_mac(struct __sk_buff *skb) {
    char mac[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x08, 0x00};

    if (bpf_skb_change_head(skb, 14, 0)) return -1;

    if (bpf_skb_store_bytes(skb, 0, mac, sizeof(mac), 0)) return -1;

    return 0;
}

SEC("tc")
int egress_packet_mark(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<-|<- egress_packet_mark <-|<-"

    if (skb->vlan_tci != 0) {
        bpf_log_info("has vlan_tci = %u", skb->vlan_tci);
        skb->mark == DIRECT_MARK;
        bpf_skb_vlan_pop(skb);
    }

    u8 action = 0;
    u8 index = 0;

    if (skb->mark == 0) {
        if (current_eth_net_offset != 0) {
            struct ethhdr *eth;
            if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
                return TC_ACT_UNSPEC;
            }

            if (eth->h_proto == ETH_ARP) {
                // bpf_log_info("has arp");
                return TC_ACT_OK;
            }

            if (eth->h_proto != ETH_IPV4 && eth->h_proto != ETH_IPV6) {
                // bpf_log_debug("has wrong h_proto: %u", eth->h_proto);
                return TC_ACT_UNSPEC;
            }

        } else {
            u8 *p_version;
            if (VALIDATE_READ_DATA(skb, &p_version, 0, sizeof(*p_version))) {
                return TC_ACT_UNSPEC;
            }
            u8 ip_version = (*p_version) >> 4;

            if (ip_version != 4 && ip_version != 6) {
                // bpf_log_debug("has wrong h_proto: %u", ip_version);
                return TC_ACT_UNSPEC;
            }
        }

        int offset = current_eth_net_offset;
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset, sizeof(*iph))) {
            return TC_ACT_UNSPEC;
        }
        offset += (iph->ihl * 4);

        struct ipv4_lpm_key find_key = {.prefixlen = 32, .addr = iph->daddr};
        // 检查当前配置的 mark
        struct ipv4_mark_action *mark_value = bpf_map_lookup_elem(&packet_mark_map, &find_key);
        if (mark_value) {
            // bpf_log_info("IP: %d.%d.%d.%d,",
            //              iph->daddr & 0xFF,
            //              (iph->daddr >> 8) & 0xFF,
            //              (iph->daddr >> 16) & 0xFF,
            //              (iph->daddr >> 24) & 0xFF
            // );
            action = mark_value->mark & ACTION_MASK;
            index = (mark_value->mark & INDEX_MASK) >> 8;
            skb->mark = mark_value->mark;
        }
    } else {
        bpf_log_info("has mark = %u", skb->mark);
        action = skb->mark & ACTION_MASK;
        index = (skb->mark & INDEX_MASK) >> 8;
    }

    if (action == OK_MARK) {
        // 进入下一个环节
        return TC_ACT_UNSPEC;
    } else if (action == DIRECT_MARK) {
        bpf_log_info("has DIRECT_MARK = %u", skb->mark);
        return TC_ACT_UNSPEC;
    } else if (action == DROP_MARK) {
        // bpf_log_info("drop packet mark %u", skb->mark);
        return TC_ACT_SHOT;
    } else if (action == REDIRECT_MARK) {
        bpf_log_info("REDIRECT_MARK %u", skb->mark);
        u32 *outer_ifindex = bpf_map_lookup_elem(&redirect_index_map, &index);
        if (outer_ifindex != NULL) {
            return bpf_redirect(*outer_ifindex, 0);
        }
    } else if (action == REDIRECT_NETNS_MARK) {
        bpf_log_info("REDIRECT_NETNS_MARK %u", skb->mark);
        u32 *outer_ifindex = bpf_map_lookup_elem(&redirect_index_map, &index);
        if (outer_ifindex != NULL) {
            if (current_eth_net_offset == 0) {
                if (prepend_dummy_mac(skb) != 0) {
                    return TC_ACT_SHOT;
                }
            }
            bpf_skb_vlan_push(skb, ETH_P_8021Q, LAND_REDIRECT_NETNS_VLAN_ID);
            return bpf_redirect(*outer_ifindex, 0);
        }
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int ingress_packet_mark(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "->|-> ingress_packet_mark ->|->"
    int offset = 0;
    struct ethhdr *eth;
    if (VALIDATE_READ_DATA(skb, &eth, offset, sizeof(*eth))) {
        return TC_ACT_UNSPEC;
    }
    if (eth->h_proto == ETH_ARP) {
        return TC_ACT_OK;
    }
    if (eth->h_proto != ETH_IPV4 && eth->h_proto != ETH_IPV6) {
        bpf_log_info("has wrong h_proto: %u", eth->h_proto);
        // 丢弃
        return TC_ACT_UNSPEC;
    }
    offset = 14;
    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, offset, sizeof(*iph))) {
        return TC_ACT_UNSPEC;
    }
    offset += (iph->ihl * 4);

    u8 action = 0;
    u8 index = 0;
    struct ipv4_lpm_key find_key = {.prefixlen = 32, .addr = iph->saddr};
    struct ipv4_mark_action *mark_value = bpf_map_lookup_elem(&packet_mark_map, &find_key);
    if (mark_value) {
        action = mark_value->mark & ACTION_MASK;
        index = (mark_value->mark & INDEX_MASK) >> 8;
    }

    if (action == OK_MARK) {
        // 进入下一个环节
        return TC_ACT_UNSPEC;
    } else if (action == DIRECT_MARK) {
        return TC_ACT_UNSPEC;
    } else if (action == DROP_MARK) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "land_dns_dispatcher.h"
#include "flow_match.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

SEC("sk_reuseport/migrate")
int reuseport_dns_dispatcher(struct sk_reuseport_md *reuse_md) {
#define BPF_LOG_TOPIC ">> select_dns"
    // struct bpf_sock *sk;
    // struct bpf_sock *msk = reuse_md->migrating_sk;

    struct flow_match_key search_key = {0};
    int ret = 0;
    __u32 flow_id = 0;
    // u8 mac_addr[6];

    // ret = bpf_skb_load_bytes_relative(reuse_md, 6, &mac_addr, 6, BPF_HDR_START_MAC);
    // if (!ret) {
    //     PRINT_MAC_ADDR(mac_addr);
    // }
    if (reuse_md->eth_protocol == ETH_IPV4) {
        search_key.prefixlen = 96;
        search_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        ret = bpf_skb_load_bytes_relative(reuse_md, offsetof(struct iphdr, saddr),
                                          &search_key.src_addr, 4, BPF_HDR_START_NET);
        if (ret) {
            bpf_log_info("reuseport_dns_dispatcher, read src IP error: %d", ret);
            return SK_DROP;
        }
        // bpf_log_info("src ip: %pI4", &search_key.src_addr);
    } else {
        search_key.prefixlen = 192;
        search_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
        ret = bpf_skb_load_bytes_relative(reuse_md, offsetof(struct ipv6hdr, saddr),
                                          &search_key.src_addr, 16, BPF_HDR_START_NET);
        if (ret) {
            bpf_log_info("reuseport_dns_dispatcher, read src IP error: %d", ret);
            return SK_DROP;
        }

        // bpf_log_info("src ip: %pI6", &search_key.src_addr);
    }

    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &search_key);
    if (flow_id_ptr != NULL) {
        flow_id = *flow_id_ptr;
    }

    // bpf_log_info("find flow_id: %d", flow_id);
    ret = bpf_sk_select_reuseport(reuse_md, &dns_flow_socks, &flow_id, 0);
    if (ret) {
        bpf_log_info("bpf_sk_select_reuseport err: %d", ret);
        return SK_DROP;
    }

    return SK_PASS;
#undef BPF_LOG_TOPIC
}

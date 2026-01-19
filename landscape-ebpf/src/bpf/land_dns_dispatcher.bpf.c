#include "vmlinux_wrapper.h"

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

    struct flow_match_key match_key = {0};
    int ret = 0;
    __u32 flow_id = 0;

    ret = bpf_skb_load_bytes_relative(reuse_md, 6, &match_key.mac.mac, 6, BPF_HDR_START_MAC);
    if (!ret) {
        match_key.prefixlen = FLOW_MAC_MATCH_LEN;
        match_key.is_match_ip = FLOW_ENTRY_MODE_MAC;

        // PRINT_MAC_ADDR(match_key.mac.mac);

        u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
        if (flow_id_ptr != NULL) {
            flow_id = *flow_id_ptr;
        }
    }

    match_key.is_match_ip = FLOW_ENTRY_MODE_IP;
    if (reuse_md->eth_protocol == ETH_IPV4) {
        match_key.prefixlen = FLOW_IP_IPV4_MATCH_LEN;
        match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        ret = bpf_skb_load_bytes_relative(reuse_md, offsetof(struct iphdr, saddr),
                                          &match_key.src_addr, 4, BPF_HDR_START_NET);
        if (ret) {
            bpf_log_info("reuseport_dns_dispatcher, read src IP error: %d", ret);
            return SK_DROP;
        }
        // bpf_log_info("src ip: %pI4", &match_key.src_addr);
    } else {
        match_key.prefixlen = FLOW_IP_IPV6_MATCH_LEN;
        match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
        ret = bpf_skb_load_bytes_relative(reuse_md, offsetof(struct ipv6hdr, saddr),
                                          &match_key.src_addr, 16, BPF_HDR_START_NET);
        if (ret) {
            bpf_log_info("reuseport_dns_dispatcher, read src IP error: %d", ret);
            return SK_DROP;
        }

        // bpf_log_info("src ip: %pI6", &match_key.src_addr);
    }

    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
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

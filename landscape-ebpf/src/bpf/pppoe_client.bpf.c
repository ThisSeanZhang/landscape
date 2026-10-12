#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"

#undef BPF_LOG_TOPIC

char LICENSE[] SEC("license") = "GPL";

#define ETH_HLEN 14

SEC("socket")
int pppoe_pnet_filter(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "pppoe_pnet_filter"
    u16 eth_proto;
    u32 start_index = ETH_HLEN;
    u8 hdr_len;
    u32 tcp_hdr_start = 0;
    u32 ip_proto = 0;
    u32 l_ip, r_ip;

    bpf_skb_load_bytes(skb, 12, &eth_proto, 2);
    // 排除非 PPPOE 协议的数据
    if (eth_proto != ETH_P_PPP_DISC && eth_proto != ETH_P_PPP_SES) return 0;

    struct pppoe_header pppoe;

    int ret = bpf_skb_load_bytes(skb, start_index, &pppoe, sizeof(struct pppoe_header));

    if (ret != 0) {
        return 0;
    }

    // 如果是 IPV4 或者 IPV6 的传输数据, 也进行过滤
    if (pppoe.protocol == ETH_P_PPP_IPV4 || pppoe.protocol == ETH_P_PPP_IPV6) {
        return 0;
    }

    // ld_bpf_log("pppoe code: %u, sid: %u, len%u", pppoe.code, pppoe.session_id, pppoe.length);

    return skb->len;
#undef BPF_LOG_TOPIC
}

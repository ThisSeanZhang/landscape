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

    bpf_skb_load_bytes(skb, 12, &eth_proto, 2);
    // Drop everything that is not PPPoE
    if (eth_proto != ETH_P_PPP_DISC && eth_proto != ETH_P_PPP_SES) return 0;

    // Load only the 6-byte PPPoE base header (version/type, code,
    // session_id, length).  Do NOT use the full struct pppoe_header (8
    // bytes): short frames without payload (e.g. a PADT without tags is
    // only 20 bytes total) have no protocol field, and the over-read would
    // fail, silently dropping the PADT.
    struct __attribute__((packed)) {
        u8 version_and_type;
        u8 code;
        __be16 session_id;
        __be16 length;
    } pppoe;

    if (bpf_skb_load_bytes(skb, ETH_HLEN, &pppoe, sizeof(pppoe)) != 0) {
        return 0;
    }

    // The PPP protocol field only exists in session-data frames (code 0)
    // with payload; short frames and tag-carrying discovery frames pass
    if (pppoe.code == 0 && skb->len >= ETH_HLEN + 8) {
        u16 protocol;
        bpf_skb_load_bytes(skb, ETH_HLEN + 6, &protocol, 2);
        // Filter out IPv4/IPv6 user data
        if (protocol == ETH_P_PPP_IPV4 || protocol == ETH_P_PPP_IPV6) {
            return 0;
        }
    }

    return skb->len;
#undef BPF_LOG_TOPIC
}

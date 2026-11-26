#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"

#include "chain/tc_cb.h"
#include "chain/tc_handoff.h"
#include "map/wan_trie.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_root_progs SEC(".maps");

/* WAN dispatch trie shared with the XDP seed (reuse_fd before load).
 * Dispatch roots are tc_pipe_root_progs slots, indexed by the owning WAN
 * link's chain id.
 */
WAN_TRIE_DECLARE(wan_trie_arena);

static __always_inline int tc_intro_pppoe(struct __sk_buff *skb) {
    const u32 l3 = sizeof(struct ethhdr) + sizeof(struct pppoe_header);
    const u32 max_head = l3 + sizeof(struct ipv6hdr);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + l3 > data_end) {
        /* Pull enough for either family while bringing the session header in. */
        u32 len = skb->len;
        if (len < l3 || bpf_skb_pull_data(skb, len < max_head ? len : max_head)) return TC_ACT_OK;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        if (data + l3 > data_end) return TC_ACT_OK;
    }

    const struct pppoe_header *ppp = data + sizeof(struct ethhdr);
    __be16 protocol = ppp->protocol;
    if (protocol != ETH_P_PPP_IPV4 && protocol != ETH_P_PPP_IPV6) return TC_ACT_OK;

    u64 key = wan_trie_key_ppp(skb->ifindex, ppp->session_id);
    u32 root = wan_trie_resolve(wan_trie_table(&wan_trie_arena), key);
    if (!root) return TC_ACT_OK;

    /* Only the local-stack exception depends on the inner destination. */
    bool is_v4 = protocol == ETH_P_PPP_IPV4;
    u32 need = is_v4 ? l3 + sizeof(struct iphdr) : max_head;
    if (data + need > data_end) {
        if (need > skb->len || bpf_skb_pull_data(skb, need)) return TC_ACT_OK;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
    }
    bool to_stack;
    __be16 proto;
    if (is_v4) {
        const struct iphdr *ip = data + l3;
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        to_stack = is_broadcast_ip4(ip->daddr);
        proto = ETH_IPV4;
    } else {
        const struct ipv6hdr *ip6 = data + l3;
        if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;
        to_stack = is_broadcast_ip6(ip6->daddr.in6_u.u6_addr8);
        proto = ETH_IPV6;
    }

    /* A single VLAN tag can live entirely in metadata. Nest and remove two
     * tags so the kernel rereads the rewritten EtherType into skb->protocol. */
    if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &proto, sizeof(proto), 0))
        return TC_ACT_SHOT;
    if (bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), 0)) return TC_ACT_SHOT;
    if (bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), 0)) return TC_ACT_SHOT;
    if (bpf_skb_vlan_pop(skb)) return TC_ACT_SHOT;
    if (bpf_skb_vlan_pop(skb)) return TC_ACT_SHOT;
    if (bpf_skb_adjust_room(skb, -(int)sizeof(*ppp), BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO))
        return TC_ACT_SHOT;

    if (to_stack) return TC_ACT_OK;
    bpf_tail_call(skb, &tc_pipe_root_progs, root);
    return TC_ACT_SHOT;
}

static __always_inline void tc_intro_dispatch(struct __sk_buff *skb, u64 key) {
    u32 root = wan_trie_resolve(wan_trie_table(&wan_trie_arena), key);
    if (root) {
        bpf_tail_call(skb, &tc_pipe_root_progs, root);
    }
}

SEC("tc/ingress")
int tc_wan_ingress_intro(struct __sk_buff *skb) {
    int handoff_ret = xdp_handoff_check(skb, false);
    if (handoff_ret != TC_ACT_OK) return handoff_ret;

    if (current_l3_offset == sizeof(struct ethhdr) && skb->protocol == ETH_P_PPP_SES)
        return tc_intro_pppoe(skb);

    u64 key64 = 0;
    bool is_ipv4;
    int ret;

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (ret != TC_ACT_OK) return TC_ACT_OK;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    if (is_ipv4) {
        if ((u64)current_l3_offset + sizeof(struct iphdr) > MAX_OFFSET) return TC_ACT_OK;
        struct iphdr *iph = (struct iphdr *)(data + current_l3_offset);
        if ((char *)(iph + 1) > data_end) {
            __u32 need = current_l3_offset + sizeof(*iph);
            if (bpf_skb_pull_data(skb, need) != 0) return TC_ACT_OK;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            iph = (struct iphdr *)(data + current_l3_offset);
            if ((char *)(iph + 1) > data_end) return TC_ACT_OK;
        }

        if (unlikely(is_broadcast_ip4(iph->daddr))) {
            return TC_ACT_OK;
        }

        key64 = wan_trie_key_v4(iph->daddr);
    } else {
        if ((u64)current_l3_offset + sizeof(struct ipv6hdr) > MAX_OFFSET) return TC_ACT_OK;
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + current_l3_offset);
        if ((char *)(ip6h + 1) > data_end) {
            __u32 need = current_l3_offset + sizeof(*ip6h);
            if (bpf_skb_pull_data(skb, need) != 0) return TC_ACT_OK;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            ip6h = (struct ipv6hdr *)(data + current_l3_offset);
            if ((char *)(ip6h + 1) > data_end) return TC_ACT_OK;
        }

        if (unlikely(is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8))) {
            return TC_ACT_OK;
        }

        __builtin_memcpy(&key64, &ip6h->daddr, sizeof(key64));
    }

    // The trie is the only dispatch authority: WAN links publish their
    // v4/v6 (and PPP) keys before this program can see their traffic.
    tc_intro_dispatch(skb, key64);

    return TC_ACT_SHOT;
}

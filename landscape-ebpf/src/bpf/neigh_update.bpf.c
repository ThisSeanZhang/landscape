#include "vmlinux_wrapper.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "neigh_ip.h"

char LICENSE[] SEC("license") = "GPL";

#define NEIGH_UPDATE_F_OVERRIDE 0x01
#define NEIGH_UPDATE_F_WEAK_OVERRIDE 0x02

#define NUD_VALID (0x02 | 0x04 | 0x40 | 0x80)
#define NUD_FAILED 0x20

SEC("kprobe/neigh_update")
int BPF_KPROBE(kprobe_neigh_update, struct neighbour *n, const u8 *new_lladdr, u8 new_state,
               u32 update_flags, u32 pid) {
    if (!n) return 0;

    u64 bpf_update_flag = 0;
    if (update_flags & NEIGH_UPDATE_F_OVERRIDE) {
        bpf_update_flag = BPF_ANY;
    } else if (update_flags & NEIGH_UPDATE_F_WEAK_OVERRIDE) {
        bpf_update_flag = BPF_NOEXIST;
    } else {
        return 0;
    }

    struct net_device *dev = BPF_CORE_READ(n, dev);
    u32 ifindex = BPF_CORE_READ(dev, ifindex);
    u16 family = BPF_CORE_READ(n, ops, family);
    u8 old_state = BPF_CORE_READ(n, nud_state);

    if (family == AF_INET) {
        struct mac_key_v4 key = {};
        bpf_probe_read_kernel(&key.addr, sizeof(key.addr), n->primary_key);

        if (key.addr == 0) {
            bpf_printk("SKIP: IP is 0.0.0.0 | state: %d -> %d", old_state, new_state);
            return 0;
        }

        if (new_state & NUD_VALID) {
            struct mac_value_v4 value = {};
            value.ifindex = ifindex;
            value.proto = ETH_IPV4;

            if (new_lladdr) {
                bpf_probe_read_kernel(value.mac, 6, new_lladdr);
            } else {
                bpf_probe_read_kernel(value.mac, 6, n->ha);
            }

            u8 *src_mac_ptr = (u8 *)BPF_CORE_READ(dev, dev_addr);
            if (src_mac_ptr) {
                bpf_probe_read_kernel(value.dev_mac, 6, src_mac_ptr);
            }

            if (value.mac[0] != 0 || value.mac[1] != 0 || value.mac[5] != 0) {
                bpf_map_update_elem(&ip_mac_v4, &key, &value, bpf_update_flag);
                // bpf_printk("Update IP:%pI4", &key.addr);
                // PRINT_MAC_ADDR(value.mac);
            }
        } else if (new_state == NUD_FAILED) {
            bpf_map_delete_elem(&ip_mac_v4, &key);
        }

        // bpf_printk("neigh state change: %d -> %d", ctx->nud_state, ctx->new_state);

    } else if (family == AF_INET6) {
        struct mac_key_v6 key = {};
        bpf_probe_read_kernel(&key.addr, sizeof(key.addr), n->primary_key);

        if (is_broadcast_ip6(key.addr.bytes)) {
            return 0;
        }

        if (new_state & NUD_VALID) {
            struct mac_value_v6 value = {};
            value.ifindex = ifindex;
            value.proto = ETH_IPV6;

            if (new_lladdr) {
                bpf_probe_read_kernel(value.mac, 6, new_lladdr);
            } else {
                bpf_probe_read_kernel(value.mac, 6, n->ha);
            }

            u8 *src_mac_ptr = (u8 *)BPF_CORE_READ(dev, dev_addr);
            if (src_mac_ptr) {
                bpf_probe_read_kernel(value.dev_mac, 6, src_mac_ptr);
            }

            if (value.mac[0] != 0 || value.mac[1] != 0 || value.mac[5] != 0) {
                bpf_map_update_elem(&ip_mac_v6, &key, &value, bpf_update_flag);
                // bpf_printk("Update: IP is %pI6 | state: %d -> %d", key.addr.bytes,
                // ctx->nud_state, ctx->new_state);
                // bpf_printk("IP:%pI6 | Flags:0x%x | %d->%d", key.addr.bytes, ctx->update_flags,
                //            ctx->nud_state, ctx->new_state);
                // PRINT_MAC_ADDR(value.mac);
            }
        } else if (new_state == NUD_FAILED) {
            bpf_map_delete_elem(&ip_mac_v6, &key);
            // bpf_printk("MAP_DELETE: ip=%pI6 due to NUD_FAILED", &key.addr);
        }

        // bpf_printk("neigh state change: %d -> %d", ctx->nud_state, ctx->new_state);
    }

    return 0;
}

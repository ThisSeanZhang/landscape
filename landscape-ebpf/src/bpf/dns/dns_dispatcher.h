#ifndef __LD_DNS_DISPATCHER_H__
#define __LD_DNS_DISPATCHER_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

enum dns_listener_role {
    DNS_LISTENER_ROLE_UDP = 0,
    DNS_LISTENER_ROLE_DOH = 1,
    DNS_LISTENER_ROLE_TCP = 2,
    /* Reserved sentinel: never a real listener role. Used as the rodata
     * default so an unset role is rejected instead of aliasing UDP. */
    DNS_LISTENER_ROLE_INVALID = 3,
};

/* dns_flow_socks key layout:
 *   bits 31..8: dns_listener_role
 *   bits  7..0: flow_id
 *
 * Keep this in sync with DnsListenerRole::socket_key() in
 * landscape-common/src/flow/flow_socket_registrar.rs.
 */
#define DNS_FLOW_KEY_ROLE_SHIFT 8

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_flow_socks SEC(".maps");

#endif /* __LD_DNS_DISPATCHER_H__ */

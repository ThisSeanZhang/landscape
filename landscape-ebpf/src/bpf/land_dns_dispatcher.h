#ifndef __LD_DNS_DISPATCHER_H__
#define __LD_DNS_DISPATCHER_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_flow_socks SEC(".maps");

#endif /* __LD_DNS_DISPATCHER_H__ */
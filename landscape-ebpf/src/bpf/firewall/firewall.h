#ifndef __LD_FIREWALL_H__
#define __LD_FIREWALL_H__
#include <bpf/bpf_endian.h>

#include <vmlinux.h>
#include "../landscape_log.h"
#include "../landscape.h"

#define IPV4_FIREWALL_EGRESS_PROG_INDEX 0
#define IPV4_FIREWALL_INGRESS_PROG_INDEX 0
#define IPV6_FIREWALL_EGRESS_PROG_INDEX 1
#define IPV6_FIREWALL_INGRESS_PROG_INDEX 1

#endif /* __LD_FIREWALL_H__ */

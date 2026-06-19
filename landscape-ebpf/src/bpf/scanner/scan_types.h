#ifndef __LD_SCAN_TYPES_H__
#define __LD_SCAN_TYPES_H__

#include <vmlinux.h>

struct scan_ipv4_idx {
    u16 l4_offset;
    u16 fragment_off;
    u16 fragment_id;
    u8 l4_protocol;
    u8 fragment_type;
    u8 pkt_type;
    u16 icmp_error_l3_offset;
    u16 icmp_error_inner_l4_offset;
    u8 icmp_error_l4_protocol;
};

struct scan_ipv6_idx {
    u16 l4_offset;
    u16 fragment_off;
    u32 fragment_id;
    u8 l4_protocol;
    u8 fragment_type;
    u8 pkt_type;
    u16 icmp_error_l3_offset;
    u16 icmp_error_inner_l4_offset;
    u8 icmp_error_l4_protocol;
};

#endif /* __LD_SCAN_TYPES_H__ */

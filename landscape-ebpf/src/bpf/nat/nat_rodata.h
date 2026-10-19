#ifndef __NAT_RODATA_H__
#define __NAT_RODATA_H__

#include <vmlinux.h>

// WAN-side address/prefix baked into the NAT objects at load time.
// Zero means "unbound" and makes the lookup paths drop.

// WAN IPv4 address, network byte order; 0 = unbound.
const volatile u32 wan_ro_addr4 = 0;

// First 8 bytes of the WAN IPv6 prefix, network order. A real prefix never
// starts with 0, so b[0] == 0 means unbound.
//
// The u64 view is used by the NPT blend. Do NOT memcpy from this object:
// only volatile member access avoids compiler folding.
union wan_prefix6 {
    u8 b[8];
    u64 q;
};
const volatile union wan_prefix6 wan_ro_prefix6 = {{0}};

// Complete WAN-side IPv6 /128 (prefix + shared IID), network order;
// all-zero = unbound.
union wan_addr6 {
    u8 b[16];
    u64 q[2];
};
const volatile union wan_addr6 wan_ro_addr6 = {{0}};

// NPT mask: bits kept from the LAN address during prefix translation.
// 0 means /64 or longer (see compute_npt_mask).
const volatile u64 wan_ro_npt_mask = 0;

#endif /* __NAT_RODATA_H__ */

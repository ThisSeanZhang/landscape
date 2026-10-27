#ifndef __NAT_RODATA4_H__
#define __NAT_RODATA4_H__

#include <vmlinux.h>

// WAN-side address baked into the NAT objects at load time.
// Zero means "unbound" and makes the lookup paths drop.

// WAN IPv4 address, network byte order; 0 = unbound.
const volatile u32 wan_ro_addr4 = 0;

#endif /* __NAT_RODATA4_H__ */

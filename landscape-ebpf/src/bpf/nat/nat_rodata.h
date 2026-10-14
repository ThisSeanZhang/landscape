#ifndef __NAT_RODATA_H__
#define __NAT_RODATA_H__

#include <vmlinux.h>

// WAN-side address/prefix baked into the NAT objects' rodata at load
// time by the stage loaders (stages/nat4.rs / stages/nat6.rs).  They
// replace the runtime `wan_ip_binding` map lookups the NAT hot paths
// used to perform: the WAN address of a link changes together with a
// session rebuild, which reloads the objects anyway.
//
// Unconfigured objects keep the zero defaults; the lookups below treat
// zero as "no WAN address bound" and drop, matching the old map-miss
// semantics.

// The WAN IPv4 address in network byte order; 0 = unconfigured.
const volatile u32 wan_ro_addr4 = 0;

// The first 8 bytes (the /64-or-shorter prefix span) of the WAN IPv6
// prefix in network byte order.  A real WAN prefix (GUA 0x2x / ULA
// 0xfd) never starts with a zero byte, so prefix6.b[0] == 0 doubles as
// the unconfigured sentinel.
//
// The union gives a u64 view for the NPT blend; every member access on
// the volatile object is a genuine volatile read, so the compiler
// cannot constant-fold it.  Do NOT memcpy from &wan_ro_prefix6 — a
// builtin byte copy is not a volatile access and folds to the initial
// zeros.
union wan_prefix6 {
    u8 b[8];
    u64 q;
};
const volatile union wan_prefix6 wan_ro_prefix6 = {{0}};

// NPT mask: bits preserved from the LAN-side address during prefix
// translation (see compute_npt_mask on the loader side); 0 = /64+.
const volatile u64 wan_ro_npt_mask = 0;

#endif /* __NAT_RODATA_H__ */

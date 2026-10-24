// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_TC_NAT4_RODATA_H
#define LAND_NAT_TC_NAT4_RODATA_H

#include <vmlinux.h>

/* Single external IPv4 address in network byte order; zero disables NAT. */
const volatile __be32 land_nat_external_addr = 0;

/* Local dynamic port ranges in host byte order; zero means unconfigured. */
const volatile __u16 land_nat_udp_range_start = 0;
const volatile __u16 land_nat_udp_range_end = 0;
const volatile __u16 land_nat_tcp_range_start = 0;
const volatile __u16 land_nat_tcp_range_end = 0;

#endif /* LAND_NAT_TC_NAT4_RODATA_H */

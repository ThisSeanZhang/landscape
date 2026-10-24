/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_PRINTK_H
#define LAND_NAT_PRINTK_H

#include <bpf/bpf_helpers.h>

/*
 * Debug logging with the enclosing function name.
 *
 * bpf_printk() requires a literal format string, so __func__ cannot be
 * concatenated into it. It is passed as the first %s argument instead.
 *
 * __func__ is lexical: a call inside a static __always_inline helper prints
 * that helper's name, not the entry program it was inlined into. There is no
 * call frame to recover, so a helper shared by several paths (for example the
 * LAN and WAN directions) cannot name the path from the function alone.
 *
 * The function name costs one variadic slot. bpf_printk() selects
 * bpf_trace_printk() for up to three variadic arguments and
 * bpf_trace_vprintk() (Linux 5.16 and later) beyond that, so a call here gets
 * at most two payload arguments on the older helper. bpf_trace_vprintk()
 * accepts at most twelve variadic arguments in total, so the hard ceiling is
 * eleven payload arguments; libbpf fails to compile beyond it.
 */
#define ld_from_lan_log(fmt, ...) bpf_printk("<<[ld]<<[%s] " fmt, __func__, ##__VA_ARGS__)

#define ld_from_wan_log(fmt, ...) bpf_printk(">>[ld]>>[%s] " fmt, __func__, ##__VA_ARGS__)

#define ld_timer_log(fmt, ...) bpf_printk("[ld][cb][%s] " fmt, __func__, ##__VA_ARGS__)

#define ld_log(fmt, ...) bpf_printk("[ld][%s] " fmt, __func__, ##__VA_ARGS__)
#endif

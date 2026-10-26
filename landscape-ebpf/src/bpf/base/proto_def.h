#ifndef __LD_PROTO_DEF_H__
#define __LD_PROTO_DEF_H__

#include <vmlinux.h>
#include "base/landscape.h"

// RFC 8200 要求支持至少 6 个扩展头
#define LD_MAX_IPV6_EXT_NUM 6

// IPv6 Next Header protocol numbers (RFC 8200 / IANA)
#define NEXTHDR_HOP 0
#define NEXTHDR_TCP 6
#define NEXTHDR_UDP 17
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH 51
#define NEXTHDR_ICMP 58
#define NEXTHDR_DEST 60

// IPv6 fragment header field masks (RFC 8200)
#define IPV6_FRAG_OFFSET 0xFFF8
#define IPV6_FRAG_MF 0x0001

// ICMPv4 type values (RFC 792; see <linux/icmp.h>)
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11

// ICMPv6 type values (RFC 4443; see <linux/icmpv6.h>)
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG 2
#define ICMPV6_TIME_EXCEED 3
#define ICMPV6_PARAMPROB 4
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

#endif /* __LD_PROTO_DEF_H__ */

#ifndef __LD_PPPOE_DEF_H__
#define __LD_PPPOE_DEF_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

// PPPoE EtherTypes (RFC 2516) and PPP protocol ids (RFC 1661)
// ETH_P_PPP_DISC / ETH_P_PPP_SES may already be defined via linux/if_ether.h
#ifndef ETH_P_PPP_DISC
#define ETH_P_PPP_DISC bpf_htons(0x8863)
#endif
#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES bpf_htons(0x8864)
#endif
#define ETH_P_PPP_IPV4 bpf_htons(0x0021)
#define ETH_P_PPP_IPV6 bpf_htons(0x0057)

// PPPoE session header (RFC 2516)
struct __attribute__((packed)) pppoe_header {
    u8 version_and_type;
    u8 code;
    __be16 session_id;
    __be16 length;
    __be16 protocol;
};

#endif /* __LD_PPPOE_DEF_H__ */

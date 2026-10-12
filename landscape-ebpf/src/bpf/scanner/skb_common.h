#ifndef __LD_SKB_SCANNER_COMMON_H__
#define __LD_SKB_SCANNER_COMMON_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"
#include "base/pkg_def.h"
#include "einat/einat_helpers.h"
#include "scanner/scan_types.h"

enum land_scan_result {
    LD_SCAN_OK = 0,
    LD_SCAN_ERR = 2,
    LD_SCAN_UNSPEC = -1,
};

enum packet_scan_depth {
    LD_SCAN_DEPTH_NONE = 0,
    LD_SCAN_DEPTH_PROTO = 1,
    LD_SCAN_DEPTH_L3 = 2,
    LD_SCAN_DEPTH_FULL = 3,
};

struct ip_scanner_ctx {
    u8 l4_protocol;
    u8 fragment_type;
    u16 fragment_off;
    u16 fragment_id;
    u16 l4_offset;
};

#endif /* __LD_SKB_SCANNER_COMMON_H__ */
